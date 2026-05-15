"""SIEM Alert Poller — polls SIEM API for unacknowledged alerts on a schedule."""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

import httpx

from app.ingestion.models import RawAlert
from app.ingestion.normalizer import Normalizer
from app.ingestion.dedup import DedupAggregator
from app.aggregation.models import Event, EventSource

logger = logging.getLogger(__name__)

SIEM_API_BASE = os.environ.get("SIEM_API_BASE", "http://siem:8080")
SIEM_API_KEY = os.environ.get("SIEM_API_KEY", "")
POLL_INTERVAL_SECONDS = float(os.environ.get("SOC_POLL_INTERVAL", "60"))
PAGE_SIZE = int(os.environ.get("SOC_POLL_PAGE_SIZE", "100"))


class SiemPoller:
    """Polls the SIEM alert query API, normalizes and aggregates alerts,
    and produces Events for AI Agent consumption."""

    def __init__(
        self,
        normalizer: Normalizer | None = None,
        aggregator: DedupAggregator | None = None,
    ):
        self._normalizer = normalizer or Normalizer()
        self._aggregator = aggregator or DedupAggregator()
        self._last_poll: str | None = None  # ISO8601 timestamp

    async def poll(self) -> list[Event]:
        """Fetch unacknowledged alerts from SIEM, aggregate, and return Events."""
        raw_alerts = await self._fetch_alerts()
        if not raw_alerts:
            return []

        # ── Normalize all fetched alerts ────────────────────────────────
        normalized = []
        for raw in raw_alerts:
            try:
                n = self._normalizer.normalize(raw, source="siem_poller")
                normalized.append(n)
            except Exception:
                logger.exception("Normalization failed for alarm_id=%s", raw.alarm_id)

        # ── Run through dedup + aggregation as a batch ───────────────────
        # Process all alerts through the aggregator. When alerts are merged,
        # the aggregated result supersedes individual ones. We keep only the
        # latest result for each alarm_id (the most merged version).
        results_by_alarm: dict[str, Event] = {}
        for alert in normalized:
            aggregated = self._aggregator.process(alert)
            if aggregated is not None:
                event = self._to_event(aggregated)
                # Index by all source alarm_ids — later entries overwrite earlier ones
                for src in event.source_alarms:
                    if src.alarm_id:
                        results_by_alarm[src.alarm_id] = event

        # Deduplicate: same Event object may be keyed by multiple alarm_ids
        seen_ids: set[int] = set()
        unique_events: list[Event] = []
        for event in results_by_alarm.values():
            if id(event) not in seen_ids:
                seen_ids.add(id(event))
                unique_events.append(event)

        logger.info(
            "Poll cycle: fetched=%d normalized=%d events=%d",
            len(raw_alerts), len(normalized), len(unique_events),
        )
        return unique_events

    async def _fetch_alerts(self) -> list[RawAlert]:
        """Fetch unacknowledged alerts from SIEM API with pagination."""
        all_alerts: list[RawAlert] = []
        page = 0
        since = self._last_poll

        async with httpx.AsyncClient(timeout=30.0, trust_env=False) as client:
            while True:
                params: dict = {"page": page, "size": PAGE_SIZE, "status": "unacknowledged"}
                if since:
                    params["since"] = since

                try:
                    resp = await client.get(
                        f"{SIEM_API_BASE}/api/v1/alerts",
                        params=params,
                        headers={"Authorization": f"Bearer {SIEM_API_KEY}"} if SIEM_API_KEY else {},
                    )
                    if resp.status_code == 404 or resp.status_code == 204:
                        break
                    resp.raise_for_status()
                    data = resp.json()
                except httpx.ConnectError:
                    logger.warning("SIEM API unreachable at %s", SIEM_API_BASE)
                    return []
                except Exception:
                    logger.exception("SIEM API request failed")
                    return []

                items = data.get("items", data.get("alerts", []))
                if not items:
                    break

                for item in items:
                    try:
                        # Adapt SIEM response into our RawAlert format
                        all_alerts.append(RawAlert(
                            alarm_id=item.get("id", item.get("alarm_id", "")),
                            alert_time=item.get("created_at", item.get("alert_time", self._now_iso())),
                            defense_line=item.get("defense_line", "endpoint"),
                            alert_name=item.get("name", item.get("alert_name", "unknown")),
                            raw_evidence=item.get("raw_evidence", item.get("evidence", {})),
                        ))
                    except Exception:
                        logger.exception("Failed to parse SIEM alert item")

                if len(items) < PAGE_SIZE:
                    break
                page += 1

        self._last_poll = self._now_iso()
        return all_alerts

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _to_event(alert) -> Event:
        """Convert an aggregated NormalizedAlert into an Event."""
        # Merge fingerprint-deduped evidence into per_alarm
        evidence = dict(alert.raw_evidence)
        if alert.deduped_evidence:
            per = evidence.setdefault("per_alarm", {})
            for alarm_id, ev in alert.deduped_evidence.items():
                per[alarm_id] = ev

        if alert.aggregation:
            sources = [
                EventSource(alarm_id=s["alarm_id"], alert_name=s.get("alert_name", alert.alert_name), alert_time=alert.created_at)
                for s in alert.aggregation.get("source_alarms", [])
            ]
            return Event(
                defense_line=alert.defense_line,
                alert_name=alert.alert_name,
                alert_type=alert.type,
                severity=alert.severity,
                source_alarms=sources or [
                    EventSource(alarm_id=alert.alarm_id or alert.id, alert_name=alert.alert_name, alert_time=alert.created_at)
                ],
                deduped_alarm_ids=list(alert.deduped_alarm_ids),
                entity_overlap=alert.aggregation.get("entity_overlap", 1.0),
                occurrence_count=len(sources),
                entities=[{"type": e.type, "value": e.value} for e in alert.entities],
                raw_evidence=evidence,
                created_at=alert.created_at,
            )
        else:
            return Event(
                defense_line=alert.defense_line,
                alert_name=alert.alert_name,
                alert_type=alert.type,
                severity=alert.severity,
                source_alarms=[
                    EventSource(alarm_id=alert.alarm_id or alert.id, alert_name=alert.alert_name, alert_time=alert.created_at)
                ],
                deduped_alarm_ids=list(alert.deduped_alarm_ids),
                entity_overlap=0.0,
                occurrence_count=1,
                entities=[{"type": e.type, "value": e.value} for e in alert.entities],
                raw_evidence=evidence,
                created_at=alert.created_at,
            )
