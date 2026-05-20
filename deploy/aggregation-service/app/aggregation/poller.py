"""SIEM Alert Poller — polls SIEM API for unacknowledged alerts on a schedule."""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

from app.ingestion.models import RawAlert
from app.ingestion.normalizer import Normalizer
from app.ingestion.dedup import DedupAggregator
from app.aggregation.models import Event, EventSource
from app.aggregation.siem_client import SiemClient

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = float(os.environ.get("SOC_POLL_INTERVAL", "60"))
PAGE_SIZE = int(os.environ.get("SOC_POLL_PAGE_SIZE", "100"))


class SiemPoller:
    """Polls the SIEM alert query API, normalizes and aggregates alerts,
    and produces Events for AI Agent consumption."""

    def __init__(
        self,
        siem_client: SiemClient | None = None,
        normalizer: Normalizer | None = None,
        aggregator: DedupAggregator | None = None,
    ):
        self._siem = siem_client or SiemClient()
        self._normalizer = normalizer or Normalizer()
        self._aggregator = aggregator or DedupAggregator()
        self._last_poll: str | None = None  # ISO8601 timestamp
        self._authenticated = False

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
        if not self._authenticated:
            try:
                await self._siem.authenticate()
            except Exception:
                logger.exception("SIEM authentication failed")
                return []
            self._authenticated = True

        all_alerts: list[RawAlert] = []
        page = 0

        while True:
            data = await self._siem.fetch_page(page=page, size=PAGE_SIZE, since=self._last_poll)
            items = data.get("items", [])
            if not items:
                break

            all_alerts.extend(items)

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
