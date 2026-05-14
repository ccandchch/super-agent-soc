"""Deduplication and aggregation engine for normalized alerts.

Two-stage pipeline:
1. Fingerprint dedup — discard exact duplicates within a time window.
2. Entity-based aggregation — merge similar alerts into groups.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.ingestion.models import AggregatedAlert, Entity, NormalizedAlert

SEVERITY_ORDER: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# ── Internal tracking structures ───────────────────────────────────────────────


@dataclass
class _DedupEntry:
    """Tracks a fingerprint's first occurrence within the dedup window."""

    first_alert: NormalizedAlert
    first_seen_time: float  # time.monotonic() timestamp
    count: int = 1
    alarm_ids_set: set[str] = field(default_factory=set)


@dataclass
class _AggGroup:
    """Tracks an aggregation group of related alerts sharing entity overlap."""

    alerts: list[NormalizedAlert]
    defense_line: str
    first_seen_time: float  # time.monotonic() timestamp
    entity_set: set[tuple[str, str]]  # accumulated (type, value) union


# ── ISO 8601 time helpers ─────────────────────────────────────────────────────


def _parse_iso(iso_str: str) -> datetime:
    """Parse an ISO 8601 string into a timezone-aware datetime.

    Handles both ``2026-05-10T14:32:00Z`` and ``2026-05-10T14:32:00`` formats.
    Missing timezone is assumed UTC.
    """
    normalized = iso_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _time_delta_seconds(iso1: str, iso2: str) -> float:
    """Return absolute time delta in seconds between two ISO 8601 strings."""
    t1 = _parse_iso(iso1)
    t2 = _parse_iso(iso2)
    return abs((t2 - t1).total_seconds())


# ── DedupAggregator ───────────────────────────────────────────────────────────


class DedupAggregator:
    """Two-stage deduplication and aggregation engine for normalized alerts.

    Stage 1 — Fingerprint dedup:
        Alerts with identical content fingerprints within *window_seconds* are
        considered duplicates.  The duplicate is discarded (``process()`` returns
        ``None``) and its ``alarm_id`` is appended to the first alert's
        ``deduped_alarm_ids``.

    Stage 2 — Entity-based aggregation:
        Alerts in the same *defense_line* with Jaccard entity overlap above
        *entity_overlap_threshold* are merged into an ``AggregatedAlert``.
        Groups are capped at *max_aggregation_size*.
    """

    def __init__(
        self,
        window_seconds: float = 600,
        entity_overlap_threshold: float = 0.55,
        aggregation_time_window_seconds: float = 300,
        max_aggregation_size: int = 10,
    ):
        self.window_seconds = window_seconds
        self.entity_overlap_threshold = entity_overlap_threshold
        self.aggregation_time_window_seconds = aggregation_time_window_seconds
        self.max_aggregation_size = max_aggregation_size

        self._fp_registry: dict[str, _DedupEntry] = {}
        self._agg_groups: dict[str, _AggGroup] = {}

    # ── Public API ──────────────────────────────────────────────────────────

    def process(self, alert: NormalizedAlert) -> NormalizedAlert | None:
        """Process a normalized alert through both dedup and aggregation stages.

        Returns:
            The alert (or aggregated alert) if it should proceed, or ``None`` if
            it was deduplicated and should be discarded.
        """
        # ── Stage 1: Fingerprint dedup ──────────────────────────────────────
        self._clean_expired_fingerprints()

        existing = self._fp_registry.get(alert.fingerprint)
        if existing is not None:
            if alert.alarm_id:
                existing.first_alert.deduped_alarm_ids.append(alert.alarm_id)
                existing.alarm_ids_set.add(alert.alarm_id)
            existing.count += 1
            return None

        # New fingerprint — register it
        self._fp_registry[alert.fingerprint] = _DedupEntry(
            first_alert=alert,
            first_seen_time=time.monotonic(),
            alarm_ids_set={alert.alarm_id} if alert.alarm_id else set(),
        )

        # ── Stage 2: Entity-based aggregation ───────────────────────────────
        self._clean_expired_agg_groups()

        group = self._find_matching_agg_group(alert)
        if group is not None:
            group.alerts.append(alert)
            alert_entities = {(e.type, e.value) for e in alert.entities}
            group.entity_set |= alert_entities

            if len(group.alerts) > 1:
                return self._build_aggregated(group)

        # No matching group — start a new one (keyed by defense_line:alarm_id)
        if alert.alarm_id is None:
            return alert

        key = f"{alert.defense_line}:{alert.alarm_id}"
        self._agg_groups[key] = _AggGroup(
            alerts=[alert],
            defense_line=alert.defense_line,
            first_seen_time=time.monotonic(),
            entity_set={(e.type, e.value) for e in alert.entities},
        )
        return alert

    # ── Fingerprint housekeeping ────────────────────────────────────────────

    def _clean_expired_fingerprints(self) -> None:
        """Remove fingerprint entries whose window has elapsed."""
        now = time.monotonic()
        expired = [
            fp
            for fp, entry in self._fp_registry.items()
            if now - entry.first_seen_time > self.window_seconds
        ]
        for fp in expired:
            del self._fp_registry[fp]

    # ── Aggregation housekeeping ────────────────────────────────────────────

    def _clean_expired_agg_groups(self) -> None:
        """Remove aggregation groups whose time window has elapsed."""
        now = time.monotonic()
        expired = [
            key
            for key, group in self._agg_groups.items()
            if now - group.first_seen_time > self.aggregation_time_window_seconds
        ]
        for key in expired:
            del self._agg_groups[key]

    def _find_matching_agg_group(self, alert: NormalizedAlert) -> _AggGroup | None:
        """Return the first aggregation group that matches *alert*, or ``None``."""
        alert_entities = {(e.type, e.value) for e in alert.entities}

        for group in self._agg_groups.values():
            # Must be in same defense line
            if group.defense_line != alert.defense_line:
                continue

            # Full groups cannot accept more alerts
            if len(group.alerts) >= self.max_aggregation_size:
                continue

            # Jaccard similarity on entity (type, value) tuples
            intersection = alert_entities & group.entity_set
            union = alert_entities | group.entity_set
            if not union:
                continue

            jaccard = len(intersection) / len(union)
            if jaccard >= self.entity_overlap_threshold:
                if _time_delta_seconds(alert.created_at, group.alerts[0].created_at) > self.aggregation_time_window_seconds:
                    continue
                return group

        return None

    # ── AggregatedAlert construction ────────────────────────────────────────

    def _build_aggregated(self, group: _AggGroup) -> AggregatedAlert:
        """Build an AggregatedAlert from all alerts in the group."""
        rep = group.alerts[0]

        # Severity: maximum among all group members
        severity = max(
            group.alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 0)
        ).severity

        # Entities: sorted union of (type, value) across all alerts
        entities = sorted(
            [Entity(type=t, value=v) for t, v in group.entity_set],
            key=lambda e: (e.type, e.value),
        )

        # Fingerprint: composite of representative's fingerprint
        fingerprint = f"merged:{rep.fingerprint}"

        # Source alarm list for traceability
        source_alarms = [
            {"alarm_id": a.alarm_id, "alert_name": a.alert_name}
            for a in group.alerts
        ]

        # Entity overlap metric (rep vs full group union)
        rep_entities = {(e.type, e.value) for e in rep.entities}
        rep_intersection = rep_entities & group.entity_set
        rep_union = rep_entities | group.entity_set
        entity_overlap = len(rep_intersection) / len(rep_union) if rep_union else 1.0

        # Time delta between earliest and latest alert in the group
        time_delta = _time_delta_seconds(
            group.alerts[0].created_at,
            group.alerts[-1].created_at,
        )

        aggregation = {
            "entity_overlap": round(entity_overlap, 4),
            "time_delta_seconds": round(time_delta, 2),
            "source_alarms": source_alarms,
        }

        # Split raw_evidence into fields common across all alerts vs per-alarm
        raw_evidence = self._split_raw_evidence(group)

        # All non-representative alarm IDs are considered deduped into this alert
        deduped_alarm_ids = [a.alarm_id for a in group.alerts if a.alarm_id]

        return AggregatedAlert(
            source=rep.source,
            defense_line=rep.defense_line,
            alert_name=rep.alert_name,
            type=rep.type,
            severity=severity,
            entities=entities,
            fingerprint=fingerprint,
            alarm_id=None,
            deduped_alarm_ids=deduped_alarm_ids,
            aggregation=aggregation,
            raw_evidence=raw_evidence,
            created_at=rep.created_at,
        )

    def _split_raw_evidence(self, group: _AggGroup) -> dict:
        """Split raw_evidence into common (same across all) and per_alarm (differs).

        Returns a dict with structure::

            {"common": {...}, "per_alarm": {alarm_id: {...}}}
        """
        # Collect all field keys across all alerts
        all_keys: set[str] = set()
        for a in group.alerts:
            all_keys.update(a.raw_evidence.keys())

        common: dict = {}
        per_alarm: dict = {}

        for key in all_keys:
            values = [a.raw_evidence.get(key) for a in group.alerts]
            first_val = values[0]

            if all(v == first_val for v in values):
                common[key] = first_val
            else:
                for a in group.alerts:
                    if key in a.raw_evidence and a.alarm_id:
                        per_alarm.setdefault(a.alarm_id, {})[key] = a.raw_evidence[key]

        return {"common": common, "per_alarm": per_alarm}
