"""Tests for dedup aggregator — fingerprint dedup and entity-based aggregation."""

from app.ingestion.models import AggregatedAlert, Entity, NormalizedAlert

# ── Helpers ─────────────────────────────────────────────────────────────────────


def make_alert(
    alarm_id: str,
    fingerprint: str,
    entities: list[Entity],
    defense_line: str = "endpoint",
    severity: str = "high",
    alert_time: str = "2026-05-10T14:32:00Z",
) -> NormalizedAlert:
    """Build a minimal NormalizedAlert for test convenience."""
    return NormalizedAlert(
        id=f"uuid-{alarm_id}",
        source="siem_splunk",
        defense_line=defense_line,
        alert_name="TestAlert",
        type="malware",
        severity=severity,
        entities=entities,
        fingerprint=fingerprint,
        alarm_id=alarm_id,
        deduped_alarm_ids=[],
        raw_evidence={"src_ip": "10.0.0.1"},
        created_at=alert_time,
    )


# ── TestFingerprintDedup ────────────────────────────────────────────────────────


class TestFingerprintDedup:
    """Fingerprint-based dedup discards exact duplicates within the time window."""

    def test_first_alert_passes_through(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(window_seconds=600)
        entities = [Entity(type="ip", value="10.0.0.1")]
        alert = make_alert("alarm-1", "fp-001", entities)

        result = agg.process(alert)

        assert result is alert, "First alert with a new fingerprint should pass through unchanged"

    def test_duplicate_fingerprint_deduped(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(window_seconds=600)
        entities = [Entity(type="ip", value="10.0.0.1")]

        alert1 = make_alert("alarm-1", "fp-001", entities)
        alert2 = make_alert("alarm-2", "fp-001", entities)

        result1 = agg.process(alert1)
        result2 = agg.process(alert2)

        assert result1 is alert1
        assert result2 is None, "Duplicate fingerprint should be deduped (return None)"

    def test_deduped_id_appended_to_first_alert(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(window_seconds=600)
        entities = [Entity(type="ip", value="10.0.0.1")]

        alert1 = make_alert("alarm-1", "fp-001", entities)
        alert2 = make_alert("alarm-2", "fp-001", entities)

        agg.process(alert1)
        agg.process(alert2)

        # After dedup, alert1's deduped_alarm_ids should contain alert2's alarm_id
        assert "alarm-2" in alert1.deduped_alarm_ids, (
            "The deduped alarm_id should be appended to the first alert's deduped_alarm_ids"
        )

    def test_different_fingerprints_not_deduped(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(window_seconds=600)

        # Use different entities so aggregation does not pick them up either
        alert1 = make_alert(
            "alarm-1", "fp-001", [Entity(type="ip", value="10.0.0.1")]
        )
        alert2 = make_alert(
            "alarm-2", "fp-002", [Entity(type="host", value="host-B")]
        )

        result1 = agg.process(alert1)
        result2 = agg.process(alert2)

        assert result1 is alert1
        assert result2 is alert2, "Different fingerprints should both pass through"

    def test_window_expiry_resets_fingerprint(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(window_seconds=0)
        entities = [Entity(type="ip", value="10.0.0.1")]

        # Use different defense_lines so aggregation does not merge them
        alert1 = make_alert("alarm-1", "fp-001", entities, defense_line="endpoint")
        alert2 = make_alert("alarm-2", "fp-001", entities, defense_line="network")

        result1 = agg.process(alert1)
        result2 = agg.process(alert2)

        # window_seconds=0 means every entry expires immediately,
        # so the second alert with the same fingerprint is treated as new
        assert result1 is alert1
        assert result2 is alert2, "With window_seconds=0, same fingerprint should not be deduped"


# ── TestEntityAggregation ───────────────────────────────────────────────────────


class TestEntityAggregation:
    """Entity-based aggregation merges similar alerts within the same defense line."""

    def test_high_overlap_aggregates(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(entity_overlap_threshold=0.75)

        # 4 entities vs 3 overlapping = 3/4 = 0.75 Jaccard
        entities1 = [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="ip", value="10.0.0.2"),
            Entity(type="host", value="host-A"),
            Entity(type="user", value="admin"),
        ]
        entities2 = [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="ip", value="10.0.0.2"),
            Entity(type="host", value="host-A"),
        ]

        alert1 = make_alert("alarm-1", "fp-001", entities1)
        alert2 = make_alert("alarm-2", "fp-002", entities2)

        result1 = agg.process(alert1)
        result2 = agg.process(alert2)

        assert result1 is alert1, "First alert should pass through"
        assert isinstance(result2, AggregatedAlert), (
            "Second alert with >=75% entity overlap should produce an AggregatedAlert"
        )

    def test_low_overlap_does_not_aggregate(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(entity_overlap_threshold=0.75)

        # Completely disjoint entities → Jaccard = 0
        entities1 = [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="host", value="host-A"),
        ]
        entities2 = [
            Entity(type="ip", value="10.0.0.99"),
            Entity(type="host", value="host-B"),
            Entity(type="user", value="bob"),
        ]

        alert1 = make_alert("alarm-1", "fp-001", entities1)
        alert2 = make_alert("alarm-2", "fp-002", entities2)

        result1 = agg.process(alert1)
        result2 = agg.process(alert2)

        assert result1 is alert1
        assert result2 is alert2, "Low overlap should return alert as-is"
        assert not isinstance(result2, AggregatedAlert)

    def test_different_defense_lines_not_aggregated(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(entity_overlap_threshold=0.5)

        entities = [Entity(type="ip", value="10.0.0.1")]

        alert1 = make_alert("alarm-1", "fp-001", entities, defense_line="endpoint")
        alert2 = make_alert("alarm-2", "fp-002", entities, defense_line="network")

        result1 = agg.process(alert1)
        result2 = agg.process(alert2)

        assert result1 is alert1
        assert result2 is alert2, "Different defense lines should not aggregate"
        assert not isinstance(result2, AggregatedAlert)

    def test_aggregation_max_severity(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(entity_overlap_threshold=0.5)

        entities = [Entity(type="ip", value="10.0.0.1")]

        alert1 = make_alert("alarm-1", "fp-001", entities, severity="medium")
        alert2 = make_alert("alarm-2", "fp-002", entities, severity="critical")

        agg.process(alert1)
        result2 = agg.process(alert2)

        assert isinstance(result2, AggregatedAlert)
        assert result2.severity == "critical", (
            "Aggregated severity should be the maximum among all group alerts"
        )

    def test_aggregation_max_limit(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(entity_overlap_threshold=0.5, max_aggregation_size=2)

        entities = [Entity(type="ip", value="10.0.0.1")]

        alert1 = make_alert("alarm-1", "fp-001", entities)
        alert2 = make_alert("alarm-2", "fp-002", entities)
        alert3 = make_alert("alarm-3", "fp-003", entities)

        result1 = agg.process(alert1)
        result2 = agg.process(alert2)
        result3 = agg.process(alert3)

        assert result1 is alert1
        assert isinstance(result2, AggregatedAlert), "Second alert should aggregate (group size=2)"
        # Group is now full (size=2), so alert3 starts a new group
        assert result3 is alert3, "Third alert should start a new group when limit reached"
        assert not isinstance(result3, AggregatedAlert)


# ── TestAggregatedAlertFields ───────────────────────────────────────────────────


class TestAggregatedAlertFields:
    """Verify the structure of AggregatedAlert returned from the aggregation stage."""

    def test_aggregation_metadata(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(entity_overlap_threshold=0.5)

        # 3 vs 2 overlapping entities = 2/3 ≈ 0.667 Jaccard >= 0.5
        entities1 = [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="host", value="host-A"),
            Entity(type="user", value="admin"),
        ]
        entities2 = [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="host", value="host-A"),
        ]

        alert1 = make_alert("alarm-1", "fp-001", entities1)
        alert2 = make_alert("alarm-2", "fp-002", entities2)

        agg.process(alert1)
        result = agg.process(alert2)

        assert isinstance(result, AggregatedAlert)
        assert result.alarm_id is None, "AggregatedAlert alarm_id should be None"
        assert result.aggregation is not None
        assert "entity_overlap" in result.aggregation
        assert "time_delta_seconds" in result.aggregation
        assert "source_alarms" in result.aggregation
        assert isinstance(result.aggregation["source_alarms"], list)
        assert len(result.aggregation["source_alarms"]) == 2

    def test_aggregation_entity_union(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(entity_overlap_threshold=0.5)

        # 3 vs 2 entities with 2 overlapping = 2/3 ≈ 0.667 Jaccard >= 0.5
        entities1 = [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="host", value="host-A"),
            Entity(type="user", value="admin"),
        ]
        entities2 = [
            Entity(type="ip", value="10.0.0.1"),  # duplicate (overlapping)
            Entity(type="host", value="host-A"),  # duplicate (overlapping)
        ]

        alert1 = make_alert("alarm-1", "fp-001", entities1)
        alert2 = make_alert("alarm-2", "fp-002", entities2)

        agg.process(alert1)
        result = agg.process(alert2)

        assert isinstance(result, AggregatedAlert)
        entity_values = {(e.type, e.value) for e in result.entities}
        assert ("ip", "10.0.0.1") in entity_values
        assert ("host", "host-A") in entity_values
        assert ("user", "admin") in entity_values
        # 3 unique entities (ip and host deduplicated in union)
        assert len(result.entities) == 3

    def test_aggregation_fingerprint_prefix(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(entity_overlap_threshold=0.5)

        entities = [Entity(type="ip", value="10.0.0.1")]

        alert1 = make_alert("alarm-1", "fp-001", entities)
        alert2 = make_alert("alarm-2", "fp-002", entities)

        agg.process(alert1)
        result = agg.process(alert2)

        assert isinstance(result, AggregatedAlert)
        assert result.fingerprint.startswith("merged:"), (
            "AggregatedAlert fingerprint should start with 'merged:'"
        )

    def test_time_delta_exceeds_window_does_not_aggregate(self):
        from app.ingestion.dedup import DedupAggregator

        da = DedupAggregator(entity_overlap_threshold=0.75, aggregation_time_window_seconds=300)
        a1 = make_alert("a1", "fp1", [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="hash", value="abc"),
        ], alert_time="2026-05-10T14:30:00Z")
        da.process(a1)
        a2 = make_alert("a2", "fp2", [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="hash", value="abc"),
        ], alert_time="2026-05-10T14:36:00Z")  # 6 minutes later

        result = da.process(a2)
        assert result is not None
        assert result.aggregation is None  # NOT aggregated, time delta exceeded

    def test_aggregation_raw_evidence_split(self):
        from app.ingestion.dedup import DedupAggregator

        agg = DedupAggregator(entity_overlap_threshold=0.5)

        alert1 = make_alert(
            "alarm-1", "fp-001",
            [Entity(type="ip", value="10.0.0.1")],
            alert_time="2026-05-10T14:32:00Z",
        )
        # Override raw_evidence for this test
        alert1.raw_evidence = {"src_ip": "10.0.0.1", "alert_type": "scan"}

        alert2 = make_alert(
            "alarm-2", "fp-002",
            [Entity(type="ip", value="10.0.0.1")],
            alert_time="2026-05-10T14:32:10Z",
        )
        alert2.raw_evidence = {"src_ip": "10.0.0.1", "alert_type": "exploit"}

        agg.process(alert1)
        result = agg.process(alert2)

        assert isinstance(result, AggregatedAlert)
        raw = result.raw_evidence
        assert "common" in raw
        assert "per_alarm" in raw
        # src_ip is same in both → common
        assert raw["common"]["src_ip"] == "10.0.0.1"
        # alert_type differs → per_alarm
        assert "alarm-1" in raw["per_alarm"]
        assert "alarm-2" in raw["per_alarm"]
        assert raw["per_alarm"]["alarm-1"]["alert_type"] == "scan"
        assert raw["per_alarm"]["alarm-2"]["alert_type"] == "exploit"
