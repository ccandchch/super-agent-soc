"""Tests for alert ingestion data models — RawAlert, NormalizedAlert, AggregatedAlert."""

import pytest
from pydantic import ValidationError

from app.ingestion.models import AggregatedAlert, DefenseLine, Entity, NormalizedAlert, RawAlert

# ── TestRawAlert ───────────────────────────────────────────────────────────────


def test_valid_raw_alert():
    """Create a RawAlert with all required fields and verify alarm_id and defense_line."""
    alert = RawAlert(
        alarm_id="alarm-001",
        alert_time="2026-05-10T12:00:00Z",
        defense_line="endpoint",
        alert_name="Suspicious PowerShell Execution",
    )
    assert alert.alarm_id == "alarm-001"
    assert alert.defense_line == DefenseLine.endpoint
    assert alert.raw_evidence == {}


def test_invalid_defense_line_rejected():
    """Passing an invalid defense_line value should raise ValidationError."""
    with pytest.raises(ValidationError):
        RawAlert(
            alarm_id="alarm-001",
            alert_time="2026-05-10T12:00:00Z",
            defense_line="invalid_line",
            alert_name="Test Alert",
        )


def test_missing_alarm_id_rejected():
    """Missing alarm_id should raise ValidationError."""
    with pytest.raises(ValidationError):
        RawAlert(
            alert_time="2026-05-10T12:00:00Z",
            defense_line="endpoint",
            alert_name="Test Alert",
        )


def test_raw_evidence_defaults_to_empty_dict():
    """raw_evidence should default to an empty dict when not provided."""
    alert = RawAlert(
        alarm_id="alarm-002",
        alert_time="2026-05-10T12:00:00Z",
        defense_line="network",
        alert_name="Suspicious Outbound Connection",
    )
    assert alert.raw_evidence == {}


def test_raw_evidence_accepts_custom_data():
    """raw_evidence should accept and store arbitrary key-value data."""
    evidence = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.100", "port": 443}
    alert = RawAlert(
        alarm_id="alarm-003",
        alert_time="2026-05-10T12:00:00Z",
        defense_line="network",
        alert_name="Test",
        raw_evidence=evidence,
    )
    assert alert.raw_evidence == evidence
    assert alert.raw_evidence["src_ip"] == "10.0.0.1"


# ── TestDefenseLine ────────────────────────────────────────────────────────────


def test_defense_line_values():
    """DefenseLine should contain all expected values."""
    expected = {"endpoint", "server", "application", "network", "email", "account"}
    actual = set(DefenseLine)
    assert actual == expected


def test_defense_line_string_equality():
    """DefenseLine enum members should equal their string values."""
    assert DefenseLine.endpoint == "endpoint"
    assert DefenseLine.server == "server"
    assert DefenseLine.application == "application"


# ── TestEntity ─────────────────────────────────────────────────────────────────


def test_entity_creation():
    """Entity should hold type and value fields."""
    entity = Entity(type="ip", value="10.0.0.1")
    assert entity.type == "ip"
    assert entity.value == "10.0.0.1"


def test_entity_missing_type_rejected():
    """Missing type should raise ValidationError."""
    with pytest.raises(ValidationError):
        Entity(value="10.0.0.1")


def test_entity_missing_value_rejected():
    """Missing value should raise ValidationError."""
    with pytest.raises(ValidationError):
        Entity(type="ip")


# ── TestNormalizedAlert ────────────────────────────────────────────────────────


def test_build_from_raw():
    """Build NormalizedAlert from raw data and verify type and entities."""
    alert = NormalizedAlert(
        id="018f3a20-1234-7abc-9def-0123456789ab",
        source="siem_splunk",
        defense_line="endpoint",
        alert_name="Suspicious PowerShell Execution",
        type="malware",
        severity="high",
        entities=[Entity(type="host", value="WS-PC-001")],
        fingerprint="abc123def456",
        alarm_id="alarm-001",
        raw_evidence={"command_line": "powershell -enc ..."},
        created_at="2026-05-10T12:00:00Z",
    )
    assert alert.type == "malware"
    assert len(alert.entities) == 1
    assert alert.entities[0].type == "host"
    assert alert.entities[0].value == "WS-PC-001"
    assert alert.alarm_id == "alarm-001"
    assert alert.deduped_alarm_ids == []
    assert alert.aggregation is None


def test_normalized_alert_without_alarm_id():
    """NormalizedAlert with alarm_id=None (for aggregated alerts)."""
    alert = NormalizedAlert(
        id="018f3a20-1234-7abc-9def-0123456789ab",
        source="siem_splunk",
        defense_line="endpoint",
        alert_name="Aggregated Alert",
        type="phishing",
        severity="medium",
        entities=[],
        fingerprint="def789",
        alarm_id=None,
        raw_evidence={},
        created_at="2026-05-10T12:00:00Z",
    )
    assert alert.alarm_id is None
    assert alert.aggregation is None


def test_normalized_alert_missing_required_fields_rejected():
    """Missing required fields should raise ValidationError."""
    with pytest.raises(ValidationError):
        NormalizedAlert(source="siem_splunk")


def test_normalized_alert_severity_values():
    """NormalizedAlert should accept all standard severity levels."""
    for sev in ("critical", "high", "medium", "low"):
        alert = NormalizedAlert(
            id="018f3a20-1234-7abc-9def-0123456789ab",
            source="siem_splunk",
            defense_line="endpoint",
            alert_name="Test",
            type="malware",
            severity=sev,
            entities=[],
            fingerprint="fp",
            raw_evidence={},
            created_at="2026-05-10T12:00:00Z",
        )
        assert alert.severity == sev


# ── TestAggregatedAlert ────────────────────────────────────────────────────────


def test_build_aggregated():
    """Build AggregatedAlert and verify aggregation dict and nested fields."""
    alert = AggregatedAlert(
        id="018f3a20-abcd-7def-9012-3456789abcde",
        source="siem_splunk",
        defense_line="network",
        alert_name="Multiple Failed Login Attempts",
        type="network_c2",
        severity="critical",
        entities=[
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="ip", value="10.0.0.2"),
        ],
        fingerprint="fp-aggregated-001",
        alarm_id=None,
        deduped_alarm_ids=["alarm-001", "alarm-002", "alarm-003"],
        aggregation={"count": 3, "window_seconds": 300},
        raw_evidence={"pattern": "brute_force"},
        created_at="2026-05-10T12:05:00Z",
    )
    assert alert.aggregation == {"count": 3, "window_seconds": 300}
    assert alert.deduped_alarm_ids == ["alarm-001", "alarm-002", "alarm-003"]
    assert alert.alarm_id is None
    assert len(alert.entities) == 2
    assert alert.severity == "critical"


def test_aggregated_alert_requires_aggregation():
    """AggregatedAlert should require aggregation (not None)."""
    with pytest.raises(ValidationError):
        AggregatedAlert(
            id="018f3a20-abcd-7def-9012-3456789abcde",
            source="siem_splunk",
            defense_line="network",
            alert_name="Test",
            type="network_c2",
            severity="high",
            entities=[],
            fingerprint="fp",
            raw_evidence={},
            created_at="2026-05-10T12:00:00Z",
            aggregation=None,  # type: ignore[arg-type] — should be rejected
        )


def test_aggregated_alert_missing_aggregation_rejected():
    """AggregatedAlert missing aggregation should raise ValidationError."""
    with pytest.raises(ValidationError):
        AggregatedAlert(
            id="018f3a20-abcd-7def-9012-3456789abcde",
            source="siem_splunk",
            defense_line="network",
            alert_name="Test",
            type="network_c2",
            severity="high",
            entities=[],
            fingerprint="fp",
            raw_evidence={},
            created_at="2026-05-10T12:00:00Z",
        )
