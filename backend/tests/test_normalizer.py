"""Tests for alert normalizer — RawAlert → NormalizedAlert transformation."""

from app.ingestion.models import DefenseLine, Entity, RawAlert
from app.ingestion.normalizer import Normalizer


# ── Helpers ─────────────────────────────────────────────────────────────────────


def _make_raw(
    alert_name: str = "Endpoint_Abnormal_Process_Outbound",
    defense_line: str = "endpoint",
    alarm_id: str = "alarm-001",
    raw_evidence: dict | None = None,
) -> RawAlert:
    """Build a minimal RawAlert for test convenience."""
    return RawAlert(
        alarm_id=alarm_id,
        alert_time="2026-05-10T12:00:00Z",
        defense_line=defense_line,  # type: ignore[arg-type]
        alert_name=alert_name,
        raw_evidence=raw_evidence or {},
    )


# ── TestDefenseLineValidation ───────────────────────────────────────────────────


class TestDefenseLineValidation:
    """Defense line values are passed through from RawAlert to NormalizedAlert."""

    def test_valid_defense_lines(self):
        normalizer = Normalizer()
        for dl in DefenseLine:
            raw = _make_raw(
                alert_name="Endpoint_Abnormal_Process_Outbound",
                defense_line=dl.value,
            )
            result = normalizer.normalize(raw, source="siem_splunk")
            assert result.defense_line == dl.value, f"Expected {dl.value}, got {result.defense_line}"


# ── TestTypeMapping ─────────────────────────────────────────────────────────────


class TestTypeMapping:
    """Alert names are mapped to unified alert types."""

    def test_known_alert_name_maps_to_type(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Endpoint_Abnormal_Process_Outbound")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.type == "malware"

    def test_unknown_alert_name_defaults_to_alert_name(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Unknown_New_Alert")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.type == "unknown_new_alert"

    def test_network_c2_maps_to_network_c2(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Network_C2_Communication", defense_line="network")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.type == "network_c2"

    def test_server_priv_esc_maps_correctly(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Server_Privilege_Escalation", defense_line="server")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.type == "privilege_escalation"


# ── TestEntityExtraction ────────────────────────────────────────────────────────


class TestEntityExtraction:
    """Entities are extracted from raw_evidence via semantic patterns and field mappings."""

    def test_semantic_field_names(self):
        normalizer = Normalizer()
        evidence = {
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.100",
            "malware_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "evil_process": "powershell.exe",
            "target_hostname": "WS-PC-001",
            "callback_url": "https://evil.example.com/c2",
            "login_user": "jdoe",
            "source_domain": "evil.example.com",
        }
        raw = _make_raw(raw_evidence=evidence)
        result = normalizer.normalize(raw, source="siem_splunk")

        entity_map: dict[str, list[str]] = {}
        for e in result.entities:
            entity_map.setdefault(e.type, []).append(e.value)

        assert "10.0.0.1" in entity_map.get("ip", [])
        assert "192.168.1.100" in entity_map.get("ip", [])
        assert "d41d8cd98f00b204e9800998ecf8427e" in entity_map.get("hash", [])
        assert "powershell.exe" in entity_map.get("process", [])
        assert "WS-PC-001" in entity_map.get("host", [])
        assert "https://evil.example.com/c2" in entity_map.get("url", [])
        assert "jdoe" in entity_map.get("user", [])
        assert "evil.example.com" in entity_map.get("domain", [])

    def test_generic_field_names_use_mapping(self):
        normalizer = Normalizer()
        evidence = {
            "key_word1": {"process_name": "malware.exe", "pid": 1234},
            "key_word2": "10.99.99.99",
            "key_word3": "abc123def456",
        }
        raw = _make_raw(
            alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence=evidence,
        )
        result = normalizer.normalize(raw, source="siem_splunk")

        entity_map: dict[str, list[str]] = {}
        for e in result.entities:
            entity_map.setdefault(e.type, []).append(e.value)

        assert "malware.exe" in entity_map.get("process", [])
        assert "10.99.99.99" in entity_map.get("ip", [])
        assert "abc123def456" in entity_map.get("hash", [])

    def test_generic_field_names_use_mapping_direct_value_when_no_entity_key(self):
        """When entity_key is not specified, the raw_evidence value is used directly."""
        normalizer = Normalizer()
        evidence = {
            "field_1": "SRV-DC-01",
        }
        raw = _make_raw(
            alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence=evidence,
        )
        result = normalizer.normalize(raw, source="siem_splunk")

        entities_by_type: dict[str, list[str]] = {}
        for e in result.entities:
            entities_by_type.setdefault(e.type, []).append(e.value)

        assert "SRV-DC-01" in entities_by_type.get("host", [])

    def test_entities_deduplicated(self):
        """Same IP appearing in two fields should produce only one entity."""
        normalizer = Normalizer()
        evidence = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.1",  # same value
            "key_word2": "10.0.0.1",  # same value via generic mapping
        }
        raw = _make_raw(
            alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence=evidence,
        )
        result = normalizer.normalize(raw, source="siem_splunk")

        ip_entities = [e for e in result.entities if e.type == "ip"]
        assert len(ip_entities) == 1
        assert ip_entities[0].value == "10.0.0.1"

    def test_empty_evidence_produces_empty_entities(self):
        normalizer = Normalizer()
        raw = _make_raw(raw_evidence={})
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.entities == []

    def test_empty_string_values_skipped(self):
        """Empty string field values should be skipped during entity extraction."""
        normalizer = Normalizer()
        evidence = {
            "src_ip": "",
            "dst_ip": "192.168.1.100",
            "evil_process": "   ",  # whitespace-only
        }
        raw = _make_raw(raw_evidence=evidence)
        result = normalizer.normalize(raw, source="siem_splunk")

        values = [e.value for e in result.entities]
        assert "" not in values
        assert "   " not in values
        assert "192.168.1.100" in values

    def test_non_string_evidence_values_skipped_in_semantic(self):
        """Non-string values (int, list, etc.) are skipped by semantic extraction."""
        normalizer = Normalizer()
        evidence = {
            "src_ip": 12345,  # not a string
            "dst_ip": "192.168.1.100",
        }
        raw = _make_raw(raw_evidence=evidence)
        result = normalizer.normalize(raw, source="siem_splunk")

        # Only the string value should be present
        ip_entities = [e for e in result.entities if e.type == "ip"]
        assert len(ip_entities) == 1
        assert ip_entities[0].value == "192.168.1.100"

    def test_md5_field_extracts_as_hash(self):
        normalizer = Normalizer()
        evidence = {"file_md5": "d41d8cd98f00b204e9800998ecf8427e"}
        raw = _make_raw(raw_evidence=evidence)
        result = normalizer.normalize(raw, source="siem_splunk")
        hash_entities = [e for e in result.entities if e.type == "hash"]
        assert len(hash_entities) == 1
        assert hash_entities[0].value == "d41d8cd98f00b204e9800998ecf8427e"

    def test_sha256_field_extracts_as_hash(self):
        normalizer = Normalizer()
        evidence = {"payload_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
        raw = _make_raw(raw_evidence=evidence)
        result = normalizer.normalize(raw, source="siem_splunk")
        hash_entities = [e for e in result.entities if e.type == "hash"]
        assert len(hash_entities) == 1

    def test_ip_src_ip_dst_suffixes(self):
        normalizer = Normalizer()
        evidence = {
            "attacker_ip_src": "1.2.3.4",
            "victim_ip_dst": "5.6.7.8",
        }
        raw = _make_raw(raw_evidence=evidence)
        result = normalizer.normalize(raw, source="siem_splunk")

        ip_values = [e.value for e in result.entities if e.type == "ip"]
        assert "1.2.3.4" in ip_values
        assert "5.6.7.8" in ip_values

    def test_account_field_extracts_as_user(self):
        normalizer = Normalizer()
        evidence = {"target_account": "admin@corp.com"}
        raw = _make_raw(raw_evidence=evidence)
        result = normalizer.normalize(raw, source="siem_splunk")
        user_entities = [e for e in result.entities if e.type == "user"]
        assert len(user_entities) == 1
        assert user_entities[0].value == "admin@corp.com"

    def test_url_in_field_name_extracts_as_url(self):
        normalizer = Normalizer()
        evidence = {"redirect_url": "https://phish.example.com"}
        raw = _make_raw(raw_evidence=evidence)
        result = normalizer.normalize(raw, source="siem_splunk")
        url_entities = [e for e in result.entities if e.type == "url"]
        assert len(url_entities) == 1
        assert url_entities[0].value == "https://phish.example.com"


# ── TestFingerprint ─────────────────────────────────────────────────────────────


class TestFingerprint:
    """Fingerprints are deterministic and order-independent."""

    def test_deterministic_fingerprint(self):
        """Same input twice produces the same fingerprint."""
        normalizer = Normalizer()
        evidence = {
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.100",
        }
        raw = _make_raw(raw_evidence=evidence)

        result1 = normalizer.normalize(raw, source="siem_splunk")
        result2 = normalizer.normalize(raw, source="siem_splunk")

        assert result1.fingerprint == result2.fingerprint
        assert len(result1.fingerprint) == 16
        # Verify it's all hex chars
        assert all(c in "0123456789abcdef" for c in result1.fingerprint)

    def test_same_entities_same_fingerprint(self):
        """Same entities in different order produce the same fingerprint."""
        normalizer = Normalizer()

        # Create two alerts where evidence keys are in different order,
        # but the extracted entities are logically the same set.
        evidence1 = {
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.100",
            "target_hostname": "WS-PC-001",
        }
        evidence2 = {
            "target_hostname": "WS-PC-001",
            "dst_ip": "192.168.1.100",
            "src_ip": "10.0.0.1",
        }

        raw1 = _make_raw(raw_evidence=evidence1)
        raw2 = _make_raw(raw_evidence=evidence2)

        result1 = normalizer.normalize(raw1, source="siem_splunk")
        result2 = normalizer.normalize(raw2, source="siem_splunk")

        assert result1.fingerprint == result2.fingerprint

    def test_different_entities_produce_different_fingerprint(self):
        """Different entity sets should produce different fingerprints."""
        normalizer = Normalizer()

        raw1 = _make_raw(raw_evidence={"src_ip": "10.0.0.1"})
        raw2 = _make_raw(raw_evidence={"src_ip": "10.0.0.2"})

        result1 = normalizer.normalize(raw1, source="siem_splunk")
        result2 = normalizer.normalize(raw2, source="siem_splunk")

        assert result1.fingerprint != result2.fingerprint

    def test_empty_entities_produce_consistent_fingerprint(self):
        """Fingerprint for empty entities should be consistent."""
        normalizer = Normalizer()
        raw = _make_raw(raw_evidence={})
        result1 = normalizer.normalize(raw, source="siem_splunk")
        result2 = normalizer.normalize(raw, source="siem_splunk")
        assert result1.fingerprint == result2.fingerprint
        assert len(result1.fingerprint) == 16


# ── TestSeverity ────────────────────────────────────────────────────────────────


class TestSeverity:
    """Default severity is assigned based on alert type and defense line."""

    def test_malware_endpoint_is_high(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Endpoint_Abnormal_Process_Outbound", defense_line="endpoint")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.severity == "high"

    def test_malware_server_is_high(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Endpoint_Ransomware_Detected", defense_line="server")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.severity == "high"

    def test_malware_network_is_medium(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Email_Malicious_Attachment", defense_line="email")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.severity == "medium"

    def test_phishing_is_high(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Email_Phishing_Link_Click", defense_line="email")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.severity == "high"

    def test_anomaly_login_is_high(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Account_Brute_Force", defense_line="account")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.severity == "high"

    def test_recon_is_medium(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Network_Port_Scan", defense_line="network")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.severity == "medium"

    def test_unknown_type_is_medium(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Custom_Detection_Rule")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.severity == "medium"

    def test_ransomware_endpoint_is_high(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Endpoint_Ransomware_Detected", defense_line="endpoint")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.severity == "high"

    def test_network_c2_server_is_high(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Network_C2_Communication", defense_line="server")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.severity == "high"

    def test_network_c2_application_is_medium(self):
        normalizer = Normalizer()
        raw = _make_raw(alert_name="Network_C2_Communication", defense_line="application")
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.severity == "medium"


# ── TestIntegration ─────────────────────────────────────────────────────────────


class TestIntegration:
    """End-to-end normalization produces a well-formed NormalizedAlert."""

    def test_normalized_alert_has_required_fields(self):
        normalizer = Normalizer()
        evidence = {
            "src_ip": "10.0.0.1",
            "evil_process": "ransomware.exe",
            "target_hostname": "WS-FIN-01",
        }
        raw = _make_raw(
            alert_name="Endpoint_Ransomware_Detected",
            defense_line="endpoint",
            alarm_id="alarm-rw-001",
            raw_evidence=evidence,
        )
        result = normalizer.normalize(raw, source="siem_qradar")

        assert result.id  # UUID v7 auto-generated
        assert result.source == "siem_qradar"
        assert result.defense_line == "endpoint"
        assert result.alert_name == "Endpoint_Ransomware_Detected"
        assert result.type == "ransomware"
        assert result.severity == "high"
        assert len(result.entities) == 3
        assert result.fingerprint
        assert result.alarm_id == "alarm-rw-001"
        assert result.raw_evidence == evidence
        assert result.created_at  # auto-generated ISO timestamp
