"""Alert normalizer — converts RawAlert into NormalizedAlert.

Performs type mapping, entity extraction (semantic + generic field patterns),
fingerprint generation, and severity assignment.
"""

from __future__ import annotations

import hashlib
import re

from app.ingestion.field_mapping import get_field_mapping
from app.ingestion.models import Entity, NormalizedAlert, RawAlert, _uuid7

# ── Alert name → unified type mapping ───────────────────────────────────────────

ALERT_TYPE_MAP: dict[str, str] = {
    "Endpoint_Abnormal_Process_Outbound": "malware",
    "Endpoint_Ransomware_Detected": "ransomware",
    "Email_Phishing_Link_Click": "phishing",
    "Email_Malicious_Attachment": "malware",
    "Network_C2_Communication": "network_c2",
    "Network_Port_Scan": "recon",
    "Account_Brute_Force": "anomaly_login",
    "Account_Impossible_Travel": "anomaly_login",
    "Server_Privilege_Escalation": "privilege_escalation",
    "Endpoint_Webshell_Detected": "malware",
    "App_SQL_Injection": "sql_injection",
    "App_XSS_Attack": "xss",
}

# ── Semantic field-name pattern → entity type ───────────────────────────────────

_SEMANTIC_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r".*(^|_)ip(_src|_dst)?$"), "ip"),
    (re.compile(r".*(^|_)hash$|.*(^|_)md5$|.*(^|_)sha256$"), "hash"),
    (re.compile(r".*(^|_)domain$"), "domain"),
    (re.compile(r".*(^|_)url$|.*url.*"), "url"),
    (re.compile(r".*(^|_)user.*|.*(^|_)account.*"), "user"),
    (re.compile(r".*(^|_)host.*|.*hostname.*"), "host"),
    (re.compile(r".*(^|_)process.*|.*process_.*"), "process"),
]


class Normalizer:
    """Converts RawAlert → NormalizedAlert with entity extraction and fingerprint."""

    def normalize(self, raw: RawAlert, source: str) -> NormalizedAlert:
        """Normalize a raw alert into the standard internal representation."""

        # 1. Type mapping
        alert_type = ALERT_TYPE_MAP.get(raw.alert_name, raw.alert_name.lower())

        # 2. Entity extraction (semantic + generic, deduplicated)
        entities = self._extract_entities(raw.alert_name, raw.raw_evidence)

        # 3. Fingerprint generation
        fingerprint = self._generate_fingerprint(entities)

        # 4. Default severity
        severity = self._determine_severity(alert_type, raw.defense_line.value)

        return NormalizedAlert(
            source=source,
            defense_line=raw.defense_line.value,
            alert_name=raw.alert_name,
            type=alert_type,
            severity=severity,
            entities=entities,
            fingerprint=fingerprint,
            alarm_id=raw.alarm_id,
            raw_evidence=raw.raw_evidence,
        )

    # ── Entity extraction ───────────────────────────────────────────────────────

    def _extract_entities(
        self, alert_name: str, evidence: dict[str, object]
    ) -> list[Entity]:
        """Extract entities from raw_evidence using semantic patterns and field mapping."""
        seen: set[tuple[str, str]] = set()
        entities: list[Entity] = []

        # Semantic field-name pattern matching
        entities.extend(
            self._extract_semantic_entities(evidence, seen)
        )

        # Generic field-name mapping (per alert name)
        entities.extend(
            self._extract_generic_entities(alert_name, evidence, seen)
        )

        return entities

    @staticmethod
    def _iter_values(raw_value: object) -> list[str]:
        """Flatten a raw_evidence field value into individual string values.

        Handles single strings, lists of strings, and nested lists.
        """
        if isinstance(raw_value, str):
            stripped = raw_value.strip()
            return [stripped] if stripped else []
        if isinstance(raw_value, (list, tuple)):
            result: list[str] = []
            for item in raw_value:
                if isinstance(item, str) and item.strip():
                    result.append(item.strip())
            return result
        return []

    def _extract_semantic_entities(
        self, evidence: dict[str, object], seen: set[tuple[str, str]]
    ) -> list[Entity]:
        """Extract entities whose field names match semantic patterns (e.g. *_ip → ip).

        Supports both single string values and lists of strings (e.g. ``src_ip: ["10.0.0.1", "10.0.0.2"]``).
        """
        entities: list[Entity] = []

        for field_name, raw_value in evidence.items():
            entity_type: str | None = None
            for pattern, etype in _SEMANTIC_PATTERNS:
                if pattern.match(field_name):
                    entity_type = etype
                    break
            if entity_type is None:
                continue

            for value in self._iter_values(raw_value):
                key = (entity_type, value)
                if key not in seen:
                    seen.add(key)
                    entities.append(Entity(type=entity_type, value=value))

        return entities

    def _extract_generic_entities(
        self, alert_name: str, evidence: dict[str, object], seen: set[tuple[str, str]]
    ) -> list[Entity]:
        """Extract entities by matching raw_evidence keys against the field mapping.

        Supports both single string values and lists (e.g. ``key_word1: ["10.0.0.1", "10.0.0.2"]``).
        """
        mapping = get_field_mapping(alert_name)
        if not mapping:
            return []

        entities: list[Entity] = []

        for field_name, meta in mapping.items():
            if field_name not in evidence:
                continue

            raw_value = evidence[field_name]
            entity_type = meta.get("entity_type", "")
            entity_key = meta.get("entity_key")

            # Resolve the value: if entity_key is given and raw_value is a dict, drill in
            if entity_key and isinstance(raw_value, dict):
                raw_value = raw_value.get(entity_key)

            for value in self._iter_values(raw_value):
                key = (entity_type, value)
                if key not in seen:
                    seen.add(key)
                    entities.append(Entity(type=entity_type, value=value))

        return entities

    # ── Fingerprint ─────────────────────────────────────────────────────────────

    @staticmethod
    def _generate_fingerprint(entities: list[Entity]) -> str:
        """Produce a deterministic content-based fingerprint from entities.

        Entities are sorted by (type, value), joined into a canonical string,
        and hashed with SHA256. The first 16 hex characters are returned.
        """
        sorted_entities = sorted(entities, key=lambda e: (e.type, e.value))
        canonical = ",".join(f"{e.type}:{e.value}" for e in sorted_entities)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    # ── Severity ────────────────────────────────────────────────────────────────

    @staticmethod
    def _determine_severity(alert_type: str, defense_line: str) -> str:
        """Assign a default severity based on alert type and defense line."""
        if alert_type in ("malware", "ransomware", "network_c2"):
            if defense_line in ("endpoint", "server"):
                return "high"
            return "medium"

        if alert_type in ("phishing", "anomaly_login"):
            return "high"

        return "medium"
