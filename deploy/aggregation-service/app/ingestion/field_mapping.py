"""Per-alert-name field mapping configuration for entity extraction.

Each entry maps field names found in raw_evidence to entity type metadata.
"""

from __future__ import annotations

FIELD_MAPPING: dict[str, dict[str, dict[str, str]]] = {
    "Endpoint_Abnormal_Process_Outbound": {
        "fields": {
            "key_word1": {"entity_type": "process", "entity_key": "process_name"},
            "key_word2": {"entity_type": "ip"},
            "key_word3": {"entity_type": "hash"},
            "field_1": {"entity_type": "host"},
        }
    },
}


def get_field_mapping(alert_name: str) -> dict[str, dict[str, str]]:
    """Return the per-alert-name field mapping, or an empty dict for unknown names."""
    entry = FIELD_MAPPING.get(alert_name, {})
    return entry.get("fields", {})
