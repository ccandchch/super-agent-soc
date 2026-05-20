# Remove ALERT_TYPE_MAP — Extract Severity from SIEM

## Motivation

`ALERT_TYPE_MAP` is a hardcoded, 12-entry dictionary that maps specific alert names
(`Endpoint_Abnormal_Process_Outbound` → `malware`, etc.) to internal alert types.
The internal type was then fed to `_determine_severity()` to derive a severity level
(`high`/`medium`).

Two problems:

1. **Hardcodes one SIEM vendor's alert taxonomy.** Third-party developers with different
   alert names must edit the map to add entries.
2. **Ignores severity data the SIEM already provides.** Nearly all SIEMs include severity
   in their alert output — but the current code derives its own from the mapped type instead
   of using it.

## Design

### Remove ALERT_TYPE_MAP

- Delete the `ALERT_TYPE_MAP` dictionary from `normalizer.py` (both `backend/` and
  `deploy/aggregation-service/` copies).
- The normalized `alert_type` field becomes the raw `alert_name` directly.
  The AI agent still sees a human-readable alert identifier — just not a hardcoded remapping of it.

### Remove `_determine_severity()`

- Delete the `_determine_severity()` static method.
- Severity is extracted from the SIEM data directly via a new `severity` field on `RawAlert`.

### Add `severity` to `RawAlert`

```python
class RawAlert(BaseModel):
    alarm_id: str
    alert_time: str
    defense_line: DefenseLine
    alert_name: str
    severity: str = Field(..., description="critical, high, medium, or low")
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
```

The normalized alert's `severity` is set to `raw.severity` directly.

### Updated normalize() flow

```
Before:  raw.alert_name → ALERT_TYPE_MAP → alert_type → _determine_severity() → severity
After:   raw.alert_name → alert_type (passthrough)
         raw.severity   → severity   (passthrough)
```

### Files changed

| File | Change |
|------|--------|
| `backend/app/ingestion/models.py` | Add `severity` to `RawAlert` |
| `backend/app/ingestion/normalizer.py` | Delete `ALERT_TYPE_MAP`, delete `_determine_severity()`, use `raw.alert_name` and `raw.severity` directly |
| `deploy/aggregation-service/app/ingestion/normalizer.py` | Same as above |
| `scripts/mock_siem_v3.py` | Add `severity` field to all 20 alerts |
| `backend/tests/test_normalizer.py` | Remove TypeMapping and Severity test classes; update fixtures |
| `deploy/aggregation-service/README.md` | Remove ALERT_TYPE_MAP documentation references |

### What does NOT change

- `_SEMANTIC_PATTERNS` — semantic field-name patterns are vendor-agnostic and stay.
- `FIELD_MAPPING` — per-alert-name generic field mapping stays (still needed for SIEMs
  that use non-semantic field names like `key_word1`).
- `SEVERITY_ORDER` in `dedup.py` and `SEVERITY_TO_SCORE` in `routers/webhooks.py` remain
  — those map severity strings to numeric values for aggregation and priority scoring.

## Third-Party SIEM Integration Guide

After this change, the integration surface for a third-party SIEM is:

### 1. Map data to the `RawAlert` contract (required)

The SIEM must produce alerts with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `alarm_id` | `str` | Unique alert identifier |
| `alert_time` | `str` | ISO 8601 timestamp |
| `defense_line` | `str` | One of: `endpoint`, `server`, `application`, `network`, `email`, `account` |
| `alert_name` | `str` | Human-readable alert name or rule title |
| `severity` | `str` | One of: `critical`, `high`, `medium`, `low` |
| `raw_evidence` | `dict` | Arbitrary evidence key-value pairs (IPs, hashes, hostnames, etc.) |

### 2. Write a custom adapter (if needed)

If the SIEM webhook sends a different JSON structure, subclass `AlertAdapter`:

```python
# backend/app/ingestion/adapters/my_siem.py
from app.ingestion.adapters.base import AlertAdapter
from app.ingestion.models import RawAlert, DefenseLine

class MySiemAdapter(AlertAdapter):
    def parse(self, body: dict, vendor: str) -> RawAlert:
        return RawAlert(
            alarm_id=body["event"]["id"],
            alert_time=body["event"]["timestamp"],
            defense_line=DefenseLine(body["category"]),
            alert_name=body["rule"]["name"],
            severity=body["severity"].lower(),
            raw_evidence=body["event"]["fields"],
        )
```

Then register it in `SIEMWebhookAdapter` or replace the adapter lookup logic.

### 3. Add field mapping (if needed)

Only required when the SIEM uses generic field names without semantic meaning
(e.g., `key_word1`, `field_1`). Add entries to `FIELD_MAPPING` in `field_mapping.py`:

```python
FIELD_MAPPING = {
    "My_SIEM_Alert_Name": {
        "fields": {
            "key_word1": {"entity_type": "ip"},
            "key_word2": {"entity_type": "domain"},
        }
    },
}
```

Semantic field names (`src_ip`, `process_hash`, `hostname`, `target_user`, etc.)
are auto-detected by `_SEMANTIC_PATTERNS` and require no configuration.

### Integration complexity by scenario

| Scenario | Work | Files to touch |
|----------|------|---------------|
| Webhook format matches `RawAlert` | Zero code — configure webhook URL | None |
| Field names differ (e.g. `alertId` → `alarm_id`) | Write adapter, ~15 lines | New file in `adapters/` |
| SIEM uses generic field names | Add field mapping, ~5 lines per alert | `field_mapping.py` |
| Different alert names (any vendor) | Zero code (ALERT_TYPE_MAP was the blocker — now gone) | None |
