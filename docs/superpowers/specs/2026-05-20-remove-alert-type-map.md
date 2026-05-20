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

- Delete the `ALERT_TYPE_MAP` dictionary from `deploy/aggregation-service/app/ingestion/normalizer.py`.
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
| `deploy/aggregation-service/app/ingestion/models.py` | Add `severity` to `RawAlert` |
| `deploy/aggregation-service/app/ingestion/normalizer.py` | Delete `ALERT_TYPE_MAP`, delete `_determine_severity()`, use `raw.alert_name` and `raw.severity` directly |
| `scripts/mock_siem_v3.py` | Add `severity` field to all 20 alerts |
| `deploy/aggregation-service/README.md` | Remove ALERT_TYPE_MAP documentation references |

### What does NOT change

- `_SEMANTIC_PATTERNS` — semantic field-name patterns are vendor-agnostic and stay.
- `FIELD_MAPPING` — per-alert-name generic field mapping stays (still needed for SIEMs
  that use non-semantic field names like `key_word1`).
- `SEVERITY_ORDER` in `dedup.py` remains — it maps severity strings to numeric values for aggregation.
- `backend/app/ingestion/` files are NOT changed. The backend copy of the ingestion pipeline is
  out of scope for this change.

## Third-Party SIEM Integration Guide

After this change, the integration surface for a third-party SIEM is:

### 1. Map data to the `RawAlert` contract (required)

Whether pushing alerts via webhook or being polled, the SIEM must produce alerts with
these fields:

| Field | Type | Description |
|-------|------|-------------|
| `alarm_id` | `str` | Unique alert identifier |
| `alert_time` | `str` | ISO 8601 timestamp |
| `defense_line` | `str` | One of: `endpoint`, `server`, `application`, `network`, `email`, `account` |
| `alert_name` | `str` | Human-readable alert name or rule title |
| `severity` | `str` | One of: `critical`, `high`, `medium`, `low` |
| `raw_evidence` | `dict` | Arbitrary evidence key-value pairs (IPs, hashes, hostnames, etc.) |

### 2. Adapt the SIEM API response format (if different)

If the SIEM API returns a different JSON structure than `RawAlert`, modify
`SiemPoller._fetch_alerts()` in `app/aggregation/poller.py` to translate the response
into `RawAlert` objects. Example: if the SIEM returns `{"alertId": ..., "timestamp": ...}`,
add a mapping layer:

```python
raw = RawAlert(
    alarm_id=item["alertId"],
    alert_time=item["timestamp"],
    defense_line=DefenseLine(item["category"]),
    alert_name=item["ruleName"],
    severity=item["severity"].lower(),
    raw_evidence=item,
)
```

For webhook-based SIEMs, write a custom adapter implementing the `AlertAdapter` interface
in `app/ingestion/adapters/`.

### 3. Add field mapping (if needed)

Only required when the SIEM uses generic field names without semantic meaning
(e.g., `key_word1`, `field_1`). Add entries to `FIELD_MAPPING` in `app/ingestion/field_mapping.py`.

Semantic field names (`src_ip`, `process_hash`, `hostname`, `target_user`, etc.)
are auto-detected by `_SEMANTIC_PATTERNS` and require no configuration.

### Integration complexity by scenario

| Scenario | Work | Files to touch |
|----------|------|---------------|
| API response matches `RawAlert` | Zero code — configure `SIEM_API_BASE` env var | None |
| API response has different field names | Add mapping in poller, ~10 lines | `app/aggregation/poller.py` |
| SIEM uses generic field names | Add field mapping, ~5 lines per alert | `app/ingestion/field_mapping.py` |
| Different alert names (any vendor) | Zero code (ALERT_TYPE_MAP was the blocker — now gone) | None |
