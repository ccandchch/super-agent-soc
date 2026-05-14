# Security Alert Triage — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the alert ingestion pipeline, SOC memory service, CMDB tool, MCP server skeletons, and frontend SOC pages per the architecture spec.

**Architecture:** New `backend/app/ingestion/` FastAPI sub-app on port 8002 receives alerts via webhook/polling, normalizes/dedups/aggregates them, and dispatches to DeerFlow's LangGraph API. A new `memory-soc` package on port 8003 provides Redis-backed session state and PostgreSQL-backed triage results with similarity query. Three MCP servers (mock) provide threat-intel, siem-search, and sandbox capabilities. Frontend adds `/soc/*` routes sharing DeerFlow's component library.

**Tech Stack:** Python 3.12+ (FastAPI, Pydantic, httpx, SQLAlchemy, redis-py), TypeScript 5.8 (Next.js 16, React 19, TanStack Query, Shadcn UI)

---

## File Structure

### Backend — Ingestion Service (new)
```
backend/app/ingestion/
├── __init__.py
├── app.py                   # FastAPI sub-app, lifespan, mount to main app
├── models.py                # Pydantic models: RawAlert, NormalizedAlert, AggregatedAlert
├── adapters/
│   ├── __init__.py
│   ├── base.py              # Abstract Adapter interface
│   └── siem_webhook.py      # Generic SIEM webhook receiver
├── normalizer.py            # Normalization engine
├── dedup.py                 # Fingerprint dedup + entity aggregation
├── queue.py                 # Priority queue (in-memory, Redis-backed later)
├── dispatcher.py            # Queue consumer → similarity query → Thread/Run creation
└── routers/
    ├── __init__.py
    ├── webhooks.py          # POST /api/soc/webhooks/{vendor}
    └── queue_status.py      # GET /api/soc/queue/status
```

### Backend — Memory-SOC (new)
```
backend/packages/memory-soc/
├── pyproject.toml
└── soc_memory/
    ├── __init__.py
    ├── app.py               # FastAPI app (localhost:8003)
    ├── models.py            # SQLAlchemy models: TriageResult, Feedback, SuppressionRule
    ├── database.py           # Database session management
    ├── session_store.py     # Redis CRUD for triage task state
    ├── result_store.py      # PostgreSQL CRUD for triage results
    ├── feedback.py           # Feedback CRUD
    ├── similarity.py         # Similar alert query logic
    ├── suppression.py        # Suppression rule CRUD
    └── routers.py            # Internal API routes
```

### Backend — CMDB Community Tool (new)
```
backend/packages/harness/deerflow/community/cmdb/
├── __init__.py
└── tools.py                 # query_asset @tool
```

### MCP Servers (new)
```
mcp-servers/
├── threat-intel/
│   ├── pyproject.toml
│   └── server.py            # Mock SSE MCP server
├── siem-search/
│   ├── pyproject.toml
│   └── server.py            # Mock SSE MCP server
└── sandbox/
    ├── pyproject.toml
    └── server.py            # Mock SSE MCP server
```

### Frontend (new)
```
frontend/src/
├── app/(workspace)/soc/
│   ├── layout.tsx
│   ├── alerts/page.tsx
│   ├── triage/[thread_id]/page.tsx
│   ├── dashboard/page.tsx   # placeholder
│   ├── rules/page.tsx       # placeholder
│   └── audit/page.tsx       # placeholder
├── core/soc/
│   ├── alerts.ts            # TanStack Query hooks
│   ├── queue.ts
│   ├── triage.ts
│   └── feedback.ts
└── components/soc/
    ├── alert-card.tsx
    ├── alert-filter.tsx
    ├── alert-summary.tsx
    ├── triage-result.tsx
    └── queue-stats.tsx
```

### Config files (modify)
```
config.yaml                  # Add soc section, cmdb tool, tool_groups.soc
extensions_config.json       # Add 3 MCP servers
```

---

## Task 1: Alert Data Models

**Files:**
- Create: `backend/app/ingestion/__init__.py`
- Create: `backend/app/ingestion/models.py`
- Test: `backend/tests/test_ingestion_models.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_ingestion_models.py
import pytest
from pydantic import ValidationError
from app.ingestion.models import (
    RawAlert,
    NormalizedAlert,
    AggregatedAlert,
    Entity,
    DedupedAlertRef,
    DefenseLine,
)


class TestRawAlert:
    def test_valid_raw_alert(self):
        alert = RawAlert(
            alarm_id="splunk-abc-12345",
            alert_time="2026-05-10T14:32:00Z",
            defense_line="endpoint",
            alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence={
                "src_ip": "10.23.45.67",
                "process_hash": "abc123def456",
                "process_name": "powershell.exe",
            },
        )
        assert alert.alarm_id == "splunk-abc-12345"
        assert alert.defense_line == DefenseLine.endpoint

    def test_invalid_defense_line_rejected(self):
        with pytest.raises(ValidationError):
            RawAlert(
                alarm_id="x",
                alert_time="2026-05-10T14:32:00Z",
                defense_line="invalid_line",
                alert_name="TestAlert",
                raw_evidence={},
            )

    def test_missing_alarm_id_rejected(self):
        with pytest.raises(ValidationError):
            RawAlert(
                alert_time="2026-05-10T14:32:00Z",
                defense_line="endpoint",
                alert_name="TestAlert",
                raw_evidence={},
            )


class TestNormalizedAlert:
    def test_build_from_raw(self):
        raw = RawAlert(
            alarm_id="splunk-abc-12345",
            alert_time="2026-05-10T14:32:00Z",
            defense_line="endpoint",
            alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence={"src_ip": "10.23.45.67", "process_hash": "abc123"},
        )
        entities = [
            Entity(type="ip", value="10.23.45.67"),
            Entity(type="hash", value="abc123"),
        ]
        normalized = NormalizedAlert(
            id="0193a...",
            source="siem_splunk",
            defense_line="endpoint",
            alert_name="Endpoint_Abnormal_Process_Outbound",
            type="malware",
            severity="high",
            entities=entities,
            fingerprint="a1b2c3d4e5f67890",
            alarm_id="splunk-abc-12345",
            deduped_alarm_ids=[],
            raw_evidence=raw.raw_evidence,
            created_at="2026-05-10T14:32:00Z",
        )
        assert normalized.type == "malware"
        assert len(normalized.entities) == 2


class TestAggregatedAlert:
    def test_build_aggregated(self):
        agg = AggregatedAlert(
            id="0193a...",
            source="siem_splunk",
            defense_line="endpoint",
            type="malware",
            severity="critical",
            entities=[Entity(type="hash", value="abc123")],
            fingerprint="merged:a1b2c3d4e5f67890",
            alarm_id=None,
            deduped_alarm_ids=[],
            aggregation={
                "entity_overlap": 0.85,
                "time_delta_seconds": 42,
                "source_alarms": [
                    {"alarm_id": "splunk-abc-12345", "alert_name": "Endpoint_Abnormal_Process_Outbound"},
                    {"alarm_id": "splunk-abc-12346", "alert_name": "Endpoint_Malicious_Network_Connection"},
                ],
            },
            raw_evidence={
                "common": {"process_hash": "abc123"},
                "per_alarm": {
                    "splunk-abc-12345": {"src_ip": "10.23.45.67"},
                    "splunk-abc-12346": {"src_ip": "10.23.45.68"},
                },
            },
            created_at="2026-05-10T14:32:00Z",
        )
        assert agg.aggregation["entity_overlap"] == 0.85
        assert len(agg.aggregation["source_alarms"]) == 2
        assert "common" in agg.raw_evidence
        assert "per_alarm" in agg.raw_evidence
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && PYTHONPATH=. uv run pytest tests/test_ingestion_models.py -v`
Expected: FAIL with "No module named 'app.ingestion.models'"

- [ ] **Step 3: Write the models**

```python
# backend/app/ingestion/__init__.py
"""Alert ingestion microservice for SOC triage."""

# backend/app/ingestion/models.py
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DefenseLine(StrEnum):
    endpoint = "endpoint"
    server = "server"
    application = "application"
    network = "network"
    email = "email"
    account = "account"


class Entity(BaseModel):
    type: str   # ip, hash, domain, url, user, host, process
    value: str


class RawAlert(BaseModel):
    """Alert received from upstream SIEM via webhook or polling."""
    alarm_id: str
    alert_time: str  # ISO8601
    defense_line: DefenseLine
    alert_name: str
    raw_evidence: dict[str, Any] = Field(default_factory=dict)


class NormalizedAlert(BaseModel):
    """Standardized alert after normalization."""
    id: str                     # UUID v7
    source: str                 # siem_splunk, etc.
    defense_line: str
    alert_name: str
    type: str                   # malware, phishing, network_c2, etc.
    severity: str               # critical, high, medium, low
    entities: list[Entity]
    fingerprint: str
    alarm_id: str | None        # primary SIEM alarm ID (None for aggregated)
    deduped_alarm_ids: list[str] = Field(default_factory=list)
    aggregation: dict[str, Any] | None = None  # set when this is an aggregated alert
    raw_evidence: dict[str, Any]
    created_at: str             # ISO8601


class AggregatedAlert(NormalizedAlert):
    """Multiple alerts merged by entity overlap."""
    aggregation: dict[str, Any]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && PYTHONPATH=. uv run pytest tests/test_ingestion_models.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/ingestion/__init__.py backend/app/ingestion/models.py backend/tests/test_ingestion_models.py
git commit -m "feat(ingestion): add alert data models — RawAlert, NormalizedAlert, AggregatedAlert"
```

---

## Task 2: Alert Normalizer

**Files:**
- Create: `backend/app/ingestion/normalizer.py`
- Create: `backend/app/ingestion/field_mapping.py`
- Test: `backend/tests/test_normalizer.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_normalizer.py
import pytest
from app.ingestion.models import RawAlert, NormalizedAlert
from app.ingestion.normalizer import Normalizer


@pytest.fixture
def normalizer():
    return Normalizer()


class TestDefenseLineValidation:
    def test_valid_defense_lines(self, normalizer):
        raw = RawAlert(
            alarm_id="a1", alert_time="2026-05-10T14:32:00Z",
            defense_line="endpoint", alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence={"src_ip": "10.0.0.1"},
        )
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.defense_line == "endpoint"


class TestTypeMapping:
    def test_known_alert_name_maps_to_type(self, normalizer):
        raw = RawAlert(
            alarm_id="a1", alert_time="2026-05-10T14:32:00Z",
            defense_line="endpoint", alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence={"src_ip": "10.0.0.1"},
        )
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.type == "malware"

    def test_unknown_alert_name_defaults_to_alert_name(self, normalizer):
        raw = RawAlert(
            alarm_id="a1", alert_time="2026-05-10T14:32:00Z",
            defense_line="network", alert_name="Unknown_New_Alert",
            raw_evidence={"src_ip": "10.0.0.1"},
        )
        result = normalizer.normalize(raw, source="siem_splunk")
        assert result.type == "unknown_new_alert"


class TestEntityExtraction:
    def test_semantic_field_names(self, normalizer):
        raw = RawAlert(
            alarm_id="a1", alert_time="2026-05-10T14:32:00Z",
            defense_line="endpoint", alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence={
                "src_ip": "10.23.45.67",
                "dst_ip": "192.168.1.100",
                "process_hash": "abc123def456",
                "process_name": "powershell.exe",
                "hostname": "prod-db-01",
            },
        )
        result = normalizer.normalize(raw, source="siem_splunk")
        entity_types = {e.type for e in result.entities}
        assert "ip" in entity_types
        assert "hash" in entity_types
        assert "process" in entity_types
        assert "host" in entity_types

    def test_generic_field_names_use_mapping(self, normalizer):
        raw = RawAlert(
            alarm_id="a1", alert_time="2026-05-10T14:32:00Z",
            defense_line="endpoint", alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence={
                "key_word1": "powershell.exe",
                "key_word2": "10.23.45.67",
                "key_word3": "abc123",
            },
        )
        result = normalizer.normalize(raw, source="siem_splunk")
        entity_types = {e.type for e in result.entities}
        assert "process" in entity_types or "ip" in entity_types or "hash" in entity_types

    def test_entities_deduplicated(self, normalizer):
        raw = RawAlert(
            alarm_id="a1", alert_time="2026-05-10T14:32:00Z",
            defense_line="endpoint", alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence={"src_ip": "10.0.0.1", "dst_ip": "10.0.0.1"},
        )
        result = normalizer.normalize(raw, source="siem_splunk")
        ip_entities = [e for e in result.entities if e.type == "ip"]
        assert len(ip_entities) == 1


class TestFingerprint:
    def test_deterministic_fingerprint(self, normalizer):
        raw = RawAlert(
            alarm_id="a1", alert_time="2026-05-10T14:32:00Z",
            defense_line="endpoint", alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence={"src_ip": "10.0.0.1", "process_hash": "abc123"},
        )
        fp1 = normalizer.normalize(raw, source="siem_splunk").fingerprint
        fp2 = normalizer.normalize(raw, source="siem_splunk").fingerprint
        assert fp1 == fp2

    def test_same_entities_same_fingerprint(self, normalizer):
        raw1 = RawAlert(
            alarm_id="a1", alert_time="2026-05-10T14:32:00Z",
            defense_line="endpoint", alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence={"src_ip": "10.0.0.1", "process_hash": "abc123"},
        )
        raw2 = RawAlert(
            alarm_id="a2", alert_time="2026-05-10T14:33:00Z",
            defense_line="endpoint", alert_name="Endpoint_Abnormal_Process_Outbound",
            raw_evidence={"process_hash": "abc123", "src_ip": "10.0.0.1"},
        )
        fp1 = normalizer.normalize(raw1, source="siem_splunk").fingerprint
        fp2 = normalizer.normalize(raw2, source="siem_splunk").fingerprint
        assert fp1 == fp2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && PYTHONPATH=. uv run pytest tests/test_normalizer.py -v`
Expected: FAIL with import error

- [ ] **Step 3: Write the implementation**

```python
# backend/app/ingestion/field_mapping.py
"""Per-alert-name field mapping for entity extraction from generic field names."""

FIELD_MAPPING: dict[str, dict[str, dict[str, str]]] = {
    "Endpoint_Abnormal_Process_Outbound": {
        "fields": {
            "key_word1": {"entity_type": "process", "entity_key": "process_name"},
            "key_word2": {"entity_type": "ip"},
            "key_word3": {"entity_type": "hash"},
            "field_1":   {"entity_type": "host"},
        }
    },
    # Add more alert_name mappings here as new alert types are onboarded
}


def get_field_mapping(alert_name: str) -> dict[str, dict[str, str]]:
    entry = FIELD_MAPPING.get(alert_name, {})
    return entry.get("fields", {})


# backend/app/ingestion/normalizer.py
import hashlib
import json
import uuid
import uuid_extensions
from app.ingestion.models import RawAlert, NormalizedAlert, Entity
from app.ingestion.field_mapping import get_field_mapping


# Alert name → unified type mapping
ALERT_TYPE_MAP: dict[str, str] = {
    "Endpoint_Abnormal_Process_Outbound": "malware",
    "Endpoint_Ransomware_Detected":       "ransomware",
    "Endpoint_Webshell_Detected":         "malware",
    "Email_Phishing_Link_Click":          "phishing",
    "Email_Malicious_Attachment":         "malware",
    "Network_C2_Communication":           "network_c2",
    "Network_Port_Scan":                  "recon",
    "Account_Brute_Force":                "anomaly_login",
    "Account_Impossible_Travel":          "anomaly_login",
    "Server_Privilege_Escalation":        "privilege_escalation",
    "Server_Webshell_Upload":             "malware",
    "App_SQL_Injection":                  "sql_injection",
    "App_XSS_Attack":                     "xss",
}

# Semantic field name → entity type patterns
ENTITY_FIELD_PATTERNS = [
    (("ip", "src_ip", "dst_ip", "source_ip", "destination_ip"), "ip"),
    (("hash", "md5", "sha1", "sha256", "file_hash"), "hash"),
    (("domain", "url"), "domain"),  # url also handled below
    (("user", "username", "account", "user_id"), "user"),
    (("host", "hostname", "asset", "server"), "host"),
    (("process", "process_name", "process_path", "parent_process"), "process"),
]


def _is_url_field(field_name: str) -> bool:
    return "url" in field_name.lower()


class Normalizer:
    def __init__(self, alert_type_map: dict[str, str] | None = None):
        self._type_map = alert_type_map or ALERT_TYPE_MAP

    def normalize(self, raw: RawAlert, source: str) -> NormalizedAlert:
        alert_type = self._map_type(raw.alert_name)
        entities = self._extract_entities(raw)
        fingerprint = self._generate_fingerprint(entities)

        return NormalizedAlert(
            id=str(uuid_extensions.uuid7()),
            source=source,
            defense_line=raw.defense_line.value,
            alert_name=raw.alert_name,
            type=alert_type,
            severity=self._default_severity(raw.defense_line.value, alert_type),
            entities=entities,
            fingerprint=fingerprint,
            alarm_id=raw.alarm_id,
            deduped_alarm_ids=[],
            raw_evidence=raw.raw_evidence,
            created_at=raw.alert_time,
        )

    def _map_type(self, alert_name: str) -> str:
        return self._type_map.get(alert_name, alert_name.lower())

    def _extract_entities(self, raw: RawAlert) -> list[Entity]:
        field_mapping = get_field_mapping(raw.alert_name)
        entities: list[Entity] = []
        seen: set[tuple[str, str]] = set()

        for field_name, value in raw.raw_evidence.items():
            if not isinstance(value, str) or not value.strip():
                continue

            entity_type = None

            # 1. Check configured field mapping first
            if field_name in field_mapping:
                entity_type = field_mapping[field_name]["entity_type"]

            # 2. Check semantic patterns
            if entity_type is None:
                for field_patterns, etype in ENTITY_FIELD_PATTERNS:
                    if any(field_name.lower() == p or field_name.lower().endswith(f"_{p}") for p in field_patterns):
                        entity_type = etype
                        break

            # 3. Special case: URL fields
            if entity_type is None and _is_url_field(field_name):
                entity_type = "url"

            if entity_type and (entity_type, value) not in seen:
                entities.append(Entity(type=entity_type, value=value))
                seen.add((entity_type, value))

        return entities

    def _generate_fingerprint(self, entities: list[Entity]) -> str:
        sorted_entities = sorted(entities, key=lambda e: (e.type, e.value))
        canonical = ",".join(f"{e.type}:{e.value}" for e in sorted_entities)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def _default_severity(self, defense_line: str, alert_type: str) -> str:
        # Initial simple default; refined by operational calibration
        if alert_type in ("malware", "ransomware", "network_c2"):
            return "high" if defense_line in ("endpoint", "server") else "medium"
        if alert_type in ("phishing", "anomaly_login"):
            return "high"
        return "medium"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && PYTHONPATH=. uv run pytest tests/test_normalizer.py -v`
Expected: PASS (may need `uv add uuid-extensions` in harness package)

- [ ] **Step 5: Commit**

```bash
git add backend/app/ingestion/normalizer.py backend/app/ingestion/field_mapping.py backend/tests/test_normalizer.py
git commit -m "feat(ingestion): add normalizer with entity extraction and fingerprint generation"
```

---

## Task 3: Dedup and Aggregation

**Files:**
- Create: `backend/app/ingestion/dedup.py`
- Test: `backend/tests/test_dedup.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_dedup.py
from app.ingestion.models import NormalizedAlert, AggregatedAlert, Entity
from app.ingestion.dedup import DedupAggregator


def make_alert(alarm_id, fingerprint, entities, alert_time="2026-05-10T14:32:00Z", **kwargs):
    return NormalizedAlert(
        id=f"uuid-{alarm_id}", source="siem_splunk", defense_line="endpoint",
        alert_name="TestAlert", type="malware", severity="high",
        entities=entities, fingerprint=fingerprint,
        alarm_id=alarm_id, deduped_alarm_ids=[],
        raw_evidence={"src_ip": "10.0.0.1"},
        created_at=alert_time,
        **({"aggregation": None} if "aggregation" not in kwargs else {}),
    )


class TestFingerprintDedup:
    def test_first_alert_passes_through(self):
        da = DedupAggregator()
        alert = make_alert("a1", "fp1", [Entity(type="ip", value="10.0.0.1")])
        result = da.process(alert)
        assert result is not None
        assert result.alarm_id == "a1"
        assert result.deduped_alarm_ids == []

    def test_duplicate_fingerprint_deduped(self):
        da = DedupAggregator()
        a1 = make_alert("a1", "fp1", [Entity(type="ip", value="10.0.0.1")])
        da.process(a1)
        a2 = make_alert("a2", "fp1", [Entity(type="ip", value="10.0.0.1")])
        result = da.process(a2)
        assert result is None  # deduped, no new alert to queue

    def test_deduped_id_appended_to_first_alert(self):
        da = DedupAggregator()
        a1 = make_alert("a1", "fp1", [Entity(type="ip", value="10.0.0.1")])
        first = da.process(a1)
        a2 = make_alert("a2", "fp1", [Entity(type="ip", value="10.0.0.1")])
        da.process(a2)
        assert "a2" in first.deduped_alarm_ids

    def test_different_fingerprints_not_deduped(self):
        da = DedupAggregator()
        a1 = make_alert("a1", "fp1", [Entity(type="ip", value="10.0.0.1")])
        da.process(a1)
        a2 = make_alert("a2", "fp2", [Entity(type="hash", value="abc")])
        result = da.process(a2)
        assert result is not None
        assert result.alarm_id == "a2"

    def test_window_expiry_resets_fingerprint(self):
        da = DedupAggregator(window_seconds=0)  # immediate expiry
        a1 = make_alert("a1", "fp1", [Entity(type="ip", value="10.0.0.1")])
        da.process(a1)
        import time
        time.sleep(0.01)
        a2 = make_alert("a2", "fp1", [Entity(type="ip", value="10.0.0.1")])
        result = da.process(a2)
        assert result is not None  # window expired, treated as new


class TestEntityAggregation:
    def test_high_overlap_aggregates(self):
        da = DedupAggregator(entity_overlap_threshold=0.75)
        a1 = make_alert("a1", "fp1", [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="hash", value="abc123"),
        ], alert_time="2026-05-10T14:30:00Z")
        da.process(a1)
        a2 = make_alert("a2", "fp2", [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="hash", value="abc123"),
            Entity(type="host", value="server01"),
        ], alert_time="2026-05-10T14:31:00Z")
        result = da.process(a2)
        assert result is not None
        assert result.aggregation is not None
        assert result.aggregation["entity_overlap"] >= 0.75

    def test_low_overlap_does_not_aggregate(self):
        da = DedupAggregator(entity_overlap_threshold=0.75)
        a1 = make_alert("a1", "fp1", [Entity(type="ip", value="10.0.0.1")])
        da.process(a1)
        a2 = make_alert("a2", "fp2", [
            Entity(type="hash", value="xyz789"),
            Entity(type="host", value="other-server"),
        ])
        result = da.process(a2)
        assert result is not None
        assert result.aggregation is None  # no aggregation

    def test_different_defense_lines_not_aggregated(self):
        da = DedupAggregator()
        a1 = make_alert("a1", "fp1", [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="hash", value="abc"),
        ])
        a2 = make_alert("a2", "fp2", [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="hash", value="abc"),
        ])
        # Override defense_line for second alert
        a2.defense_line = "server"
        da.process(a1)
        result = da.process(a2)
        assert result is not None
        assert result.aggregation is None

    def test_aggregation_max_severity(self):
        da = DedupAggregator(entity_overlap_threshold=0.75)
        a1 = make_alert("a1", "fp1", [
            Entity(type="ip", value="10.0.0.1"), Entity(type="hash", value="abc"),
        ], severity="medium")
        da.process(a1)
        a2 = make_alert("a2", "fp2", [
            Entity(type="ip", value="10.0.0.1"), Entity(type="hash", value="abc"),
        ], severity="critical")
        result = da.process(a2)
        assert result is not None
        assert result.aggregation is not None
        assert result.severity == "critical"

    def test_aggregation_max_limit(self):
        da = DedupAggregator(entity_overlap_threshold=0.75, max_aggregation_size=2)
        a1 = make_alert("a1", "fp1", [
            Entity(type="ip", value="10.0.0.1"), Entity(type="hash", value="abc"),
        ])
        da.process(a1)
        a2 = make_alert("a2", "fp2", [
            Entity(type="ip", value="10.0.0.1"), Entity(type="hash", value="abc"),
        ])
        da.process(a2)
        a3 = make_alert("a3", "fp3", [
            Entity(type="ip", value="10.0.0.1"), Entity(type="hash", value="abc"),
        ])
        result = da.process(a3)
        # Limit hit: a3 starts a new aggregation group
        assert result is not None
        assert result.aggregation is None  # new group
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && PYTHONPATH=. uv run pytest tests/test_dedup.py -v`
Expected: FAIL

- [ ] **Step 3: Write the implementation**

```python
# backend/app/ingestion/dedup.py
import time
from collections import defaultdict
from dataclasses import dataclass, field
from app.ingestion.models import NormalizedAlert, AggregatedAlert, Entity


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class _DedupEntry:
    first_alert: NormalizedAlert
    first_seen: float
    count: int = 1
    alarm_ids: set = field(default_factory=set)

    def is_expired(self, window_seconds: float) -> bool:
        return (time.monotonic() - self.first_seen) > window_seconds


@dataclass
class _AggregationGroup:
    alerts: list[NormalizedAlert] = field(default_factory=list)

    def can_add(self, max_size: int) -> bool:
        return len(self.alerts) < max_size


class DedupAggregator:
    def __init__(
        self,
        window_seconds: float = 600,          # fingerprint dedup window (10 min)
        entity_overlap_threshold: float = 0.75,
        aggregation_time_window_seconds: float = 300,  # aggregation window (5 min)
        max_aggregation_size: int = 10,
    ):
        self._window_seconds = window_seconds
        self._entity_overlap_threshold = entity_overlap_threshold
        self._aggregation_window = aggregation_time_window_seconds
        self._max_aggregation_size = max_aggregation_size
        self._fingerprints: dict[str, _DedupEntry] = {}
        self._aggregation_groups: dict[str, _AggregationGroup] = {}

    def process(self, alert: NormalizedAlert) -> NormalizedAlert | None:
        """Process an alert through dedup and aggregation.
        Returns None if deduped, the alert (possibly aggregated) if it should proceed.
        """
        self._cleanup_expired()

        # Step 1: Fingerprint dedup
        entry = self._fingerprints.get(alert.fingerprint)
        if entry is not None:
            entry.alarm_ids.add(alert.alarm_id)
            entry.first_alert.deduped_alarm_ids.append(alert.alarm_id)
            entry.count += 1
            return None  # deduped, discard

        self._fingerprints[alert.fingerprint] = _DedupEntry(
            first_alert=alert, first_seen=time.monotonic(), alarm_ids={alert.alarm_id}
        )

        # Step 2: Entity-based aggregation (same defense line only)
        for group_key, group in list(self._aggregation_groups.items()):
            defense_line = group_key.split(":", 1)[0]
            if defense_line != alert.defense_line:
                continue
            if not group.can_add(self._max_aggregation_size):
                continue

            rep = group.alerts[0]
            overlap = _entity_overlap(rep.entities, alert.entities)
            time_delta = _time_delta_seconds(rep.created_at, alert.created_at)

            if overlap >= self._entity_overlap_threshold and time_delta <= self._aggregation_window:
                group.alerts.append(alert)
                return _build_aggregated_alert(group.alerts, overlap, time_delta)

        # No match — start a new aggregation group
        self._aggregation_groups[f"{alert.defense_line}:{alert.alarm_id}"] = _AggregationGroup(alerts=[alert])
        return alert

    def _cleanup_expired(self):
        expired_fps = [fp for fp, e in self._fingerprints.items() if e.is_expired(self._window_seconds)]
        for fp in expired_fps:
            del self._fingerprints[fp]


def _entity_overlap(entities_a: list[Entity], entities_b: list[Entity]) -> float:
    set_a = {(e.type, e.value) for e in entities_a}
    set_b = {(e.type, e.value) for e in entities_b}
    if not set_a and not set_b:
        return 0.0
    if not set_a or not set_b:
        return 0.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union)


def _time_delta_seconds(time_a: str, time_b: str) -> float:
    from datetime import datetime
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    try:
        ta = datetime.strptime(time_a[:19] + "Z", fmt) if not time_a.endswith("Z") else datetime.strptime(time_a, fmt)
        tb = datetime.strptime(time_b[:19] + "Z", fmt) if not time_b.endswith("Z") else datetime.strptime(time_b, fmt)
        return abs((tb - ta).total_seconds())
    except (ValueError, IndexError):
        return float("inf")


def _build_aggregated_alert(alerts: list[NormalizedAlert], overlap: float, time_delta: float) -> AggregatedAlert:
    first = alerts[0]
    rep = first

    # Take max severity
    severity = rep.severity
    for a in alerts[1:]:
        if SEVERITY_ORDER.get(a.severity, 0) > SEVERITY_ORDER.get(severity, 0):
            severity = a.severity

    # Merge entities
    all_entities: dict[tuple[str, str], Entity] = {}
    for a in alerts:
        for e in a.entities:
            all_entities[(e.type, e.value)] = e

    # Build raw_evidence: common + per_alarm
    all_field_keys = set()
    for a in alerts:
        all_field_keys.update(a.raw_evidence.keys())

    common: dict = {}
    per_alarm: dict[str, dict] = {}
    for key in all_field_keys:
        values = []
        for a in alerts:
            val = a.raw_evidence.get(key)
            if val is not None:
                values.append(val)
        if len(set(str(v) for v in values)) == 1 and values:
            common[key] = values[0]
        else:
            for a in alerts:
                if key in a.raw_evidence:
                    per_alarm.setdefault(a.alarm_id, {})[key] = a.raw_evidence[key]

    return AggregatedAlert(
        id=rep.id,
        source=rep.source,
        defense_line=rep.defense_line,
        alert_name=rep.alert_name,
        type=rep.type,
        severity=severity,
        entities=list(all_entities.values()),
        fingerprint=f"merged:{rep.fingerprint}",
        alarm_id=None,
        deduped_alarm_ids=[],
        aggregation={
            "entity_overlap": round(overlap, 4),
            "time_delta_seconds": int(time_delta),
            "source_alarms": [
                {"alarm_id": a.alarm_id, "alert_name": a.alert_name}
                for a in alerts
            ],
        },
        raw_evidence={"common": common, "per_alarm": per_alarm},
        created_at=rep.created_at,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && PYTHONPATH=. uv run pytest tests/test_dedup.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/ingestion/dedup.py backend/tests/test_dedup.py
git commit -m "feat(ingestion): add fingerprint dedup and entity-based aggregation"
```

---

## Task 4: Priority Queue

**Files:**
- Create: `backend/app/ingestion/queue.py`
- Test: `backend/tests/test_queue.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_queue.py
import pytest
from app.ingestion.models import NormalizedAlert, Entity
from app.ingestion.queue import PriorityQueue, PriorityScore


def make_alert(alarm_id, severity="high", defense_line="server"):
    return NormalizedAlert(
        id=f"uuid-{alarm_id}", source="siem_splunk", defense_line=defense_line,
        alert_name="TestAlert", type="malware", severity=severity,
        entities=[Entity(type="ip", value="10.0.0.1")],
        fingerprint=f"fp-{alarm_id}", alarm_id=alarm_id,
        deduped_alarm_ids=[], raw_evidence={},
        created_at="2026-05-10T14:32:00Z",
    )


class TestPriorityQueue:
    def test_enqueue_dequeue_order(self):
        q = PriorityQueue()
        low = make_alert("low", severity="low")
        critical = make_alert("critical", severity="critical")
        q.enqueue(low, PriorityScore(alert_severity=1, asset_criticality=0.5, alert_density=0, uncertainty=0.1))
        q.enqueue(critical, PriorityScore(alert_severity=4, asset_criticality=0.9, alert_density=0, uncertainty=0.1))

        first = q.dequeue()
        assert first.alarm_id == "critical"

        second = q.dequeue()
        assert second.alarm_id == "low"

    def test_empty_queue_raises(self):
        q = PriorityQueue()
        with pytest.raises(IndexError):
            q.dequeue()

    def test_peek_top_n(self):
        q = PriorityQueue()
        for i in range(5):
            a = make_alert(f"a{i}", severity="medium")
            q.enqueue(a, PriorityScore(alert_severity=3, asset_criticality=0.5, alert_density=0, uncertainty=0.1))
        top = q.peek_top(3)
        assert len(top) == 3

    def test_queue_size(self):
        q = PriorityQueue()
        assert q.size == 0
        q.enqueue(make_alert("a1"), PriorityScore(alert_severity=3, asset_criticality=0.5, alert_density=0, uncertainty=0.1))
        assert q.size == 1

    def test_queue_status(self):
        q = PriorityQueue()
        for i in range(3):
            a = make_alert(f"a{i}", severity="medium")
            q.enqueue(a, PriorityScore(alert_severity=3, asset_criticality=0.5, alert_density=0, uncertainty=0.1))
        status = q.status()
        assert status["depth"] == 3


class TestPriorityScore:
    def test_calculates_weighted_score(self):
        ps = PriorityScore(alert_severity=4, asset_criticality=0.9, alert_density=0.5, uncertainty=0.1)
        expected = 0.40 * (4/4) + 0.30 * 0.9 + 0.20 * 0.5 + 0.10 * 0.1
        assert abs(ps.calculate() - expected) < 0.001
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && PYTHONPATH=. uv run pytest tests/test_queue.py -v`
Expected: FAIL

- [ ] **Step 3: Write the implementation**

```python
# backend/app/ingestion/queue.py
import heapq
from dataclasses import dataclass, field
from typing import Any
from app.ingestion.models import NormalizedAlert


@dataclass
class PriorityScore:
    alert_severity: float     # 1-4 mapped: low=1, medium=2, high=3, critical=4
    asset_criticality: float  # 0.0-1.0 from CMDB
    alert_density: float      # 0.0-1.0 normalized
    uncertainty: float        # 0.0-1.0 (lower = more uncertain = higher priority)

    # Weights (configurable)
    w_severity: float = 0.40
    w_asset: float = 0.30
    w_density: float = 0.20
    w_uncertainty: float = 0.10

    def calculate(self) -> float:
        return (
            self.w_severity * (self.alert_severity / 4.0)
            + self.w_asset * self.asset_criticality
            + self.w_density * self.alert_density
            + self.w_uncertainty * self.uncertainty
        )


@dataclass(order=True)
class _QueueItem:
    priority: float
    alert: Any = field(compare=False)


class PriorityQueue:
    def __init__(self):
        self._heap: list[_QueueItem] = []
        self._counter = 0

    def enqueue(self, alert: NormalizedAlert, score: PriorityScore) -> None:
        # Negate priority for max-heap behavior
        item = _QueueItem(priority=-score.calculate(), alert=alert)
        heapq.heappush(self._heap, item)

    def dequeue(self) -> NormalizedAlert:
        if not self._heap:
            raise IndexError("Queue is empty")
        item = heapq.heappop(self._heap)
        return item.alert

    def peek_top(self, n: int) -> list[NormalizedAlert]:
        return [item.alert for item in heapq.nsmallest(n, self._heap)][:n]

    @property
    def size(self) -> int:
        return len(self._heap)

    def status(self) -> dict[str, int]:
        return {"depth": self.size}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && PYTHONPATH=. uv run pytest tests/test_queue.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/ingestion/queue.py backend/tests/test_queue.py
git commit -m "feat(ingestion): add priority queue with weighted multi-factor scoring"
```

---

## Task 5: Ingestion FastAPI App + Routers

**Files:**
- Create: `backend/app/ingestion/app.py`
- Create: `backend/app/ingestion/routers/__init__.py`
- Create: `backend/app/ingestion/routers/webhooks.py`
- Create: `backend/app/ingestion/routers/queue_status.py`
- Modify: `backend/app/gateway/app.py` (mount ingestion sub-app)
- Test: `backend/tests/test_ingestion_api.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_ingestion_api.py
import pytest
from httpx import AsyncClient, ASGITransport
from app.ingestion.app import make_ingestion_app


@pytest.fixture
def ingestion_app():
    return make_ingestion_app()


@pytest.mark.asyncio
async def test_webhook_endpoint_accepts_valid_alert(ingestion_app):
    transport = ASGITransport(app=ingestion_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/webhooks/siem_splunk",
            json={
                "alarm_id": "splunk-abc-12345",
                "alert_time": "2026-05-10T14:32:00Z",
                "defense_line": "endpoint",
                "alert_name": "Endpoint_Abnormal_Process_Outbound",
                "raw_evidence": {"src_ip": "10.23.45.67", "process_hash": "abc123"},
            },
        )
    assert resp.status_code == 202
    data = resp.json()
    assert data["accepted"] is True
    assert "alert_id" in data


@pytest.mark.asyncio
async def test_webhook_rejects_missing_required_fields(ingestion_app):
    transport = ASGITransport(app=ingestion_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/webhooks/siem_splunk",
            json={"alarm_id": "x"},  # missing alert_time, defense_line, alert_name
        )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_webhook_rejects_invalid_defense_line(ingestion_app):
    transport = ASGITransport(app=ingestion_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/webhooks/siem_splunk",
            json={
                "alarm_id": "x", "alert_time": "2026-05-10T14:32:00Z",
                "defense_line": "bogus", "alert_name": "Test",
                "raw_evidence": {},
            },
        )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_queue_status_endpoint(ingestion_app):
    transport = ASGITransport(app=ingestion_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/queue/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "depth" in data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && PYTHONPATH=. uv run pytest tests/test_ingestion_api.py -v`
Expected: FAIL

- [ ] **Step 3: Write the implementation**

```python
# backend/app/ingestion/app.py
from fastapi import FastAPI
from app.ingestion.normalizer import Normalizer
from app.ingestion.dedup import DedupAggregator
from app.ingestion.queue import PriorityQueue
from app.ingestion.routers import webhooks, queue_status


def make_ingestion_app() -> FastAPI:
    app = FastAPI(title="SOC Alert Ingestion", version="0.1.0")

    # Shared state (replace with dependency injection for production)
    app.state.normalizer = Normalizer()
    app.state.dedup_aggregator = DedupAggregator()
    app.state.queue = PriorityQueue()

    app.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"])
    app.include_router(queue_status.router, prefix="/queue", tags=["queue"])

    return app


# backend/app/ingestion/routers/__init__.py
"""Ingestion routers."""

# backend/app/ingestion/routers/webhooks.py
import logging
from fastapi import APIRouter, Request
from app.ingestion.models import RawAlert
from app.ingestion.queue import PriorityScore
from app.ingestion.adapters.siem_webhook import SIEMWebhookAdapter

logger = logging.getLogger(__name__)

router = APIRouter()
_adapter = SIEMWebhookAdapter()

SEVERITY_TO_SCORE = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@router.post("/{vendor}")
async def receive_alert(vendor: str, body: dict, request: Request):
    raw = _adapter.parse(body, vendor)

    normalizer = request.app.state.normalizer
    dedup = request.app.state.dedup_aggregator
    queue = request.app.state.queue

    normalized = normalizer.normalize(raw, source=vendor)
    result = dedup.process(normalized)

    if result is not None:
        severity_score = SEVERITY_TO_SCORE.get(result.severity, 2)
        score = PriorityScore(
            alert_severity=severity_score,
            asset_criticality=0.5,  # placeholder, will be enriched via CMDB
            alert_density=0.0,
            uncertainty=0.1,
        )
        queue.enqueue(result, score)

    logger.info(
        "Alert received vendor=%s alarm_id=%s accepted=%s deduped=%s",
        vendor, raw.alarm_id, True, result is None,
    )
    return {"accepted": True, "alert_id": normalized.id}


# backend/app/ingestion/routers/queue_status.py
from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/status")
async def get_queue_status(request: Request):
    q = request.app.state.queue
    return q.status()
```

```python
# backend/app/ingestion/adapters/__init__.py
"""Alert adapters."""

# backend/app/ingestion/adapters/base.py
from abc import ABC, abstractmethod
from app.ingestion.models import RawAlert


class AlertAdapter(ABC):
    @abstractmethod
    def parse(self, body: dict, vendor: str) -> RawAlert:
        ...


# backend/app/ingestion/adapters/siem_webhook.py
from app.ingestion.adapters.base import AlertAdapter
from app.ingestion.models import RawAlert


class SIEMWebhookAdapter(AlertAdapter):
    """Generic SIEM webhook adapter — the upstream already sends in our standard format."""
    def parse(self, body: dict, vendor: str) -> RawAlert:
        return RawAlert(**body)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && PYTHONPATH=. uv run pytest tests/test_ingestion_api.py -v`
Expected: PASS

- [ ] **Step 5: Mount ingestion app into existing Gateway**

```python
# In backend/app/gateway/app.py, add after the existing router includes:
from app.ingestion.app import make_ingestion_app

# Inside lifespan or app creation:
soc_ingestion = make_ingestion_app()
app.mount("/api/soc", soc_ingestion)
```

- [ ] **Step 6: Commit**

```bash
git add backend/app/ingestion/app.py backend/app/ingestion/routers/ backend/app/ingestion/adapters/ backend/tests/test_ingestion_api.py
git commit -m "feat(ingestion): add FastAPI app with webhook receiver and queue status endpoints"
```

---

## Task 6: Dispatcher — Queue Consumer + Thread/Run Creation

**Files:**
- Create: `backend/app/ingestion/dispatcher.py`
- Test: `backend/tests/test_dispatcher.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_dispatcher.py
from unittest.mock import AsyncMock, patch, MagicMock
from app.ingestion.models import NormalizedAlert, Entity
from app.ingestion.queue import PriorityQueue, PriorityScore
from app.ingestion.dispatcher import Dispatcher


def make_alert(alarm_id="a1"):
    return NormalizedAlert(
        id=f"uuid-{alarm_id}", source="siem_splunk", defense_line="endpoint",
        alert_name="Test", type="malware", severity="high",
        entities=[Entity(type="ip", value="10.0.0.1")],
        fingerprint=f"fp-{alarm_id}", alarm_id=alarm_id,
        deduped_alarm_ids=[], raw_evidence={"src_ip": "10.0.0.1"},
        created_at="2026-05-10T14:32:00Z",
    )


class TestDispatcher:
    @patch("app.ingestion.dispatcher.httpx")
    def test_dispatch_creates_thread_and_run(self, mock_httpx):
        mock_client = MagicMock()
        mock_client.post.side_effect = [
            MagicMock(status_code=200, json=lambda: {"thread_id": "thread-1"}),
            MagicMock(status_code=200, json=lambda: {"run_id": "run-1"}),
        ]
        mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client

        q = PriorityQueue()
        q.enqueue(make_alert("a1"), PriorityScore(alert_severity=3, asset_criticality=0.5, alert_density=0, uncertainty=0.1))

        dispatcher = Dispatcher(
            langgraph_url="http://localhost:2026/api/langgraph",
            memory_soc_url="http://localhost:8003",
        )

        async def run():
            await dispatcher.dispatch_one(q)

        import asyncio
        asyncio.run(run())

        assert q.size == 0  # dequeued
        assert mock_client.post.call_count == 2  # create thread + create run

    @patch("app.ingestion.dispatcher.httpx")
    def test_empty_queue_does_nothing(self, mock_httpx):
        mock_client = MagicMock()
        mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client

        q = PriorityQueue()
        dispatcher = Dispatcher()

        async def run():
            await dispatcher.dispatch_one(q)

        import asyncio
        asyncio.run(run())

        mock_client.post.assert_not_called()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && PYTHONPATH=. uv run pytest tests/test_dispatcher.py -v`
Expected: FAIL

- [ ] **Step 3: Write the implementation**

```python
# backend/app/ingestion/dispatcher.py
import json
import logging
import httpx
from app.ingestion.queue import PriorityQueue

logger = logging.getLogger(__name__)


class Dispatcher:
    def __init__(
        self,
        langgraph_url: str = "http://localhost:2026/api/langgraph",
        memory_soc_url: str = "http://localhost:8003",
        recursion_limit: int = 100,
        model_name: str = "claude-opus-4-7",
    ):
        self.langgraph_url = langgraph_url
        self.memory_soc_url = memory_soc_url
        self.recursion_limit = recursion_limit
        self.model_name = model_name

    async def dispatch_one(self, queue: PriorityQueue) -> dict | None:
        """Pull one alert from queue, query similar alerts, create Thread/Run.
        Returns the dispatch result dict or None if nothing to process.
        """
        try:
            alert = queue.dequeue()
        except IndexError:
            return None

        # Query similar historical alerts
        similar = await self._query_similar(alert)

        # Fast triage: exact match + high confidence → skip LLM
        if similar and similar.get("exact_match"):
            em = similar["exact_match"]
            if em["confidence"] >= 0.95:
                logger.info(
                    "Fast triage: exact match for fingerprint=%s, reusing result=%s",
                    alert.fingerprint, em["result_id"],
                )
                return {"fast_triage": True, "reused_result_id": em["result_id"], "alert_id": alert.id}

        # Build first message with alert + history context
        message_content = self._build_message(alert, similar)

        # Create thread
        thread_id = await self._create_thread()
        if not thread_id:
            return None

        # Create run
        run_id = await self._create_run(thread_id, message_content)
        if not run_id:
            return None

        logger.info("Dispatched alert_id=%s to thread=%s run=%s", alert.id, thread_id, run_id)
        return {"fast_triage": False, "thread_id": thread_id, "run_id": run_id, "alert_id": alert.id}

    async def _query_similar(self, alert) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.memory_soc_url}/api/similar-alerts",
                    params={
                        "fingerprint": alert.fingerprint,
                        "defense_line": alert.defense_line,
                        "alert_name": alert.alert_name,
                        "entities": json.dumps([{"type": e.type, "value": e.value} for e in alert.entities]),
                        "lookback_days": 30,
                    },
                )
                if resp.status_code == 200:
                    return resp.json()
        except Exception as e:
            logger.warning("Similar alert query failed: %s", e)
        return None

    def _build_message(self, alert, similar: dict | None) -> str:
        parts = [f"<alert>\n{json.dumps(alert.model_dump(), indent=2, ensure_ascii=False)}\n</alert>"]

        if similar:
            if similar.get("exact_match"):
                em = similar["exact_match"]
                parts.append(
                    f"\n<historical_context>\n"
                    f"该告警与历史上已研判告警完全相同（指纹={alert.fingerprint}），"
                    f"上次判定: {em['verdict']}（置信度 {em['confidence']}），出现次数: {em['occurrence_count']}。"
                    f"\n</historical_context>"
                )

            same_stats = similar.get("same_type_stats", {})
            if same_stats:
                parts.append(
                    f"\n<type_statistics>\n"
                    f"过去30天同类告警({alert.alert_name})统计: "
                    f"总数 {same_stats.get('total', 0)}，"
                    f"恶意 {same_stats.get('malicious', 0)}，"
                    f"误报 {same_stats.get('false_positive', 0)}，"
                    f"不确定 {same_stats.get('uncertain', 0)}"
                    f"\n</type_statistics>"
                )

        return "\n".join(parts)

    async def _create_thread(self) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{self.langgraph_url}/threads",
                    json={"metadata": {"source": "soc-ingestion"}},
                )
                if resp.status_code == 200:
                    return resp.json()["thread_id"]
                logger.error("Failed to create thread: %s %s", resp.status_code, resp.text)
        except Exception as e:
            logger.error("Thread creation failed: %s", e)
        return None

    async def _create_run(self, thread_id: str, content: str) -> str | None:
        try:
            payload = {
                "input": {
                    "messages": [{"role": "user", "content": content}],
                },
                "config": {
                    "recursion_limit": self.recursion_limit,
                    "configurable": {
                        "model_name": self.model_name,
                        "thinking_enabled": True,
                    },
                },
                "stream_mode": ["values", "messages-tuple", "custom"],
            }
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{self.langgraph_url}/threads/{thread_id}/runs",
                    json=payload,
                )
                if resp.status_code == 200:
                    return resp.json().get("run_id")
                logger.error("Failed to create run: %s %s", resp.status_code, resp.text)
        except Exception as e:
            logger.error("Run creation failed: %s", e)
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && PYTHONPATH=. uv run pytest tests/test_dispatcher.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/ingestion/dispatcher.py backend/tests/test_dispatcher.py
git commit -m "feat(ingestion): add dispatcher with similarity query and Thread/Run creation"
```

---

## Task 7: Memory-SOC — Models and Database

**Files:**
- Create: `backend/packages/memory-soc/pyproject.toml`
- Create: `backend/packages/memory-soc/soc_memory/__init__.py`
- Create: `backend/packages/memory-soc/soc_memory/models.py`
- Create: `backend/packages/memory-soc/soc_memory/database.py`

- [ ] **Step 1: Write pyproject.toml**

```toml
# backend/packages/memory-soc/pyproject.toml
[project]
name = "memory-soc"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0",
    "sqlalchemy[asyncio]>=2.0,<3.0",
    "redis>=5.0.0",
    "httpx>=0.28.0",
    "pydantic>=2.12.5",
    "uvicorn[standard]>=0.34.0",
    "apscheduler>=3.10.0",
]
```

- [ ] **Step 2: Write database and models**

```python
# backend/packages/memory-soc/soc_memory/__init__.py
"""SOC Memory Service — session state, triage results, feedback, suppression rules."""

# backend/packages/memory-soc/soc_memory/database.py
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

DATABASE_URL = "sqlite+aiosqlite:///soc_memory.db"  # default for dev; PostgreSQL for prod

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    from soc_memory.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# backend/packages/memory-soc/soc_memory/models.py
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, Boolean, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.dialects.postgresql import UUID


class Base(DeclarativeBase):
    pass


def new_uuid():
    return str(uuid.uuid4())


class TriageResult(Base):
    __tablename__ = "triage_results"

    result_id = Column(String, primary_key=True, default=new_uuid)
    alert_id = Column(String, nullable=False)
    thread_id = Column(String, nullable=False)
    defense_line = Column(String)
    alert_name = Column(String)
    verdict = Column(String)        # malicious | false_positive | benign_anomaly | uncertain
    confidence = Column(Float)
    confidence_level = Column(String)  # high | medium | low
    severity = Column(String)
    summary = Column(Text)
    evidence_timeline = Column(JSON)
    action_suggestion = Column(JSON)
    uncertainties = Column(JSON)
    skill_version = Column(String)
    degraded = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(String, primary_key=True, default=new_uuid)
    result_id = Column(String, ForeignKey("triage_results.result_id"), nullable=False)
    analyst = Column(String)
    action = Column(String)         # accepted | rejected | escalated
    reject_reason = Column(String)  # evidence_insufficient | logic_error | threshold_conservative | other
    comment = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class SuppressionRule(Base):
    __tablename__ = "suppression_rules"

    id = Column(String, primary_key=True, default=new_uuid)
    rule_id = Column(String)
    entity_pattern = Column(JSON)   # { "defense_line": "endpoint", "host": "test-*" }
    status = Column(String, default="draft")  # draft | active | expired
    valid_until = Column(DateTime)
    created_by = Column(String)
    approved_by = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
```

- [ ] **Step 3: Commit**

```bash
git add backend/packages/memory-soc/
git commit -m "feat(memory-soc): add project scaffold with SQLAlchemy models"
```

---

## Task 8: Memory-SOC — API and Similarity Query

**Files:**
- Create: `backend/packages/memory-soc/soc_memory/app.py`
- Create: `backend/packages/memory-soc/soc_memory/session_store.py`
- Create: `backend/packages/memory-soc/soc_memory/result_store.py`
- Create: `backend/packages/memory-soc/soc_memory/feedback.py`
- Create: `backend/packages/memory-soc/soc_memory/similarity.py`
- Create: `backend/packages/memory-soc/soc_memory/routers.py`

- [ ] **Step 1: Write the implementation**

```python
# backend/packages/memory-soc/soc_memory/session_store.py
"""Redis-backed session state for triage tasks."""
import json
import redis.asyncio as aioredis

REDIS_URL = "redis://localhost:6379/0"
TTL_SECONDS = 86400  # 24 hours


async def get_redis() -> aioredis.Redis:
    return await aioredis.from_url(REDIS_URL, decode_responses=True)


async def set_session(task_id: str, data: dict) -> None:
    r = await get_redis()
    key = f"triage:task:{task_id}"
    await r.set(key, json.dumps(data), ex=TTL_SECONDS)


async def get_session(task_id: str) -> dict | None:
    r = await get_redis()
    data = await r.get(f"triage:task:{task_id}")
    return json.loads(data) if data else None


# backend/packages/memory-soc/soc_memory/result_store.py
"""PostgreSQL CRUD for triage results."""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from soc_memory.models import TriageResult


async def save_result(db: AsyncSession, data: dict) -> TriageResult:
    result = TriageResult(**data)
    db.add(result)
    await db.commit()
    await db.refresh(result)
    return result


async def get_result(db: AsyncSession, result_id: str) -> TriageResult | None:
    return await db.get(TriageResult, result_id)


# backend/packages/memory-soc/soc_memory/feedback.py
"""Feedback CRUD."""
from sqlalchemy.ext.asyncio import AsyncSession
from soc_memory.models import Feedback


async def save_feedback(db: AsyncSession, data: dict) -> Feedback:
    fb = Feedback(**data)
    db.add(fb)
    await db.commit()
    await db.refresh(fb)
    return fb


# backend/packages/memory-soc/soc_memory/similarity.py
"""Similar alert query engine."""
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from soc_memory.models import TriageResult


async def find_similar(
    db: AsyncSession,
    fingerprint: str,
    defense_line: str,
    alert_name: str,
    entities: list[dict],
    lookback_days: int = 30,
) -> dict:
    # Exact fingerprint match
    result = await db.execute(
        select(TriageResult).where(
            TriageResult.alert_name == alert_name,
            # We match on alert_name + check evidence for fingerprint match
            # (fingerprint is stored within the alert, matched via raw_evidence)
        ).order_by(TriageResult.created_at.desc()).limit(1)
    )
    exact = result.scalar_one_or_none()

    # Same type statistics
    from datetime import datetime, timedelta
    since = datetime.utcnow() - timedelta(days=lookback_days)
    stats_result = await db.execute(
        select(
            TriageResult.verdict,
            func.count(TriageResult.verdict),
        ).where(
            TriageResult.alert_name == alert_name,
            TriageResult.created_at >= since,
        ).group_by(TriageResult.verdict)
    )
    rows = stats_result.all()
    stats = {"total": sum(c for _, c in rows)}
    for verdict, count in rows:
        stats[verdict] = count

    return {
        "exact_match": {
            "result_id": exact.result_id,
            "verdict": exact.verdict,
            "confidence": exact.confidence,
            "created_at": exact.created_at.isoformat() if exact.created_at else None,
            "occurrence_count": stats.get("total", 0),
        } if exact else None,
        "similar_alerts": [],
        "same_type_stats": stats,
    }


# backend/packages/memory-soc/soc_memory/routers.py
"""Internal API routes."""
import json
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from soc_memory.database import get_db
from soc_memory import result_store, feedback, similarity, session_store

router = APIRouter()


@router.get("/api/similar-alerts")
async def similar_alerts(
    fingerprint: str = Query(...),
    defense_line: str = Query(...),
    alert_name: str = Query(...),
    entities: str = Query(...),
    lookback_days: int = Query(30),
    db: AsyncSession = Depends(get_db),
):
    entity_list = json.loads(entities)
    return await similarity.find_similar(db, fingerprint, defense_line, alert_name, entity_list, lookback_days)


@router.post("/api/results")
async def create_result(data: dict, db: AsyncSession = Depends(get_db)):
    r = await result_store.save_result(db, data)
    return {"result_id": r.result_id}


@router.get("/api/results/{result_id}")
async def get_result(result_id: str, db: AsyncSession = Depends(get_db)):
    r = await result_store.get_result(db, result_id)
    if r is None:
        return {"error": "not found"}, 404
    return {"result_id": r.result_id, "verdict": r.verdict, "confidence": r.confidence}


@router.post("/api/feedback")
async def submit_feedback(data: dict, db: AsyncSession = Depends(get_db)):
    fb = await feedback.save_feedback(db, data)
    return {"id": fb.id}


# backend/packages/memory-soc/soc_memory/app.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from soc_memory.database import init_db
from soc_memory.routers import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


def make_app() -> FastAPI:
    app = FastAPI(title="SOC Memory Service", version="0.1.0", lifespan=lifespan)
    app.include_router(router)
    return app


app = make_app()
```

- [ ] **Step 2: Commit**

```bash
git add backend/packages/memory-soc/
git commit -m "feat(memory-soc): add API routes, similarity query, session store"
```

---

## Task 9: CMDB Community Tool

**Files:**
- Create: `backend/packages/harness/deerflow/community/cmdb/__init__.py`
- Create: `backend/packages/harness/deerflow/community/cmdb/tools.py`
- Modify: `config.yaml` (add tool + tool_group entry)

- [ ] **Step 1: Write the tool**

```python
# backend/packages/harness/deerflow/community/cmdb/__init__.py
"""CMDB asset query tool."""

# backend/packages/harness/deerflow/community/cmdb/tools.py
import json
import httpx
from langchain.tools import tool
from deerflow.config import get_app_config


@tool("query_asset", parse_docstring=True)
def query_asset_tool(query: str) -> str:
    """Query CMDB for asset information by IP address or hostname.

    Args:
        query: IP address or hostname to look up.
    """
    config = get_app_config().get_tool_config("query_asset")
    api_base_url = config.model_extra.get("api_base_url")
    api_key = config.model_extra.get("api_key")

    if not api_base_url:
        # Mock response for dev
        return json.dumps({
            "asset_id": f"asset-{query}",
            "hostname": query,
            "ip": query if "." in query else None,
            "business_criticality": "high",
            "department": "Engineering",
            "network_zone": "internal-db",
            "patch_status": "latest",
            "owner": "ops-team",
        }, indent=2, ensure_ascii=False)

    try:
        resp = httpx.get(
            f"{api_base_url}/api/v1/assets/lookup",
            params={"q": query},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": str(e)})
```

- [ ] **Step 2: Update config.yaml**

Add to the `tools` section:
```yaml
  - name: query_asset
    group: soc
    use: deerflow.community.cmdb.tools:query_asset_tool
    api_base_url: $CMDB_API_URL
    api_key: $CMDB_API_KEY
```

Add to the `tool_groups` section:
```yaml
  - name: soc
```

- [ ] **Step 3: Commit**

```bash
git add backend/packages/harness/deerflow/community/cmdb/ config.yaml
git commit -m "feat(cmdb): add query_asset community tool"
```

---

## Task 10: MCP Server Skeletons (Mock)

**Files:**
- Create: `mcp-servers/threat-intel/pyproject.toml`
- Create: `mcp-servers/threat-intel/server.py`
- Create: `mcp-servers/siem-search/pyproject.toml`
- Create: `mcp-servers/siem-search/server.py`
- Create: `mcp-servers/sandbox/pyproject.toml`
- Create: `mcp-servers/sandbox/server.py`
- Modify: `extensions_config.json` (add 3 MCP servers)

- [ ] **Step 1: Write threat-intel MCP server**

```toml
# mcp-servers/threat-intel/pyproject.toml
[project]
name = "soc-threat-intel"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = ["mcp>=1.0.0"]
```

```python
# mcp-servers/threat-intel/server.py
"""Mock threat intelligence MCP server."""
import json
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("threat-intel")

MOCK_TI_DATA = {
    "malicious": {"verdict": "malicious", "confidence": 0.95, "sources": ["VT", "AlienVault"], "tags": ["emotet", "trojan"], "last_seen": "2026-05-10T10:00:00Z"},
    "suspicious": {"verdict": "suspicious", "confidence": 0.60, "sources": ["AbuseIPDB"], "tags": ["scanner"], "last_seen": "2026-05-09T00:00:00Z"},
    "clean": {"verdict": "clean", "confidence": 0.98, "sources": ["VT"], "tags": [], "last_seen": "2026-05-10T12:00:00Z"},
    "unknown": {"verdict": "unknown", "confidence": 0.0, "sources": [], "tags": [], "last_seen": None},
}

def _mock_result(input_str: str) -> dict:
    h = hash(input_str) % 4
    return list(MOCK_TI_DATA.values())[h]


@mcp.tool()
def query_ip(ip: str) -> str:
    """Query threat intelligence for an IP address."""
    result = _mock_result(ip)
    result["geo"] = {"country": "US", "city": "New York"}
    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def query_hash(hash_value: str) -> str:
    """Query threat intelligence for a file hash."""
    result = _mock_result(hash_value)
    result["family"] = "emotet" if result["verdict"] == "malicious" else None
    result["first_seen"] = "2026-01-15T00:00:00Z"
    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def query_domain(domain: str) -> str:
    """Query threat intelligence for a domain."""
    result = _mock_result(domain)
    result["category"] = "malware" if result["verdict"] == "malicious" else "business"
    result["registrar"] = "Namecheap"
    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def query_url(url: str) -> str:
    """Query threat intelligence for a URL."""
    result = _mock_result(url)
    result["category"] = "phishing" if result["verdict"] == "malicious" else "benign"
    return json.dumps(result, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run(transport="sse", host="localhost", port=8101)
```

- [ ] **Step 2: Write siem-search and sandbox MCP servers** (same pattern, abbreviated)

```python
# mcp-servers/siem-search/server.py
"""Mock SIEM search MCP server."""
import json
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("siem-search")


@mcp.tool()
def search_events(entity: str, entity_type: str, time_window: str) -> str:
    """Search SIEM events for an entity within a time window."""
    return json.dumps({
        "events": [
            {"timestamp": "2026-05-10T14:30:00Z", "event_type": "process_create", "summary": f"Process created by {entity}"},
            {"timestamp": "2026-05-10T14:31:00Z", "event_type": "network_connect", "summary": f"Network connection from {entity}"},
        ],
        "total_count": 2,
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def get_alert_context(alert_id: str) -> str:
    """Get detailed context for a specific alert."""
    return json.dumps({
        "alert_detail": {"id": alert_id, "rule": "Endpoint_Abnormal_Process_Outbound"},
        "related_events": [],
        "same_host_alerts_24h": 3,
        "same_user_alerts_24h": 0,
    }, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run(transport="sse", host="localhost", port=8102)


# mcp-servers/sandbox/server.py
"""Mock sandbox analysis MCP server."""
import json
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sandbox")


@mcp.tool()
def get_report(hash_value: str) -> str:
    """Get sandbox analysis report for a file hash."""
    return json.dumps({
        "report_id": f"report-{hash_value[:8]}",
        "hash": hash_value,
        "verdict": "malicious",
        "behavioral_summary": "Creates persistence via registry, connects to C2 at 192.168.1.100:443",
        "network_connections": [{"dst_ip": "192.168.1.100", "dst_port": 443, "protocol": "tcp"}],
        "file_operations": [{"operation": "write", "path": "C:\\Windows\\Temp\\payload.dll"}],
        "created_at": "2026-05-10T14:00:00Z",
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def submit_file(file_path: str) -> str:
    """Submit a file for sandbox analysis."""
    return json.dumps({
        "report_id": "report-new-001",
        "status": "queued",
    }, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run(transport="sse", host="localhost", port=8103)
```

- [ ] **Step 3: Update extensions_config.json**

```json
{
  "mcpServers": {
    "threat-intel": {
      "enabled": false,
      "type": "sse",
      "url": "http://localhost:8101/sse",
      "description": "多源威胁情报聚合：query_ip, query_hash, query_domain, query_url"
    },
    "siem-search": {
      "enabled": false,
      "type": "sse",
      "url": "http://localhost:8102/sse",
      "description": "SIEM 日志检索：search_events, get_alert_context"
    },
    "sandbox": {
      "enabled": false,
      "type": "sse",
      "url": "http://localhost:8103/sse",
      "description": "沙箱分析：get_report, submit_file"
    },
    "filesystem": { "enabled": false, "type": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/allowed/files"], "env": {}, "description": "Provides filesystem access within allowed directories" },
    "github": { "enabled": false, "type": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": { "GITHUB_TOKEN": "$GITHUB_TOKEN" }, "description": "GitHub MCP server for repository operations" },
    "postgres": { "enabled": false, "type": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/mydb"], "env": {}, "description": "PostgreSQL database access" }
  },
  "skills": {}
}
```

- [ ] **Step 4: Commit**

```bash
git add mcp-servers/ extensions_config.json
git commit -m "feat(mcp): add mock threat-intel, siem-search, and sandbox MCP servers"
```

---

## Task 11: Frontend — SOC Layout and Alert Workbench

**Files:**
- Create: `frontend/src/app/(workspace)/soc/layout.tsx`
- Create: `frontend/src/app/(workspace)/soc/alerts/page.tsx`
- Create: `frontend/src/core/soc/alerts.ts`
- Create: `frontend/src/core/soc/queue.ts`
- Create: `frontend/src/components/soc/alert-card.tsx`
- Create: `frontend/src/components/soc/alert-filter.tsx`
- Create: `frontend/src/components/soc/queue-stats.tsx`

- [ ] **Step 1: Write core hooks**

```typescript
// frontend/src/core/soc/alerts.ts
"use client";

import { useQuery } from "@tanstack/react-query";

export interface AlertItem {
  id: string;
  defense_line: string;
  alert_name: string;
  severity: string;
  type: string;
  entities: { type: string; value: string }[];
  fingerprint: string;
  alarm_id: string | null;
  aggregation: Record<string, unknown> | null;
  created_at: string;
}

export interface AlertsResponse {
  alerts: AlertItem[];
  total: number;
}

export function useAlerts(filters?: Record<string, string>) {
  return useQuery<AlertsResponse>({
    queryKey: ["soc", "alerts", filters],
    queryFn: async () => {
      const params = new URLSearchParams(filters ?? {});
      const res = await fetch(`/api/soc/queue/alerts?${params}`);
      if (!res.ok) throw new Error("Failed to fetch alerts");
      return res.json();
    },
    refetchInterval: 10_000,
  });
}

// frontend/src/core/soc/queue.ts
"use client";

import { useQuery } from "@tanstack/react-query";

export interface QueueStatus {
  depth: number;
}

export function useQueueStatus() {
  return useQuery<QueueStatus>({
    queryKey: ["soc", "queue", "status"],
    queryFn: async () => {
      const res = await fetch("/api/soc/queue/status");
      if (!res.ok) throw new Error("Failed to fetch queue status");
      return res.json();
    },
    refetchInterval: 5_000,
  });
}
```

- [ ] **Step 2: Write components**

```tsx
// frontend/src/components/soc/queue-stats.tsx
"use client";

import { useQueueStatus } from "@/core/soc/queue";

export function QueueStats() {
  const { data, isLoading } = useQueueStatus();

  return (
    <div className="flex gap-4">
      <StatBadge label="队列积压" value={isLoading ? "—" : String(data?.depth ?? 0)} />
    </div>
  );
}

function StatBadge({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border px-3 py-1.5 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="ml-2 font-mono font-semibold">{value}</span>
    </div>
  );
}
```

```tsx
// frontend/src/components/soc/alert-card.tsx
"use client";

import Link from "next/link";
import type { AlertItem } from "@/core/soc/alerts";

const severityColor: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-slate-400",
};

const defenseLineLabel: Record<string, string> = {
  endpoint: "终端",
  server: "服务器",
  application: "应用",
  network: "网络",
  email: "邮件",
  account: "账号",
};

export function AlertCard({ alert }: { alert: AlertItem }) {
  const dotColor = severityColor[alert.severity] ?? "bg-slate-400";
  const lineLabel = defenseLineLabel[alert.defense_line] ?? alert.defense_line;
  const mainEntity = alert.entities?.[0]?.value ?? "—";

  return (
    <Link href={`/soc/triage/${alert.id}`}>
      <div className="rounded-lg border p-3 hover:border-primary/50 transition-colors cursor-pointer">
        <div className="flex items-center gap-2">
          <span className={`inline-block w-2 h-2 rounded-full ${dotColor}`} />
          <span className="text-xs font-medium uppercase text-muted-foreground">
            {alert.severity}
          </span>
          <span className="text-xs text-muted-foreground">|</span>
          <span className="text-xs font-medium">{lineLabel}</span>
          <span className="text-xs text-muted-foreground">|</span>
          <span className="text-xs font-mono truncate">{alert.alert_name}</span>
        </div>
        <div className="mt-1 text-sm text-muted-foreground truncate">
          {mainEntity}
          {alert.aggregation && (
            <span className="ml-2 text-xs bg-blue-100 dark:bg-blue-900 px-1 rounded">
              聚合
            </span>
          )}
        </div>
      </div>
    </Link>
  );
}
```

```tsx
// frontend/src/components/soc/alert-filter.tsx
"use client";

const DEFENSE_LINES = [
  { value: "endpoint", label: "终端" },
  { value: "server", label: "服务器" },
  { value: "application", label: "应用" },
  { value: "network", label: "网络" },
  { value: "email", label: "邮件" },
  { value: "account", label: "账号" },
];

const SEVERITIES = ["critical", "high", "medium", "low"];

export function AlertFilter({
  filters,
  onChange,
}: {
  filters: Record<string, string>;
  onChange: (key: string, value: string | null) => void;
}) {
  return (
    <div className="space-y-4 w-48 shrink-0">
      <div>
        <h3 className="text-sm font-medium mb-2">防线</h3>
        {DEFENSE_LINES.map((dl) => (
          <label key={dl.value} className="flex items-center gap-2 text-sm py-0.5">
            <input
              type="checkbox"
              checked={filters.defense_line === dl.value}
              onChange={() =>
                onChange("defense_line", filters.defense_line === dl.value ? null : dl.value)
              }
            />
            {dl.label}
          </label>
        ))}
      </div>
      <div>
        <h3 className="text-sm font-medium mb-2">严重级别</h3>
        {SEVERITIES.map((s) => (
          <label key={s} className="flex items-center gap-2 text-sm py-0.5">
            <input
              type="checkbox"
              checked={filters.severity === s}
              onChange={() => onChange("severity", filters.severity === s ? null : s)}
            />
            {s}
          </label>
        ))}
      </div>
      <div>
        <h3 className="text-sm font-medium mb-2">时间范围</h3>
        {["1h", "24h", "7d"].map((t) => (
          <label key={t} className="flex items-center gap-2 text-sm py-0.5">
            <input
              type="radio"
              name="time_range"
              checked={filters.time_range === t || (!filters.time_range && t === "24h")}
              onChange={() => onChange("time_range", t)}
            />
            {t}
          </label>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Write pages**

```tsx
// frontend/src/app/(workspace)/soc/layout.tsx
import type { ReactNode } from "react";

export default function SocLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-col h-full">
      <div className="border-b px-4 py-2 text-sm text-muted-foreground">
        Workspace &gt; SOC &gt; 告警工作台
      </div>
      {children}
    </div>
  );
}
```

```tsx
// frontend/src/app/(workspace)/soc/alerts/page.tsx
"use client";

import { useState } from "react";
import { QueueStats } from "@/components/soc/queue-stats";
import { AlertFilter } from "@/components/soc/alert-filter";
import { AlertCard } from "@/components/soc/alert-card";
import { useAlerts } from "@/core/soc/alerts";

export default function AlertsPage() {
  const [filters, setFilters] = useState<Record<string, string>>({ time_range: "24h" });
  const { data, isLoading } = useAlerts(filters);

  const handleFilterChange = (key: string, value: string | null) => {
    setFilters((prev) => {
      const next = { ...prev };
      if (value === null) {
        delete next[key];
      } else {
        next[key] = value;
      }
      return next;
    });
  };

  return (
    <div className="flex flex-1 overflow-hidden">
      <aside className="border-r p-3 overflow-y-auto">
        <AlertFilter filters={filters} onChange={handleFilterChange} />
      </aside>
      <main className="flex-1 overflow-y-auto p-4">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-lg font-semibold">告警工作台</h1>
          <QueueStats />
        </div>
        {isLoading ? (
          <p className="text-muted-foreground">加载中...</p>
        ) : (
          <div className="space-y-2">
            {data?.alerts.map((alert) => (
              <AlertCard key={alert.id} alert={alert} />
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
```

- [ ] **Step 4: Commit**

```bash
git add frontend/src/app/\(workspace\)/soc/ frontend/src/core/soc/ frontend/src/components/soc/
git commit -m "feat(frontend): add SOC layout, alert workbench page with filters and cards"
```

---

## Task 12: Frontend — Triage Detail Page

**Files:**
- Create: `frontend/src/app/(workspace)/soc/triage/[thread_id]/page.tsx`
- Create: `frontend/src/components/soc/alert-summary.tsx`
- Create: `frontend/src/components/soc/triage-result.tsx`
- Create: `frontend/src/core/soc/triage.ts`
- Create: `frontend/src/core/soc/feedback.ts`

- [ ] **Step 1: Write triage hooks**

```typescript
// frontend/src/core/soc/triage.ts
"use client";

import { useQuery } from "@tanstack/react-query";

export interface TriageResult {
  result_id: string;
  verdict: string;
  confidence: number;
  confidence_level: string;
  severity: string;
  summary: string;
  evidence_timeline: { step: number; name: string; tool: string; finding: string }[];
  action_suggestion: { primary: string; params: Record<string, string>; rationale: string } | null;
  uncertainties: string[];
}

export function useTriageResult(threadId: string) {
  return useQuery<TriageResult | null>({
    queryKey: ["soc", "triage", threadId],
    queryFn: async () => {
      const res = await fetch(`/api/soc/results/${threadId}`);
      if (res.status === 404) return null;
      if (!res.ok) throw new Error("Failed to fetch triage result");
      return res.json();
    },
    refetchInterval: 10_000,
  });
}

// frontend/src/core/soc/feedback.ts
"use client";

import { useMutation } from "@tanstack/react-query";

export function useSubmitFeedback() {
  return useMutation({
    mutationFn: async (data: {
      result_id: string;
      action: "accepted" | "rejected" | "escalated";
      reject_reason?: string;
      comment?: string;
    }) => {
      const res = await fetch("/api/soc/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error("Failed to submit feedback");
      return res.json();
    },
  });
}
```

- [ ] **Step 2: Write components**

```tsx
// frontend/src/components/soc/alert-summary.tsx
export function AlertSummary({
  defenseLine,
  alertName,
  severity,
  createdAt,
}: {
  defenseLine: string;
  alertName: string;
  severity: string;
  createdAt: string;
}) {
  return (
    <div className="border-b px-4 py-2 flex items-center gap-3 text-sm bg-muted/50">
      <span className="font-medium">{defenseLine}</span>
      <span className="text-muted-foreground">|</span>
      <span className="font-mono text-xs">{alertName}</span>
      <span className="text-muted-foreground">|</span>
      <span className="capitalize">{severity}</span>
      <span className="text-muted-foreground">|</span>
      <span className="text-xs text-muted-foreground">{createdAt}</span>
    </div>
  );
}

// frontend/src/components/soc/triage-result.tsx
"use client";

import { useTriageResult } from "@/core/soc/triage";
import { useSubmitFeedback } from "@/core/soc/feedback";

const verdictLabel: Record<string, string> = {
  malicious: "恶意",
  false_positive: "误报",
  benign_anomaly: "良性异常",
  uncertain: "不确定",
};

const verdictColor: Record<string, string> = {
  malicious: "text-red-600",
  false_positive: "text-green-600",
  benign_anomaly: "text-blue-600",
  uncertain: "text-yellow-600",
};

export function TriageResultPanel({ threadId }: { threadId: string }) {
  const { data: result, isLoading } = useTriageResult(threadId);
  const feedback = useSubmitFeedback();

  if (isLoading) return <div className="p-4 text-sm text-muted-foreground">加载研判结果...</div>;
  if (!result) return <div className="p-4 text-sm text-muted-foreground">等待研判完成...</div>;

  return (
    <div className="p-4 space-y-4 border-l h-full overflow-y-auto w-80 shrink-0">
      <div>
        <h3 className="text-sm font-medium text-muted-foreground">判定</h3>
        <p className={`text-lg font-bold ${verdictColor[result.verdict] ?? ""}`}>
          {verdictLabel[result.verdict] ?? result.verdict}
        </p>
      </div>

      <div>
        <h3 className="text-sm font-medium text-muted-foreground">置信度</h3>
        <p className="text-lg font-mono">{(result.confidence * 100).toFixed(0)}%</p>
        <p className="text-xs text-muted-foreground">{result.confidence_level}</p>
      </div>

      <div>
        <h3 className="text-sm font-medium text-muted-foreground">摘要</h3>
        <p className="text-sm">{result.summary}</p>
      </div>

      {result.evidence_timeline.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-muted-foreground mb-1">证据链</h3>
          <ul className="space-y-1">
            {result.evidence_timeline.map((e) => (
              <li key={e.step} className="text-xs border-l-2 pl-2 py-0.5">
                <span className="font-medium">{e.name}</span>
                <span className="text-muted-foreground ml-1">via {e.tool}</span>
                <p className="text-muted-foreground">{e.finding}</p>
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.action_suggestion && (
        <div>
          <h3 className="text-sm font-medium text-muted-foreground">建议操作</h3>
          <p className="text-sm font-mono">{result.action_suggestion.primary}</p>
          <p className="text-xs text-muted-foreground">{result.action_suggestion.rationale}</p>
        </div>
      )}

      <div className="flex gap-2 pt-2 border-t">
        <button
          className="flex-1 rounded bg-green-600 px-3 py-1.5 text-sm text-white hover:bg-green-700 disabled:opacity-50"
          disabled={feedback.isPending}
          onClick={() => feedback.mutate({ result_id: result.result_id, action: "accepted" })}
        >
          采纳
        </button>
        <button
          className="flex-1 rounded bg-red-600 px-3 py-1.5 text-sm text-white hover:bg-red-700 disabled:opacity-50"
          disabled={feedback.isPending}
          onClick={() => feedback.mutate({ result_id: result.result_id, action: "rejected" })}
        >
          否决
        </button>
        <button
          className="flex-1 rounded bg-yellow-600 px-3 py-1.5 text-sm text-white hover:bg-yellow-700 disabled:opacity-50"
          disabled={feedback.isPending}
          onClick={() => feedback.mutate({ result_id: result.result_id, action: "escalated" })}
        >
          升级
        </button>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Write triage page**

```tsx
// frontend/src/app/(workspace)/soc/triage/[thread_id]/page.tsx
"use client";

import { useParams } from "next/navigation";
import { AlertSummary } from "@/components/soc/alert-summary";
import { TriageResultPanel } from "@/components/soc/triage-result";

export default function TriagePage() {
  const params = useParams();
  const threadId = params.thread_id as string;

  return (
    <div className="flex flex-col flex-1 overflow-hidden">
      <AlertSummary
        defenseLine="endpoint"
        alertName="Endpoint_Abnormal_Process_Outbound"
        severity="high"
        createdAt="2026-05-10T14:32:00Z"
      />
      <div className="flex flex-1 overflow-hidden">
        <div className="flex-1 overflow-y-auto p-4">
          <p className="text-sm text-muted-foreground">
            Agent 研判对话流（复用 DeerFlow Chat 组件渲染 Thread 消息）
          </p>
        </div>
        <TriageResultPanel threadId={threadId} />
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Commit**

```bash
git add frontend/src/app/\(workspace\)/soc/triage/ frontend/src/components/soc/alert-summary.tsx frontend/src/components/soc/triage-result.tsx frontend/src/core/soc/triage.ts frontend/src/core/soc/feedback.ts
git commit -m "feat(frontend): add SOC triage detail page with result panel and feedback actions"
```

---

## Task 13: Frontend — Placeholder Pages

**Files:**
- Create: `frontend/src/app/(workspace)/soc/dashboard/page.tsx`
- Create: `frontend/src/app/(workspace)/soc/rules/page.tsx`
- Create: `frontend/src/app/(workspace)/soc/audit/page.tsx`

- [ ] **Step 1: Write placeholder pages**

```tsx
// frontend/src/app/(workspace)/soc/dashboard/page.tsx
export default function DashboardPage() {
  return (
    <div className="p-4">
      <h1 className="text-lg font-semibold mb-2">运营仪表盘</h1>
      <p className="text-sm text-muted-foreground">Coming soon — 系统健康 / 研判质量 / 业务价值指标</p>
    </div>
  );
}

// frontend/src/app/(workspace)/soc/rules/page.tsx
export default function RulesPage() {
  return (
    <div className="p-4">
      <h1 className="text-lg font-semibold mb-2">抑制规则管理</h1>
      <p className="text-sm text-muted-foreground">Coming soon — 规则 CRUD / 审批流 / 有效期管理</p>
    </div>
  );
}

// frontend/src/app/(workspace)/soc/audit/page.tsx
export default function AuditPage() {
  return (
    <div className="p-4">
      <h1 className="text-lg font-semibold mb-2">审计日志</h1>
      <p className="text-sm text-muted-foreground">Coming soon — 告警全生命周期审计追踪</p>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add frontend/src/app/\(workspace\)/soc/dashboard/ frontend/src/app/\(workspace\)/soc/rules/ frontend/src/app/\(workspace\)/soc/audit/
git commit -m "feat(frontend): add SOC placeholder pages for dashboard, rules, and audit"
```

---

## Task 14: Integration — Wiring and Verification

**Files:**
- Modify: `backend/app/gateway/app.py` (mount ingestion, add soc Nginx config notes)
- Verify: integration test

- [ ] **Step 1: Mount ingestion in Gateway**

```python
# In backend/app/gateway/app.py, add after the app is created:
from app.ingestion.app import make_ingestion_app

# Mount the SOC ingestion sub-app under /api/soc
# The ingestion app handles /api/soc/webhooks/{vendor} and /api/soc/queue/status
soc_ingestion = make_ingestion_app()
app.mount("/api/soc", soc_ingestion)
```

- [ ] **Step 2: Verify full pipeline**

Run the services and test end-to-end:

```bash
# Terminal 1: Start memory-soc
cd backend && PYTHONPATH=. uv run uvicorn soc_memory.app:app --port 8003

# Terminal 2: Start DeerFlow Gateway (with ingestion mounted)
cd backend && make gateway

# Terminal 3: Send a test webhook
curl -X POST http://localhost:8001/api/soc/webhooks/siem_splunk \
  -H "Content-Type: application/json" \
  -d '{
    "alarm_id": "test-001",
    "alert_time": "2026-05-10T14:32:00Z",
    "defense_line": "endpoint",
    "alert_name": "Endpoint_Abnormal_Process_Outbound",
    "raw_evidence": {"src_ip": "10.23.45.67", "process_hash": "abc123", "process_name": "powershell.exe"}
  }'

# Expected: 202 {"accepted": true, "alert_id": "..."}

# Check queue status
curl http://localhost:8001/api/soc/queue/status
# Expected: {"depth": 1}
```

- [ ] **Step 3: Commit**

```bash
git add backend/app/gateway/app.py
git commit -m "feat(ingestion): mount SOC ingestion sub-app in Gateway at /api/soc"
```

---

## Dependency Graph

```
Task 1 (models)
  ├─▶ Task 2 (normalizer)
  └─▶ Task 3 (dedup)
         └─▶ Task 4 (queue)
                └─▶ Task 5 (routers)
                       └─▶ Task 6 (dispatcher)
                              │
Task 7 (memory-soc models) ──┤
  └─▶ Task 8 (memory-soc API)─┘

Task 9 (cmdb tool) ── independent
Task 10 (mcp servers) ── independent
Task 11 (frontend workbench) ── independent
Task 12 (frontend triage) ── depends on Task 11
Task 13 (frontend placeholders) ── independent
Task 14 (wiring) ── depends on Tasks 1-6, 7-8
```

**Parallelizable pairs:**
- Tasks 1-6 (backend ingestion) and Tasks 7-8 (memory-soc) can run in parallel
- Tasks 9, 10, 11, 13 are fully independent
- Task 12 requires Task 11 (shared component patterns)
- Task 14 waits for all backend tasks
