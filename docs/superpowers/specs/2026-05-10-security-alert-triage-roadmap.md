# Security Alert Triage System — Development Roadmap

## Decisions

| Dimension | Decision |
|-----------|----------|
| MVP Scope | Core 3 layers: Ingestion/Routing → Orchestration → Triage Analysis |
| Integration | Fork DeerFlow, deep modification within harness (`deerflow/triage/`) |
| Defense Line | Endpoint (终端防线), malware alerts |
| Data Source | Mock SIEM adapter (Splunk-style: polling + webhook) |
| Output | REST API + minimal review page in DeerFlow frontend |
| Strategy | Horizontal layer-by-layer (横向逐层夯实) — complete each layer before next |

## What We Don't Do in MVP

- No attack chain correlator (cross-alert linking)
- No feedback clustering engine (auto pattern discovery)
- No suppression rule manager
- No ops dashboard
- No real SIEM/EDR integration (mock only)
- No automatic action execution (requires secondary confirmation gate, out of scope)
- No multi-view routing (analyst/ops/trainee cards)
- No baseline MCP server

## Directory Structure

```
packages/harness/deerflow/triage/
├── __init__.py
├── models/              # Shared data models (Phase 0)
│   ├── alert.py         # NormalizedAlert, RawAlert, Entity, AlertType, Severity
│   ├── task.py          # AnalysisTask, TaskStatus, TaskQuota
│   └── result.py        # TriagingResult, Verdict, Evidence, ActionSuggestion
├── storage/             # Persistence layer (Phase 0)
│   ├── alert_store.py   # Alert CRUD
│   ├── result_store.py  # Result CRUD
│   └── session_store.py # KV session state
├── adapters/            # Multi-source adapters (Phase 1)
│   ├── base.py          # BaseAdapter ABC, WebhookReceiver protocol
│   ├── registry.py      # Adapter registry
│   └── mock_siem.py     # Mock SIEM (poll + webhook)
├── normalizer/          # Normalization engine (Phase 1)
│   ├── engine.py        # Orchestrator: extract → map → fingerprint
│   ├── entity_extractor.py  # Regex/pattern-based entity extraction
│   ├── field_mapper.py  # Vendor → unified model mapping
│   └── severity.py      # Severity normalization
├── queue/               # Priority queue (Phase 1)
│   ├── dedup.py         # Deduplication + aggregation
│   └── priority_queue.py # Weighted 5-slot priority queue
├── scheduler/           # Master Agent scheduler (Phase 2)
│   ├── scheduler.py     # Main loop: dequeue → match → dispatch
│   ├── pattern_matcher.py  # Real-time clustering + suppression check
│   └── load_manager.py  # Concurrency control + per-task quota
├── skills/              # Triage skill library (Phase 3)
│   ├── loader.py        # Skill YAML loader
│   ├── engine.py        # Step execution engine
│   ├── models.py        # SkillMeta, SkillStep, SkillConclusion, SkillScoring
│   └── definitions/     # Skill YAML files
│       └── malware-triage.yaml
├── subagent/            # Triage subagent (Phase 3)
│   ├── triage_subagent.py   # Skill-bound subagent (reuses deerflow.subagents)
│   ├── tool_proxy.py    # Tool call proxy: count + timeout
│   └── context.py       # Subagent context structure
└── scorer/              # Confidence scorer (Phase 3)
    ├── scorer.py        # Multi-factor weighted scoring
    └── degradation.py   # Degradation penalty rules

app/gateway/routers/
└── triage.py            # /api/triage/* routes (Phase 4)
```

## Phase 0 — Foundation (~1 week)

Objective: Data contracts, config schema, storage schema, directory scaffolding.

| # | Task | Output |
|---|------|--------|
| 0.1 | Unified alert data models | `NormalizedAlert`, `RawAlert`, `AnalysisTask`, `TriagingResult`, `Entity`, `Verdict` Pydantic models |
| 0.2 | Config system extension | `config.yaml` → `triage` section: queue capacity, scheduler params, skill paths, degradation matrix |
| 0.3 | Storage schema | SQLite tables for alerts/results + Redis-compatible KV session store interface |
| 0.4 | Directory scaffolding | `deerflow/triage/` tree with ABC stubs, passing imports |

## Phase 1 — Alert Ingestion & Routing (~2-3 weeks)

Objective: RawAlert enters, NormalizedAlert exits queue (de-duped, prioritized).

| # | Task | Key Details |
|---|------|-------------|
| 1.1 | Adapter framework + Mock SIEM | `BaseAdapter.poll()` → `list[RawAlert]`, `WebhookReceiver` protocol. Mock: 3-5 malware alert templates, configurable rate |
| 1.2 | Normalization engine | Entity extractor (IP/domain/hash/user/host/process/file_path), field mapper (vendor → unified), severity normalization (configurable table), fingerprint (SHA-256 of sorted entities) |
| 1.3 | Dedup + aggregator | 3 strategies: exact dedup (fingerprint window), flood upgrade (>threshold → AggregatedAlert), cross-source merge (>75% entity overlap + <1min) |
| 1.4 | Priority queue | 5 slots, weighted scoring (severity 0.4 + asset criticality 0.3 + density 0.2 + uncertainty 0.1), `enqueue/dequeue/peek/reprioritize` |
| 1.5 | Layer integration test | Mock → Adapter → Normalizer → Dedup → Queue, verify NormalizedAlert correctness and priority ordering |

## Phase 2 — Agent Orchestration (~2-3 weeks)

Objective: Dequeue alerts, match skills, dispatch subagents, monitor lifecycle, collect results.

| # | Task | Key Details |
|---|------|-------------|
| 2.1 | Scheduler | Main loop (5 steps), lifecycle callbacks (`on_start/progress/complete/timeout/error`), clustering dispatch |
| 2.2 | Pattern matcher | Real-time clustering by `(rule_id, entity_key)` with 5min window, suppression rule matching |
| 2.3 | Load manager | Max concurrent subagents (20), per-task quota (50 tool calls / 120s), quota breach → force interrupt + escalate |
| 2.4 | Session state store | KV by `task_id`: status/heartbeat/tool_count/current_step/result_ref/consumer_states. Reuses DeerFlow Subagent thread pool |
| 2.5 | Layer integration test | Mock queue → Scheduler → dispatch to stub Subagent → verify state transitions and result collection |

## Phase 3 — Triage Analysis (~3-4 weeks)

Objective: Skill-driven subagent executes triage steps, produces structured conclusion with confidence scoring.

| # | Task | Key Details |
|---|------|-------------|
| 3.1 | Skill engine + malware-triage | Skill definition model (Pydantic): meta, steps, branches, conclusions, scoring. malware-triage v1.0: 4 steps (hash TI → path context → host context → score) |
| 3.2 | Skill version management | YAML storage, loader scans `skills/triage/`, 30-day rollback window, reuses DeerFlow skill framework |
| 3.3 | Triage subagent | Tool call proxy (count + timeout), skill-bound execution (no free reasoning), step state persistence, failure isolation + recovery from session store |
| 3.4 | Confidence scorer | Multi-factor weighted: TI match (0.4) + path anomaly (0.2) + sandbox confirm (0.3) + org prevalence (0.1). Band mapping: ≥0.95→high, 0.70-0.95→medium, <0.70→low |
| 3.5 | Mock MCP tools | threat-intel (query_hash/query_ip), siem-search (search_events). Real sources deferred |
| 3.6 | Layer integration test | AnalysisTask → Skill Engine → Mock MCP → Scorer → TriagingResult. Validate 3 paths (malicious/clean/uncertain), timeout interrupt, degradation penalty |

## Phase 4 — Output & Integration (~1-2 weeks)

Objective: Expose results via API, build minimal review UI, end-to-end validation.

| # | Task | Key Details |
|---|------|-------------|
| 4.1 | Triage API routes | `GET /api/triage/alerts`, `GET /api/triage/alerts/{id}`, `GET /api/triage/alerts/{id}/result`, `POST /api/triage/alerts/webhook`, `GET /api/triage/results`, `GET /api/triage/results/{id}`, `POST /api/triage/results/{id}/feedback`, `GET /api/triage/queue/status` |
| 4.2 | Frontend review page | Alert list (table: time/type/severity/confidence/status), detail page (summary + evidence timeline + reasoning path + action suggestion), actions: accept/reject (with reason picker)/escalate. Uses existing Shadcn UI + TanStack Query |
| 4.3 | End-to-end tests | 6 paths: normal, false-positive, uncertain, timeout, degraded, dedup. Backend: pytest. Frontend: Vitest + Playwright |

## MVP Done Definition

A mock endpoint malware alert enters via SIEM adapter, flows through normalization → dedup → priority queue → scheduler → skill-driven subagent triage → confidence scoring, and the structured `TriagingResult` appears in both the API and the frontend review page. An analyst can accept/reject the verdict, with feedback persisted.

## Estimated Timeline

| Phase | Duration | Cumulative |
|-------|----------|------------|
| Phase 0 | ~1 week | 1 week |
| Phase 1 | ~2-3 weeks | 3-4 weeks |
| Phase 2 | ~2-3 weeks | 5-7 weeks |
| Phase 3 | ~3-4 weeks | 8-11 weeks |
| Phase 4 | ~1-2 weeks | 9-13 weeks |

## Out of Scope (Future Iterations)

- Real SIEM/EDR adapters (CrowdStrike, SentinelOne, etc.)
- Attack chain correlator (cross-alert pattern matching)
- Feedback clustering engine (auto suppression rule suggestions)
- Ops dashboard and metrics collection
- Multi-view rendering (analyst/ops/trainee cards)
- Automatic action execution (isolate_host, disable_user)
- Production-grade deployment (Docker, K8s)
- Audit logging infrastructure
- Consumer state machine for multi-role triage flow
