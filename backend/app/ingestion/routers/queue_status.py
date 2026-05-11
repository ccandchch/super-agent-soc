"""Queue monitoring endpoints.

GET /queue/status → {"depth": N}
GET /queue/alerts → {"alerts": [...], "total": N}
GET /queue/rules → [...] (list suppression rules)
POST /queue/rules → {...} (create rule)
DELETE /queue/rules/{rule_id} → {"deleted": true}
GET /queue/audit → {"lines": [...]} (gateway log excerpts)
"""

from __future__ import annotations

import os
import uuid

from fastapi import APIRouter, Query, Request

router = APIRouter()

# ── In-memory suppression rules store (backed by memory-soc later) ──────
_rules_store: list[dict] = []


@router.get("/status")
async def get_queue_status(request: Request) -> dict:
    """Return the current depth of the alert priority queue."""
    queue = request.app.state.queue
    return queue.status()


@router.get("/alerts")
async def list_alerts(
    request: Request,
    defense_line: str | None = Query(None),
    severity: str | None = Query(None),
    time_range: str | None = Query("24h"),
) -> dict:
    """List alerts currently in the priority queue with optional filters.

    Returns all queued alerts for the frontend workbench.
    Filtering by defense_line/severity is done client-side for simplicity;
    this endpoint returns the full queue snapshot.
    """
    queue = request.app.state.queue
    alerts = queue.peek_all()
    alert_dicts = [a.model_dump() for a in alerts]
    return {"alerts": alert_dicts, "total": len(alert_dicts)}


@router.get("/alert-info/{lookup_id}")
async def get_alert_info(lookup_id: str, request: Request) -> dict:
    """Return alert metadata for a thread_id or alert_id."""
    mapping: dict = getattr(request.app.state, "thread_alert_map", {})
    # Try direct thread_id lookup first
    if lookup_id in mapping:
        return mapping[lookup_id]
    # Try alert_id lookup
    for meta in mapping.values():
        if meta.get("alert_id") == lookup_id:
            return meta
    from fastapi.responses import JSONResponse
    return JSONResponse({"error": "not found"}, status_code=404)


# ── Suppression rules ───────────────────────────────────────────────────


@router.get("/rules")
async def list_rules(request: Request) -> list[dict]:
    """List all suppression rules (in-memory store)."""
    return _rules_store


@router.post("/rules")
async def create_rule(rule: dict, request: Request) -> dict:
    """Create a new suppression rule."""
    rule["id"] = str(uuid.uuid4())
    rule["status"] = "active"
    rule["created_at"] = "now"
    _rules_store.append(rule)
    return rule


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str, request: Request) -> dict:
    """Delete a suppression rule by ID."""
    global _rules_store
    _rules_store = [r for r in _rules_store if r.get("id") != rule_id]
    return {"deleted": True}


# ── Audit logs ──────────────────────────────────────────────────────────


@router.get("/audit")
async def get_audit_logs(request: Request, lines: int = 100) -> dict:
    """Return recent gateway log lines filtered for SOC-relevant entries."""
    log_path = os.environ.get("GATEWAY_LOG_PATH", "/app/logs/gateway.log")
    try:
        with open(log_path) as f:
            all_lines = f.readlines()
            recent = all_lines[-lines:]
            soc_lines = [
                l.strip()
                for l in recent
                if any(kw in l for kw in ["SOC", "dispatch", "webhook", "alert", "triage", "Run"])
            ]
            return {"lines": soc_lines[-50:]}
    except Exception:
        return {"lines": ["Log file not available"]}
