"""Queue monitoring endpoints.

GET /queue/status → {"depth": N}
GET /queue/alerts → {"alerts": [...], "total": N}
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request

router = APIRouter()


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
