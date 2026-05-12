"""Consumption API — Agent pulls events one at a time."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/events/next")
async def get_next_event(request: Request) -> dict:
    """Pull the next unconsumed event. Returns 204 if queue is empty."""
    store = request.app.state.event_store
    event = await store.next()
    if event is None:
        return JSONResponse({"events_available": False}, status_code=204)
    return event.model_dump()


@router.get("/events/status")
async def get_event_status(request: Request) -> dict:
    """Return event queue status."""
    store = request.app.state.event_store
    return await store.status()


@router.get("/events/peek")
async def peek_events(request: Request) -> list[dict]:
    """Return all events (for dashboard — does not mark consumed)."""
    store = request.app.state.event_store
    events = await store.peek_all()
    return [e.model_dump() for e in events]
