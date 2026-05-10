"""Queue status endpoint — exposes current queue depth for monitoring.

GET /queue/status → {"depth": N}
"""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/status")
async def get_queue_status(request: Request) -> dict:
    """Return the current depth of the alert priority queue.

    Returns:
        A dict with a single ``depth`` key whose value is the number of
        alerts currently waiting in the queue.
    """
    queue = request.app.state.queue
    return queue.status()
