"""Webhook receiver — accepts alerts from upstream SIEMs and detection systems.

POST /webhooks/{vendor}
    Body: RawAlert JSON
    Pipeline: Adapter.parse → Normalizer.normalize → batch buffer → DedupAggregator → PriorityQueue.enqueue
    Response: 202 {"accepted": true, "alert_id": "..."}

Alerts are buffered for a short window (default 3s) before being flushed
through the dedup/aggregation pipeline. This gives the entity-based
aggregator time to merge related alerts before the Dispatcher consumes them.
"""

from __future__ import annotations

import asyncio
import logging
import os

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError

from app.ingestion.adapters.siem_webhook import SIEMWebhookAdapter
from app.ingestion.models import NormalizedAlert
from app.ingestion.queue import PriorityScore

logger = logging.getLogger(__name__)

router = APIRouter()

SEVERITY_TO_SCORE: dict[str, float] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_SCORE = 2.0

# Default batch flush interval. Set SOC_FLUSH_INTERVAL env var to override.
_DEFAULT_FLUSH_INTERVAL = 30.0  # seconds


def _get_flush_interval() -> float:
    return float(os.environ.get("SOC_FLUSH_INTERVAL", str(_DEFAULT_FLUSH_INTERVAL)))


def _compute_priority_score(alert: NormalizedAlert) -> PriorityScore:
    """Build a PriorityScore from a NormalizedAlert using severity and defaults."""
    return PriorityScore(
        alert_severity=SEVERITY_TO_SCORE.get(alert.severity, DEFAULT_SCORE),
        asset_criticality=0.5,
        alert_density=0.5,
        uncertainty=0.5,
    )


def _ensure_flush_task(request: Request) -> None:
    """Create a background flush task on the first webhook call, if needed."""
    if getattr(request.app.state, "_flush_task", None) is not None:
        return

    async def _flush_loop():
        interval = _get_flush_interval()
        logger.info("Webhook batch flush loop started (interval=%ss)", interval)
        while True:
            await asyncio.sleep(interval)
            buffer: list[NormalizedAlert] = request.app.state._alert_buffer
            if not buffer:
                continue
            # Take pending alerts
            batch = buffer[:]
            buffer.clear()
            # Run through dedup/aggregation as a batch
            dedup = request.app.state.dedup_aggregator
            queue = request.app.state.queue
            for alert in batch:
                result = dedup.process(alert)
                if result is not None:
                    queue.enqueue(result, _compute_priority_score(result))
            logger.debug("Flushed %d alerts through dedup", len(batch))

    request.app.state._alert_buffer = []
    request.app.state._flush_task = asyncio.create_task(_flush_loop())


@router.post("/{vendor}", status_code=202)
async def receive_webhook(vendor: str, body: dict, request: Request) -> dict:
    """Receive a raw alert webhook from an upstream SIEM or detection system."""
    # ── Parse ──────────────────────────────────────────────────────────
    adapter = SIEMWebhookAdapter()
    try:
        raw_alert = adapter.parse(body, vendor)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    # ── Normalize ──────────────────────────────────────────────────────
    normalizer = request.app.state.normalizer
    normalized = normalizer.normalize(raw_alert, source=vendor)

    # ── Route: synchronous or buffered ─────────────────────────────────
    if _get_flush_interval() <= 0:
        # Synchronous path (tests / low-latency)
        dedup_aggregator = request.app.state.dedup_aggregator
        result = dedup_aggregator.process(normalized)
        if result is not None:
            request.app.state.queue.enqueue(result, _compute_priority_score(result))
    else:
        # Buffered path — alerts accumulate and are flushed in batches
        _ensure_flush_task(request)
        request.app.state._alert_buffer.append(normalized)
        logger.debug("Buffered alert %s (buffer size=%d)", normalized.id, len(request.app.state._alert_buffer))

    return {"accepted": True, "alert_id": normalized.id}
