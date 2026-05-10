"""Webhook receiver — accepts alerts from upstream SIEMs and detection systems.

POST /webhooks/{vendor}
    Body: RawAlert JSON
    Pipeline: Adapter.parse → Normalizer.normalize → DedupAggregator.process → PriorityQueue.enqueue
    Response: 202 {"accepted": true, "alert_id": "..."}
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError

from app.ingestion.adapters.siem_webhook import SIEMWebhookAdapter
from app.ingestion.models import NormalizedAlert
from app.ingestion.queue import PriorityScore

router = APIRouter()

SEVERITY_TO_SCORE: dict[str, float] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_SCORE = 2.0


def _compute_priority_score(alert: NormalizedAlert) -> PriorityScore:
    """Build a PriorityScore from a NormalizedAlert using severity and defaults.

    Uses default asset_criticality (0.5), alert_density (0.5), and uncertainty (0.5)
    since webhook alerts carry no CMDB or density metadata.
    """
    return PriorityScore(
        alert_severity=SEVERITY_TO_SCORE.get(alert.severity, DEFAULT_SCORE),
        asset_criticality=0.5,
        alert_density=0.5,
        uncertainty=0.5,
    )


@router.post("/{vendor}", status_code=202)
async def receive_webhook(vendor: str, body: dict, request: Request) -> dict:
    """Receive a raw alert webhook from an upstream SIEM or detection system.

    Path parameter:
        vendor: Identifier for the source system (e.g. ``siem_splunk``).

    Request body:
        A JSON object conforming to the RawAlert schema.

    Returns 202 with ``{"accepted": true, "alert_id": "..."}`` on success.
    Returns 422 if the body fails validation against RawAlert.
    """
    # ── Parse ──────────────────────────────────────────────────────────
    adapter = SIEMWebhookAdapter()
    try:
        raw_alert = adapter.parse(body, vendor)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    # ── Normalize ──────────────────────────────────────────────────────
    normalizer = request.app.state.normalizer
    normalized = normalizer.normalize(raw_alert, source=vendor)

    # ── Dedup aggregate ────────────────────────────────────────────────
    dedup_aggregator = request.app.state.dedup_aggregator
    result = dedup_aggregator.process(normalized)

    # ── Enqueue if not deduplicated ────────────────────────────────────
    if result is not None:
        priority_score = _compute_priority_score(result)
        request.app.state.queue.enqueue(result, priority_score)

    # Use the original normalized alert's ID for the response
    # (even when deduplicated, so the caller can track it)
    return {"accepted": True, "alert_id": normalized.id}
