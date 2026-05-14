"""API routes for SOC Memory Service."""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from soc_memory.database import get_db
from soc_memory.feedback import save_feedback
from soc_memory.result_store import get_result, save_result
from soc_memory.similarity import find_similar

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/api/similar-alerts")
async def similar_alerts(
    fingerprint: str = Query(..., description="Alert fingerprint hash"),
    defense_line: str = Query(..., description="Defense line / data source"),
    alert_name: str = Query(..., description="Alert name / rule name"),
    entities: str = Query(..., description="JSON-encoded list of entity dicts"),
    lookback_days: int = Query(30, description="How many days to look back"),
    db: AsyncSession = Depends(get_db),
):
    """Query for alerts similar to a newly-ingested alert."""
    try:
        parsed_entities = json.loads(entities)
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="entities must be valid JSON")

    if not isinstance(parsed_entities, list):
        raise HTTPException(status_code=422, detail="entities must be a JSON array")

    result = await find_similar(
        db=db,
        fingerprint=fingerprint,
        defense_line=defense_line,
        alert_name=alert_name,
        entities=parsed_entities,
        lookback_days=lookback_days,
    )
    return result


@router.post("/api/results")
async def create_result(
    data: dict,
    db: AsyncSession = Depends(get_db),
):
    """Persist a new triage result."""
    try:
        result = await save_result(db, data)
    except Exception:
        logger.exception("Failed to save triage result")
        raise HTTPException(status_code=500, detail="Failed to save result")
    return {
        "result_id": result.result_id,
        "alert_id": result.alert_id,
        "verdict": result.verdict,
        "created_at": result.created_at.isoformat() if result.created_at else None,
    }


@router.get("/api/results/{result_id}")
async def get_triage_result(
    result_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Fetch a single triage result by ID."""
    result = await get_result(db, result_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not found")
    return {
        "result_id": result.result_id,
        "alert_id": result.alert_id,
        "thread_id": result.thread_id,
        "defense_line": result.defense_line,
        "alert_name": result.alert_name,
        "verdict": result.verdict,
        "confidence": result.confidence,
        "confidence_level": result.confidence_level,
        "severity": result.severity,
        "summary": result.summary,
        "evidence_timeline": result.evidence_timeline,
        "action_suggestion": result.action_suggestion,
        "uncertainties": result.uncertainties,
        "skill_version": result.skill_version,
        "degraded": result.degraded,
        "created_at": result.created_at.isoformat() if result.created_at else None,
    }


@router.post("/api/feedback")
async def submit_feedback(
    data: dict,
    db: AsyncSession = Depends(get_db),
):
    """Submit analyst feedback for a triage result."""
    try:
        feedback = await save_feedback(db, data)
    except Exception:
        logger.exception("Failed to save feedback")
        raise HTTPException(status_code=500, detail="Failed to save feedback")
    return {
        "id": feedback.id,
        "result_id": feedback.result_id,
        "analyst": feedback.analyst,
        "action": feedback.action,
        "created_at": feedback.created_at.isoformat() if feedback.created_at else None,
    }
