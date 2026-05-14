"""Similar-alert query engine.

Queries the TriageResult table for alerts that share characteristics
with a newly-ingested alert to help analysts understand context and
historical outcomes.
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_memory.models import TriageResult

logger = logging.getLogger(__name__)


async def find_similar(
    db: AsyncSession,
    fingerprint: str,
    defense_line: str,
    alert_name: str,
    entities: list[dict],
    lookback_days: int = 30,
) -> dict:
    """Return similar-alert data for a given ingest fingerprint.

    Returns
    -------
    dict
        ``exact_match``
            The most recent TriageResult whose ``alert_name`` matches,
            or *None*.

        ``similar_alerts``
            A list of recent results with the same *alert_name*,
            ordered by ``created_at`` descending (capped to 20 rows).

        ``same_type_stats``
            A list of ``{verdict, count}`` dicts grouped by verdict
            for alerts matching *alert_name* within the lookback window.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    # --- exact match: most recent result with the same alert_name ---
    exact_stmt = (
        select(TriageResult)
        .where(TriageResult.alert_name == alert_name)
        .order_by(TriageResult.created_at.desc())
        .limit(1)
    )
    exact_row = (await db.execute(exact_stmt)).scalar_one_or_none()

    # --- similar alerts: up to 20 recent results with same alert_name ---
    similar_stmt = (
        select(TriageResult)
        .where(TriageResult.alert_name == alert_name)
        .order_by(TriageResult.created_at.desc())
        .limit(20)
    )
    similar_rows = (await db.execute(similar_stmt)).scalars().all()

    # --- same-type stats: verdict distribution in the lookback window ---
    stats_stmt = (
        select(
            TriageResult.verdict,
            func.count(TriageResult.result_id).label("count"),
        )
        .where(
            TriageResult.alert_name == alert_name,
            TriageResult.created_at >= cutoff,
        )
        .group_by(TriageResult.verdict)
    )
    stats_rows = (await db.execute(stats_stmt)).all()

    exact_match = _row_to_dict(exact_row) if exact_row else None
    similar_alerts = [_row_to_dict(r) for r in similar_rows]
    same_type_stats = [{"verdict": v, "count": c} for v, c in stats_rows]

    return {
        "exact_match": exact_match,
        "similar_alerts": similar_alerts,
        "same_type_stats": same_type_stats,
    }


def _row_to_dict(row: TriageResult) -> dict:
    """Serialize a TriageResult ORM row to a plain dictionary."""
    return {
        "result_id": row.result_id,
        "alert_id": row.alert_id,
        "thread_id": row.thread_id,
        "defense_line": row.defense_line,
        "alert_name": row.alert_name,
        "verdict": row.verdict,
        "confidence": row.confidence,
        "confidence_level": row.confidence_level,
        "severity": row.severity,
        "summary": row.summary,
        "evidence_timeline": row.evidence_timeline,
        "action_suggestion": row.action_suggestion,
        "uncertainties": row.uncertainties,
        "skill_version": row.skill_version,
        "degraded": row.degraded,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
