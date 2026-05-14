"""CRUD helpers for the TriageResult model."""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_memory.models import TriageResult

logger = logging.getLogger(__name__)


async def save_result(db: AsyncSession, data: dict) -> TriageResult:
    """Persist a new triage result row and return it."""
    result = TriageResult(**data)
    db.add(result)
    await db.commit()
    await db.refresh(result)
    return result


async def get_result(db: AsyncSession, result_id: str) -> TriageResult | None:
    """Look up a single triage result by primary key."""
    stmt = select(TriageResult).where(TriageResult.result_id == result_id)
    return (await db.execute(stmt)).scalar_one_or_none()
