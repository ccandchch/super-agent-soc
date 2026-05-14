"""CRUD helpers for the Feedback model."""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from soc_memory.models import Feedback

logger = logging.getLogger(__name__)


async def save_feedback(db: AsyncSession, data: dict) -> Feedback:
    """Persist a new feedback row and return it."""
    feedback = Feedback(**data)
    db.add(feedback)
    await db.commit()
    await db.refresh(feedback)
    return feedback
