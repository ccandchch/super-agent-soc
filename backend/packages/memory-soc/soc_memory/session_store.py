"""Redis session-state storage for triage-task progress."""

import json
import logging
import os

logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
TTL_SECONDS = 86400  # 24 hours


async def _get_redis():
    """Lazily create and return a Redis connection.

    Handles import and connection errors gracefully — logs a warning
    and returns None so callers can fall back without crashing.
    """
    try:
        import redis.asyncio as aioredis
    except ImportError:
        logger.warning("redis package not installed; session store unavailable")
        return None

    try:
        return aioredis.from_url(REDIS_URL, decode_responses=True)
    except Exception:
        logger.warning("Unable to connect to Redis at %s", REDIS_URL)
        return None


async def set_session(task_id: str, data: dict) -> None:
    """Store triage task state with 24h TTL.

    Key format: ``triage:task:{task_id}``
    """
    r = await _get_redis()
    if r is None:
        return
    try:
        key = f"triage:task:{task_id}"
        await r.set(key, json.dumps(data), ex=TTL_SECONDS)
    except Exception:
        logger.warning("Failed to write session for task %s", task_id, exc_info=True)


async def get_session(task_id: str) -> dict | None:
    """Retrieve triage task state.

    Returns ``None`` if the key does not exist or Redis is unreachable.
    """
    r = await _get_redis()
    if r is None:
        return None
    try:
        key = f"triage:task:{task_id}"
        raw = await r.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception:
        logger.warning("Failed to read session for task %s", task_id, exc_info=True)
        return None
