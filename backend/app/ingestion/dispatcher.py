"""Dispatcher — pulls alerts from the priority queue and creates DeerFlow Thread/Run.

The dispatcher consumes alerts from the ingestion priority queue, queries
memory-soc for similar historical alerts (with graceful fallback), and
creates a LangGraph Thread + Run for LLM triage when fast-triage criteria
are not met.
"""

from __future__ import annotations

import json
import logging

import httpx

from app.ingestion.models import NormalizedAlert
from app.ingestion.queue import PriorityQueue

logger = logging.getLogger(__name__)


class Dispatcher:
    """Pulls alerts from the priority queue, queries memory-soc for similar
    historical alerts, and creates DeerFlow Thread + Run via the LangGraph API.

    Fast-triage optimisation: when memory-soc returns an exact match with
    confidence >= 0.95 the LLM call is skipped entirely and the previous
    triage result is reused.
    """

    def __init__(
        self,
        langgraph_url: str = "http://localhost:2026/api/langgraph",
        memory_soc_url: str = "http://localhost:8003",
        recursion_limit: int = 100,
        model_name: str = "claude-opus-4-7",
    ) -> None:
        self.langgraph_url = langgraph_url
        self.memory_soc_url = memory_soc_url
        self.recursion_limit = recursion_limit
        self.model_name = model_name

    # ── Public API ──────────────────────────────────────────────────────────

    async def dispatch_one(self, queue: PriorityQueue) -> dict | None:
        """Pull one alert from queue, query similar alerts, create Thread/Run.

        Args:
            queue: The ingestion priority queue to dequeue from.

        Returns:
            A dispatch result dict on success, or ``None`` if the queue is empty.

        Result dict shape (fast triage)::

            {
                "fast_triage": True,
                "reused_result_id": "...",
                "alert_id": "...",
            }

        Result dict shape (normal dispatch)::

            {
                "fast_triage": False,
                "thread_id": "...",
                "run_id": "...",
                "alert_id": "...",
            }
        """
        # 1. Dequeue
        try:
            alert = queue.dequeue()
        except IndexError:
            return None

        # 2. Query similar alerts (graceful fallback)
        similar = await self._query_similar_alerts(alert)

        # 3. Fast triage check
        if similar:
            exact_match = similar.get("exact_match")
            if exact_match and exact_match.get("confidence", 0) >= 0.95:
                return {
                    "fast_triage": True,
                    "reused_result_id": exact_match.get("result_id"),
                    "alert_id": alert.id,
                }

        # 4. Build message content
        message_content = self._build_message(alert, similar)

        # 5-6. Create Thread + Run
        async with httpx.AsyncClient(timeout=10.0) as client:
            thread_id = await self._create_thread(client)
            run_id = await self._create_run(client, thread_id, message_content)

        # 7. Return dispatch result
        return {
            "fast_triage": False,
            "thread_id": thread_id,
            "run_id": run_id,
            "alert_id": alert.id,
        }

    # ── Memory-SOC query ────────────────────────────────────────────────────

    async def _query_similar_alerts(self, alert: NormalizedAlert) -> dict | None:
        """Query memory-soc for similar historical alerts.

        Returns the parsed JSON response dict, or ``None`` if the request
        fails (connection error, timeout, etc.).
        """
        entities_param = ",".join(
            f"{e.type}:{e.value}" for e in alert.entities
        )
        params = {
            "fingerprint": alert.fingerprint,
            "defense_line": alert.defense_line,
            "alert_name": alert.alert_name,
            "entities": entities_param,
            "lookback_days": 30,
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"{self.memory_soc_url}/api/similar-alerts",
                    params=params,
                )
                response.raise_for_status()
                return response.json()
        except Exception:
            logger.warning(
                "Failed to query memory-soc for similar alerts "
                "(fingerprint=%s)",
                alert.fingerprint,
                exc_info=True,
            )
            return None

    # ── Message building ────────────────────────────────────────────────────

    @staticmethod
    def _build_message(alert: NormalizedAlert, similar: dict | None) -> str:
        """Build the user message content for the LLM run.

        Always includes an ``<alert>`` block with the full alert JSON.
        When similar historical data is available, appends
        ``<historical_context>`` and ``<type_statistics>`` blocks.
        """
        parts = [f"<alert>{json.dumps(alert.model_dump())}</alert>"]

        if similar:
            historical = similar.get("historical_context")
            if historical:
                parts.append(
                    f"<historical_context>{json.dumps(historical)}</historical_context>"
                )
            type_stats = similar.get("type_statistics")
            if type_stats:
                parts.append(
                    f"<type_statistics>{json.dumps(type_stats)}</type_statistics>"
                )

        return "\n".join(parts)

    # ── LangGraph API helpers ───────────────────────────────────────────────

    async def _create_thread(self, client: httpx.AsyncClient) -> str:
        """Create a new LangGraph thread and return its ``thread_id``."""
        response = await client.post(
            f"{self.langgraph_url}/threads",
            json={"metadata": {"source": "soc-ingestion"}},
        )
        response.raise_for_status()
        data = response.json()
        return data["thread_id"]

    async def _create_run(
        self,
        client: httpx.AsyncClient,
        thread_id: str,
        message_content: str,
    ) -> str:
        """Create a new Run on the given thread and return its ``run_id``."""
        body = {
            "input": {
                "messages": [{"role": "user", "content": message_content}],
            },
            "config": {
                "recursion_limit": self.recursion_limit,
                "configurable": {
                    "model_name": self.model_name,
                    "thinking_enabled": True,
                },
            },
            "stream_mode": ["values", "messages-tuple", "custom"],
        }
        response = await client.post(
            f"{self.langgraph_url}/threads/{thread_id}/runs",
            json=body,
        )
        response.raise_for_status()
        data = response.json()
        return data["run_id"]
