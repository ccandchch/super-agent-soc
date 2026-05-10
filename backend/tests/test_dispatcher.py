"""Tests for Dispatcher — queue consumer with similarity query and Thread/Run creation."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.ingestion.dispatcher import Dispatcher
from app.ingestion.models import Entity, NormalizedAlert
from app.ingestion.queue import PriorityQueue, PriorityScore

# ── Helpers ──────────────────────────────────────────────────────────────────────


def _make_alert(severity: str = "critical", **kwargs) -> NormalizedAlert:
    """Build a minimal NormalizedAlert for dispatcher testing."""
    defaults = {
        "source": "siem_splunk",
        "defense_line": "endpoint",
        "alert_name": "Suspicious PowerShell Execution",
        "type": "malware",
        "severity": severity,
        "entities": [
            Entity(type="ip", value="10.0.0.1"),
            Entity(type="host", value="WS-PC-001"),
        ],
        "fingerprint": "fp-test-dispatcher-001",
        "raw_evidence": {"src_ip": "10.0.0.1", "process": "powershell.exe"},
    }
    defaults.update(kwargs)
    return NormalizedAlert(**defaults)


def _make_score(alert: NormalizedAlert) -> PriorityScore:
    """Build a PriorityScore for the given alert."""
    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return PriorityScore(
        alert_severity=severity_map.get(alert.severity, 3),
        asset_criticality=0.5,
        alert_density=0.5,
        uncertainty=0.5,
    )


# ── TestDispatcher ───────────────────────────────────────────────────────────────


class TestDispatcher:
    """Tests for the Dispatcher class."""

    @patch("app.ingestion.dispatcher.httpx")
    def test_dispatch_creates_thread_and_run(self, mock_httpx):
        """Enqueue an alert, dispatch it, and verify thread + run POST calls."""
        # Arrange
        queue = PriorityQueue()
        alert = _make_alert("critical")
        queue.enqueue(alert, _make_score(alert))

        # Mock httpx responses
        mock_client = AsyncMock()

        # -- memory-soc GET returns empty (no similar alerts) --
        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {}
        mock_get_response.raise_for_status.return_value = None
        mock_client.get.return_value = mock_get_response

        # -- langgraph POST: thread creation --
        mock_thread_response = MagicMock()
        mock_thread_response.json.return_value = {"thread_id": "thread-1"}
        mock_thread_response.raise_for_status.return_value = None

        # -- langgraph POST: run creation --
        mock_run_response = MagicMock()
        mock_run_response.json.return_value = {"run_id": "run-1"}
        mock_run_response.raise_for_status.return_value = None

        mock_client.post.side_effect = [mock_thread_response, mock_run_response]

        mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client

        dispatcher = Dispatcher()

        # Act
        result = asyncio.run(dispatcher.dispatch_one(queue))

        # Assert
        assert result is not None
        assert result["fast_triage"] is False
        assert result["thread_id"] == "thread-1"
        assert result["run_id"] == "run-1"
        assert result["alert_id"] == alert.id

        # Verify exactly 2 POST calls: thread creation + run creation
        assert mock_client.post.call_count == 2

        # Verify the first POST was for thread creation
        thread_call_args = mock_client.post.call_args_list[0]
        assert "/threads" in thread_call_args[0][0]
        assert mock_httpx.AsyncClient.call_count == 2  # one GET client, one POST client

    @patch("app.ingestion.dispatcher.httpx")
    def test_empty_queue_does_nothing(self, mock_httpx):
        """Dispatch on an empty queue returns None with no HTTP calls."""
        queue = PriorityQueue()
        dispatcher = Dispatcher()

        result = asyncio.run(dispatcher.dispatch_one(queue))

        assert result is None
        mock_httpx.AsyncClient.assert_not_called()

    @patch("app.ingestion.dispatcher.httpx")
    def test_fast_triage_skips_llm(self, mock_httpx):
        """When memory-soc returns exact_match with confidence >= 0.95,
        skip LLM call and return fast_triage=True."""
        # Arrange
        queue = PriorityQueue()
        alert = _make_alert("critical")
        queue.enqueue(alert, _make_score(alert))

        # Mock memory-soc response with high-confidence exact match
        mock_client = AsyncMock()

        mock_similar_response = MagicMock()
        mock_similar_response.json.return_value = {
            "exact_match": {
                "confidence": 0.97,
                "result_id": "prev-result-42",
                "alert_name": "Suspicious PowerShell Execution",
            },
        }
        mock_similar_response.raise_for_status.return_value = None
        mock_client.get.return_value = mock_similar_response

        mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client

        dispatcher = Dispatcher()

        # Act
        result = asyncio.run(dispatcher.dispatch_one(queue))

        # Assert
        assert result is not None
        assert result["fast_triage"] is True
        assert result["reused_result_id"] == "prev-result-42"
        assert result["alert_id"] == alert.id

        # No thread/run POST calls should have been made
        mock_client.post.assert_not_called()

        # Only the memory-soc AsyncClient was created (fast-triage returns early)
        assert mock_httpx.AsyncClient.call_count == 1

    @patch("app.ingestion.dispatcher.httpx")
    def test_memory_soc_failure_proceeds_without_similar(self, mock_httpx):
        """When memory-soc is unreachable, log a warning and continue with similar=None."""
        # Arrange
        queue = PriorityQueue()
        alert = _make_alert("high")
        queue.enqueue(alert, _make_score(alert))

        mock_client = AsyncMock()

        # memory-soc GET raises an exception
        mock_client.get.side_effect = RuntimeError("Connection refused")

        # langgraph POST responses
        mock_thread_response = MagicMock()
        mock_thread_response.json.return_value = {"thread_id": "thread-2"}
        mock_thread_response.raise_for_status.return_value = None

        mock_run_response = MagicMock()
        mock_run_response.json.return_value = {"run_id": "run-2"}
        mock_run_response.raise_for_status.return_value = None

        mock_client.post.side_effect = [mock_thread_response, mock_run_response]

        mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client

        dispatcher = Dispatcher()

        # Act
        result = asyncio.run(dispatcher.dispatch_one(queue))

        # Assert — dispatch proceeds normally without similar data
        assert result is not None
        assert result["fast_triage"] is False
        assert result["thread_id"] == "thread-2"
        assert result["run_id"] == "run-2"
        assert mock_client.post.call_count == 2

    @patch("app.ingestion.dispatcher.httpx")
    def test_build_message_with_similar_data(self, mock_httpx):
        """When memory-soc returns similar data, it should be included in the message."""
        # Arrange
        queue = PriorityQueue()
        alert = _make_alert("high")
        queue.enqueue(alert, _make_score(alert))

        mock_client = AsyncMock()

        # memory-soc GET returns similar data (but no high-confidence exact match)
        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {
            "exact_match": None,
            "historical_context": {
                "similar_alerts": 5,
                "common_resolutions": ["Contain host", "Block IP"],
            },
            "type_statistics": {
                "total_occurrences": 42,
                "false_positive_rate": 0.1,
            },
        }
        mock_get_response.raise_for_status.return_value = None
        mock_client.get.return_value = mock_get_response

        # Capture the run POST body for inspection
        mock_thread_response = MagicMock()
        mock_thread_response.json.return_value = {"thread_id": "thread-3"}
        mock_thread_response.raise_for_status.return_value = None

        mock_run_response = MagicMock()
        mock_run_response.json.return_value = {"run_id": "run-3"}
        mock_run_response.raise_for_status.return_value = None

        mock_client.post.side_effect = [mock_thread_response, mock_run_response]

        mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client

        dispatcher = Dispatcher()

        # Act
        result = asyncio.run(dispatcher.dispatch_one(queue))

        # Assert
        assert result is not None
        assert result["fast_triage"] is False

        # Verify the run POST body contains the similar data blocks
        run_call = mock_client.post.call_args_list[1]
        run_body = run_call[1]["json"]
        message_content = run_body["input"]["messages"][0]["content"]

        assert "<alert>" in message_content
        assert "</alert>" in message_content
        assert "<historical_context>" in message_content
        assert "</historical_context>" in message_content
        assert "<type_statistics>" in message_content
        assert "</type_statistics>" in message_content
