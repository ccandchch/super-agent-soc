"""Tests for the SOC Alert Ingestion FastAPI app — webhook receiver and queue status."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.ingestion.app import make_ingestion_app


@pytest.fixture(autouse=True)
def _disable_batching(monkeypatch):
    """Set flush interval to 0 so alerts bypass the buffer in tests."""
    monkeypatch.setenv("SOC_FLUSH_INTERVAL", "0")


@pytest.fixture
def ingestion_app():
    """Return a freshly configured ingestion FastAPI sub-application."""
    return make_ingestion_app()


# ── Helpers ───────────────────────────────────────────────────────────

_VALID_BODY: dict = {
    "alarm_id": "alarm-001",
    "alert_time": "2026-05-10T12:00:00Z",
    "defense_line": "endpoint",
    "alert_name": "Suspicious PowerShell Execution",
    "raw_evidence": {"src_ip": "10.0.0.1", "evil_process": "powershell.exe"},
}


def _client(app):
    """Build an httpx AsyncClient backed by ASGITransport for *app*."""
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ── Webhook endpoint tests ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_webhook_endpoint_accepts_valid_alert(ingestion_app):
    """POST a valid alert → 202 with accepted=True and an alert_id."""
    async with _client(ingestion_app) as client:
        response = await client.post("/webhooks/siem_splunk", json=_VALID_BODY)

    assert response.status_code == 202
    data = response.json()
    assert data["accepted"] is True
    assert "alert_id" in data


@pytest.mark.asyncio
async def test_webhook_rejects_missing_required_fields(ingestion_app):
    """Missing required fields (e.g. alarm_id) → 422."""
    body = {
        "alert_time": "2026-05-10T12:00:00Z",
        "defense_line": "endpoint",
        "alert_name": "Test Alert",
        # alarm_id is missing
    }
    async with _client(ingestion_app) as client:
        response = await client.post("/webhooks/siem_splunk", json=body)

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_webhook_rejects_invalid_defense_line(ingestion_app):
    """Invalid defense_line value → 422."""
    body = {
        ** _VALID_BODY,
        "defense_line": "invalid_line",
    }
    async with _client(ingestion_app) as client:
        response = await client.post("/webhooks/siem_splunk", json=body)

    assert response.status_code == 422


# ── Queue status endpoint tests ───────────────────────────────────────

@pytest.mark.asyncio
async def test_queue_status_endpoint_returns_depth(ingestion_app):
    """GET /queue/status → 200 with a 'depth' key."""
    async with _client(ingestion_app) as client:
        response = await client.get("/queue/status")

    assert response.status_code == 200
    data = response.json()
    assert "depth" in data


@pytest.mark.asyncio
async def test_queue_depth_increments_after_webhook(ingestion_app):
    """Queue depth should increase after a valid webhook is accepted."""
    async with _client(ingestion_app) as client:
        # Initially empty
        r = await client.get("/queue/status")
        assert r.json()["depth"] == 0

        # Post a valid alert
        await client.post("/webhooks/siem_splunk", json=_VALID_BODY)

        # Queue should now have depth 1
        r = await client.get("/queue/status")
        assert r.json()["depth"] == 1


@pytest.mark.asyncio
async def test_deduplicated_alert_does_not_enqueue(ingestion_app):
    """A duplicate alert (same fingerprint) should be deduplicated and not enqueued."""
    async with _client(ingestion_app) as client:
        # First alert → enqueued
        r1 = await client.post("/webhooks/siem_splunk", json=_VALID_BODY)
        assert r1.status_code == 202

        # Same alert within dedup window → deduplicated, not enqueued
        r2 = await client.post("/webhooks/siem_splunk", json=_VALID_BODY)
        assert r2.status_code == 202

        # Queue should still have depth 1
        r = await client.get("/queue/status")
        assert r.json()["depth"] == 1
