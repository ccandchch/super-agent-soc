"""SIEM API client — encapsulates authentication and alert fetching.

Third-party developers: subclass ``SiemClient`` and override ``authenticate()``
and/or ``_parse_item()`` to adapt to your SIEM's API contract.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

import httpx

from app.ingestion.models import RawAlert

logger = logging.getLogger(__name__)

SIEM_API_BASE = os.environ.get("SIEM_API_BASE", "http://siem:8080")
SIEM_API_KEY = os.environ.get("SIEM_API_KEY", "")


class SiemClient:
    """Fetches alerts from an upstream SIEM API.

    Override points for third-party integration:
        - ``authenticate()`` — login flow, return token
        - ``_headers()`` — custom request headers
        - ``_build_params()`` — custom query parameters
        - ``_parse_item()`` — map one SIEM alert dict → RawAlert
        - ``_items_from_response()`` — extract item list from API response
    """

    def __init__(self, base_url: str | None = None):
        self._base_url = base_url or SIEM_API_BASE
        self._token: str | None = None
        self._client: httpx.AsyncClient | None = None

    # ── Public API ──────────────────────────────────────────────────────────────

    async def authenticate(self) -> None:
        """Obtain an API token. Default: reads SIEM_API_KEY env var.

        Override for login-based SIEM (POST /api/login → token).
        """
        self._token = SIEM_API_KEY or None

    async def fetch_page(
        self, page: int = 0, size: int = 100, since: str | None = None
    ) -> dict:
        """Fetch one page of unacknowledged alerts.

        Returns:
            ``{"items": [...], "total": N}`` on success, or ``{"items": [], "total": 0}``
            when no alerts remain or the API is unreachable.
        """
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0, trust_env=False)

        params = self._build_params(page, size, since)
        headers = self._headers()

        try:
            resp = await self._client.get(
                f"{self._base_url}/api/v1/alerts",
                params=params,
                headers=headers,
            )
            if resp.status_code in (404, 204):
                return {"items": [], "total": 0}
            resp.raise_for_status()
            return self._items_from_response(resp.json())
        except httpx.ConnectError:
            logger.warning("SIEM API unreachable at %s", self._base_url)
            return {"items": [], "total": 0}
        except Exception:
            logger.exception("SIEM API request failed")
            return {"items": [], "total": 0}

    async def close(self) -> None:
        """Release the underlying HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    # ── Override points ──────────────────────────────────────────────────────────

    def _headers(self) -> dict:
        headers: dict = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _build_params(
        self, page: int, size: int, since: str | None
    ) -> dict:
        params: dict = {"page": page, "size": size, "status": "unacknowledged"}
        if since:
            params["since"] = since
        return params

    def _items_from_response(self, data: dict) -> dict:
        items = data.get("items", data.get("alerts", []))
        return {"items": [self._parse_item(i) for i in items], "total": data.get("total", len(items))}

    def _parse_item(self, item: dict) -> RawAlert:
        """Map one SIEM alert dict to a RawAlert.

        Override if your SIEM uses different field names.
        """
        return RawAlert(
            alarm_id=item.get("id", item.get("alarm_id", "")),
            alert_time=item.get("created_at", item.get("alert_time", self._now_iso())),
            defense_line=item.get("defense_line", "endpoint"),
            alert_name=item.get("name", item.get("alert_name", "unknown")),
            severity=item.get("severity", "medium"),
            raw_evidence=item.get("raw_evidence", item.get("evidence", {})),
        )

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
