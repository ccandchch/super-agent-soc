"""Generic SIEM webhook adapter — passes through the raw JSON body as a RawAlert."""

from __future__ import annotations

from app.ingestion.adapters.base import AlertAdapter
from app.ingestion.models import RawAlert


class SIEMWebhookAdapter(AlertAdapter):
    """A pass-through adapter that constructs a RawAlert directly from the JSON body.

    Assumes the webhook payload already conforms to the RawAlert schema.
    """

    def parse(self, body: dict, vendor: str) -> RawAlert:
        """Parse the webhook body into a RawAlert by passing through the dict fields.

        Args:
            body: The JSON-decoded request body (expected to match RawAlert fields).
            vendor: The vendor identifier (unused in this adapter).

        Returns:
            A RawAlert constructed from *body*.
        """
        return RawAlert(**body)
