"""Alert adapters — parse vendor-specific webhook payloads into RawAlert instances."""

from app.ingestion.adapters.base import AlertAdapter
from app.ingestion.adapters.siem_webhook import SIEMWebhookAdapter

__all__ = ["AlertAdapter", "SIEMWebhookAdapter"]
