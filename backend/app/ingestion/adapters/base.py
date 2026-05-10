"""Abstract base class for alert adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.ingestion.models import RawAlert


class AlertAdapter(ABC):
    """Abstract adapter that parses a vendor-specific webhook body into a RawAlert."""

    @abstractmethod
    def parse(self, body: dict, vendor: str) -> RawAlert:
        """Parse a raw webhook body into a RawAlert.

        Args:
            body: The JSON-decoded request body.
            vendor: The vendor identifier from the URL path (e.g. ``siem_splunk``).

        Returns:
            A populated RawAlert instance.
        """
        ...
