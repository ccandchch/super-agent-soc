"""Pydantic data models for the SOC alert ingestion pipeline.

These types form the data contract between all ingestion stages:
raw SIEM input → normalization → deduplication → aggregation → dispatch.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _uuid7() -> str:
    """Generate a UUID v7 string (time-ordered, RFC 9562).

    Uses the Unix timestamp in milliseconds for the first 48 bits,
    followed by version-7 and variant bits plus random payload.
    """
    # Timestamp: milliseconds since Unix epoch
    ts = int(datetime.now(UTC).timestamp() * 1000)

    # Random bytes (10 bytes = 80 bits)
    random_bytes = uuid.uuid4().bytes

    # Build 16 bytes for UUID v7:
    # Bytes 0-5: timestamp (48 bits, big-endian from top of ts)
    ts_bytes = ts.to_bytes(8, "big")[2:]  # take lowest 6 bytes

    b = bytearray(16)
    b[0:6] = ts_bytes
    # Byte 6 (top nibble = version 7, low nibble = random)
    b[6] = (random_bytes[6] & 0x0F) | 0x70
    # Byte 7: random
    b[7] = random_bytes[7]
    # Byte 8 (top 2 bits = variant 10, rest random)
    b[8] = (random_bytes[8] & 0x3F) | 0x80
    # Bytes 9-15: random
    b[9:16] = random_bytes[9:16]

    return str(uuid.UUID(bytes=bytes(b)))


def _utc_iso_now() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(UTC).isoformat()


class DefenseLine(StrEnum):
    """Security defense-line categories for alert classification."""

    endpoint = "endpoint"
    server = "server"
    application = "application"
    network = "network"
    email = "email"
    account = "account"


class Entity(BaseModel):
    """A named entity extracted from an alert (IP, hostname, user, etc.)."""

    type: str = Field(..., description="Entity type (e.g. ip, host, user, file_hash)")
    value: str = Field(..., description="Entity value (e.g. 10.0.0.1, WS-PC-001)")


class RawAlert(BaseModel):
    """Raw alert as received from an upstream SIEM or detection system."""

    alarm_id: str = Field(..., description="Unique identifier from the upstream system")
    alert_time: str = Field(..., description="Alert time in ISO 8601 format")
    defense_line: DefenseLine = Field(..., description="Defense-line category")
    alert_name: str = Field(..., description="Human-readable alert name or rule title")
    raw_evidence: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary evidence payload from the source"
    )


class NormalizedAlert(BaseModel):
    """Standardized alert representation used throughout the pipeline."""

    id: str = Field(
        default_factory=_uuid7,
        description="UUID v7 identifier generated at normalization time",
    )
    source: str = Field(..., description="Source system identifier (e.g. siem_splunk)")
    defense_line: str = Field(..., description="Defense-line category")
    alert_name: str = Field(..., description="Alert name or rule title")
    type: str = Field(..., description="Alert type (malware, phishing, network_c2, etc.)")
    severity: str = Field(..., description="Severity level: critical, high, medium, low")
    entities: list[Entity] = Field(..., description="Extracted entities from the alert")
    fingerprint: str = Field(..., description="Content-based deduplication fingerprint")
    alarm_id: str | None = Field(
        None, description="Original alarm ID from upstream (None for aggregated alerts)"
    )
    deduped_alarm_ids: list[str] = Field(
        default_factory=list,
        description="Alarm IDs that were deduplicated into this alert",
    )
    aggregation: dict[str, Any] | None = Field(
        None, description="Aggregation metadata (set for aggregated alerts)"
    )
    raw_evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Original evidence payload from the source system",
    )
    created_at: str = Field(
        default_factory=_utc_iso_now,
        description="Creation timestamp in ISO 8601 format",
    )


class AggregatedAlert(NormalizedAlert):
    """An alert that represents multiple deduplicated raw alerts.

    Inherits all NormalizedAlert fields but makes ``aggregation`` required.
    """

    aggregation: dict[str, Any] = Field(
        ..., description="Aggregation metadata (count, window, strategy, etc.)"
    )
