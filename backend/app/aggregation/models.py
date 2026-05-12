"""Event model — the output of the aggregation pipeline, consumed by the AI Agent."""

from __future__ import annotations

import uuid
from pydantic import BaseModel, Field


class EventSource(BaseModel):
    """A single alert that contributed to this aggregated event."""
    alarm_id: str
    alert_name: str
    alert_time: str


class Event(BaseModel):
    """An aggregated security event ready for AI Agent triage."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    defense_line: str
    alert_name: str
    alert_type: str
    severity: str
    source_alarms: list[EventSource]
    entity_overlap: float
    occurrence_count: int
    entities: list[dict]
    raw_evidence: dict
    created_at: str
    consumed: bool = False
