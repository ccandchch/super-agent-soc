import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


def new_uuid() -> str:
    return str(uuid.uuid4())


class TriageResult(Base):
    __tablename__ = "triage_results"

    result_id = Column(String, primary_key=True, default=new_uuid)
    alert_id = Column(String, nullable=False)
    thread_id = Column(String, nullable=False)
    defense_line = Column(String)
    alert_name = Column(String)
    verdict = Column(String)
    confidence = Column(Float)
    confidence_level = Column(String)
    severity = Column(String)
    summary = Column(Text)
    evidence_timeline = Column(JSON)
    action_suggestion = Column(JSON)
    uncertainties = Column(JSON)
    skill_version = Column(String)
    degraded = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(String, primary_key=True, default=new_uuid)
    result_id = Column(String, ForeignKey("triage_results.result_id"), nullable=False)
    analyst = Column(String)
    action = Column(String)
    reject_reason = Column(String)
    comment = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SuppressionRule(Base):
    __tablename__ = "suppression_rules"

    id = Column(String, primary_key=True, default=new_uuid)
    rule_id = Column(String)
    entity_pattern = Column(JSON)
    status = Column(String, default="draft")
    valid_until = Column(DateTime)
    created_by = Column(String)
    approved_by = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
