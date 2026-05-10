import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from soc_memory.models import Base, Feedback, SuppressionRule, TriageResult


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Initialize in-memory SQLite database before each test."""
    from soc_memory import database as db_module

    original_url = db_module.DATABASE_URL
    original_engine = db_module.engine
    original_sessionmaker = db_module.AsyncSessionLocal

    db_module.DATABASE_URL = "sqlite+aiosqlite://"
    db_module.engine = create_async_engine(db_module.DATABASE_URL, echo=False)
    db_module.AsyncSessionLocal = async_sessionmaker(db_module.engine, expire_on_commit=False)

    # Enable foreign key enforcement in SQLite (off by default)
    async with db_module.engine.begin() as conn:
        await conn.run_sync(lambda sync_conn: sync_conn.execute(
            __import__("sqlalchemy").text("PRAGMA foreign_keys = ON")
        ))

    await db_module.init_db()

    yield

    # Tear down: drop all tables and restore original engine
    async with db_module.engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await db_module.engine.dispose()

    db_module.DATABASE_URL = original_url
    db_module.engine = original_engine
    db_module.AsyncSessionLocal = original_sessionmaker


@pytest.mark.asyncio
class TestTriageResult:
    async def test_create_result(self):
        """Verify that a TriageResult can be inserted and read back."""
        from soc_memory.database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            result = TriageResult(
                alert_id="alert-001",
                thread_id="thread-abc",
                defense_line="network",
                alert_name="Suspicious Login",
                verdict="true_positive",
                confidence=0.95,
                confidence_level="high",
                severity="critical",
                summary="Multiple failed login attempts from unusual IP.",
                evidence_timeline=[{"event": "Failed SSH login", "ts": "2025-01-01T00:00:00Z"}],
                action_suggestion={"action": "Block IP", "reason": "Brute force"},
                uncertainties=["Could be a misconfigured script."],
                skill_version="1.0.0",
            )
            session.add(result)
            await session.commit()
            await session.refresh(result)

        async with AsyncSessionLocal() as session:
            stmt = select(TriageResult).where(TriageResult.alert_id == "alert-001")
            fetched = (await session.execute(stmt)).scalar_one()
            assert fetched.verdict == "true_positive"
            assert fetched.confidence == 0.95
            assert fetched.severity == "critical"
            assert fetched.created_at is not None
            assert fetched.degraded is False

    async def test_result_defaults(self):
        """Verify default values on TriageResult."""
        from soc_memory.database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            result = TriageResult(
                alert_id="alert-002",
                thread_id="thread-def",
            )
            session.add(result)
            await session.commit()
            await session.refresh(result)

            assert result.result_id is not None
            assert len(result.result_id) == 36  # UUID4 string length
            assert result.degraded is False
            assert result.created_at is not None


@pytest.mark.asyncio
class TestFeedback:
    async def test_create_feedback(self):
        """Verify that Feedback can be linked to a TriageResult."""
        from soc_memory.database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            triage = TriageResult(
                alert_id="alert-003",
                thread_id="thread-ghi",
                verdict="false_positive",
            )
            session.add(triage)
            await session.commit()
            await session.refresh(triage)

            feedback = Feedback(
                result_id=triage.result_id,
                analyst="analyst@example.com",
                action="confirm_false_positive",
                comment="Confirmed false positive - expected maintenance window.",
            )
            session.add(feedback)
            await session.commit()
            await session.refresh(feedback)

            assert feedback.id is not None
            assert feedback.result_id == triage.result_id
            assert feedback.action == "confirm_false_positive"
            assert feedback.created_at is not None

    async def test_feedback_reject(self):
        """Verify Feedback with reject_reason."""
        from soc_memory.database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            triage = TriageResult(
                alert_id="alert-004",
                thread_id="thread-jkl",
            )
            session.add(triage)
            await session.commit()
            await session.refresh(triage)

            feedback = Feedback(
                result_id=triage.result_id,
                analyst="analyst2@example.com",
                action="reject",
                reject_reason="Insufficient evidence",
            )
            session.add(feedback)
            await session.commit()
            await session.refresh(feedback)

            assert feedback.reject_reason == "Insufficient evidence"

    async def test_feedback_cascade_on_delete(self):
        """Verify Feedback referencing a non-existent TriageResult fails FK constraint."""
        from soc_memory.database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            feedback = Feedback(
                result_id="non-existent-id",
                analyst="analyst@example.com",
            )
            session.add(feedback)
            with pytest.raises(Exception):
                await session.commit()
            await session.rollback()


@pytest.mark.asyncio
class TestSuppressionRule:
    async def test_create_rule(self):
        """Verify that a SuppressionRule can be created."""
        from soc_memory.database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            rule = SuppressionRule(
                rule_id="suppress-001",
                entity_pattern={"ip": "192.168.1.100", "reason": "known scanner"},
                status="active",
                created_by="admin@example.com",
            )
            session.add(rule)
            await session.commit()
            await session.refresh(rule)

            assert rule.id is not None
            assert rule.rule_id == "suppress-001"
            assert rule.status == "active"
            assert rule.entity_pattern["ip"] == "192.168.1.100"
            assert rule.created_at is not None
            assert rule.valid_until is None  # No expiry set

    async def test_rule_defaults(self):
        """Verify SuppressionRule default values."""
        from soc_memory.database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            rule = SuppressionRule(
                rule_id="suppress-002",
                entity_pattern={"hostname": "build-server-*"},
            )
            session.add(rule)
            await session.commit()
            await session.refresh(rule)

            assert rule.status == "draft"
            assert rule.valid_until is None
            assert rule.created_by is None
            assert rule.approved_by is None

    async def test_rule_with_expiry(self):
        """Verify SuppressionRule with valid_until."""
        from datetime import datetime, timezone

        from soc_memory.database import AsyncSessionLocal

        expiry = datetime(2025, 12, 31, tzinfo=timezone.utc)

        async with AsyncSessionLocal() as session:
            rule = SuppressionRule(
                rule_id="suppress-003",
                entity_pattern={"domain": "test.example.com"},
                valid_until=expiry,
                created_by="admin@example.com",
                approved_by="manager@example.com",
            )
            session.add(rule)
            await session.commit()
            await session.refresh(rule)

            # SQLite stores datetimes without timezone; compare as UTC timestamps
            assert rule.valid_until is not None
            assert rule.valid_until.replace(tzinfo=timezone.utc) == expiry
            assert rule.approved_by == "manager@example.com"
