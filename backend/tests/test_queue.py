"""Tests for PriorityQueue and PriorityScore — weighted multi-factor alert ordering."""

import pytest

from app.ingestion.models import Entity, NormalizedAlert
from app.ingestion.queue import PriorityQueue, PriorityScore


# ── Helpers ──────────────────────────────────────────────────────────────────────


def _make_alert(severity: str, **kwargs) -> NormalizedAlert:
    """Build a minimal NormalizedAlert for queue testing."""
    defaults = {
        "source": "siem_splunk",
        "defense_line": "endpoint",
        "alert_name": "Test Alert",
        "type": "malware",
        "severity": severity,
        "entities": [Entity(type="host", value="WS-PC-001")],
        "fingerprint": f"fp-{severity}",
        "raw_evidence": {},
    }
    defaults.update(kwargs)
    return NormalizedAlert(**defaults)


def _severity_to_numeric(severity: str) -> float:
    """Map severity string to numeric value: low=1, medium=2, high=3, critical=4."""
    mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return mapping[severity]


# ── TestPriorityScore ────────────────────────────────────────────────────────────


class TestPriorityScore:
    """Tests for the PriorityScore dataclass and its weighted calculation."""

    def test_calculates_weighted_score(self):
        """Verify the weighted multi-factor formula produces the expected score."""
        score = PriorityScore(
            alert_severity=4,   # critical
            asset_criticality=1.0,
            alert_density=0.5,
            uncertainty=0.5,
            # default weights: w_severity=0.40, w_asset=0.30, w_density=0.20, w_uncertainty=0.10
        )
        result = score.calculate()
        expected = 0.40 * (4 / 4.0) + 0.30 * 1.0 + 0.20 * 0.5 + 0.10 * 0.5
        assert result == pytest.approx(expected)

    def test_default_weights_sum_to_one(self):
        """Default weights should sum to 1.0 so the score is in [0, 1]."""
        score = PriorityScore(
            alert_severity=1,
            asset_criticality=0.0,
            alert_density=0.0,
            uncertainty=0.0,
        )
        assert score.w_severity + score.w_asset + score.w_density + score.w_uncertainty == pytest.approx(1.0)

    def test_max_score_is_one(self):
        """With all inputs at maximum, the score should be 1.0."""
        score = PriorityScore(
            alert_severity=4,
            asset_criticality=1.0,
            alert_density=1.0,
            uncertainty=1.0,
        )
        assert score.calculate() == pytest.approx(1.0)

    def test_min_score_is_zero(self):
        """With all inputs at minimum, the score should be 0.0."""
        score = PriorityScore(
            alert_severity=1,
            asset_criticality=0.0,
            alert_density=0.0,
            uncertainty=0.0,
        )
        expected = 0.40 * (1 / 4.0) + 0.30 * 0.0 + 0.20 * 0.0 + 0.10 * 0.0  # = 0.10
        # Minimum score is not zero because severity=1 still contributes 0.40 * 0.25 = 0.10
        assert score.calculate() == pytest.approx(expected)

    def test_custom_weights(self):
        """Custom weights should be respected in the calculation."""
        score = PriorityScore(
            alert_severity=4,
            asset_criticality=1.0,
            alert_density=1.0,
            uncertainty=1.0,
            w_severity=0.25,
            w_asset=0.25,
            w_density=0.25,
            w_uncertainty=0.25,
        )
        expected = 0.25 * 1.0 + 0.25 * 1.0 + 0.25 * 1.0 + 0.25 * 1.0
        assert score.calculate() == pytest.approx(expected)

    def test_severity_scales_linearly(self):
        """Doubling severity (from 2 to 4) should double the severity contribution."""
        score_low = PriorityScore(
            alert_severity=2,
            asset_criticality=0.5,
            alert_density=0.5,
            uncertainty=0.5,
        )
        score_high = PriorityScore(
            alert_severity=4,
            asset_criticality=0.5,
            alert_density=0.5,
            uncertainty=0.5,
        )
        # The difference should be w_severity * (4/4 - 2/4) = 0.40 * 0.5 = 0.20
        assert score_high.calculate() - score_low.calculate() == pytest.approx(0.20)


# ── TestPriorityQueue ────────────────────────────────────────────────────────────


class TestPriorityQueue:
    """Tests for the PriorityQueue class using heapq-based max-heap ordering."""

    def test_enqueue_dequeue_order(self):
        """A low-severity alert should be dequeued after a critical-severity alert."""
        queue = PriorityQueue()

        alert_low = _make_alert("low")
        alert_critical = _make_alert("critical")

        score_low = PriorityScore(
            alert_severity=_severity_to_numeric("low"),
            asset_criticality=0.5,
            alert_density=0.5,
            uncertainty=0.5,
        )
        score_critical = PriorityScore(
            alert_severity=_severity_to_numeric("critical"),
            asset_criticality=0.5,
            alert_density=0.5,
            uncertainty=0.5,
        )

        queue.enqueue(alert_low, score_low)
        queue.enqueue(alert_critical, score_critical)

        # Critical should be dequeued first
        first = queue.dequeue()
        assert first.severity == "critical"

        # Low should be dequeued second
        second = queue.dequeue()
        assert second.severity == "low"

    def test_empty_queue_raises(self):
        """Dequeue on an empty queue should raise IndexError."""
        queue = PriorityQueue()
        with pytest.raises(IndexError, match="dequeue from empty PriorityQueue"):
            queue.dequeue()

    def test_peek_top_n(self):
        """peek_top(3) should return at most 3 alerts without removing them."""
        queue = PriorityQueue()

        for severity in ("low", "medium", "high", "critical"):
            alert = _make_alert(severity)
            score = PriorityScore(
                alert_severity=_severity_to_numeric(severity),
                asset_criticality=0.5,
                alert_density=0.5,
                uncertainty=0.5,
            )
            queue.enqueue(alert, score)

        # peek_top(3) should return 3 alerts
        top = queue.peek_top(3)
        assert len(top) == 3

        # The highest severity (critical) should be first in the peeked list
        assert top[0].severity == "critical"

        # Queue size should be unchanged after peek
        assert queue.size == 4

    def test_peek_top_exceeds_size(self):
        """peek_top with n greater than queue size should return all items."""
        queue = PriorityQueue()
        alert = _make_alert("high")
        score = PriorityScore(
            alert_severity=_severity_to_numeric("high"),
            asset_criticality=0.5,
            alert_density=0.5,
            uncertainty=0.5,
        )
        queue.enqueue(alert, score)

        top = queue.peek_top(5)
        assert len(top) == 1
        assert queue.size == 1

    def test_peek_top_zero(self):
        """peek_top(0) should return an empty list."""
        queue = PriorityQueue()
        alert = _make_alert("high")
        score = PriorityScore(
            alert_severity=_severity_to_numeric("high"),
            asset_criticality=0.5,
            alert_density=0.5,
            uncertainty=0.5,
        )
        queue.enqueue(alert, score)

        assert queue.peek_top(0) == []
        assert queue.size == 1

    def test_queue_size(self):
        """size should reflect the number of enqueued alerts."""
        queue = PriorityQueue()
        assert queue.size == 0

        alert = _make_alert("medium")
        score = PriorityScore(
            alert_severity=_severity_to_numeric("medium"),
            asset_criticality=0.5,
            alert_density=0.5,
            uncertainty=0.5,
        )
        queue.enqueue(alert, score)
        assert queue.size == 1

        queue.enqueue(alert, score)
        assert queue.size == 2

        queue.dequeue()
        assert queue.size == 1

    def test_queue_status(self):
        """status() should return a dict with the 'depth' key."""
        queue = PriorityQueue()

        # Empty queue
        assert queue.status() == {"depth": 0}

        # Add 3 alerts
        for severity in ("low", "medium", "high"):
            alert = _make_alert(severity)
            score = PriorityScore(
                alert_severity=_severity_to_numeric(severity),
                asset_criticality=0.5,
                alert_density=0.5,
                uncertainty=0.5,
            )
            queue.enqueue(alert, score)

        assert queue.status() == {"depth": 3}

    def test_same_score_tiebreaker(self):
        """Alerts with identical scores should be dequeued in FIFO insertion order."""
        queue = PriorityQueue()

        first = _make_alert("critical", alert_name="First")
        second = _make_alert("critical", alert_name="Second")

        # Both get the same score
        score = PriorityScore(
            alert_severity=_severity_to_numeric("critical"),
            asset_criticality=0.5,
            alert_density=0.5,
            uncertainty=0.5,
        )

        queue.enqueue(first, score)
        queue.enqueue(second, score)

        assert queue.dequeue().alert_name == "First"
        assert queue.dequeue().alert_name == "Second"
