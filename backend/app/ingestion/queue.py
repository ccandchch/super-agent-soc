"""Priority queue for SOC alert triage.

Orders alerts by a weighted multi-factor score before they are dispatched
for triage, ensuring the most critical alerts are handled first.
"""

from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass, field

from app.ingestion.models import NormalizedAlert


@dataclass
class PriorityScore:
    """Weighted multi-factor priority score for an alert.

    Attributes:
        alert_severity: Numeric severity 1-4 (low=1, medium=2, high=3, critical=4).
        asset_criticality: Asset criticality 0.0-1.0 from CMDB (default 0.5 when unknown).
        alert_density: Normalized alert density 0.0-1.0.
        uncertainty: Uncertainty 0.0-1.0 (lower = more uncertain, first-time=0.1).
        w_severity: Configurable weight for severity (default 0.40).
        w_asset: Configurable weight for asset criticality (default 0.30).
        w_density: Configurable weight for alert density (default 0.20).
        w_uncertainty: Configurable weight for uncertainty (default 0.10).
    """

    alert_severity: float      # 1-4: low=1, medium=2, high=3, critical=4
    asset_criticality: float   # 0.0-1.0 from CMDB (default 0.5 when unknown)
    alert_density: float       # 0.0-1.0 normalized
    uncertainty: float         # 0.0-1.0 (lower = more uncertain, first-time=0.1)

    # Weights (configurable)
    w_severity: float = 0.40
    w_asset: float = 0.30
    w_density: float = 0.20
    w_uncertainty: float = 0.10

    def calculate(self) -> float:
        """Compute the weighted priority score.

        Returns a float in [0.0, 1.0] where higher values indicate higher priority.
        """
        return (
            self.w_severity * (self.alert_severity / 4.0)
            + self.w_asset * self.asset_criticality
            + self.w_density * self.alert_density
            + self.w_uncertainty * self.uncertainty
        )


@dataclass(order=True)
class _QueueItem:
    """Internal heap item ordered by (priority, counter)."""

    priority: float
    counter: int
    alert: NormalizedAlert = field(compare=False)


class PriorityQueue:
    """Max-heap priority queue for NormalizedAlert dispatch.

    Alerts are ordered by their PriorityScore (descending), so the alert
    with the highest weighted score is always dequeued first.
    """

    def __init__(self) -> None:
        self._heap: list[_QueueItem] = []
        self._counter = itertools.count()

    def enqueue(self, alert: NormalizedAlert, score: PriorityScore) -> None:
        """Add an alert to the queue with its priority score.

        Args:
            alert: The normalized alert to enqueue.
            score: The weighted priority score for this alert.
        """
        # Negate priority for max-heap behavior (heapq is a min-heap)
        item = _QueueItem(
            priority=-score.calculate(),
            counter=next(self._counter),
            alert=alert,
        )
        heapq.heappush(self._heap, item)

    def dequeue(self) -> NormalizedAlert:
        """Remove and return the highest-priority alert.

        Returns:
            The NormalizedAlert with the highest priority score.

        Raises:
            IndexError: If the queue is empty.
        """
        if not self._heap:
            raise IndexError("dequeue from empty PriorityQueue")
        item = heapq.heappop(self._heap)
        return item.alert

    def peek_top(self, n: int) -> list[NormalizedAlert]:
        """Return the top *n* highest-priority alerts without removing them.

        Args:
            n: Maximum number of alerts to return.

        Returns:
            A list of at most *n* NormalizedAlert instances in priority order.
            Returns fewer than *n* if the queue has fewer items.
        """
        if n <= 0:
            return []
        top_items = heapq.nsmallest(n, self._heap)
        return [item.alert for item in top_items]

    def peek_all(self) -> list[NormalizedAlert]:
        """Return all alerts in the queue without removing them.

        Returns:
            A list of all NormalizedAlert instances in priority order.
        """
        return self.peek_top(self.size)

    @property
    def size(self) -> int:
        """Return the number of alerts currently in the queue."""
        return len(self._heap)

    def status(self) -> dict[str, int]:
        """Return queue status as a dictionary.

        Returns:
            A dict with key ``"depth"`` mapped to the current queue size.
        """
        return {"depth": len(self._heap)}
