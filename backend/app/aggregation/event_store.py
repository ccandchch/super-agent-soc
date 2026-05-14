"""Event Store — thread-safe queue of aggregated events for Agent consumption."""

from __future__ import annotations

import asyncio
import logging
from collections import deque

from app.aggregation.models import Event

logger = logging.getLogger(__name__)


class EventStore:
    """FIFO queue of Events, consumed one-at-a-time by the AI Agent."""

    def __init__(self, max_size: int = 10000):
        self._queue: deque[Event] = deque()
        self._max_size = max_size
        self._lock = asyncio.Lock()

    async def push(self, event: Event) -> None:
        """Add an event to the queue."""
        async with self._lock:
            if len(self._queue) >= self._max_size:
                self._queue.popleft()  # drop oldest
            self._queue.append(event)

    async def push_batch(self, events: list[Event]) -> None:
        """Add multiple events."""
        async with self._lock:
            for event in events:
                if len(self._queue) >= self._max_size:
                    self._queue.popleft()
                self._queue.append(event)

    async def replace_superseded(self, events: list[Event]) -> None:
        """Add new events and remove any unconsumed events whose source_alarm_ids
        overlap with the new events (superseded by more complete aggregation)."""
        async with self._lock:
            new_alarm_ids: set[str] = set()
            for e in events:
                for s in e.source_alarms:
                    if s.alarm_id:
                        new_alarm_ids.add(s.alarm_id)

            # Remove unconsumed events that share any alarm_id with new events
            kept: list[Event] = []
            for existing in self._queue:
                if existing.consumed:
                    kept.append(existing)
                    continue
                existing_ids = {s.alarm_id for s in existing.source_alarms}
                if existing_ids & new_alarm_ids:
                    continue  # superseded — drop
                kept.append(existing)

            self._queue.clear()
            self._queue.extend(kept)

            # Now add the new events
            for event in events:
                if len(self._queue) >= self._max_size:
                    self._queue.popleft()
                self._queue.append(event)

    async def next(self) -> Event | None:
        """Return the next unconsumed event, mark it consumed, or None if empty."""
        async with self._lock:
            for event in self._queue:
                if not event.consumed:
                    event.consumed = True
                    return event
            return None

    async def peek_all(self) -> list[Event]:
        """Return all events without marking consumed (for dashboard)."""
        async with self._lock:
            return list(self._queue)

    async def status(self) -> dict:
        """Return queue status."""
        async with self._lock:
            unconsumed = sum(1 for e in self._queue if not e.consumed)
            return {"total": len(self._queue), "unconsumed": unconsumed}
