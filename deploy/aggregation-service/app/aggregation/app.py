"""Alert Aggregation Microservice — polls SIEM, aggregates, serves events to Agent.

Standalone FastAPI app on port 8004 (configurable via AGGREGATION_PORT).
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.aggregation.event_store import EventStore
from app.aggregation.poller import SiemPoller, POLL_INTERVAL_SECONDS
from app.aggregation.routers import consumption

logger = logging.getLogger(__name__)

AGGREGATION_PORT = int(os.environ.get("AGGREGATION_PORT", "8004"))


def make_app() -> FastAPI:
    """Create the Aggregation microservice app."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        poller = SiemPoller()
        stop_event = asyncio.Event()

        async def poll_loop():
            logger.info("SIEM poller started (interval=%ss)", POLL_INTERVAL_SECONDS)
            # Initial delay to let everything settle
            await asyncio.sleep(5)
            while not stop_event.is_set():
                try:
                    events = await poller.poll()
                    if events:
                        await app.state.event_store.replace_superseded(events)
                        logger.info("Poll produced %d events", len(events))
                except Exception:
                    logger.exception("Poll cycle failed")
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
            logger.info("SIEM poller stopped")

        task = asyncio.create_task(poll_loop())
        yield
        stop_event.set()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    app = FastAPI(title="SOC Alert Aggregation", version="0.1.0", lifespan=lifespan)
    app.state.event_store = EventStore()
    app.include_router(consumption.router, prefix="/api/aggregation")
    return app


app = make_app()
