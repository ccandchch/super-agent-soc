"""SOC Alert Ingestion — FastAPI sub-application factory.

Provides webhook receiver and queue status endpoints.

Usage:
    from app.ingestion.app import make_ingestion_app
    ingestion = make_ingestion_app()
    main_app.mount("/ingestion", ingestion)
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.ingestion.dedup import DedupAggregator
from app.ingestion.dispatcher import Dispatcher
from app.ingestion.normalizer import Normalizer
from app.ingestion.queue import PriorityQueue
from app.ingestion.routers import queue_status, webhooks

logger = logging.getLogger(__name__)


def make_ingestion_app() -> FastAPI:
    """Create and configure the SOC Alert Ingestion FastAPI sub-application.

    Initialises the normalizer, dedup-aggregator, and priority queue on
    ``app.state`` so every route handler can access them via
    ``request.app.state``.

    Returns:
        A configured FastAPI instance ready for mounting or standalone use.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        dispatcher = Dispatcher()
        stop_event = asyncio.Event()

        async def dispatch_loop():
            logger.info("Dispatcher loop started")
            while not stop_event.is_set():
                try:
                    result = await dispatcher.dispatch_one(app.state.queue)
                    if result is None:
                        await asyncio.sleep(1)
                    else:
                        logger.info("Dispatched: %s", result)
                except Exception:
                    logger.exception("Dispatch error")
                    await asyncio.sleep(5)
                await asyncio.sleep(0.5)

        task = asyncio.create_task(dispatch_loop())
        yield
        stop_event.set()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        logger.info("Dispatcher loop stopped")

    app = FastAPI(title="SOC Alert Ingestion", version="0.1.0", lifespan=lifespan)

    app.state.normalizer = Normalizer()
    app.state.dedup_aggregator = DedupAggregator()
    app.state.queue = PriorityQueue()

    app.include_router(webhooks.router, prefix="/webhooks")
    app.include_router(queue_status.router, prefix="/queue")

    return app
