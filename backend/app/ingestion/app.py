"""SOC Alert Ingestion — FastAPI sub-application factory.

Provides webhook receiver and queue status endpoints.
State (normalizer, dedup, queue) is shared with the main Gateway lifespan
which runs the Dispatcher background loop.

Usage:
    from app.ingestion.app import make_ingestion_app
    ingestion = make_ingestion_app()
    main_app.mount("/ingestion", ingestion)
"""

from __future__ import annotations

from fastapi import FastAPI

from app.ingestion.dedup import DedupAggregator
from app.ingestion.normalizer import Normalizer
from app.ingestion.queue import PriorityQueue
from app.ingestion.routers import queue_status, webhooks


def make_ingestion_app() -> FastAPI:
    """Create and configure the SOC Alert Ingestion FastAPI sub-application.

    Initialises the normalizer, dedup-aggregator, and priority queue on
    ``app.state`` so every route handler can access them via
    ``request.app.state``.

    The Dispatcher background loop is started by the main Gateway lifespan,
    not here — sub-app lifespans are unreliable with app.mount().

    Returns:
        A configured FastAPI instance ready for mounting or standalone use.
    """
    app = FastAPI(title="SOC Alert Ingestion", version="0.1.0")

    app.state.normalizer = Normalizer()
    app.state.dedup_aggregator = DedupAggregator()
    app.state.queue = PriorityQueue()

    app.include_router(webhooks.router, prefix="/webhooks")
    app.include_router(queue_status.router, prefix="/queue")

    return app
