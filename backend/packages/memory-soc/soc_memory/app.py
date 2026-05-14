"""FastAPI application for the SOC Memory Service."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from soc_memory.routers import router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database on startup; tear down on shutdown."""
    from soc_memory.database import init_db

    await init_db()
    logger.info("SOC Memory Service started")
    yield


def make_app() -> FastAPI:
    """Build and return the FastAPI application instance."""
    app = FastAPI(
        title="SOC Memory Service",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(router)
    return app


app = make_app()
