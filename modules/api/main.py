"""CTI Aggregator API — FastAPI application."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from modules.api.routers import auth, metrics, objects, perimeters, sources
from modules.api.routers import settings as settings_router
from shared.config import get_settings
from shared.db import close_engine
from shared.logging import configure_logging

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    configure_logging()
    log.info("api_starting")
    yield
    await close_engine()
    log.info("api_stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="CTI Aggregator API",
        description="On-premise Cyber Threat Intelligence aggregation platform",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.base_url],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(auth.router)
    app.include_router(sources.router)
    app.include_router(objects.router)
    app.include_router(perimeters.router)
    app.include_router(metrics.router)
    app.include_router(settings_router.router)

    @app.get("/health", tags=["health"])
    async def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
