"""
Async SQLAlchemy engine and session factory.
All modules that need database access import from here.
"""
from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from functools import lru_cache

import structlog
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from shared.config import get_settings

log = structlog.get_logger()


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,       # Detect stale connections
        pool_recycle=3600,        # Recycle connections every hour
        echo=False,               # Set True for SQL query logging during debug
    )


@lru_cache(maxsize=1)
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=get_engine(),
        class_=AsyncSession,
        expire_on_commit=False,   # Keep objects accessible after commit
        autocommit=False,
        autoflush=False,
    )


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide a transactional database session.

    Usage:
        async with get_session() as session:
            result = await session.execute(select(StixObject))
            await session.commit()

    The session is automatically closed on exit.
    Exceptions are re-raised after rollback.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_engine() -> None:
    """Dispose the engine connection pool. Call on application shutdown."""
    engine = get_engine()
    await engine.dispose()
    log.info("db_engine_closed")
