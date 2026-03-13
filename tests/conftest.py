"""
Shared pytest fixtures for all test suites.

Fixtures provided:
- settings:       Overridden Settings instance for tests
- redis_client:   Async Redis client connected to test DB (db=1)
- db_session:     Async SQLAlchemy session with automatic rollback
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from shared.config import Settings


# ── Event loop ────────────────────────────────────────────────

@pytest.fixture(scope="session")
def event_loop_policy() -> asyncio.DefaultEventLoopPolicy:
    return asyncio.DefaultEventLoopPolicy()


# ── Settings override ─────────────────────────────────────────

@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Settings instance with test-safe values. Does not require a .env file."""
    return Settings(
        postgres_host="localhost",
        postgres_port=5432,
        postgres_db="cti_test",
        postgres_user="cti",
        postgres_password="test_password",
        redis_host="localhost",
        redis_port=6379,
        redis_password="test_password",
        jwt_secret="test_jwt_secret_at_least_32_chars_long_for_hmac",
        ollama_base_url="http://127.0.0.1:11434",
        llm_model="llama3.3:70b-instruct-q4_K_M",
        llm_fallback_model="mistral:7b-instruct-q4_K_M",
        embedding_model="BAAI/bge-m3",
        module_name="test",
        log_level="WARNING",
    )


# ── Redis (integration tests only) ────────────────────────────

@pytest_asyncio.fixture
async def redis_client(test_settings: Settings) -> AsyncGenerator[object, None]:
    """
    Async Redis client connected to test database (db=1).
    Flushes db=1 before and after each test.
    Skipped if Redis is not available.
    """
    import redis.asyncio as aioredis
    from redis.exceptions import ConnectionError as RedisConnectionError

    client = aioredis.from_url(
        f"redis://:{test_settings.redis_password}@{test_settings.redis_host}"
        f":{test_settings.redis_port}/1",
        encoding="utf-8",
        decode_responses=True,
    )
    try:
        await client.ping()
    except (RedisConnectionError, OSError):
        await client.aclose()
        pytest.skip("Redis not available — skipping integration test")

    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()


# ── Database session (integration tests only) ─────────────────

@pytest_asyncio.fixture
async def db_session(test_settings: Settings) -> AsyncGenerator[AsyncSession, None]:
    """
    Async SQLAlchemy session for integration tests.
    Uses a transaction that is rolled back after each test — no data persists.
    Skipped if PostgreSQL is not available.
    """
    from sqlalchemy.exc import OperationalError

    engine = create_async_engine(
        test_settings.database_url,
        echo=False,
        pool_pre_ping=True,
    )

    try:
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
    except (OperationalError, OSError):
        await engine.dispose()
        pytest.skip("PostgreSQL not available — skipping integration test")

    # Wrap entire test in a savepoint so we can rollback all changes
    async with engine.begin() as conn:
        factory = async_sessionmaker(bind=conn, expire_on_commit=False)
        async with factory() as session:
            yield session
            await session.rollback()

    await engine.dispose()
