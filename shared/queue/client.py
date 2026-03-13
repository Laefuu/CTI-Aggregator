"""
Redis Streams abstraction for inter-module communication.

Usage — producer:
    from shared.queue.client import get_redis, publish
    await publish("cti:raw", message.model_dump())

Usage — consumer:
    from shared.queue.client import consume_stream
    await consume_stream("cti:raw", "preprocessor-group", "preprocessor-1", handler)
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable, Coroutine
from typing import Any

import redis.asyncio as aioredis
import structlog
from redis.exceptions import ResponseError

from shared.config import get_settings

log = structlog.get_logger()

# ── Stream names ──────────────────────────────────────────────
STREAM_RAW          = "cti:raw"
STREAM_CHUNKS       = "cti:chunks"
STREAM_STIX_RAW     = "cti:stix_raw"
STREAM_STIX_VALID   = "cti:stix_valid"
STREAM_STIX_REJECTED = "cti:stix_rejected"
STREAM_STIX_FINAL   = "cti:stix_final"
STREAM_ENRICHMENT   = "cti:enrichment"
STREAM_ALERTS       = "cti:alerts"

# ── Connection ────────────────────────────────────────────────

_redis_client: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    """Return the shared async Redis client, creating it if needed."""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
        )
    return _redis_client


async def close_redis() -> None:
    """Close the Redis connection. Call on application shutdown."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


# ── Producer ─────────────────────────────────────────────────

async def publish(stream: str, payload: dict[str, Any]) -> str:
    """
    Publish a message to a Redis Stream.
    The payload is serialised as a single JSON field 'data'.
    Returns the message ID assigned by Redis.
    """
    client = await get_redis()
    # Redis Stream fields must be strings — serialise the entire payload as JSON
    msg_id: str = await client.xadd(stream, {"data": json.dumps(payload, default=str)})
    log.debug("stream_published", stream=stream, msg_id=msg_id)
    return msg_id


# ── Consumer ─────────────────────────────────────────────────

Handler = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


async def ensure_consumer_group(stream: str, group: str) -> None:
    """Create the consumer group if it does not already exist."""
    client = await get_redis()
    try:
        await client.xgroup_create(stream, group, id="0", mkstream=True)
        log.info("consumer_group_created", stream=stream, group=group)
    except ResponseError as e:
        if "BUSYGROUP" in str(e):
            pass  # Group already exists — normal on restart
        else:
            raise


async def consume_stream(
    stream: str,
    group: str,
    consumer: str,
    handler: Handler,
    *,
    batch_size: int = 10,
    block_ms: int = 5000,
) -> None:
    """
    Consume messages from a Redis Stream using consumer groups.

    - Messages are ACKed only after successful handler execution.
    - On handler failure: the message is NOT ACKed and will be redelivered
      on the next consumer restart (pending entries list).
    - Runs indefinitely until cancelled.

    Args:
        stream:     Stream name (e.g. STREAM_RAW)
        group:      Consumer group name
        consumer:   Unique consumer name within the group
        handler:    Async function receiving the deserialized message dict
        batch_size: Number of messages to fetch per XREADGROUP call
        block_ms:   How long to block waiting for messages (milliseconds)
    """
    client = await get_redis()
    await ensure_consumer_group(stream, group)

    log.info("consumer_started", stream=stream, group=group, consumer=consumer)

    while True:
        try:
            results = await client.xreadgroup(
                groupname=group,
                consumername=consumer,
                streams={stream: ">"},
                count=batch_size,
                block=block_ms,
            )
        except Exception as exc:
            log.error("stream_read_error", stream=stream, error=str(exc))
            continue

        if not results:
            continue  # Timeout — no messages, loop

        for _stream_name, entries in results:
            for msg_id, fields in entries:
                raw_data = fields.get("data", "{}")
                try:
                    payload = json.loads(raw_data)
                except json.JSONDecodeError as exc:
                    log.error(
                        "message_deserialise_failed",
                        stream=stream,
                        msg_id=msg_id,
                        error=str(exc),
                    )
                    # ACK malformed messages to avoid infinite retry
                    await client.xack(stream, group, msg_id)
                    continue

                try:
                    await handler(payload)
                    await client.xack(stream, group, msg_id)
                    log.debug("message_processed", stream=stream, msg_id=msg_id)
                except Exception as exc:
                    # Do NOT ACK — message stays in pending list for redelivery
                    log.error(
                        "handler_failed",
                        stream=stream,
                        msg_id=msg_id,
                        error=str(exc),
                        exc_info=True,
                    )


async def get_stream_length(stream: str) -> int:
    """Return the number of messages in a stream."""
    client = await get_redis()
    return await client.xlen(stream)


async def get_pending_count(stream: str, group: str) -> int:
    """Return the number of pending (unACKed) messages for a consumer group."""
    client = await get_redis()
    info = await client.xpending(stream, group)
    return info.get("pending", 0) if isinstance(info, dict) else 0
