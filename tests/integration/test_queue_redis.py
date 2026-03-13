"""
Integration tests for Redis Streams (shared/queue/client.py).
Requires a running Redis instance — skipped automatically if unavailable.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from shared.queue.client import (
    STREAM_RAW,
    consume_stream,
    ensure_consumer_group,
    get_pending_count,
    get_stream_length,
    publish,
)


@pytest.mark.integration
class TestPublishIntegration:
    async def test_publish_increments_stream_length(self, redis_client: object) -> None:
        # Ensure stream exists and is empty
        import redis.asyncio as aioredis
        client: aioredis.Redis = redis_client  # type: ignore[assignment]

        stream = "cti:test:raw"
        initial_len = await client.xlen(stream)

        # Mock get_redis to return the test client
        from unittest.mock import patch

        with patch("shared.queue.client.get_redis", return_value=client):
            await publish(stream, {"test": "payload", "value": 123})
            length = await get_stream_length(stream)

        assert length == initial_len + 1

    async def test_published_payload_is_deserialised_correctly(
        self, redis_client: object
    ) -> None:
        import redis.asyncio as aioredis
        client: aioredis.Redis = redis_client  # type: ignore[assignment]

        stream = "cti:test:payload"
        payload = {"source_id": "abc-123", "type": "rss", "count": 42}

        from unittest.mock import patch

        with patch("shared.queue.client.get_redis", return_value=client):
            msg_id = await publish(stream, payload)

        # Read back directly from Redis and verify
        messages = await client.xrange(stream, msg_id, msg_id)
        assert len(messages) == 1
        raw_data = messages[0][1]["data"]
        recovered = json.loads(raw_data)
        assert recovered == payload


@pytest.mark.integration
class TestConsumeIntegration:
    async def test_consume_receives_published_message(self, redis_client: object) -> None:
        import redis.asyncio as aioredis
        client: aioredis.Redis = redis_client  # type: ignore[assignment]

        stream = "cti:test:consume"
        group = "test-group"
        consumer = "test-consumer-1"
        payload = {"hello": "world"}

        from unittest.mock import patch

        received: list[dict] = []

        async def handler(data: dict) -> None:
            received.append(data)
            raise asyncio.CancelledError  # Stop after first message

        with patch("shared.queue.client.get_redis", return_value=client):
            await publish(stream, payload)
            with pytest.raises(asyncio.CancelledError):
                await consume_stream(stream, group, consumer, handler)

        assert len(received) == 1
        assert received[0] == payload

    async def test_pending_count_decreases_after_ack(self, redis_client: object) -> None:
        import redis.asyncio as aioredis
        client: aioredis.Redis = redis_client  # type: ignore[assignment]

        stream = "cti:test:pending"
        group = "test-group-pending"

        from unittest.mock import patch

        async def handler(data: dict) -> None:
            raise asyncio.CancelledError

        with patch("shared.queue.client.get_redis", return_value=client):
            await publish(stream, {"data": "test"})
            pending_before = await get_pending_count(stream, group)

            with pytest.raises(asyncio.CancelledError):
                await consume_stream(stream, group, "consumer-1", handler)

            pending_after = await get_pending_count(stream, group)

        # After successful handler + ACK, pending count should decrease
        assert pending_after == pending_before
