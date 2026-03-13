"""
Unit tests for Redis Streams abstraction (shared/queue/client.py).

Tests use a mock Redis client — no live Redis required.
Integration tests with a real Redis instance are in tests/integration/.
"""
from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from shared.queue.client import (
    STREAM_CHUNKS,
    STREAM_RAW,
    ensure_consumer_group,
    publish,
)


@pytest.mark.unit
class TestPublish:
    async def test_publish_calls_xadd(self) -> None:
        mock_redis = AsyncMock()
        mock_redis.xadd = AsyncMock(return_value="1234567890-0")

        with patch("shared.queue.client.get_redis", return_value=mock_redis):
            msg_id = await publish(STREAM_RAW, {"key": "value", "number": 42})

        assert msg_id == "1234567890-0"
        mock_redis.xadd.assert_called_once()
        call_args = mock_redis.xadd.call_args
        assert call_args[0][0] == STREAM_RAW
        # Payload is serialised as JSON in the 'data' field
        data_field = call_args[0][1]["data"]
        parsed = json.loads(data_field)
        assert parsed["key"] == "value"
        assert parsed["number"] == 42

    async def test_publish_serialises_non_string_values(self) -> None:
        """Ensures UUIDs, datetimes etc. don't crash serialisation."""
        import uuid
        from datetime import UTC, datetime

        mock_redis = AsyncMock()
        mock_redis.xadd = AsyncMock(return_value="100-0")

        with patch("shared.queue.client.get_redis", return_value=mock_redis):
            msg_id = await publish(STREAM_RAW, {
                "id": uuid.uuid4(),
                "ts": datetime.now(UTC),
            })

        assert msg_id == "100-0"
        # Verify it didn't crash
        call_args = mock_redis.xadd.call_args[0][1]["data"]
        assert isinstance(call_args, str)


@pytest.mark.unit
class TestEnsureConsumerGroup:
    async def test_creates_group_when_absent(self) -> None:
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(return_value=True)

        with patch("shared.queue.client.get_redis", return_value=mock_redis):
            await ensure_consumer_group(STREAM_RAW, "preprocessor-group")

        mock_redis.xgroup_create.assert_called_once_with(
            STREAM_RAW, "preprocessor-group", id="0", mkstream=True
        )

    async def test_ignores_busygroup_error(self) -> None:
        """BUSYGROUP means the group already exists — should not raise."""
        from redis.exceptions import ResponseError

        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(
            side_effect=ResponseError("BUSYGROUP Consumer Group name already exists")
        )

        with patch("shared.queue.client.get_redis", return_value=mock_redis):
            # Must not raise
            await ensure_consumer_group(STREAM_RAW, "preprocessor-group")

    async def test_reraises_non_busygroup_redis_errors(self) -> None:
        """Other Redis errors must propagate."""
        from redis.exceptions import ResponseError

        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(
            side_effect=ResponseError("WRONGTYPE Operation against a key holding wrong kind")
        )

        with patch("shared.queue.client.get_redis", return_value=mock_redis):
            with pytest.raises(ResponseError, match="WRONGTYPE"):
                await ensure_consumer_group(STREAM_RAW, "some-group")


@pytest.mark.unit
class TestConsumeStream:
    async def test_handler_called_and_message_acked(self) -> None:
        """Happy path: message received → handler called → ACK sent."""
        import asyncio

        from shared.queue.client import consume_stream

        payload = {"source_id": "abc", "type": "rss"}
        serialised = json.dumps(payload)

        received: list[dict] = []

        async def handler(data: dict) -> None:
            received.append(data)
            # Handler succeeds — does NOT raise here

        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(
            side_effect=__import__("redis").exceptions.ResponseError("BUSYGROUP ...")
        )
        # First call: one message. Second call: CancelledError to stop the loop.
        mock_redis.xreadgroup = AsyncMock(side_effect=[
            [(STREAM_RAW, [("1234-0", {"data": serialised})])],
            asyncio.CancelledError(),
        ])
        mock_redis.xack = AsyncMock()

        with patch("shared.queue.client.get_redis", return_value=mock_redis):
            with pytest.raises(asyncio.CancelledError):
                await consume_stream(STREAM_RAW, "group", "consumer-1", handler)

        assert len(received) == 1
        assert received[0] == payload
        mock_redis.xack.assert_called_once_with(STREAM_RAW, "group", "1234-0")

    async def test_handler_failure_does_not_ack(self) -> None:
        """If handler raises, the message must NOT be ACKed (will be redelivered)."""
        import asyncio

        from shared.queue.client import consume_stream

        call_count = 0

        async def failing_handler(data: dict) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("processing failed")
            raise asyncio.CancelledError  # Stop on second call

        serialised = json.dumps({"key": "val"})
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(
            side_effect=__import__("redis").exceptions.ResponseError("BUSYGROUP ...")
        )
        mock_redis.xreadgroup = AsyncMock(return_value=[
            (STREAM_RAW, [("msg-1", {"data": serialised})])
        ])
        mock_redis.xack = AsyncMock()

        with patch("shared.queue.client.get_redis", return_value=mock_redis):
            with pytest.raises(asyncio.CancelledError):
                await consume_stream(STREAM_RAW, "group", "consumer-1", failing_handler)

        # ACK must NOT have been called on the first (failed) invocation
        mock_redis.xack.assert_not_called()

    async def test_malformed_json_is_acked_and_skipped(self) -> None:
        """Unparseable messages are ACKed (to avoid infinite retry) and skipped."""
        import asyncio

        from shared.queue.client import consume_stream

        handler_called = False

        async def handler(data: dict) -> None:
            nonlocal handler_called
            handler_called = True

        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(
            side_effect=__import__("redis").exceptions.ResponseError("BUSYGROUP ...")
        )
        # First message: malformed JSON
        # Second call: return empty to trigger stop (via block timeout returning empty)
        mock_redis.xreadgroup = AsyncMock(side_effect=[
            [(STREAM_RAW, [("bad-1", {"data": "not valid json {{{"})])],
            [],  # Empty result → loop continues but handler never called again
            asyncio.CancelledError(),
        ])
        mock_redis.xack = AsyncMock()

        with patch("shared.queue.client.get_redis", return_value=mock_redis):
            with pytest.raises(asyncio.CancelledError):
                await consume_stream(STREAM_RAW, "group", "consumer-1", handler)

        # Malformed message should be ACKed to prevent infinite retry
        mock_redis.xack.assert_called_once_with(STREAM_RAW, "group", "bad-1")
        assert not handler_called