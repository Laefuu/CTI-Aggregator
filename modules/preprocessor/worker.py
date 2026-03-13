"""
Preprocessor worker — consumes cti:raw, produces cti:chunks.

For each RawMessage:
    1. Decode base64 content
    2. Extract text (HTML/PDF/JSON)
    3. Detect language
    4. Split into chunks
    5. Publish N ChunkMessages to cti:chunks

One ChunkMessage per chunk, with chunk_index and chunk_total for reassembly.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone

import structlog

from modules.preprocessor.chunker import chunk_text
from modules.preprocessor.extractor import extract_text
from modules.preprocessor.language import detect_language
from shared.metrics import record_metric
from shared.models.enums import SourceType, TLPLevel
from shared.models.messages import ChunkMessage, RawMessage
from shared.queue import STREAM_CHUNKS, STREAM_RAW, consume_stream, publish

log = structlog.get_logger()

_GROUP = "preprocessor-group"
_CONSUMER = "preprocessor-1"


async def handle_raw_message(payload: dict) -> None:
    """
    Process one RawMessage from cti:raw.
    Publishes 0..N ChunkMessages to cti:chunks.
    """
    try:
        msg = RawMessage.model_validate(payload)
    except Exception as exc:
        log.error("preprocessor_invalid_message", error=str(exc))
        return

    worker_log = log.bind(source_id=str(msg.source_id), url=msg.source_url)
    worker_log.info("preprocessor_received")

    # 1. Decode
    try:
        content_bytes = base64.b64decode(msg.content_b64)
    except Exception as exc:
        worker_log.error("preprocessor_decode_failed", error=str(exc))
        await record_metric("preprocessor.decode_error", 1)
        return

    # 2. Extract text
    text = extract_text(content_bytes, msg.content_type)
    if not text:
        worker_log.warning("preprocessor_no_text_extracted", content_type=msg.content_type)
        await record_metric("preprocessor.no_text", 1, content_type=msg.content_type)
        return

    # 3. Detect language
    language = detect_language(text)

    # 4. Chunk
    chunks = chunk_text(text)
    if not chunks:
        worker_log.warning("preprocessor_no_chunks", word_count=len(text.split()))
        await record_metric("preprocessor.no_chunks", 1)
        return

    # 5. Publish
    published_at: datetime | None = None
    if msg.metadata.get("published_at"):
        try:
            published_at = datetime.fromisoformat(msg.metadata["published_at"])
        except (ValueError, TypeError):
            pass

    for i, chunk in enumerate(chunks):
        chunk_msg = ChunkMessage(
            source_id=msg.source_id,
            source_url=msg.source_url,
            source_type=msg.source_type,
            chunk_index=i,
            chunk_total=len(chunks),
            chunk_text=chunk,
            language=language,
            tlp_level=msg.tlp_level,
            published_at=published_at,
            fetched_at=msg.fetched_at,
        )
        await publish(STREAM_CHUNKS, chunk_msg.model_dump())

    await record_metric(
        "preprocessor.chunks_published",
        len(chunks),
        source_id=str(msg.source_id),
        language=language,
        content_type=msg.content_type,
    )

    worker_log.info(
        "preprocessor_done",
        chunks=len(chunks),
        language=language,
        words=len(text.split()),
    )


async def run() -> None:
    """Start the preprocessor consumer loop."""
    log.info("preprocessor_starting", group=_GROUP, consumer=_CONSUMER)
    await consume_stream(
        stream=STREAM_RAW,
        group=_GROUP,
        consumer=_CONSUMER,
        handler=handle_raw_message,
    )
