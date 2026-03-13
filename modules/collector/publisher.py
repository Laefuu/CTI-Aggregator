"""
Publisher — converts RawDocument → RawMessage and publishes to cti:raw.

Handles:
- Fetch-level deduplication (skip already-seen content hashes)
- Base64 encoding of content bytes
- Metrics recording
"""
from __future__ import annotations

import base64
from datetime import UTC, datetime

import structlog

from modules.collector.base import RawDocument
from modules.collector.dedup import check_and_mark
from shared.metrics import record_metric
from shared.models.messages import RawMessage
from shared.queue import STREAM_RAW, publish

log = structlog.get_logger()


async def publish_document(doc: RawDocument) -> bool:
    """
    Publish a RawDocument to cti:raw after dedup check.

    Returns True if published, False if skipped (duplicate).
    """
    content_hash = doc.content_hash()

    if await check_and_mark(content_hash):
        await record_metric("collector.dedup_skipped", 1, source_id=doc.source_id)
        return False

    message = RawMessage(
        source_id=doc.source_id,  # type: ignore[arg-type]
        source_url=doc.source_url,
        source_type=doc.source_type,
        content_b64=base64.b64encode(doc.content_bytes).decode("ascii"),
        content_type=doc.content_type,
        fetched_at=doc.fetched_at,
        tlp_level=doc.tlp_level,
        metadata={
            **doc.metadata,
            "published_at": doc.published_at.isoformat() if doc.published_at else None,
            "content_size": len(doc.content_bytes),
        },
    )

    await publish(STREAM_RAW, message.model_dump())
    await record_metric(
        "collector.published",
        1,
        source_id=doc.source_id,
        source_type=doc.source_type.value,
        content_type=doc.content_type,
    )

    log.info(
        "document_published",
        source_id=doc.source_id,
        url=doc.source_url,
        size=len(doc.content_bytes),
    )
    return True
