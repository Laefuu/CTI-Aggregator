"""
Fetch-level deduplication using Redis SET with TTL.

Before publishing a RawDocument, the Collector checks if its content hash
has been seen recently. If yes, it is skipped silently.

TTL is controlled by FETCH_DEDUP_TTL_SECONDS (default: 7 days).
Key format: dedup:fetch:<sha256_of_content>
"""
from __future__ import annotations

import structlog

from shared.config import get_settings
from shared.queue import get_redis

log = structlog.get_logger()

_KEY_PREFIX = "dedup:fetch:"


async def is_duplicate(content_hash: str) -> bool:
    """
    Return True if this content hash was already processed within the TTL window.
    """
    client = await get_redis()
    key = f"{_KEY_PREFIX}{content_hash}"
    exists: int = await client.exists(key)
    return exists > 0


async def mark_seen(content_hash: str) -> None:
    """
    Mark a content hash as seen. Expires after FETCH_DEDUP_TTL_SECONDS.
    """
    settings = get_settings()
    client = await get_redis()
    key = f"{_KEY_PREFIX}{content_hash}"
    await client.setex(key, settings.fetch_dedup_ttl_seconds, "1")


async def check_and_mark(content_hash: str) -> bool:
    """
    Atomic check-and-mark. Returns True if duplicate (should skip).
    Returns False if new (marks as seen and proceeds).
    """
    if await is_duplicate(content_hash):
        log.debug("fetch_duplicate_skipped", hash=content_hash[:16])
        return True
    await mark_seen(content_hash)
    return False
