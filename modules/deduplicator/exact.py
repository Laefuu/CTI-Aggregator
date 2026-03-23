"""
Exact deduplication — SHA-256 of the normalized STIX pattern.

Key format: dedup:stix:<sha256>
TTL: STIX_DEDUP_TTL_SECONDS (default: 60 days, matching retention policy)

Returns the existing stix_id if a duplicate is found, None otherwise.
"""
from __future__ import annotations

import hashlib
import json

import structlog

from shared.config import get_settings
from shared.queue import get_redis

log = structlog.get_logger()

_KEY_PREFIX = "dedup:stix:"


def _pattern_hash(stix_pattern: str) -> str:
    """
    Normalize and hash a STIX pattern for exact deduplication.

    Normalization: strip whitespace, lowercase.
    This catches identical IoCs with trivial formatting differences.
    """
    normalized = stix_pattern.strip().lower()
    return hashlib.sha256(normalized.encode()).hexdigest()


async def lookup_exact(stix_pattern: str) -> str | None:
    """
    Check if this pattern was already stored.
    Returns the existing stix_id, or None if not found.
    """
    client = await get_redis()
    key = f"{_KEY_PREFIX}{_pattern_hash(stix_pattern)}"
    value = await client.get(key)
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode()
    return value


async def mark_exact(stix_pattern: str, stix_id: str) -> None:
    """
    Register a pattern hash → stix_id mapping with TTL.
    """
    settings = get_settings()
    client = await get_redis()
    key = f"{_KEY_PREFIX}{_pattern_hash(stix_pattern)}"
    await client.setex(key, settings.fetch_dedup_ttl_seconds, stix_id)
    log.debug("dedup_exact_marked", stix_id=stix_id, hash=key[-16:])
