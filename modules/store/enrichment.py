"""
Enrichment auto-trigger — publishes EnrichmentRequest to cti:enrichment
for IP, domain, and file hash indicators after they are stored.

Only triggers if at least one external API key is configured
(checked via settings.enrichment_enabled).

IoC type detection from STIX pattern:
    [ipv4-addr:value = ...]     → ipv4-addr
    [ipv6-addr:value = ...]     → ipv6-addr
    [domain-name:value = ...]   → domain-name
    [file:hashes.SHA256 = ...]  → file (hash)
    [url:value = ...]           → url (not enriched — too noisy)
    [email-addr:value = ...]    → email (not enriched)

VirusTotal and Shodan are queried by the Enricher module.
"""
from __future__ import annotations

import re
from typing import Any

import structlog

from shared.config import get_settings
from shared.models.messages import EnrichmentRequest
from shared.queue import STREAM_ENRICHMENT, publish

log = structlog.get_logger()

# Types that are worth enriching externally
_ENRICHABLE_TYPES = frozenset({"ipv4-addr", "ipv6-addr", "domain-name", "file"})

_PATTERN_TYPE_RE = re.compile(
    r"\[(?P<type>[a-zA-Z0-9_-]+(?::[a-zA-Z0-9_.]+)?)\s*=\s*'(?P<value>[^']+)'\]"
)


def _parse_pattern(pattern: str) -> tuple[str, str] | None:
    """
    Parse a STIX pattern into (ioc_type, ioc_value).
    Returns None if not parseable or not enrichable.

    Examples:
        "[ipv4-addr:value = '1.2.3.4']"     → ("ipv4-addr", "1.2.3.4")
        "[file:hashes.SHA256 = 'abc...']"   → ("file", "abc...")
        "[url:value = 'https://...']"       → None (not enriched)
    """
    m = _PATTERN_TYPE_RE.search(pattern)
    if not m:
        return None

    raw_type = m.group("type")
    value = m.group("value")

    # Normalize: "ipv4-addr:value" → "ipv4-addr"
    ioc_type = raw_type.split(":")[0].lower()

    if ioc_type not in _ENRICHABLE_TYPES:
        return None

    return ioc_type, value


async def maybe_trigger_enrichment(stix_object: dict[str, Any]) -> bool:
    """
    Publish an EnrichmentRequest if this object warrants external enrichment.

    Returns True if enrichment was triggered, False otherwise.
    """
    settings = get_settings()

    if not settings.enrichment_enabled:
        return False

    if stix_object.get("type") != "indicator":
        return False

    pattern = stix_object.get("pattern", "")
    parsed = _parse_pattern(pattern)
    if not parsed:
        return False

    ioc_type, ioc_value = parsed
    stix_id = stix_object.get("id", "")

    request = EnrichmentRequest(
        stix_id=stix_id,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        requested_by="auto",
    )

    await publish(STREAM_ENRICHMENT, request.model_dump())
    log.info(
        "enrichment_triggered",
        stix_id=stix_id,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
    )
    return True
