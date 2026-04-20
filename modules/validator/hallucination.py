"""
Hallucination detection — cross-checks LLM-injected metadata against
the original message metadata from Redis.

The LLM prompt instructs the model to copy x_cti_source_url and
x_cti_published_at verbatim. If the model hallucinated different values,
we correct them from the authoritative metadata rather than rejecting
the object entirely (the IoC value itself may still be correct).

Checks performed:
1. x_cti_source_url is present and non-empty
2. x_cti_source_url matches the source_url from the ChunkMessage
   (normalized: strip trailing slash, lowercase scheme+host)
3. x_cti_published_at is present (corrected from metadata if missing)
"""
from __future__ import annotations

import re
from urllib.parse import urlparse
import uuid as uuid_lib

import structlog

log = structlog.get_logger()


def validate_and_fix_metadata(
    stix_obj: dict,
    expected_source_url: str,
    published_at_fallback: str,
) -> tuple[dict, list[str]]:
    """
    Validate and correct x_cti_* extension fields in a STIX object.

    Returns:
        (corrected_stix_obj, list_of_warnings)
        Warnings are logged but do not cause rejection.
    """
    warnings: list[str] = []
    obj = dict(stix_obj)
    stix_type = obj.get("type", "indicator")
    try:
        suffix = obj["id"].split("--")[1]
        uuid_lib.UUID(suffix, version=4)
    except (KeyError, ValueError, IndexError):
        obj["id"] = f"{stix_type}--{uuid_lib.uuid4()}"
    # ── x_cti_source_url ─────────────────────────────────────
    llm_url = obj.get("x_cti_source_url", "")

    if not llm_url:
        warnings.append("x_cti_source_url missing — corrected from metadata")
        obj["x_cti_source_url"] = expected_source_url
    elif not _urls_match(llm_url, expected_source_url):
        warnings.append(
            f"x_cti_source_url mismatch: LLM={llm_url!r} expected={expected_source_url!r} "
            "— corrected from metadata"
        )
        obj["x_cti_source_url"] = expected_source_url

    # ── x_cti_published_at ────────────────────────────────────
    if not obj.get("x_cti_published_at"):
        warnings.append("x_cti_published_at missing — corrected from metadata")
        obj["x_cti_published_at"] = published_at_fallback

    return obj, warnings


def _urls_match(url_a: str, url_b: str) -> bool:
    """
    Compare two URLs with normalization:
    - Lowercase scheme and host
    - Strip trailing slash from path
    - Ignore fragment
    """
    def normalize(url: str) -> str:
        try:
            p = urlparse(url.strip())
            host = (p.netloc or "").lower()
            path = p.path.rstrip("/")
            scheme = p.scheme.lower()
            query = p.query
            return f"{scheme}://{host}{path}{'?' + query if query else ''}"
        except Exception:
            return url.strip().lower().rstrip("/")

    return normalize(url_a) == normalize(url_b)
