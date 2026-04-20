"""
Perimeter matching — checks STIX objects against all enabled perimeters.

Criteria evaluated per STIX type:

    indicator
        • ioc_values   — exact match of extracted IoC value
        • ip_ranges    — CIDR containment for IPv4/IPv6 indicators

    threat-actor
        • sectors      — keyword appears in actor's sectors / description / types
        • geo_countries — keyword appears in actor's name / aliases / description

    attack-pattern
        • sectors       — keyword appears in name / description / tactic
        • software_products — keyword appears in name / description / platforms

Any one criterion matching is sufficient to create an alert.
The alert inherits the severity configured on the perimeter.

Pattern extraction:
    [ipv4-addr:value = '1.2.3.4']      → type=ipv4-addr, value='1.2.3.4'
    [domain-name:value = 'evil.com']   → type=domain-name, value='evil.com'
    [file:hashes.SHA256 = 'abc...']    → type=file, value='abc...'
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

import structlog
from sqlalchemy import text

from shared.db import get_session

log = structlog.get_logger()

_PATTERN_VALUE_RE = re.compile(r"'([^']+)'")
_PATTERN_TYPE_RE  = re.compile(r"\[\s*([\w-]+):")


# ── Public entry point ────────────────────────────────────────

async def match_perimeters(
    stix_object_id: str,
    stix_object: dict[str, Any],
    source_url: str,
) -> int:
    """
    Check a STIX object against all enabled perimeters.

    Creates alert rows for each match and returns the number of matches.
    """
    stix_type = stix_object.get("type")
    if stix_type not in ("indicator", "threat-actor", "attack-pattern"):
        return 0

    # Quick pre-checks before hitting the DB
    if stix_type == "indicator":
        if not extract_ioc_value(stix_object.get("pattern", "")):
            return 0

    async with get_session() as session:
        result = await session.execute(text("""
            SELECT id::text, name, ioc_values, sectors, geo_countries,
                   software_products, ip_ranges, severity
            FROM perimeters
            WHERE enabled = TRUE
        """))
        perimeters = result.mappings().all()

    matches = 0
    matched_perimeters: list[dict[str, Any]] = []

    for p in perimeters:
        reason = _perimeter_matches(stix_type, stix_object, p)
        if reason:
            matched_perimeters.append({"perimeter": p, "reason": reason})

    if not matched_perimeters:
        return 0

    async with get_session() as session:
        for m in matched_perimeters:
            p = m["perimeter"]
            await session.execute(
                text("""
                    INSERT INTO alerts
                        (perimeter_id, stix_object_id, source_url, severity)
                    VALUES
                        (CAST(:perimeter_id AS uuid),
                         CAST(:stix_object_id AS uuid),
                         :source_url,
                         :severity)
                    ON CONFLICT DO NOTHING
                """),
                {
                    "perimeter_id": p["id"],
                    "stix_object_id": stix_object_id,
                    "source_url": source_url,
                    "severity": p["severity"],
                },
            )
            matches += 1
            log.info(
                "alert_created",
                perimeter=p["name"],
                stix_type=stix_type,
                stix_id=stix_object.get("id"),
                reason=m["reason"],
                severity=p["severity"],
            )
        await session.commit()

    return matches


# ── Dispatch ──────────────────────────────────────────────────

def _perimeter_matches(
    stix_type: str,
    stix_obj: dict[str, Any],
    perimeter: Any,
) -> str | None:
    """
    Return a reason string if the perimeter matches, None otherwise.
    The reason is used for logging only.
    """
    if stix_type == "indicator":
        return _match_indicator(stix_obj, perimeter)
    if stix_type == "threat-actor":
        return _match_threat_actor(stix_obj, perimeter)
    if stix_type == "attack-pattern":
        return _match_attack_pattern(stix_obj, perimeter)
    return None


# ── Per-type matching ─────────────────────────────────────────

def _match_indicator(stix_obj: dict[str, Any], p: Any) -> str | None:
    pattern = stix_obj.get("pattern", "")
    ioc_value = extract_ioc_value(pattern)

    # 1. Exact IoC value match
    if ioc_value and ioc_value in (p["ioc_values"] or []):
        return f"ioc_value:{ioc_value}"

    # 2. CIDR containment for IP indicators
    if ioc_value and p["ip_ranges"]:
        ioc_type = _extract_pattern_type(pattern)
        if ioc_type in ("ipv4-addr", "ipv6-addr") and ip_in_ranges(ioc_value, p["ip_ranges"]):
            return f"ip_range:{ioc_value}"

    return None


def _match_threat_actor(stix_obj: dict[str, Any], p: Any) -> str | None:
    # Build a searchable text corpus from all relevant fields
    corpus = _build_corpus(
        stix_obj.get("name", ""),
        *stix_obj.get("aliases", []),
        stix_obj.get("description", ""),
        *stix_obj.get("threat_actor_types", []),
        # LLM may inject a custom sectors list directly on the object
        *stix_obj.get("sectors", []),
    )

    if p["sectors"] and keywords_match(p["sectors"], corpus):
        return "sector"
    if p["geo_countries"] and keywords_match(p["geo_countries"], corpus):
        return "geo_country"
    return None


def _match_attack_pattern(stix_obj: dict[str, Any], p: Any) -> str | None:
    corpus = _build_corpus(
        stix_obj.get("name", ""),
        stix_obj.get("description", ""),
        stix_obj.get("x_mitre_tactic", ""),
        # x_mitre_platforms is a list of platform names (Windows, Linux…)
        *stix_obj.get("x_mitre_platforms", []),
    )

    if p["sectors"] and keywords_match(p["sectors"], corpus):
        return "sector"
    if p["software_products"] and keywords_match(p["software_products"], corpus):
        return "software_product"
    return None


# ── Helper functions (also exported for testing) ──────────────

def extract_ioc_value(pattern: str) -> str | None:
    """Extract the IoC value from a STIX pattern string (first quoted value)."""
    m = _PATTERN_VALUE_RE.search(pattern)
    return m.group(1) if m else None


def _extract_pattern_type(pattern: str) -> str:
    """Extract the STIX object type from a pattern (e.g. 'ipv4-addr')."""
    m = _PATTERN_TYPE_RE.search(pattern)
    return m.group(1) if m else ""


def ip_in_ranges(ip_str: str, ranges: list[str]) -> bool:
    """Return True if ip_str falls within any CIDR range in ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for cidr in ranges:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def keywords_match(keywords: list[str], corpus: str) -> bool:
    """
    Return True if any keyword appears as a case-insensitive substring in corpus.
    Empty keywords list → False (no criteria = no match).
    """
    if not keywords:
        return False
    corpus_lower = corpus.lower()
    return any(kw.lower() in corpus_lower for kw in keywords if kw.strip())


def _build_corpus(*parts: str) -> str:
    """Concatenate text parts into a single searchable string."""
    return " ".join(p for p in parts if p)
