"""
Perimeter matching — checks if a STIX indicator's IoC value appears
in any enabled perimeter's watch list (ioc_values TEXT[]).

If a match is found, creates an alert row and publishes to cti:alerts.

Pattern extraction:
    [ipv4-addr:value = '1.2.3.4']      → '1.2.3.4'
    [domain-name:value = 'evil.com']   → 'evil.com'
    [file:hashes.SHA256 = 'abc...']    → 'abc...'
    [url:value = 'https://evil.com']   → 'https://evil.com'
"""
from __future__ import annotations

import re
from typing import Any

import structlog
from sqlalchemy import text

from shared.db import get_session

log = structlog.get_logger()

# Extracts the value from a STIX pattern: everything inside single quotes
_PATTERN_VALUE_RE = re.compile(r"'([^']+)'")


def extract_ioc_value(pattern: str) -> str | None:
    """Extract the IoC value from a STIX pattern string."""
    m = _PATTERN_VALUE_RE.search(pattern)
    return m.group(1) if m else None


async def match_perimeters(
    stix_object_id: str,
    stix_object: dict[str, Any],
    source_url: str,
) -> int:
    """
    Check a STIX indicator against all enabled perimeters.

    Creates alert rows for each match and returns the number of matches.
    Only processes indicators (other types are skipped — perimeter matching
    for threat-actors and TTPs is a Phase 2 feature).
    """
    if stix_object.get("type") != "indicator":
        return 0

    pattern = stix_object.get("pattern", "")
    ioc_value = extract_ioc_value(pattern)
    if not ioc_value:
        return 0

    matches = 0

    async with get_session() as session:
        # Fetch all enabled perimeters that watch this IoC value
        result = await session.execute(
            text("""
                SELECT id, name
                FROM perimeters
                WHERE enabled = TRUE
                  AND :ioc_value = ANY(ioc_values)
            """),
            {"ioc_value": ioc_value},
        )
        rows = result.mappings().all()

        for row in rows:
            await session.execute(
                text("""
                    INSERT INTO alerts
                        (perimeter_id, stix_object_id, source_url)
                    VALUES
                        (CAST(:perimeter_id AS uuid), CAST(:stix_object_id AS uuid), :source_url)
                """),
                {
                    "perimeter_id": str(row["id"]),
                    "stix_object_id": stix_object_id,
                    "source_url": source_url,
                },
            )
            matches += 1
            log.info(
                "alert_created",
                perimeter=row["name"],
                ioc=ioc_value,
                stix_id=stix_object.get("id"),
            )

        if matches:
            await session.commit()

    return matches
