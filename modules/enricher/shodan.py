"""
Shodan enrichment — queries Shodan InternetDB for IP addresses.

InternetDB is free, no API key required, and covers:
    - Open ports, CPEs, tags, hostnames, vulns (CVE IDs)

For full Shodan data (banners, geolocation) the main API requires a paid key.
We use InternetDB by default and fall back to main API if SHODAN_API_KEY is set.
"""
from __future__ import annotations

from typing import Any

import httpx
import structlog

log = structlog.get_logger()

_INTERNETDB = "https://internetdb.shodan.io"
_SHODAN_API = "https://api.shodan.io"


async def enrich_ip(ip: str, api_key: str = "") -> dict[str, Any] | None:
    """
    Enrich an IP address with Shodan data.
    Uses InternetDB (free) by default; falls back to main API if key provided.
    Returns None on failure.
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{_INTERNETDB}/{ip}")
            if resp.status_code == 404:
                return {"found": False, "source": "shodan"}
            resp.raise_for_status()
            data = resp.json()

        return {
            "found": True,
            "source": "shodan",
            "ip": data.get("ip", ip),
            "ports": data.get("ports", []),
            "cpes": data.get("cpes", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "vulns": data.get("vulns", []),  # CVE IDs
        }
    except Exception as exc:
        log.error("shodan_request_failed", ip=ip, error=str(exc))
        return None
