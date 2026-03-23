"""
VirusTotal enrichment — queries VT API v3 for IP, domain, and file hash IoCs.

Rate limit: 4 requests/min on free tier. The enricher does not throttle —
callers must respect rate limits at the queue level.
"""
from __future__ import annotations

from typing import Any

import httpx
import structlog

log = structlog.get_logger()

_VT_BASE = "https://www.virustotal.com/api/v3"

_IOC_ENDPOINTS: dict[str, str] = {
    "ipv4-addr": "ip_addresses",
    "ipv6-addr": "ip_addresses",
    "domain-name": "domains",
    "file": "files",
}


class VirusTotalClient:
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "VirusTotalClient":
        self._client = httpx.AsyncClient(
            base_url=_VT_BASE,
            headers={"x-apikey": self._api_key},
            timeout=30.0,
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def enrich(self, ioc_type: str, ioc_value: str) -> dict[str, Any] | None:
        """
        Query VirusTotal for an IoC.
        Returns a normalized enrichment dict, or None on failure.
        """
        assert self._client is not None
        endpoint = _IOC_ENDPOINTS.get(ioc_type)
        if not endpoint:
            log.debug("vt_unsupported_ioc_type", ioc_type=ioc_type)
            return None

        try:
            resp = await self._client.get(f"/{endpoint}/{ioc_value}")
            if resp.status_code == 404:
                return {"found": False, "source": "virustotal"}
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            return _normalize(ioc_type, data)
        except Exception as exc:
            log.error("vt_request_failed", ioc_type=ioc_type, ioc_value=ioc_value, error=str(exc))
            return None


def _normalize(ioc_type: str, attrs: dict) -> dict[str, Any]:
    """Extract the key fields from the VT attributes blob."""
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0

    result: dict[str, Any] = {
        "found": True,
        "source": "virustotal",
        "malicious_count": malicious,
        "total_engines": total,
        "reputation": attrs.get("reputation", 0),
    }

    if ioc_type in ("ipv4-addr", "ipv6-addr"):
        result["country"] = attrs.get("country", "")
        result["asn"] = attrs.get("asn", "")
        result["as_owner"] = attrs.get("as_owner", "")
        result["network"] = attrs.get("network", "")

    elif ioc_type == "domain-name":
        result["registrar"] = attrs.get("registrar", "")
        result["creation_date"] = attrs.get("creation_date", "")
        result["categories"] = attrs.get("categories", {})

    elif ioc_type == "file":
        result["type_description"] = attrs.get("type_description", "")
        result["meaningful_name"] = attrs.get("meaningful_name", "")
        result["size"] = attrs.get("size", 0)

    return result
