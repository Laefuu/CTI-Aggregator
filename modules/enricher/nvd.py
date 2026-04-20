"""NVD (National Vulnerability Database) enricher for CVE indicators.

Queries the NVD REST API 2.0 to retrieve CVSS scores for CVE identifiers.
Free API — no key required (rate-limited to 5 requests/30 seconds without key).
"""
from __future__ import annotations

import re
from typing import Any

import httpx
import structlog

log = structlog.get_logger()

_CVE_RE = re.compile(r"CVE-\d{4}-\d+")
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def enrich_cve(cve_id: str) -> dict[str, Any] | None:
    """
    Query NVD for a CVE and return CVSS score info.

    Returns dict with: cve_id, cvss_score, cvss_severity, cvss_vector, source
    or None if not found / error.
    """
    if not _CVE_RE.fullmatch(cve_id):
        return None

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                _NVD_BASE,
                params={"cveId": cve_id},
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        log.warning("nvd_timeout", cve_id=cve_id)
        return None
    except httpx.HTTPStatusError as exc:
        log.warning("nvd_http_error", cve_id=cve_id, status=exc.response.status_code)
        return None
    except Exception as exc:
        log.warning("nvd_unexpected_error", cve_id=cve_id, error=str(exc))
        return None

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    cve_item = vulnerabilities[0].get("cve", {})
    metrics = cve_item.get("metrics", {})

    # Try CVSS 3.1 first, then 3.0, then 2.0
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None

    for version_key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")
            break

    if cvss_score is None:
        metric_list = metrics.get("cvssMetricV2", [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = metric_list[0].get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")

    if cvss_score is None:
        return {"cve_id": cve_id, "found": True, "cvss_score": None, "cvss_severity": None}

    return {
        "cve_id": cve_id,
        "found": True,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "source": "nvd",
    }
