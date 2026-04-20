"""GET /metrics — pipeline observability for dashboard."""
from __future__ import annotations

from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from modules.api.deps import get_current_user, get_db
from shared.config import get_settings

router = APIRouter(prefix="/metrics", tags=["metrics"])


class MetricPoint(BaseModel):
    recorded_at: datetime
    module: str
    metric: str
    value: float
    labels: dict


class PipelineSummary(BaseModel):
    total_objects: int
    objects_last_24h: int
    active_sources: int
    alerts_new: int
    top_stix_types: list[dict]


@router.get("/summary", response_model=PipelineSummary)
async def get_summary(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> PipelineSummary:
    row = dict((await db.execute(text("""
        SELECT
            (SELECT COUNT(*) FROM stix_objects WHERE is_merged = FALSE)        AS total_objects,
            (SELECT COUNT(*) FROM stix_objects
             WHERE is_merged = FALSE AND created_at > NOW() - INTERVAL '24h') AS objects_last_24h,
            (SELECT COUNT(*) FROM sources WHERE enabled = TRUE)                AS active_sources,
            (SELECT COUNT(*) FROM alerts WHERE status = 'new')                 AS alerts_new
    """))).mappings().first())

    types = [dict(r) for r in (await db.execute(text("""
        SELECT stix_type, COUNT(*) AS count
        FROM stix_objects WHERE is_merged = FALSE
        GROUP BY stix_type ORDER BY count DESC
    """))).mappings().all()]

    return PipelineSummary(
        total_objects=int(row["total_objects"]),
        objects_last_24h=int(row["objects_last_24h"]),
        active_sources=int(row["active_sources"]),
        alerts_new=int(row["alerts_new"]),
        top_stix_types=types,
    )


class IncidentCounts(BaseModel):
    new: int | None
    acknowledged: int | None
    resolved: int | None
    source: str  # "grafana" | "unavailable"


@router.get("/incidents", response_model=IncidentCounts)
async def get_incident_counts(
    _: dict = Depends(get_current_user),
) -> IncidentCounts:
    """
    Proxy to Grafana Alertmanager API for incident counts.
    Returns None values when Grafana is not configured or unreachable.
    """
    settings = get_settings()
    if not settings.grafana_url or not settings.grafana_api_key:
        return IncidentCounts(new=None, acknowledged=None, resolved=None, source="unavailable")

    url = settings.grafana_url.rstrip("/") + "/api/alertmanager/grafana/api/v2/alerts"
    headers = {"Authorization": f"Bearer {settings.grafana_api_key}"}

    try:
        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return IncidentCounts(new=None, acknowledged=None, resolved=None, source="unavailable")

        alerts = resp.json()
        counts: dict[str, int] = {"new": 0, "acknowledged": 0, "resolved": 0}
        for alert in alerts:
            state = (alert.get("status", {}).get("state") or "").lower()
            if state == "active":
                counts["new"] += 1
            elif state == "suppressed":
                counts["acknowledged"] += 1
            elif state == "unprocessed":
                counts["resolved"] += 1
        return IncidentCounts(
            new=counts["new"],
            acknowledged=counts["acknowledged"],
            resolved=counts["resolved"],
            source="grafana",
        )
    except Exception:
        return IncidentCounts(new=None, acknowledged=None, resolved=None, source="unavailable")


@router.get("/top-threats", response_model=list[dict])
async def get_top_threats(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> list[dict]:
    """Top 6 threat-actors by confidence, with alert count."""
    rows = (await db.execute(text("""
        SELECT
            so.stix_id,
            so.stix_data->>'name'            AS name,
            so.confidence,
            so.modified_at,
            COUNT(a.id)                      AS alert_count
        FROM stix_objects so
        LEFT JOIN alerts a ON a.stix_object_id = so.id AND a.status = 'new'
        WHERE so.stix_type = 'threat-actor' AND so.is_merged = FALSE
        GROUP BY so.id
        ORDER BY so.confidence DESC, alert_count DESC
        LIMIT 6
    """))).mappings().all()
    return [dict(r) for r in rows]


@router.get("/recent-cves", response_model=list[dict])
async def get_recent_cves(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> list[dict]:
    """Last 10 CVE objects — indicators whose name matches CVE-YYYY-NNNNN."""
    rows = (await db.execute(text("""
        SELECT
            so.stix_id,
            (regexp_match(so.stix_data->>'name', 'CVE-[0-9]{4}-[0-9]+'))[1] AS cve_id,
            so.stix_data->>'description'      AS description,
            so.stix_data->>'x_cti_source_url' AS source_url,
            so.confidence,
            so.created_at,
            (so.stix_data #>> '{x_cti_enrichment,nvd,cvss_score}')::float AS cvss_score,
            so.stix_data #>> '{x_cti_enrichment,nvd,cvss_severity}' AS cvss_severity
        FROM stix_objects so
        WHERE so.is_merged = FALSE
          AND so.stix_data->>'name' ~ 'CVE-[0-9]{4}-[0-9]+'
        ORDER BY so.created_at DESC
        LIMIT 10
    """))).mappings().all()
    return [dict(r) for r in rows]


@router.get("", response_model=list[MetricPoint])
async def get_metrics(
    module: str | None = Query(default=None),
    metric: str | None = Query(default=None),
    hours: int = Query(default=24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> list[MetricPoint]:
    conditions = ["recorded_at > NOW() - INTERVAL '1 hour' * :hours"]
    params: dict = {"hours": hours, "limit": 1000}
    if module:
        conditions.append("module = :module")
        params["module"] = module
    if metric:
        conditions.append("metric = :metric")
        params["metric"] = metric

    result = await db.execute(
        text(f"""
            SELECT recorded_at, module, metric, value, labels
            FROM pipeline_metrics
            WHERE {" AND ".join(conditions)}
            ORDER BY recorded_at DESC LIMIT :limit
        """),
        params,
    )
    return [MetricPoint(**dict(r)) for r in result.mappings().all()]
