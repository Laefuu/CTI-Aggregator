"""GET /metrics — pipeline observability for dashboard."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from modules.api.deps import get_current_user, get_db

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
