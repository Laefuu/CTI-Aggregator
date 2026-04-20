"""GET /objects — paginated STIX object listing with filters.
POST /objects/{stix_id}/enrich — trigger async enrichment via cti:enrichment stream.
"""
from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from modules.api.deps import get_current_user, get_db
from modules.api.schemas.object import StixObjectListResponse, StixObjectResponse
from shared.models.messages import EnrichmentRequest
from shared.queue import STREAM_ENRICHMENT, publish

router = APIRouter(prefix="/objects", tags=["objects"])

_OBJECT_SELECT = """
    SELECT so.id::text, so.stix_id, so.stix_type, so.stix_data,
           so.confidence, so.tlp_level, so.is_merged, so.merged_into,
           so.created_at, so.modified_at,
           COUNT(os.id) AS source_count
    FROM stix_objects so
    LEFT JOIN object_sources os ON os.stix_object_id = so.id
"""


@router.get("", response_model=StixObjectListResponse)
async def list_objects(
    stix_type: str | None = Query(default=None),
    tlp_level: str | None = Query(default=None),
    min_confidence: int | None = Query(default=None, ge=0, le=100),
    is_merged: bool = Query(default=False),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> StixObjectListResponse:
    conditions = ["1=1"]
    params: dict[str, Any] = {"limit": page_size, "offset": (page - 1) * page_size}

    if not is_merged:
        conditions.append("so.is_merged = FALSE")
    if stix_type:
        conditions.append("so.stix_type = :stix_type")
        params["stix_type"] = stix_type
    if tlp_level:
        conditions.append("so.tlp_level = :tlp_level")
        params["tlp_level"] = tlp_level
    if min_confidence is not None:
        conditions.append("so.confidence >= :min_confidence")
        params["min_confidence"] = min_confidence
    if search:
        conditions.append("so.stix_data::text ILIKE :search")
        params["search"] = f"%{search}%"

    where = " AND ".join(conditions)

    total = (await db.execute(
        text(f"SELECT COUNT(*) FROM stix_objects so WHERE {where}"), params
    )).scalar() or 0

    result = await db.execute(
        text(f"""
            {_OBJECT_SELECT}
            WHERE {where}
            GROUP BY so.id
            ORDER BY so.confidence DESC, so.created_at DESC
            LIMIT :limit OFFSET :offset
        """),
        params,
    )
    items = [StixObjectResponse(**dict(r)) for r in result.mappings().all()]
    return StixObjectListResponse(items=items, total=int(total), page=page, page_size=page_size)


@router.get("/{stix_id}", response_model=StixObjectResponse)
async def get_object(
    stix_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> StixObjectResponse:
    result = await db.execute(
        text(f"""
            {_OBJECT_SELECT}
            WHERE so.stix_id = :stix_id
            GROUP BY so.id
        """),
        {"stix_id": stix_id},
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Object not found")
    return StixObjectResponse(**dict(row))


@router.post("/{stix_id}/enrich", status_code=202)
async def enrich_object(
    stix_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> Response:
    """
    Trigger asynchronous enrichment for a STIX object.

    Publishes an EnrichmentRequest to cti:enrichment and returns 202 Accepted.
    The Enricher module will pick it up and write results into stix_data.x_cti_enrichment.
    """
    result = await db.execute(
        text("SELECT stix_id, stix_type, stix_data FROM stix_objects WHERE stix_id = :stix_id"),
        {"stix_id": stix_id},
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Object not found")

    ioc_type, ioc_value = _extract_ioc(row["stix_type"], row["stix_data"])

    req = EnrichmentRequest(
        stix_id=stix_id,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        requested_by=current_user.get("email", "analyst"),
    )
    await publish(STREAM_ENRICHMENT, req.model_dump())

    import json
    return Response(
        content=json.dumps({"status": "queued", "stix_id": stix_id}),
        status_code=202,
        media_type="application/json",
    )


# ── Helpers ───────────────────────────────────────────────────

_PATTERN_RE = re.compile(
    r"\[\s*([\w-]+):[^\s=]+\s*=\s*['\"]([^'\"]+)['\"]\s*\]"
)


def _extract_ioc(stix_type: str, stix_data: dict[str, Any]) -> tuple[str, str]:
    """
    Extract (ioc_type, ioc_value) from a STIX object for the enrichment request.

    For indicators: parse the STIX pattern (e.g. [ipv4-addr:value = '1.2.3.4']).
    For other types: use stix_type + name field.
    """
    if stix_type == "indicator":
        pattern = stix_data.get("pattern", "")
        m = _PATTERN_RE.search(pattern)
        if m:
            return m.group(1), m.group(2)

    name = stix_data.get("name", stix_data.get("value", "unknown"))
    return stix_type, str(name)
