"""CRUD /sources — manage collection sources."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from modules.api.deps import get_current_user, get_db
from modules.api.schemas.source import SourceCreate, SourceResponse, SourceUpdate

router = APIRouter(prefix="/sources", tags=["sources"])

_SELECT = """
    SELECT id::text, name, type, url, config, frequency_min,
           category, tlp_level, enabled,
           last_run_at, last_status, last_error,
           created_at, updated_at
    FROM sources
"""


@router.get("", response_model=list[SourceResponse])
async def list_sources(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> list[SourceResponse]:
    result = await db.execute(text(f"{_SELECT} ORDER BY name"))
    return [SourceResponse(**dict(r)) for r in result.mappings().all()]


@router.post("", response_model=SourceResponse, status_code=status.HTTP_201_CREATED)
async def create_source(
    body: SourceCreate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> SourceResponse:
    result = await db.execute(
        text(f"""
            INSERT INTO sources
                (name, type, url, config, frequency_min, category, tlp_level, enabled)
            VALUES
                (:name, :type, :url, CAST(:config AS jsonb), :frequency_min,
                 :category, :tlp_level, :enabled)
            RETURNING id::text, name, type, url, config, frequency_min,
                      category, tlp_level, enabled,
                      last_run_at, last_status, last_error, created_at, updated_at
        """),
        {
            "name": body.name, "type": body.type, "url": body.url,
            "config": json.dumps(body.config), "frequency_min": body.frequency_min,
            "category": body.category, "tlp_level": body.tlp_level, "enabled": body.enabled,
        },
    )
    await db.commit()
    return SourceResponse(**dict(result.mappings().first()))


@router.get("/{source_id}", response_model=SourceResponse)
async def get_source(
    source_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> SourceResponse:
    result = await db.execute(
        text(f"{_SELECT} WHERE id = CAST(:id AS uuid)"), {"id": source_id}
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Source not found")
    return SourceResponse(**dict(row))


@router.patch("/{source_id}", response_model=SourceResponse)
async def update_source(
    source_id: str,
    body: SourceUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> SourceResponse:
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    set_parts = []
    params: dict[str, Any] = {"id": source_id}
    for field, value in updates.items():
        if field == "config":
            set_parts.append(f"{field} = CAST(:{field} AS jsonb)")
            params[field] = json.dumps(value)
        else:
            set_parts.append(f"{field} = :{field}")
            params[field] = value

    result = await db.execute(
        text(f"""
            UPDATE sources SET {", ".join(set_parts)}
            WHERE id = CAST(:id AS uuid)
            RETURNING id::text, name, type, url, config, frequency_min,
                      category, tlp_level, enabled,
                      last_run_at, last_status, last_error, created_at, updated_at
        """),
        params,
    )
    await db.commit()
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Source not found")
    return SourceResponse(**dict(row))


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(
    source_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> None:
    result = await db.execute(
        text("DELETE FROM sources WHERE id = CAST(:id AS uuid) RETURNING id"), {"id": source_id}
    )
    await db.commit()
    if not result.first():
        raise HTTPException(status_code=404, detail="Source not found")
