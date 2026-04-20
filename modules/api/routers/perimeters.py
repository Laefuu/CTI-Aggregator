"""CRUD /perimeters and GET/PATCH /alerts."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from modules.api.deps import get_current_user, get_db
from modules.api.schemas.perimeter import (
    AlertAck, AlertResponse, PerimeterCreate, PerimeterResponse, PerimeterUpdate,
)

router = APIRouter(tags=["perimeters"])

_PERI_COLS = """
    id::text, name, description,
    ioc_values, sectors, geo_countries, software_products, ip_ranges,
    severity, enabled, webhook_url, created_at, updated_at
"""

_PERI_SELECT = f"SELECT {_PERI_COLS} FROM perimeters"

_ALERT_SELECT = """
    SELECT a.id::text, a.perimeter_id::text,
           p.name AS perimeter_name,
           a.stix_object_id::text, so.stix_id,
           a.source_url, a.triggered_at, a.status, a.severity,
           a.notified, a.acked_by, a.acked_at
    FROM alerts a
    JOIN perimeters p ON p.id = a.perimeter_id
    JOIN stix_objects so ON so.id = a.stix_object_id
"""

# Severity sort expression — critical first, then high, medium, low
_SEVERITY_ORDER = """
    CASE a.severity
        WHEN 'critical' THEN 1
        WHEN 'high'     THEN 2
        WHEN 'medium'   THEN 3
        WHEN 'low'      THEN 4
    END
"""


@router.get("/perimeters", response_model=list[PerimeterResponse])
async def list_perimeters(
    db: AsyncSession = Depends(get_db), _: dict = Depends(get_current_user)
) -> list[PerimeterResponse]:
    result = await db.execute(text(f"{_PERI_SELECT} ORDER BY name"))
    return [PerimeterResponse(**dict(r)) for r in result.mappings().all()]


@router.post("/perimeters", response_model=PerimeterResponse, status_code=201)
async def create_perimeter(
    body: PerimeterCreate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> PerimeterResponse:
    result = await db.execute(
        text(f"""
            INSERT INTO perimeters
                (name, description, ioc_values, sectors, geo_countries,
                 software_products, ip_ranges, severity, enabled, webhook_url)
            VALUES
                (:name, :description, :ioc_values, :sectors, :geo_countries,
                 :software_products, :ip_ranges, :severity, :enabled, :webhook_url)
            RETURNING {_PERI_COLS}
        """),
        {
            "name": body.name,
            "description": body.description,
            "ioc_values": body.ioc_values,
            "sectors": body.sectors,
            "geo_countries": body.geo_countries,
            "software_products": body.software_products,
            "ip_ranges": body.ip_ranges,
            "severity": body.severity,
            "enabled": body.enabled,
            "webhook_url": body.webhook_url,
        },
    )
    await db.commit()
    return PerimeterResponse(**dict(result.mappings().first()))  # type: ignore[arg-type]


@router.get("/perimeters/{perimeter_id}", response_model=PerimeterResponse)
async def get_perimeter(
    perimeter_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> PerimeterResponse:
    result = await db.execute(
        text(f"{_PERI_SELECT} WHERE id = CAST(:id AS uuid)"), {"id": perimeter_id}
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Perimeter not found")
    return PerimeterResponse(**dict(row))


@router.patch("/perimeters/{perimeter_id}", response_model=PerimeterResponse)
async def update_perimeter(
    perimeter_id: str,
    body: PerimeterUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> PerimeterResponse:
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")
    set_parts = [f"{k} = :{k}" for k in updates]
    result = await db.execute(
        text(f"""
            UPDATE perimeters SET {", ".join(set_parts)}
            WHERE id = CAST(:id AS uuid)
            RETURNING {_PERI_COLS}
        """),
        {**updates, "id": perimeter_id},
    )
    await db.commit()
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Perimeter not found")
    return PerimeterResponse(**dict(row))


@router.delete("/perimeters/{perimeter_id}", status_code=204)
async def delete_perimeter(
    perimeter_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> None:
    result = await db.execute(
        text("DELETE FROM perimeters WHERE id = CAST(:id AS uuid) RETURNING id"),
        {"id": perimeter_id},
    )
    await db.commit()
    if not result.first():
        raise HTTPException(status_code=404, detail="Perimeter not found")


@router.get("/alerts", response_model=list[AlertResponse])
async def list_alerts(
    status: str | None = Query(default=None, pattern="^(new|acked|false_positive)$"),
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical)$"),
    perimeter_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> list[AlertResponse]:
    conditions = ["1=1"]
    params: dict[str, Any] = {"limit": limit}

    if status:
        conditions.append("a.status = :status")
        params["status"] = status
    if severity:
        conditions.append("a.severity = :severity")
        params["severity"] = severity
    if perimeter_id:
        conditions.append("a.perimeter_id = CAST(:perimeter_id AS uuid)")
        params["perimeter_id"] = perimeter_id

    result = await db.execute(
        text(f"""
            {_ALERT_SELECT}
            WHERE {" AND ".join(conditions)}
            ORDER BY {_SEVERITY_ORDER}, a.triggered_at DESC
            LIMIT :limit
        """),
        params,
    )
    return [AlertResponse(**dict(r)) for r in result.mappings().all()]


@router.patch("/alerts/{alert_id}", response_model=AlertResponse)
async def patch_alert(
    alert_id: str,
    body: AlertAck,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AlertResponse:
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    set_parts: list[str] = []
    params: dict[str, Any] = {"id": alert_id}

    if "status" in updates:
        set_parts.append("status = :status")
        params["status"] = updates["status"]
        # Record who acknowledged
        set_parts.append("acked_by = :email")
        set_parts.append("acked_at = NOW()")
        params["email"] = current_user.get("email")
    if "severity" in updates:
        set_parts.append("severity = :severity")
        params["severity"] = updates["severity"]

    await db.execute(
        text(f"UPDATE alerts SET {', '.join(set_parts)} WHERE id = CAST(:id AS uuid)"),
        params,
    )
    await db.commit()

    result = await db.execute(
        text(f"{_ALERT_SELECT} WHERE a.id = CAST(:id AS uuid)"), {"id": alert_id}
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertResponse(**dict(row))
