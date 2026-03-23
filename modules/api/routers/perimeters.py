"""CRUD /perimeters and GET/PATCH /alerts."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from modules.api.deps import get_current_user, get_db
from modules.api.schemas.perimeter import (
    AlertAck, AlertResponse, PerimeterCreate, PerimeterResponse, PerimeterUpdate,
)

router = APIRouter(tags=["perimeters"])

_PERI_SELECT = """
    SELECT id::text, name, description, ioc_values, sectors,
           enabled, webhook_url, created_at, updated_at
    FROM perimeters
"""

_ALERT_SELECT = """
    SELECT a.id::text, a.perimeter_id::text,
           p.name AS perimeter_name,
           a.stix_object_id::text, so.stix_id,
           a.source_url, a.triggered_at, a.status,
           a.notified, a.acked_by, a.acked_at
    FROM alerts a
    JOIN perimeters p ON p.id = a.perimeter_id
    JOIN stix_objects so ON so.id = a.stix_object_id
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
                (name, description, ioc_values, sectors, enabled, webhook_url)
            VALUES (:name, :description, :ioc_values, :sectors, :enabled, :webhook_url)
            RETURNING id::text, name, description, ioc_values, sectors,
                      enabled, webhook_url, created_at, updated_at
        """),
        {
            "name": body.name, "description": body.description,
            "ioc_values": body.ioc_values, "sectors": body.sectors,
            "enabled": body.enabled, "webhook_url": body.webhook_url,
        },
    )
    await db.commit()
    return PerimeterResponse(**dict(result.mappings().first()))


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
            RETURNING id::text, name, description, ioc_values, sectors,
                      enabled, webhook_url, created_at, updated_at
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
        text("DELETE FROM perimeters WHERE id = CAST(:id AS uuid) RETURNING id"), {"id": perimeter_id}
    )
    await db.commit()
    if not result.first():
        raise HTTPException(status_code=404, detail="Perimeter not found")


@router.get("/alerts", response_model=list[AlertResponse])
async def list_alerts(
    status: str | None = Query(default=None, pattern="^(new|acked|false_positive)$"),
    perimeter_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> list[AlertResponse]:
    conditions = ["1=1"]
    params: dict = {"limit": limit}
    if status:
        conditions.append("a.status = :status")
        params["status"] = status
    if perimeter_id:
        conditions.append("a.perimeter_id = CAST(:perimeter_id AS uuid)")
        params["perimeter_id"] = perimeter_id

    result = await db.execute(
        text(f"{_ALERT_SELECT} WHERE {' AND '.join(conditions)} ORDER BY a.triggered_at DESC LIMIT :limit"),
        params,
    )
    return [AlertResponse(**dict(r)) for r in result.mappings().all()]


@router.patch("/alerts/{alert_id}", response_model=AlertResponse)
async def ack_alert(
    alert_id: str,
    body: AlertAck,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AlertResponse:
    await db.execute(
        text("""
            UPDATE alerts SET status = :status, acked_by = :email, acked_at = NOW()
            WHERE id = CAST(:id AS uuid)
        """),
        {"id": alert_id, "status": body.status, "email": current_user.get("email")},
    )
    await db.commit()
    result = await db.execute(
        text(f"{_ALERT_SELECT} WHERE a.id = CAST(:id AS uuid)"), {"id": alert_id}
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertResponse(**dict(row))
