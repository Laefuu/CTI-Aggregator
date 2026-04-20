"""CRUD /sources — manage collection sources.
POST /sources/upload — ingest a PDF/TXT/HTML file directly into the pipeline.
"""
from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from modules.api.deps import get_current_user, get_db
from modules.api.schemas.source import SourceCreate, SourceResponse, SourceUpdate
from shared.config import get_settings
from shared.models.messages import RawMessage
from shared.queue import CHANNEL_SOURCES_UPDATED, STREAM_RAW, publish, publish_event

log = structlog.get_logger()

router = APIRouter(prefix="/sources", tags=["sources"])

_SELECT = """
    SELECT id::text, name, type, url, config, frequency_min,
           category, tlp_level, enabled,
           last_run_at, last_status, last_error,
           created_at, updated_at
    FROM sources
"""

_ALLOWED_SUFFIXES: dict[str, str] = {
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".html": "text/html",
    ".htm": "text/html",
}


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
    await publish_event(CHANNEL_SOURCES_UPDATED)
    return SourceResponse(**dict(result.mappings().first()))  # type: ignore[arg-type]


@router.post("/upload", response_model=SourceResponse, status_code=status.HTTP_201_CREATED)
async def upload_source(
    file: UploadFile = File(...),
    name: str = Form(..., min_length=1, max_length=200),
    category: str = Form(default="unknown", pattern="^(trusted|known|unknown)$"),
    tlp_level: str = Form(default="WHITE", pattern="^(WHITE|GREEN)$"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> SourceResponse:
    """
    Upload a file (PDF, TXT, HTML) as a CTI source.

    - Saves to /data/uploads/{uuid}.{ext}
    - Creates a source row with type=pdf_upload
    - Immediately publishes a RawMessage to cti:raw to trigger the pipeline
    """
    settings = get_settings()

    # ── Validate file extension ───────────────────────────────
    original_name = file.filename or ""
    suffix = Path(original_name).suffix.lower()
    if suffix not in _ALLOWED_SUFFIXES:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported file type {suffix!r}. Allowed: {', '.join(_ALLOWED_SUFFIXES)}",
        )
    content_type = _ALLOWED_SUFFIXES[suffix]

    # ── Read and size-check ───────────────────────────────────
    max_bytes = settings.max_pdf_size_mb * 1024 * 1024
    content = await file.read()
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Limit: {settings.max_pdf_size_mb} MB",
        )

    # ── Save to upload directory ──────────────────────────────
    upload_dir = Path(settings.upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)

    file_id = str(uuid.uuid4())
    dest = upload_dir / f"{file_id}{suffix}"
    dest.write_bytes(content)

    file_url = f"file://{dest}"

    # ── Create source row ─────────────────────────────────────
    result = await db.execute(
        text(f"""
            INSERT INTO sources
                (name, type, url, config, frequency_min, category, tlp_level, enabled)
            VALUES
                (:name, 'pdf_upload', :url, CAST(:config AS jsonb),
                 525600, :category, :tlp_level, TRUE)
            RETURNING id::text, name, type, url, config, frequency_min,
                      category, tlp_level, enabled,
                      last_run_at, last_status, last_error, created_at, updated_at
        """),
        {
            "name": name,
            "url": file_url,
            "config": json.dumps({"original_filename": original_name}),
            "category": category,
            "tlp_level": tlp_level,
        },
    )
    await db.commit()
    row = result.mappings().first()
    source = SourceResponse(**dict(row))  # type: ignore[arg-type]

    # ── Publish immediately to cti:raw ────────────────────────
    fetched_at = datetime.now(UTC)
    raw_msg = RawMessage(
        source_id=uuid.UUID(source.id),
        source_url=file_url,
        source_type="pdf_upload",  # type: ignore[arg-type]
        content_b64=base64.b64encode(content).decode("ascii"),
        content_type=content_type,
        fetched_at=fetched_at,
        tlp_level=tlp_level,  # type: ignore[arg-type]
        metadata={"original_filename": original_name, "content_size": len(content)},
    )
    await publish(STREAM_RAW, raw_msg.model_dump())
    await publish_event(CHANNEL_SOURCES_UPDATED)

    log.info(
        "source_file_uploaded",
        source_id=source.id,
        filename=original_name,
        size=len(content),
        path=str(dest),
    )

    return source


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
    await publish_event(CHANNEL_SOURCES_UPDATED)
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
    await publish_event(CHANNEL_SOURCES_UPDATED)
