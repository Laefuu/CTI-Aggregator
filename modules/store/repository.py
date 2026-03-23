"""
Store repository — all database operations for the Store worker.

Three main operations:
    insert_object()  — new STIX object, first occurrence
    merge_object()   — duplicate found, mark as merged, add source provenance
    get_source_category() — resolve source category from sources table

All operations are async and use SQLAlchemy 2.x async sessions.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import text

from shared.db import get_session
from shared.models.messages import StixFinalMessage

log = structlog.get_logger()


async def get_source_category(source_id: str) -> str:
    """
    Resolve the category of a source from the sources table.
    Returns 'unknown' if the source is not found.
    """
    try:
        async with get_session() as session:
            result = await session.execute(
                text("SELECT category FROM sources WHERE id = CAST(:id AS uuid)"),
                {"id": source_id},
            )
            row = result.first()
            return str(row[0]) if row else "unknown"
    except Exception as exc:
        log.warning("store_source_category_lookup_failed", source_id=source_id, error=str(exc))
        return "unknown"


async def insert_object(
    msg: StixFinalMessage,
    source_category: str,
    final_confidence: int,
) -> str:
    """
    Insert a new STIX object and its provenance.

    Returns the internal UUID of the created stix_objects row.
    """
    stix_obj = msg.stix_object
    stix_id = stix_obj["id"]
    stix_type = stix_obj["type"]

    async with get_session() as session:
        # 1. Insert into stix_objects
        result = await session.execute(
            text("""
                INSERT INTO stix_objects
                    (stix_id, stix_type, stix_data, confidence, tlp_level)
                VALUES
                    (:stix_id, :stix_type, CAST(:stix_data AS jsonb), :confidence, :tlp_level)
                ON CONFLICT (stix_id) DO NOTHING
                RETURNING id
            """),
            {
                "stix_id": stix_id,
                "stix_type": stix_type,
                "stix_data": json.dumps(stix_obj),
                "confidence": final_confidence,
                "tlp_level": msg.tlp_level.value,
            },
        )
        row = result.first()
        if row is None:
            # Already exists (concurrent insert) — fetch the existing id
            result2 = await session.execute(
                text("SELECT id FROM stix_objects WHERE stix_id = :stix_id"),
                {"stix_id": stix_id},
            )
            row = result2.first()

        object_uuid = str(row[0])

        # 2. Insert provenance
        await _insert_source(
            session,
            stix_object_id=object_uuid,
            msg=msg,
            confidence_score=float(final_confidence),
        )

        # 3. Insert embedding (if present)
        if msg.embedding:
            vector_str = "[" + ",".join(f"{v:.8f}" for v in msg.embedding) + "]"
            await session.execute(
                text("""
                    INSERT INTO stix_embeddings (stix_object_id, embedding)
                    VALUES (CAST(:id AS uuid), CAST(:emb AS vector))
                    ON CONFLICT (stix_object_id) DO NOTHING
                """),
                {"id": object_uuid, "emb": vector_str},
            )

        await session.commit()
        log.info("store_inserted", stix_id=stix_id, stix_type=stix_type, confidence=final_confidence)
        return object_uuid


async def merge_object(
    msg: StixFinalMessage,
    target_stix_id: str,
    source_category: str,
) -> None:
    """
    Record a merge: mark the incoming object as duplicate, add provenance
    to the canonical target, and recalculate its confidence.
    """
    from modules.validator.confidence import compute_confidence

    stix_obj = msg.stix_object
    incoming_stix_id = stix_obj["id"]

    async with get_session() as session:
        # 1. Fetch target internal UUID and current source count
        result = await session.execute(
            text("""
                SELECT so.id, COUNT(os.id) AS source_count
                FROM stix_objects so
                LEFT JOIN object_sources os ON os.stix_object_id = so.id
                WHERE so.stix_id = :stix_id
                GROUP BY so.id
            """),
            {"stix_id": target_stix_id},
        )
        row = result.mappings().first()
        if row is None:
            log.error("store_merge_target_not_found", target_stix_id=target_stix_id)
            return

        target_uuid = str(row["id"])
        new_source_count = int(row["source_count"]) + 1

        # 2. Insert the incoming object as merged
        await session.execute(
            text("""
                INSERT INTO stix_objects
                    (stix_id, stix_type, stix_data, confidence, tlp_level, is_merged, merged_into)
                VALUES
                    (:stix_id, :stix_type, CAST(:stix_data AS jsonb), :confidence, :tlp_level, TRUE, :merged_into)
                ON CONFLICT (stix_id) DO UPDATE
                    SET is_merged = TRUE, merged_into = :merged_into
            """),
            {
                "stix_id": incoming_stix_id,
                "stix_type": stix_obj["type"],
                "stix_data": json.dumps(stix_obj),
                "confidence": msg.confidence,
                "tlp_level": msg.tlp_level.value,
                "merged_into": target_stix_id,
            },
        )

        # 3. Add provenance to the canonical target
        await _insert_source(
            session,
            stix_object_id=target_uuid,
            msg=msg,
            confidence_score=float(msg.confidence),
        )

        # 4. Recalculate confidence on the canonical object
        new_confidence = compute_confidence(
            source_category=source_category,
            published_at=msg.published_at,
            fetched_at=msg.fetched_at,
            source_count=new_source_count,
        )
        await session.execute(
            text("""
                UPDATE stix_objects
                SET confidence = :confidence
                WHERE id = CAST(:id AS uuid)
            """),
            {"confidence": new_confidence, "id": target_uuid},
        )

        await session.commit()
        log.info(
            "store_merged",
            incoming=incoming_stix_id,
            target=target_stix_id,
            source_count=new_source_count,
            new_confidence=new_confidence,
        )


async def _insert_source(
    session: Any,
    stix_object_id: str,
    msg: StixFinalMessage,
    confidence_score: float,
) -> None:
    """Insert a row into object_sources."""
    await session.execute(
        text("""
            INSERT INTO object_sources
                (stix_object_id, source_url, source_type, llm_model,
                 llm_duration_ms, confidence_score)
            VALUES
                (CAST(:stix_object_id AS uuid), :source_url, :source_type,
                 :llm_model, :llm_duration_ms, :confidence_score)
        """),
        {
            "stix_object_id": stix_object_id,
            "source_url": msg.source_url,
            "source_type": msg.source_type.value,
            "llm_model": msg.llm_model,
            "llm_duration_ms": msg.llm_duration_ms,
            "confidence_score": confidence_score,
        },
    )


async def get_object_by_stix_id(stix_id: str) -> dict[str, Any] | None:
    """Fetch a stix_objects row by stix_id. Returns None if not found."""
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT id::text, stix_id, stix_type, stix_data,
                       confidence, tlp_level, is_merged
                FROM stix_objects
                WHERE stix_id = :stix_id
            """),
            {"stix_id": stix_id},
        )
        row = result.mappings().first()
        return dict(row) if row else None
