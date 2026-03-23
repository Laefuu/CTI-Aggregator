"""
Semantic deduplication — finds near-duplicate STIX objects using pgvector.

Search strategy:
    1. Restrict to same STIX type (indicator vs indicator, etc.)
    2. ANN search via pgvector <=> operator (cosine distance)
    3. Candidate is a duplicate if similarity ≥ SEMANTIC_DEDUP_THRESHOLD (0.92)
    4. Returns the closest match above threshold, or None

The threshold of 0.92 was chosen conservatively — it should be validated
empirically during Phase 3 testing (P3-04).

Note: ivfflat index requires ≥ 1000 rows for good recall. Below that,
the search falls back to exact scan (still correct, just slower).
"""
from __future__ import annotations

import structlog
from sqlalchemy import text

from shared.config import get_settings
from shared.db import get_session

log = structlog.get_logger()


async def find_semantic_duplicate(
    embedding: list[float],
    stix_type: str,
) -> str | None:
    """
    Search pgvector for the nearest existing embedding of the same STIX type.

    Returns the stix_id of the nearest duplicate if similarity >= threshold,
    or None if no duplicate found.
    """
    settings = get_settings()
    threshold = settings.semantic_dedup_threshold

    # pgvector: <=> is cosine distance (1 - similarity)
    # We want similarity >= threshold → distance <= 1 - threshold
    max_distance = 1.0 - threshold

    # Format vector as pgvector literal: '[0.1,0.2,...]'
    vector_str = "[" + ",".join(f"{v:.8f}" for v in embedding) + "]"

    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT so.stix_id,
                       (se.embedding <=> CAST(:vector AS vector)) AS distance
                FROM stix_embeddings se
                JOIN stix_objects so ON so.id = se.stix_object_id
                WHERE so.stix_type = :stix_type
                  AND so.is_merged = false
                  AND (se.embedding <=> CAST(:vector AS vector)) <= :max_distance
                ORDER BY distance ASC
                LIMIT 1
            """),
            {
                "vector": vector_str,
                "stix_type": stix_type,
                "max_distance": max_distance,
            },
        )
        row = result.mappings().first()

    if row is None:
        return None

    similarity = 1.0 - float(row["distance"])
    log.info(
        "semantic_duplicate_found",
        stix_id=row["stix_id"],
        similarity=round(similarity, 4),
        stix_type=stix_type,
    )
    return str(row["stix_id"])
