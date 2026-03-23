"""
Deduplicator worker — consumes cti:stix_valid, produces cti:stix_final.

For each StixValidMessage:

  1. Extract STIX pattern (indicators) or name (other types) for hashing.

  2. Exact dedup (Redis):
     - Pattern hash found → emit MERGE action, update existing record.
     - Not found → continue to semantic check.

  3. Semantic dedup (pgvector):
     - Embedding similarity ≥ 0.92 → emit MERGE action.
     - No match → emit INSERT action.

  4. Publish StixFinalMessage to cti:stix_final.

Merge semantics:
  - NEVER delete the original object.
  - Set is_merged=True on the duplicate, merged_into=<target_stix_id>.
  - Recalculate confidence on the target using merged source count.
  - The Store handles the actual DB write.
"""
from __future__ import annotations

import structlog

from modules.deduplicator.embedding import embed, text_for_embedding
from modules.deduplicator.exact import lookup_exact, mark_exact
from modules.deduplicator.semantic import find_semantic_duplicate

from shared.metrics import record_metric
from shared.models.messages import StixFinalMessage, StixValidMessage
from shared.models.enums import DedupAction
from shared.queue import STREAM_STIX_FINAL, STREAM_STIX_VALID, consume_stream, publish

log = structlog.get_logger()

_GROUP = "deduplicator-group"
_CONSUMER = "deduplicator-1"


async def handle_stix_valid_message(payload: dict) -> None:
    """Process one StixValidMessage from cti:stix_valid."""
    try:
        msg = StixValidMessage.model_validate(payload)
    except Exception as exc:
        log.error("deduplicator_invalid_message", error=str(exc))
        return

    stix_obj = msg.stix_object
    stix_type = stix_obj.get("type", "unknown")
    stix_id = stix_obj.get("id", "")
    pattern = stix_obj.get("pattern", "")

    worker_log = log.bind(
        source_id=str(msg.source_id),
        stix_id=stix_id,
        stix_type=stix_type,
    )
    worker_log.info("deduplicator_received")

    # ── 1. Exact dedup (indicators only — pattern hash) ───────
    existing_id: str | None = None

    if stix_type == "indicator" and pattern:
        existing_id = await lookup_exact(pattern)
        if existing_id:
            worker_log.info("dedup_exact_hit", existing_id=existing_id)
            await record_metric("deduplicator.exact_hit", 1, stix_type=stix_type)
            await _publish_merge(msg, stix_obj, existing_id, "exact")
            return

    # ── 2. Semantic dedup (all types) ─────────────────────────
    embed_text = text_for_embedding(stix_obj)
    if not embed_text.strip():
        # Nothing to embed — treat as new
        worker_log.warning("deduplicator_no_embed_text", stix_type=stix_type)
        await _publish_insert(msg, stix_obj, embedding=[])
        return

    try:
        embedding = embed(embed_text)
    except Exception as exc:
        worker_log.error("deduplicator_embed_failed", error=str(exc))
        # Degrade gracefully: skip semantic check, treat as new
        embedding = []
        await _publish_insert(msg, stix_obj, embedding=embedding)
        return

    existing_id = await find_semantic_duplicate(embedding, stix_type)
    if existing_id:
        worker_log.info("dedup_semantic_hit", existing_id=existing_id)
        await record_metric("deduplicator.semantic_hit", 1, stix_type=stix_type)
        await _publish_merge(msg, stix_obj, existing_id, "semantic")
        return

    # ── 3. New object ─────────────────────────────────────────
    # Register in exact-dedup index for future lookups
    if stix_type == "indicator" and pattern:
        await mark_exact(pattern, stix_id)

    await record_metric("deduplicator.new_object", 1, stix_type=stix_type)
    await _publish_insert(msg, stix_obj, embedding=embedding)
    worker_log.info("deduplicator_new_object")


async def _publish_insert(
    msg: StixValidMessage,
    stix_obj: dict,
    embedding: list[float],
) -> None:
    out = StixFinalMessage(
        source_id=msg.source_id,
        source_url=msg.source_url,
        source_type=msg.source_type,
        source_category=msg.source_category,
        tlp_level=msg.tlp_level,
        published_at=msg.published_at,
        fetched_at=msg.fetched_at,
        llm_model=msg.llm_model,
        llm_duration_ms=msg.llm_duration_ms,
        confidence=msg.confidence,
        stix_object=stix_obj,
        embedding=embedding,
        action=DedupAction.INSERT,
        target_stix_id=None,
    )
    await publish(STREAM_STIX_FINAL, out.model_dump())


async def _publish_merge(
    msg: StixValidMessage,
    stix_obj: dict,
    target_stix_id: str,
    method: str,
) -> None:
    # Confidence recalculation happens in the Store (it knows source_count)
    out = StixFinalMessage(
        source_id=msg.source_id,
        source_url=msg.source_url,
        source_type=msg.source_type,
        source_category=msg.source_category,
        tlp_level=msg.tlp_level,
        published_at=msg.published_at,
        fetched_at=msg.fetched_at,
        llm_model=msg.llm_model,
        llm_duration_ms=msg.llm_duration_ms,
        confidence=msg.confidence,
        stix_object=stix_obj,
        embedding=[],  # Store will use target's existing embedding
        action=DedupAction.MERGE,
        target_stix_id=target_stix_id,
        merge_method=method,
    )
    await publish(STREAM_STIX_FINAL, out.model_dump())


async def run() -> None:
    """Start the deduplicator consumer loop."""
    log.info("deduplicator_starting", group=_GROUP, consumer=_CONSUMER)
    await consume_stream(
        stream=STREAM_STIX_VALID,
        group=_GROUP,
        consumer=_CONSUMER,
        handler=handle_stix_valid_message,
    )
