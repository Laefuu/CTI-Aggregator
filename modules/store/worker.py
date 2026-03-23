"""
Store worker — consumes cti:stix_final, persists to PostgreSQL.

For each StixFinalMessage:
    1. Resolve source_category from sources table
    2. Compute final confidence with resolved category
    3. INSERT or MERGE based on action field
    4. Run perimeter matching → create alerts if matched
    5. Trigger enrichment for eligible indicators
"""
from __future__ import annotations

import structlog

from modules.store.enrichment import maybe_trigger_enrichment
from modules.store.perimeter import match_perimeters
from modules.store.repository import (
    get_source_category,
    insert_object,
    merge_object,
)
from modules.validator.confidence import compute_confidence
from shared.metrics import record_metric
from shared.models.enums import DedupAction
from shared.models.messages import StixFinalMessage
from shared.queue import STREAM_STIX_FINAL, consume_stream

log = structlog.get_logger()

_GROUP = "store-group"
_CONSUMER = "store-1"


async def handle_stix_final_message(payload: dict) -> None:
    """Process one StixFinalMessage from cti:stix_final."""
    try:
        msg = StixFinalMessage.model_validate(payload)
    except Exception as exc:
        log.error("store_invalid_message", error=str(exc))
        return

    stix_obj = msg.stix_object
    stix_id = stix_obj.get("id", "unknown")
    stix_type = stix_obj.get("type", "unknown")

    worker_log = log.bind(
        stix_id=stix_id,
        stix_type=stix_type,
        action=msg.action,
    )
    worker_log.info("store_received")

    # 1. Resolve source category for accurate confidence
    source_category = await get_source_category(str(msg.source_id))

    # 2. Compute final confidence with resolved category
    final_confidence = compute_confidence(
        source_category=source_category,
        published_at=msg.published_at,
        fetched_at=msg.fetched_at,
        source_count=1,
    )

    # 3. Persist
    try:
        if msg.action == DedupAction.INSERT:
            object_uuid = await insert_object(msg, source_category, final_confidence)

            # 4. Perimeter matching (only on new objects, not merges)
            alert_count = await match_perimeters(
                stix_object_id=object_uuid,
                stix_object=stix_obj,
                source_url=msg.source_url,
            )
            if alert_count:
                await record_metric(
                    "store.alerts_created", alert_count, stix_type=stix_type
                )

            # 5. Enrichment trigger
            triggered = await maybe_trigger_enrichment(stix_obj)
            if triggered:
                await record_metric("store.enrichment_triggered", 1, stix_type=stix_type)

            await record_metric("store.inserted", 1, stix_type=stix_type)
            worker_log.info("store_insert_done", confidence=final_confidence, alerts=alert_count)

        elif msg.action == DedupAction.MERGE:
            target = msg.target_stix_id
            if not target:
                worker_log.error("store_merge_missing_target")
                return
            await merge_object(msg, target, source_category)
            await record_metric(
                "store.merged", 1,
                stix_type=stix_type,
                method=msg.merge_method or "unknown",
            )
            worker_log.info("store_merge_done", target=target)

        else:
            worker_log.error("store_unknown_action", action=msg.action)

    except Exception as exc:
        worker_log.error("store_persistence_failed", error=str(exc), exc_info=True)
        await record_metric("store.error", 1, stix_type=stix_type)


async def run() -> None:
    """Start the store consumer loop."""
    log.info("store_starting", group=_GROUP, consumer=_CONSUMER)
    await consume_stream(
        stream=STREAM_STIX_FINAL,
        group=_GROUP,
        consumer=_CONSUMER,
        handler=handle_stix_final_message,
    )
