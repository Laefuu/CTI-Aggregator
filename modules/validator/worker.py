"""
Validator worker — consumes cti:stix_raw, produces cti:stix_valid and cti:stix_rejected.

For each StixRawMessage:
    For each STIX object in stix_objects:
        1. Validate and correct x_cti_* metadata (hallucination check)
        2. Validate with Pydantic STIX models
        3. Compute confidence score
        4. Publish valid → cti:stix_valid, invalid → cti:stix_rejected
"""
from __future__ import annotations

from datetime import UTC, datetime

import structlog

from modules.validator.confidence import compute_confidence_with_detail
from modules.validator.hallucination import validate_and_fix_metadata
from modules.validator.stix_validator import validate_stix_object
from shared.metrics import record_metric
from shared.models.messages import StixRawMessage, StixValidMessage
from shared.queue import (
    STREAM_STIX_RAW,
    STREAM_STIX_REJECTED,
    STREAM_STIX_VALID,
    consume_stream,
    publish,
)

log = structlog.get_logger()

_GROUP = "validator-group"
_CONSUMER = "validator-1"


async def handle_stix_raw_message(payload: dict) -> None:
    """Process one StixRawMessage from cti:stix_raw."""
    try:
        msg = StixRawMessage.model_validate(payload)
    except Exception as exc:
        log.error("validator_invalid_message", error=str(exc))
        return

    worker_log = log.bind(source_id=str(msg.source_id), url=msg.source_url)
    worker_log.info("validator_received", object_count=len(msg.stix_objects))

    published_at_str = (
        msg.published_at.isoformat()
        if msg.published_at
        else msg.fetched_at.isoformat()
    )

    valid_count = rejected_count = skipped_count = 0

    for raw_obj in msg.stix_objects:
        stix_type = raw_obj.get("type", "unknown")

        # 1. Hallucination check + metadata correction
        corrected, warnings = validate_and_fix_metadata(
            stix_obj=raw_obj,
            expected_source_url=msg.source_url,
            published_at_fallback=published_at_str,
        )
        if warnings:
            worker_log.warning(
                "validator_metadata_corrected",
                stix_type=stix_type,
                warnings=warnings,
            )
            await record_metric(
                "validator.hallucination_corrected",
                len(warnings),
                stix_type=stix_type,
            )

        # 2. Pydantic validation
        result = validate_stix_object(corrected)

        if result.skipped:
            skipped_count += 1
            worker_log.debug("validator_skipped", stix_type=stix_type, reason=result.error)
            continue

        if not result.valid:
            rejected_count += 1
            worker_log.warning(
                "validator_rejected",
                stix_type=stix_type,
                reason=result.error,
            )
            await publish(
                STREAM_STIX_REJECTED,
                {
                    "source_url": msg.source_url,
                    "stix_type": stix_type,
                    "reason": result.error,
                    "raw_object": raw_obj,
                    "rejected_at": datetime.now(UTC).isoformat(),
                },
            )
            await record_metric(
                "validator.rejected", 1, stix_type=stix_type, reason=result.error
            )
            continue

        # 3. Confidence score
        confidence, confidence_detail = compute_confidence_with_detail(
            source_category=msg.source_type.value,  # placeholder until source row is loaded
            published_at=msg.published_at,
            fetched_at=msg.fetched_at,
            hallucination_count=len(warnings),
            stix_obj=result.obj,
        )

        # Inject confidence breakdown into the STIX object
        validated_obj = dict(result.obj)  # type: ignore[arg-type]
        validated_obj["x_cti_confidence_detail"] = confidence_detail

        # 4. Publish valid
        out_msg = StixValidMessage(
            source_id=msg.source_id,
            source_url=msg.source_url,
            source_type=msg.source_type,
            source_category="unknown",  # resolved by Store from sources table
            tlp_level=msg.tlp_level,
            published_at=msg.published_at,
            fetched_at=msg.fetched_at,
            llm_model=msg.llm_model,
            llm_duration_ms=msg.llm_duration_ms,
            confidence=confidence,
            stix_object=validated_obj,
        )

        await publish(STREAM_STIX_VALID, out_msg.model_dump())
        valid_count += 1

    await record_metric(
        "validator.valid", valid_count, source_id=str(msg.source_id)
    )
    await record_metric(
        "validator.rejected_total", rejected_count, source_id=str(msg.source_id)
    )

    worker_log.info(
        "validator_done",
        valid=valid_count,
        rejected=rejected_count,
        skipped=skipped_count,
    )


async def run() -> None:
    """Start the validator consumer loop."""
    log.info("validator_starting", group=_GROUP, consumer=_CONSUMER)
    await consume_stream(
        stream=STREAM_STIX_RAW,
        group=_GROUP,
        consumer=_CONSUMER,
        handler=handle_stix_raw_message,
    )
