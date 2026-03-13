"""
LLM Normalizer worker — consumes cti:chunks, produces cti:stix_raw.

For each ChunkMessage:
    1. Build system + user prompt
    2. Call Ollama → list of raw STIX dicts
    3. Wrap in StixRawMessage
    4. Publish to cti:stix_raw
    5. Record metrics
"""
from __future__ import annotations

import structlog

from modules.llm_normalizer.client import OllamaClient
from modules.llm_normalizer.prompt import SYSTEM_PROMPT, build_user_prompt
from shared.metrics import record_metric
from shared.models.messages import ChunkMessage, StixRawMessage
from shared.queue import STREAM_CHUNKS, STREAM_STIX_RAW, consume_stream, publish

log = structlog.get_logger()

_GROUP = "llm-normalizer-group"
_CONSUMER = "llm-normalizer-1"

# Module-level client — shared across all messages in the worker lifetime
_ollama: OllamaClient | None = None


async def _get_client() -> OllamaClient:
    global _ollama
    if _ollama is None:
        _ollama = OllamaClient()
        await _ollama.__aenter__()
    return _ollama


async def handle_chunk_message(payload: dict) -> None:
    """Process one ChunkMessage from cti:chunks."""
    try:
        msg = ChunkMessage.model_validate(payload)
    except Exception as exc:
        log.error("llm_normalizer_invalid_message", error=str(exc))
        return

    worker_log = log.bind(
        source_id=str(msg.source_id),
        chunk=f"{msg.chunk_index + 1}/{msg.chunk_total}",
    )
    worker_log.info("llm_normalizer_received")

    published_at_str = (
        msg.published_at.isoformat() if msg.published_at else msg.fetched_at.isoformat()
    )

    user_prompt = build_user_prompt(
        chunk_text=msg.chunk_text,
        source_url=msg.source_url,
        published_at=published_at_str,
        language=msg.language,
    )

    client = await _get_client()
    stix_objects, model_used, duration_ms = await client.extract_stix(
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt,
    )

    await record_metric(
        "llm.inference_ms",
        duration_ms,
        model=model_used,
        source_id=str(msg.source_id),
    )

    if not stix_objects:
        worker_log.info("llm_normalizer_no_objects", model=model_used, duration_ms=duration_ms)
        await record_metric("llm.empty_response", 1, model=model_used)
        return

    out_msg = StixRawMessage(
        source_id=msg.source_id,
        source_url=msg.source_url,
        source_type=msg.source_type,
        tlp_level=msg.tlp_level,
        published_at=msg.published_at,
        fetched_at=msg.fetched_at,
        llm_model=model_used,
        llm_duration_ms=duration_ms,
        stix_objects=stix_objects,
    )

    await publish(STREAM_STIX_RAW, out_msg.model_dump())
    await record_metric(
        "llm.objects_produced",
        len(stix_objects),
        model=model_used,
        source_id=str(msg.source_id),
    )

    worker_log.info(
        "llm_normalizer_done",
        model=model_used,
        objects=len(stix_objects),
        duration_ms=duration_ms,
    )


async def run() -> None:
    """Start the LLM normalizer consumer loop."""
    log.info("llm_normalizer_starting", group=_GROUP, consumer=_CONSUMER)
    await consume_stream(
        stream=STREAM_CHUNKS,
        group=_GROUP,
        consumer=_CONSUMER,
        handler=handle_chunk_message,
    )
