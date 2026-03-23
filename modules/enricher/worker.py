"""
Enricher worker — consumes cti:enrichment, queries external APIs,
updates stix_data JSONB with enrichment results.

For each EnrichmentRequest:
    1. Query VirusTotal (if API key configured)
    2. Query Shodan InternetDB (for IPs, always)
    3. Merge results into stix_data.x_cti_enrichment
    4. Update stix_objects row
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

import structlog
from sqlalchemy import text

from shared.config import get_settings
from shared.db import get_session
from shared.metrics import record_metric
from shared.models.messages import EnrichmentRequest
from shared.queue import STREAM_ENRICHMENT, consume_stream

log = structlog.get_logger()

_GROUP = "enricher-group"
_CONSUMER = "enricher-1"


async def handle_enrichment_request(payload: dict) -> None:
    """Process one EnrichmentRequest from cti:enrichment."""
    try:
        req = EnrichmentRequest.model_validate(payload)
    except Exception as exc:
        log.error("enricher_invalid_message", error=str(exc))
        return

    settings = get_settings()
    enrichment: dict = {}

    # ── VirusTotal ────────────────────────────────────────────
    if settings.virustotal_api_key:
        from modules.enricher.virustotal import VirusTotalClient
        async with VirusTotalClient(settings.virustotal_api_key) as vt:
            vt_result = await vt.enrich(req.ioc_type, req.ioc_value)
        if vt_result:
            enrichment["virustotal"] = vt_result
            await record_metric(
                "enricher.vt_queried", 1,
                ioc_type=req.ioc_type,
                found=str(vt_result.get("found", False)),
            )

    # ── Shodan (IPs only) ─────────────────────────────────────
    if req.ioc_type in ("ipv4-addr", "ipv6-addr"):
        from modules.enricher.shodan import enrich_ip
        shodan_result = await enrich_ip(req.ioc_value, settings.shodan_api_key)
        if shodan_result:
            enrichment["shodan"] = shodan_result
            await record_metric(
                "enricher.shodan_queried", 1,
                found=str(shodan_result.get("found", False)),
            )

    if not enrichment:
        log.debug("enricher_no_results", stix_id=req.stix_id, ioc_type=req.ioc_type)
        return

    # ── Write enrichment to stix_data ─────────────────────────
    await _update_stix_enrichment(req.stix_id, enrichment)
    log.info(
        "enricher_done",
        stix_id=req.stix_id,
        ioc_type=req.ioc_type,
        sources=list(enrichment.keys()),
    )


async def _update_stix_enrichment(stix_id: str, enrichment: dict) -> None:
    """Merge enrichment data into stix_data JSONB."""
    enrichment_with_ts = {
        **enrichment,
        "enriched_at": datetime.now(UTC).isoformat(),
    }
    try:
        async with get_session() as session:
            await session.execute(
                text("""
                    UPDATE stix_objects
                    SET stix_data = jsonb_set(
                        stix_data,
                        '{x_cti_enrichment}',
                        :enrichment::jsonb,
                        true
                    ),
                    modified_at = NOW()
                    WHERE stix_id = :stix_id
                """),
                {
                    "stix_id": stix_id,
                    "enrichment": json.dumps(enrichment_with_ts),
                },
            )
            await session.commit()
        await record_metric("enricher.stix_updated", 1)
    except Exception as exc:
        log.error("enricher_db_update_failed", stix_id=stix_id, error=str(exc))


async def run() -> None:
    log.info("enricher_starting", group=_GROUP, consumer=_CONSUMER)
    await consume_stream(
        stream=STREAM_ENRICHMENT,
        group=_GROUP,
        consumer=_CONSUMER,
        handler=handle_enrichment_request,
    )
