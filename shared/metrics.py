"""
Pipeline metrics — stored directly in PostgreSQL (pipeline_metrics table).

Usage:
    from shared.metrics import record_metric
    await record_metric("llm.inference_ms", 24300)
    await record_metric("validator.rejected", 1, reason="invalid_ipv4", stix_type="indicator")

The module name is read from the MODULE_NAME environment variable,
which is injected per-service by docker-compose.
"""
from __future__ import annotations

import os
from typing import Any

import structlog

log = structlog.get_logger()

# Import deferred to avoid circular imports at module level
# Database session is obtained lazily on first call


async def record_metric(
    metric: str,
    value: float,
    module: str | None = None,
    **labels: Any,
) -> None:
    """
    Record a pipeline metric to the pipeline_metrics table.

    Args:
        metric: Metric name, dot-separated (e.g. "llm.inference_ms")
        value:  Numeric value
        module: Module name override. Defaults to MODULE_NAME env var.
        **labels: Arbitrary key-value labels stored as JSONB
    """
    from sqlalchemy import text

    from shared.db import get_session

    resolved_module = module or os.environ.get("MODULE_NAME", "unknown")

    try:
        async with get_session() as session:
            await session.execute(
                text(
                    """
                    INSERT INTO pipeline_metrics (module, metric, value, labels)
                    VALUES (:module, :metric, :value, :labels::jsonb)
                    """
                ),
                {
                    "module": resolved_module,
                    "metric": metric,
                    "value": float(value),
                    "labels": _labels_to_json(labels),
                },
            )
            await session.commit()
    except Exception as exc:
        # Metrics must never crash the calling module
        log.warning("metric_record_failed", metric=metric, error=str(exc))


def _labels_to_json(labels: dict[str, Any]) -> str:
    import json
    return json.dumps({k: str(v) for k, v in labels.items()})
