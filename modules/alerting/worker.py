"""
Alerting worker — consumes cti:alerts, dispatches webhook and email notifications.

For each AlertMessage:
    1. Fetch perimeter details (webhook_url, name)
    2. Send webhook POST if configured
    3. Send email if SMTP configured and recipients set
    4. Mark alert as notified in DB
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import structlog
from sqlalchemy import text

from shared.config import get_settings
from shared.db import get_session
from shared.metrics import record_metric
from shared.queue import STREAM_ALERTS, consume_stream

log = structlog.get_logger()

_GROUP = "alerting-group"
_CONSUMER = "alerting-1"


async def handle_alert(payload: dict) -> None:
    """Process one alert notification."""
    alert_id = payload.get("alert_id") or payload.get("id")
    if not alert_id:
        log.error("alerting_missing_alert_id", payload=payload)
        return

    # Fetch full alert + perimeter details
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT a.id::text, a.source_url, a.triggered_at,
                       p.name AS perimeter_name, p.webhook_url,
                       so.stix_id, so.stix_type, so.stix_data,
                       so.confidence, so.tlp_level
                FROM alerts a
                JOIN perimeters p ON p.id = a.perimeter_id
                JOIN stix_objects so ON so.id = a.stix_object_id
                WHERE a.id = :id::uuid AND a.notified = FALSE
            """),
            {"id": alert_id},
        )
        row = result.mappings().first()

    if not row:
        log.debug("alerting_already_notified_or_not_found", alert_id=alert_id)
        return

    row = dict(row)
    notified = False

    # 1. Webhook
    if row.get("webhook_url"):
        notified = await _send_webhook(row) or notified

    # 2. Email
    settings = get_settings()
    if settings.smtp_host and settings.alert_recipients:
        notified = await _send_email(row, settings) or notified

    # 3. Mark notified
    if notified:
        async with get_session() as session:
            await session.execute(
                text("""
                    UPDATE alerts
                    SET notified = TRUE, notified_at = NOW()
                    WHERE id = :id::uuid
                """),
                {"id": alert_id},
            )
            await session.commit()
        await record_metric("alerting.notified", 1)
        log.info("alert_notified", alert_id=alert_id, perimeter=row["perimeter_name"])
    else:
        log.info("alert_no_channels", alert_id=alert_id)


async def _send_webhook(row: dict) -> bool:
    """POST alert payload to the perimeter webhook URL. Returns True on success."""
    payload = {
        "alert_id": row["id"],
        "perimeter": row["perimeter_name"],
        "triggered_at": row["triggered_at"].isoformat() if hasattr(row["triggered_at"], "isoformat") else str(row["triggered_at"]),
        "stix_id": row["stix_id"],
        "stix_type": row["stix_type"],
        "confidence": row["confidence"],
        "tlp_level": row["tlp_level"],
        "source_url": row["source_url"],
        "ioc_pattern": row["stix_data"].get("pattern") if row["stix_data"] else None,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                row["webhook_url"],
                json=payload,
                headers={"Content-Type": "application/json", "X-CTI-Source": "cti-aggregator"},
            )
            resp.raise_for_status()
        log.info("webhook_sent", url=row["webhook_url"], status=resp.status_code)
        await record_metric("alerting.webhook_sent", 1)
        return True
    except Exception as exc:
        log.error("webhook_failed", url=row["webhook_url"], error=str(exc))
        await record_metric("alerting.webhook_failed", 1)
        return False


async def _send_email(row: dict, settings) -> bool:
    """Send email notification via SMTP. Returns True on success."""
    import smtplib
    from email.mime.text import MIMEText

    recipients = [r.strip() for r in settings.alert_recipients.split(",") if r.strip()]
    if not recipients:
        return False

    subject = f"[CTI Alert] {row['perimeter_name']} — {row['stix_type']} detected"
    body = (
        f"Alert triggered for perimeter: {row['perimeter_name']}\n\n"
        f"STIX ID:    {row['stix_id']}\n"
        f"Type:       {row['stix_type']}\n"
        f"Confidence: {row['confidence']}/100\n"
        f"TLP Level:  {row['tlp_level']}\n"
        f"Source URL: {row['source_url']}\n"
        f"Triggered:  {row['triggered_at']}\n"
    )
    if row["stix_data"] and row["stix_data"].get("pattern"):
        body += f"Pattern:    {row['stix_data']['pattern']}\n"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from or "cti-aggregator@localhost"
    msg["To"] = ", ".join(recipients)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            smtp.sendmail(msg["From"], recipients, msg.as_string())
        log.info("email_sent", recipients=recipients, subject=subject)
        await record_metric("alerting.email_sent", 1)
        return True
    except Exception as exc:
        log.error("email_failed", error=str(exc))
        await record_metric("alerting.email_failed", 1)
        return False


async def run() -> None:
    log.info("alerting_starting", group=_GROUP, consumer=_CONSUMER)
    await consume_stream(
        stream=STREAM_ALERTS,
        group=_GROUP,
        consumer=_CONSUMER,
        handler=handle_alert,
    )
