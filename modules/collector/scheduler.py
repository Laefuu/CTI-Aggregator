"""
Collector Scheduler — drives all enabled sources via APScheduler.

On startup:
    1. Loads all enabled sources from the database
    2. Creates one job per source with interval = source.frequency_min
    3. Runs each job immediately once (first_run=True) then on schedule

Each job:
    1. Instantiates the appropriate connector via registry.get_connector()
    2. Calls connector.fetch()
    3. Publishes each RawDocument via publisher.publish_document()
    4. Updates source.last_run_at and last_status in the database
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import text

from modules.collector.publisher import publish_document
from modules.collector.registry import get_connector
from modules.collector.base import SourceMeta
from shared.config import get_settings
from shared.db import get_session
from shared.metrics import record_metric
from shared.models.enums import SourceType, TLPLevel
from shared.queue import CHANNEL_SOURCES_UPDATED, get_redis

log = structlog.get_logger()


class CollectorScheduler:
    """Manages APScheduler jobs for all configured sources."""

    def __init__(self) -> None:
        self._scheduler = AsyncIOScheduler(timezone="UTC")
        self._running = False

    async def start(self) -> None:
        """Load sources from DB and start the scheduler."""
        sources = await self._load_sources()
        log.info("scheduler_loading_sources", count=len(sources))

        for source in sources:
            self._register_job(source)

        self._scheduler.start()
        self._running = True
        log.info("scheduler_started", job_count=len(sources))

    async def stop(self) -> None:
        """Gracefully shut down the scheduler."""
        if self._running:
            self._scheduler.shutdown(wait=False)
            self._running = False
            log.info("scheduler_stopped")

    def _register_job(self, source: SourceMeta) -> None:
        """Register an interval job for a single source."""
        self._scheduler.add_job(
            func=self._run_source,
            trigger=IntervalTrigger(minutes=source.frequency_min),
            args=[source],
            id=f"source_{source.id}",
            name=source.name,
            replace_existing=True,
            # Run immediately on first start
            next_run_time=datetime.now(UTC),
            misfire_grace_time=60,
            coalesce=True,  # Skip missed runs if the previous is still running
        )
        log.info(
            "job_registered",
            source_id=source.id,
            source_name=source.name,
            frequency_min=source.frequency_min,
        )

    async def _run_source(self, source: SourceMeta) -> None:
        """Execute a single source collection run."""
        run_log = log.bind(source_id=source.id, source_name=source.name)
        run_log.info("source_run_start")
        start_time = asyncio.get_event_loop().time()

        try:
            connector_class = get_connector(source.type)
        except KeyError:
            run_log.error("unknown_connector_type", source_type=source.type)
            await self._update_source_status(source.id, "error", "Unknown connector type")
            return

        published = 0
        error: str | None = None

        try:
            async with connector_class(source) as connector:
                documents = await connector.fetch()
                for doc in documents:
                    if await publish_document(doc):
                        published += 1
        except Exception as exc:
            error = str(exc)
            run_log.error("source_run_failed", error=error, exc_info=True)

        elapsed_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
        status = "error" if error else "ok"

        await self._update_source_status(source.id, status, error)
        await record_metric(
            "collector.run_duration_ms",
            elapsed_ms,
            source_id=source.id,
            source_type=source.type.value,
        )
        await record_metric(
            "collector.documents_published",
            published,
            source_id=source.id,
        )

        run_log.info(
            "source_run_complete",
            status=status,
            published=published,
            elapsed_ms=elapsed_ms,
        )

    async def run_once(self, source_id: str) -> None:
        """Force an immediate run for a specific source (used by make run-source)."""
        sources = await self._load_sources()
        source = next((s for s in sources if s.id == source_id), None)
        if source is None:
            raise ValueError(f"Source not found: {source_id}")
        await self._run_source(source)

    async def _load_sources(self) -> list[SourceMeta]:
        """Load all enabled sources from the database."""
        async with get_session() as session:
            result = await session.execute(
                text("""
                    SELECT id::text, name, type, url, config,
                           category, tlp_level, frequency_min
                    FROM sources
                    WHERE enabled = true
                    ORDER BY name
                """)
            )
            rows = result.mappings().all()

        sources = []
        for row in rows:
            try:
                sources.append(
                    SourceMeta(
                        id=row["id"],
                        name=row["name"],
                        type=SourceType(row["type"]),
                        url=row["url"],
                        config=row["config"] or {},
                        category=row["category"],
                        tlp_level=TLPLevel(row["tlp_level"]),
                        frequency_min=row["frequency_min"],
                    )
                )
            except Exception as exc:
                log.warning("source_load_failed", source_id=row["id"], error=str(exc))

        return sources

    async def listen_for_updates(self) -> None:
        """Subscribe to sources:updated pub/sub channel and reload jobs on change."""
        client = await get_redis()
        pubsub = client.pubsub()
        await pubsub.subscribe(CHANNEL_SOURCES_UPDATED)
        log.info("collector_pubsub_subscribed", channel=CHANNEL_SOURCES_UPDATED)

        try:
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                log.info("collector_sources_changed", trigger="pubsub")
                await self._sync_jobs()
        finally:
            await pubsub.unsubscribe(CHANNEL_SOURCES_UPDATED)
            await pubsub.aclose()

    async def _sync_jobs(self) -> None:
        """Reload sources from DB and add/remove scheduler jobs accordingly."""
        sources = await self._load_sources()
        current_ids = {f"source_{s.id}" for s in sources}
        existing_ids = {j.id for j in self._scheduler.get_jobs()}

        # Remove jobs for sources that no longer exist or are disabled
        for job_id in existing_ids - current_ids:
            self._scheduler.remove_job(job_id)
            log.info("job_removed", job_id=job_id)

        # Add or update jobs for current sources
        for source in sources:
            self._register_job(source)

        log.info("scheduler_synced", job_count=len(sources))

    async def _update_source_status(
        self,
        source_id: str,
        status: str,
        error: str | None = None,
    ) -> None:
        """Update last_run_at, last_status, and last_error in the database."""
        try:
            async with get_session() as session:
                await session.execute(
                    text("""
                        UPDATE sources
                        SET last_run_at = NOW(),
                            last_status = :status,
                            last_error  = :error
                        WHERE id = CAST(:id AS uuid)
                    """),
                    {"id": source_id, "status": status, "error": error},
                )
                await session.commit()
        except Exception as exc:
            log.warning("source_status_update_failed", source_id=source_id, error=str(exc))
