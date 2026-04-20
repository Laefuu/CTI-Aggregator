"""
Collector — main entrypoint.
Started by Docker as: python -m collector
"""
from __future__ import annotations

import asyncio
import signal

import structlog

from modules.collector.scheduler import CollectorScheduler
from shared.logging import configure_logging
from shared.queue import close_redis
from shared.db import close_engine

log = structlog.get_logger()


async def main() -> None:
    configure_logging()
    log.info("collector_starting")

    scheduler = CollectorScheduler()
    stop_event = asyncio.Event()

    def _handle_signal() -> None:
        log.info("collector_shutdown_signal")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _handle_signal)

    try:
        await scheduler.start()
        # Listen for source changes via Redis pub/sub in background
        pubsub_task = asyncio.create_task(scheduler.listen_for_updates())
        await stop_event.wait()
        pubsub_task.cancel()
    finally:
        await scheduler.stop()
        await close_redis()
        await close_engine()
        log.info("collector_stopped")


if __name__ == "__main__":
    asyncio.run(main())
