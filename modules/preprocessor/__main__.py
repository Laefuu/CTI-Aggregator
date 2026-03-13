"""Preprocessor — main entrypoint. Started by Docker as: python -m preprocessor"""
from __future__ import annotations

import asyncio
import signal

import structlog

from modules.preprocessor.worker import run
from shared.logging import configure_logging
from shared.queue import close_redis

log = structlog.get_logger()


async def main() -> None:
    configure_logging()
    log.info("preprocessor_starting")

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    worker_task = asyncio.create_task(run())

    await stop_event.wait()
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass
    finally:
        await close_redis()
        log.info("preprocessor_stopped")


if __name__ == "__main__":
    asyncio.run(main())
