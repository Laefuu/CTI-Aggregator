"""LLM Normalizer — entrypoint. Started by Docker as: python -m llm_normalizer"""
from __future__ import annotations

import asyncio
import signal

import structlog

from modules.llm_normalizer.worker import run, _ollama
from shared.logging import configure_logging
from shared.queue import close_redis

log = structlog.get_logger()


async def main() -> None:
    configure_logging()
    log.info("llm_normalizer_starting")

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
        if _ollama is not None:
            await _ollama.__aexit__(None, None, None)
        await close_redis()
        log.info("llm_normalizer_stopped")


if __name__ == "__main__":
    asyncio.run(main())
