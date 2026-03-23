from __future__ import annotations
import asyncio, signal
import structlog
from modules.enricher.worker import run
from shared.logging import configure_logging
from shared.queue import close_redis
from shared.db import close_engine

log = structlog.get_logger()

async def main() -> None:
    configure_logging()
    log.info("enricher_starting")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    t = asyncio.create_task(run())
    await stop.wait()
    t.cancel()
    try: await t
    except asyncio.CancelledError: pass
    finally:
        await close_redis(); await close_engine()
        log.info("enricher_stopped")

if __name__ == "__main__":
    asyncio.run(main())
