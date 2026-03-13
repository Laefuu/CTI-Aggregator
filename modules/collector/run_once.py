"""
CLI entrypoint for forced immediate collection of a single source.
Used by: make run-source SOURCE_ID=<uuid>
"""
from __future__ import annotations

import argparse
import asyncio

import structlog

from modules.collector.scheduler import CollectorScheduler
from shared.logging import configure_logging
from shared.queue import close_redis
from shared.db import close_engine

log = structlog.get_logger()


async def run(source_id: str) -> None:
    configure_logging()
    log.info("run_once_start", source_id=source_id)
    scheduler = CollectorScheduler()
    try:
        await scheduler.run_once(source_id)
    finally:
        await close_redis()
        await close_engine()
    log.info("run_once_done", source_id=source_id)


def main() -> None:
    parser = argparse.ArgumentParser(description="Force collection of a single source")
    parser.add_argument("--source-id", required=True, help="UUID of the source to collect")
    args = parser.parse_args()
    asyncio.run(run(args.source_id))


if __name__ == "__main__":
    main()
