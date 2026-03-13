"""
Alembic migration environment.
Loads database URL from application settings — no credentials in config files.
"""
from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# Load application settings to get the database URL
from shared.config import get_settings

# Alembic Config object — access to values in alembic.ini
config = context.config

# Override sqlalchemy.url with the value from our settings
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url_sync)

# Setup logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Metadata for autogenerate — import all models here
# (We use raw SQL DDL in init.sql, so target_metadata=None is correct for now.
#  When using SQLAlchemy ORM models, set target_metadata = Base.metadata)
target_metadata = None


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — no live DB connection required."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations using async engine — required for asyncpg."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        # Override to use async driver
        url=settings.database_url,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
