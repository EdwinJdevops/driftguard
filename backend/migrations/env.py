from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from backend.db_url import normalize_database_url
from backend.models import incidents as incident_models
from backend.models import models as core_models
from backend.models.base import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

_REGISTERED_MODEL_MODULES = (core_models, incident_models)
target_metadata = Base.metadata


def _database_url() -> str:
    explicit = config.attributes.get("connection_url")
    if explicit:
        return normalize_database_url(str(explicit))
    return normalize_database_url(
        os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./driftguard.db")
    )


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        compare_server_default=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _database_url()
    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(_run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
