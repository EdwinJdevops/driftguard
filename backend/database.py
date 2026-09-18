"""
DriftGuard — Database Layer

Async SQLAlchemy 2.0 engine and session management.
Works with PostgreSQL (production) and SQLite (local dev/testing).

Production schema changes are managed by Alembic. ``init_db()`` remains a
local-development/test bootstrap only; it is not a migration mechanism.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .db_url import normalize_database_url
from .models import incidents as incident_models
from .models import models as core_models
from .models.base import Base

_REGISTERED_MODEL_MODULES = (core_models, incident_models)

DATABASE_URL = normalize_database_url(
    os.getenv(
        "DATABASE_URL",
        "sqlite+aiosqlite:///./driftguard.db",
    )
)

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_size=5 if "postgresql" in DATABASE_URL else 0,
    max_overflow=10 if "postgresql" in DATABASE_URL else 0,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """Local dev/test bootstrap. Production deployments must run migrations."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency — yields a session, commits on success, rolls back on error."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def db_session() -> AsyncIterator[AsyncSession]:
    """Context manager for use outside FastAPI request scope (Celery tasks, scripts)."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
