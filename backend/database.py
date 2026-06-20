"""
DriftGuard — Database Layer

Async SQLAlchemy 2.0 engine and session management.
Works with PostgreSQL (production) and SQLite (local dev/testing).

Production: set DATABASE_URL to a Postgres connection string.
Recommended free provider: Neon.tech (serverless Postgres, no
expiry on free tier, unlike Render's 90-day free Postgres).

  postgresql+asyncpg://user:pass@host/dbname

Local dev / CI: falls back to SQLite if DATABASE_URL is unset.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .models.base import Base

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./driftguard.db",
)

# Neon/Postgres URLs from providers often come as postgres:// — normalize.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+asyncpg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# SQLite needs check_same_thread=False equivalent handled by aiosqlite driver;
# no special connect_args required for asyncpg or aiosqlite.
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
    """Create all tables. Call once on startup. Safe to call repeatedly (no-op if tables exist)."""
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
