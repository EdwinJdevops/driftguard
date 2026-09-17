from __future__ import annotations


def normalize_database_url(url: str) -> str:
    """Normalize provider-style database URLs for SQLAlchemy async engines."""
    url = url.strip()
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    if url.startswith("postgresql://") and "+asyncpg" not in url:
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url
