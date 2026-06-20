"""
DriftGuard — API Key Authentication

Pattern matches Stripe/GitHub: raw key shown once at creation,
only SHA-256 hash stored. Verification is a hash lookup, not
a database scan of plaintext secrets.

Key format: dg_live_<43 url-safe base64 chars> (256 bits entropy)
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.models import APIKey, Organization

KEY_PREFIX = "dg_live_"
_api_key_header = APIKeyHeader(name="Authorization", auto_error=False)


def generate_api_key() -> tuple[str, str, str]:
    """
    Returns (raw_key, key_hash, key_prefix_display).
    raw_key is shown to the user ONCE. Only key_hash is persisted.
    """
    raw_secret = secrets.token_urlsafe(32)  # 256 bits
    raw_key = f"{KEY_PREFIX}{raw_secret}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    display_prefix = raw_key[:12] + "…"  # e.g. "dg_live_8f2a…" for UI display
    return raw_key, key_hash, display_prefix


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def verify_api_key(
    authorization: str | None = Security(_api_key_header),
    db: AsyncSession = Depends(get_db),
) -> Organization:
    """
    FastAPI dependency. Extracts Bearer token, validates against stored hash,
    checks active + not expired, updates last_used_at, returns the Organization.

    Usage in routes:
        @router.post("/workspaces")
        async def create_workspace(org: Organization = Depends(verify_api_key)):
            ...
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header. Expected: Bearer dg_live_...",
        )

    raw_key = authorization.removeprefix("Bearer ").strip()
    if not raw_key.startswith(KEY_PREFIX):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format.",
        )

    key_hash = hash_key(raw_key)

    result = await db.execute(select(APIKey).where(APIKey.key_hash == key_hash))
    api_key = result.scalar_one_or_none()

    if not api_key or not api_key.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key.",
        )

    if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired.",
        )

    org_result = await db.execute(select(Organization).where(Organization.id == api_key.org_id))
    org = org_result.scalar_one_or_none()

    if not org or not org.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization is inactive.",
        )

    await db.execute(
        update(APIKey)
        .where(APIKey.id == api_key.id)
        .values(last_used_at=datetime.now(timezone.utc))
    )
    await db.commit()

    return org
