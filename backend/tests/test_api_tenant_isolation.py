from __future__ import annotations

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.api.main import create_app
from backend.core.auth import verify_api_key
from backend.database import get_db
from backend.models.base import Base
from backend.models.models import (
    CloudProvider,
    DriftFinding,
    DriftScan,
    Organization,
    ScanStatus,
    Workspace,
)


@pytest.mark.asyncio
async def test_scan_endpoint_enforces_tenant_ownership_and_finding_scope():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
    )
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with Session() as db:
        org_a = Organization(name="Org A", slug="org-a")
        org_b = Organization(name="Org B", slug="org-b")
        db.add_all([org_a, org_b])
        await db.flush()

        workspace_a = Workspace(
            org_id=org_a.id,
            name="prod-a",
            slug="prod-a",
            provider=CloudProvider.AWS,
            region="us-east-1",
        )
        workspace_b = Workspace(
            org_id=org_b.id,
            name="prod-b",
            slug="prod-b",
            provider=CloudProvider.AWS,
            region="us-east-1",
        )
        db.add_all([workspace_a, workspace_b])
        await db.flush()

        scan_a = DriftScan(
            workspace_id=workspace_a.id,
            status=ScanStatus.COMPLETED,
        )
        db.add(scan_a)
        await db.flush()

        owned_finding = DriftFinding(
            workspace_id=workspace_a.id,
            scan_id=scan_a.id,
            resource_type="aws_instance",
            resource_id="i-owned",
        )
        inconsistent_finding = DriftFinding(
            workspace_id=workspace_b.id,
            scan_id=scan_a.id,
            resource_type="aws_instance",
            resource_id="i-cross-tenant",
        )
        db.add_all([owned_finding, inconsistent_finding])
        await db.commit()

    app = create_app()

    async def override_db():
        async with Session() as db:
            yield db

    async def authenticate_org_a():
        return org_a

    async def authenticate_org_b():
        return org_b

    app.dependency_overrides[get_db] = override_db
    transport = httpx.ASGITransport(app=app)

    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            app.dependency_overrides[verify_api_key] = authenticate_org_a
            own_response = await client.get(f"/scans/{scan_a.id}")
            assert own_response.status_code == 200
            own_payload = own_response.json()
            assert [finding["resource_id"] for finding in own_payload["findings"]] == ["i-owned"]

            app.dependency_overrides[verify_api_key] = authenticate_org_b
            cross_tenant_response = await client.get(f"/scans/{scan_a.id}")
            assert cross_tenant_response.status_code == 404
            assert cross_tenant_response.json() == {"detail": "Scan not found."}

            app.dependency_overrides.pop(verify_api_key)
            unauthenticated_response = await client.get(f"/scans/{scan_a.id}")
            assert unauthenticated_response.status_code == 401
    finally:
        app.dependency_overrides.clear()
        await engine.dispose()
