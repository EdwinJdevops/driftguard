from __future__ import annotations

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.api.main import create_app
from backend.core.auth import verify_api_key
from backend.database import get_db
from backend.models.base import Base
from backend.models.incidents import (
    EvidenceSubmission,
    FindingIncident,
    FindingOccurrence,
)
from backend.models.models import CloudProvider, DriftScan, Organization, Workspace


def _request_payload() -> dict:
    return {
        "submission_id": "gha:run-123:attempt-1",
        "bundle": {
            "schema_version": "1.0",
            "iac_engine": "terraform",
            "iac_engine_version": "1.16.2",
            "source_format_version": "1.2",
            "plan_timestamp": "2026-09-17T16:00:00Z",
            "plan_applyable": True,
            "plan_complete": True,
            "redaction_policy": "omit_change_values",
            "findings": [
                {
                    "source": "resource_drift",
                    "resource_address": 'module.web.aws_instance.app["blue"]',
                    "previous_resource_address": None,
                    "module_address": "module.web",
                    "deposed_key": None,
                    "resource_type": "aws_instance",
                    "resource_name": "app",
                    "resource_index": "blue",
                    "provider_name": "registry.terraform.io/hashicorp/aws",
                    "actions": ["update"],
                    "changed_paths": ["/instance_type"],
                    "sensitive_paths": [],
                    "unknown_paths": [],
                }
            ],
            "skipped_nonmanaged": 0,
        },
    }


@pytest.mark.asyncio
async def test_evidence_ingest_is_disabled_by_default_and_rejects_raw_change_values(monkeypatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with sessions() as db:
        org = Organization(name="Evidence Org", slug="evidence-org")
        db.add(org)
        await db.flush()
        workspace = Workspace(
            org_id=org.id,
            name="prod",
            slug="prod",
            provider=CloudProvider.AWS,
            region="us-east-1",
        )
        db.add(workspace)
        await db.commit()

    app = create_app()

    async def override_db():
        async with sessions() as db:
            try:
                yield db
                await db.commit()
            except Exception:
                await db.rollback()
                raise

    async def authenticate():
        return org

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[verify_api_key] = authenticate
    transport = httpx.ASGITransport(app=app)

    try:
        monkeypatch.delenv("DRIFTGUARD_EVIDENCE_INGEST_ENABLED", raising=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            disabled = await client.post(
                f"/workspaces/{workspace.id}/evidence",
                json=_request_payload(),
            )
            assert disabled.status_code == 503

            monkeypatch.setenv("DRIFTGUARD_EVIDENCE_INGEST_ENABLED", "true")
            raw_payload = _request_payload()
            raw_payload["bundle"]["findings"][0]["before"] = "DO_NOT_STORE_ME"
            rejected = await client.post(
                f"/workspaces/{workspace.id}/evidence",
                json=raw_payload,
            )
            assert rejected.status_code == 422

        async with sessions() as db:
            assert await db.scalar(select(func.count()).select_from(EvidenceSubmission)) == 0
    finally:
        app.dependency_overrides.clear()
        await engine.dispose()


@pytest.mark.asyncio
async def test_evidence_ingest_is_tenant_scoped_replay_safe_and_persists_only_redacted_provenance(monkeypatch):
    monkeypatch.setenv("DRIFTGUARD_EVIDENCE_INGEST_ENABLED", "1")
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with sessions() as db:
        org_a = Organization(name="Org A", slug="evidence-org-a")
        org_b = Organization(name="Org B", slug="evidence-org-b")
        db.add_all([org_a, org_b])
        await db.flush()
        workspace = Workspace(
            org_id=org_a.id,
            name="prod",
            slug="prod",
            provider=CloudProvider.AWS,
            region="us-east-1",
        )
        db.add(workspace)
        await db.commit()

    app = create_app()

    async def override_db():
        async with sessions() as db:
            try:
                yield db
                await db.commit()
            except Exception:
                await db.rollback()
                raise

    async def authenticate_a():
        return org_a

    async def authenticate_b():
        return org_b

    app.dependency_overrides[get_db] = override_db
    transport = httpx.ASGITransport(app=app)

    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            app.dependency_overrides[verify_api_key] = authenticate_a
            first = await client.post(
                f"/workspaces/{workspace.id}/evidence",
                json=_request_payload(),
            )
            assert first.status_code == 200
            first_payload = first.json()
            assert first_payload["replayed"] is False
            assert first_payload["lifecycle"]["created"] == 1
            scan_id = first_payload["scan_id"]

            replay = await client.post(
                f"/workspaces/{workspace.id}/evidence",
                json=_request_payload(),
            )
            assert replay.status_code == 200
            assert replay.json()["replayed"] is True
            assert replay.json()["scan_id"] == scan_id
            assert replay.json()["lifecycle"]["already_reconciled"] is True

            changed = _request_payload()
            changed["bundle"]["findings"][0]["changed_paths"] = ["/ami"]
            conflict = await client.post(
                f"/workspaces/{workspace.id}/evidence",
                json=changed,
            )
            assert conflict.status_code == 409

            app.dependency_overrides[verify_api_key] = authenticate_b
            cross_tenant = await client.post(
                f"/workspaces/{workspace.id}/evidence",
                json={**_request_payload(), "submission_id": "other-org-attempt"},
            )
            assert cross_tenant.status_code == 404

        async with sessions() as db:
            assert await db.scalar(select(func.count()).select_from(DriftScan)) == 1
            assert await db.scalar(select(func.count()).select_from(EvidenceSubmission)) == 1
            assert await db.scalar(select(func.count()).select_from(FindingIncident)) == 1
            assert await db.scalar(select(func.count()).select_from(FindingOccurrence)) == 1

            submission = (await db.execute(select(EvidenceSubmission))).scalar_one()
            assert submission.submission_id == "gha:run-123:attempt-1"
            assert submission.iac_engine == "terraform"
            assert submission.finding_count == 1
            assert submission.plan_complete is True

            incident = (await db.execute(select(FindingIncident))).scalar_one()
            assert incident.resource_address == 'module.web.aws_instance.app["blue"]'
            assert incident.changed_paths == ["/instance_type"]
    finally:
        app.dependency_overrides.clear()
        await engine.dispose()
