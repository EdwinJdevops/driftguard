from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.evidence.lifecycle import (
    INCIDENT_OPEN,
    LifecycleReconcileError,
    finding_fingerprint,
    reconcile_evidence_bundle,
    remediation_branch_for_fingerprint,
)
from backend.evidence.models import DriftEvidence, EvidenceBundle
from backend.models.base import Base
from backend.models.incidents import (
    EvidenceReconciliation,
    FindingIncident,
    FindingOccurrence,
)
from backend.models.models import CloudProvider, DriftScan, Organization, ScanStatus, Workspace


def _finding(
    *,
    address: str = 'module.compute.aws_instance.web["blue"]',
    deposed_key: str | None = None,
    actions: list[str] | None = None,
    changed_paths: list[str] | None = None,
    sensitive_paths: list[str] | None = None,
    unknown_paths: list[str] | None = None,
) -> DriftEvidence:
    return DriftEvidence(
        resource_address=address,
        previous_resource_address=None,
        module_address="module.compute",
        deposed_key=deposed_key,
        resource_type="aws_instance",
        resource_name="web",
        resource_index="blue",
        provider_name="registry.terraform.io/hashicorp/aws",
        actions=actions or ["update"],
        changed_paths=changed_paths or ["/instance_type"],
        sensitive_paths=sensitive_paths or [],
        unknown_paths=unknown_paths or [],
    )


def _bundle(*findings: DriftEvidence, complete: bool | None = True) -> EvidenceBundle:
    return EvidenceBundle(
        iac_engine="terraform",
        iac_engine_version="1.16.2",
        source_format_version="1.2",
        plan_timestamp="2026-09-14T13:00:00Z",
        plan_applyable=True,
        plan_complete=complete,
        findings=list(findings),
    )


async def _new_database():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
    )
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine, Session


async def _seed_workspace_and_scans(Session, scan_count: int = 4):
    async with Session() as db:
        org = Organization(name="Lifecycle Org", slug=f"lifecycle-org-{scan_count}")
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
        await db.flush()
        scans = [
            DriftScan(workspace_id=workspace.id, status=ScanStatus.COMPLETED)
            for _ in range(scan_count)
        ]
        db.add_all(scans)
        await db.commit()
        return workspace.id, [scan.id for scan in scans]


def test_fingerprint_is_deterministic_but_preserves_semantic_identity_boundaries():
    base = _finding(changed_paths=["/tags", "/instance_type", "/tags"])
    reordered = _finding(changed_paths=["/instance_type", "/tags"])
    mask_only_change = _finding(
        changed_paths=["/instance_type", "/tags"],
        sensitive_paths=["/tags"],
        unknown_paths=["/instance_type"],
    )

    fingerprint = finding_fingerprint(base)
    assert fingerprint == finding_fingerprint(reordered)
    assert fingerprint == finding_fingerprint(mask_only_change)
    assert len(fingerprint) == 64

    assert fingerprint != finding_fingerprint(_finding(address="aws_instance.other"))
    assert fingerprint != finding_fingerprint(_finding(deposed_key="deadbeef"))
    assert fingerprint != finding_fingerprint(_finding(actions=["delete", "create"]))
    assert fingerprint != finding_fingerprint(_finding(changed_paths=["/ami"]))
    assert remediation_branch_for_fingerprint(fingerprint) == f"driftguard/fix-{fingerprint}"


@pytest.mark.asyncio
async def test_lifecycle_create_repeat_resolve_and_reopen():
    engine, Session = await _new_database()
    workspace_id, scan_ids = await _seed_workspace_and_scans(Session, 4)
    finding = _finding()
    fingerprint = finding_fingerprint(finding)
    t0 = datetime(2026, 9, 14, 13, 0, tzinfo=UTC)

    try:
        async with Session() as db:
            first = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[0],
                bundle=_bundle(finding),
                observed_at=t0,
            )
            await db.commit()
            assert first.created == 1
            assert first.resolution_performed is True

        async with Session() as db:
            second = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[1],
                bundle=_bundle(finding),
                observed_at=t0 + timedelta(hours=1),
            )
            await db.commit()
            assert second.observed_existing == 1

        async with Session() as db:
            third = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[2],
                bundle=_bundle(),
                observed_at=t0 + timedelta(hours=2),
            )
            await db.commit()
            assert third.resolved == 1

        async with Session() as db:
            fourth = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[3],
                bundle=_bundle(finding),
                observed_at=t0 + timedelta(hours=3),
            )
            await db.commit()
            assert fourth.reopened == 1

        async with Session() as db:
            incident = (
                await db.execute(
                    select(FindingIncident).where(
                        FindingIncident.workspace_id == workspace_id,
                        FindingIncident.fingerprint == fingerprint,
                    )
                )
            ).scalar_one()
            assert incident.status == INCIDENT_OPEN
            assert incident.occurrence_count == 3
            assert incident.reopen_count == 1
            assert incident.resolved_at is None
            assert incident.remediation_branch == f"driftguard/fix-{fingerprint}"

            occurrence_count = await db.scalar(
                select(func.count()).select_from(FindingOccurrence)
            )
            reconciliation_count = await db.scalar(
                select(func.count()).select_from(EvidenceReconciliation)
            )
            assert occurrence_count == 3
            assert reconciliation_count == 4
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_incomplete_plan_cannot_resolve_missing_incident():
    engine, Session = await _new_database()
    workspace_id, scan_ids = await _seed_workspace_and_scans(Session, 2)
    finding = _finding()
    t0 = datetime(2026, 9, 14, 13, 0, tzinfo=UTC)

    try:
        async with Session() as db:
            await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[0],
                bundle=_bundle(finding),
                observed_at=t0,
            )
            await db.commit()

        async with Session() as db:
            result = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[1],
                bundle=_bundle(complete=False),
                observed_at=t0 + timedelta(hours=1),
            )
            await db.commit()
            assert result.resolution_performed is False
            assert result.resolved == 0

        async with Session() as db:
            incident = (
                await db.execute(
                    select(FindingIncident).where(FindingIncident.workspace_id == workspace_id)
                )
            ).scalar_one()
            assert incident.status == INCIDENT_OPEN
            assert incident.resolved_at is None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_clean_scan_replay_is_exactly_once_and_inconsistent_replay_fails_closed():
    engine, Session = await _new_database()
    workspace_id, scan_ids = await _seed_workspace_and_scans(Session, 1)
    t0 = datetime(2026, 9, 14, 13, 0, tzinfo=UTC)

    try:
        async with Session() as db:
            first = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[0],
                bundle=_bundle(),
                observed_at=t0,
            )
            await db.commit()
            assert first.already_reconciled is False

        async with Session() as db:
            replay = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[0],
                bundle=_bundle(),
                observed_at=t0 + timedelta(minutes=1),
            )
            await db.commit()
            assert replay.already_reconciled is True

        async with Session() as db:
            with pytest.raises(LifecycleReconcileError, match="Scan replay differs"):
                await reconcile_evidence_bundle(
                    db,
                    workspace_id=workspace_id,
                    scan_id=scan_ids[0],
                    bundle=_bundle(_finding()),
                    observed_at=t0 + timedelta(minutes=2),
                )
            await db.rollback()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_scan_workspace_mismatch_fails_before_lifecycle_mutation():
    engine, Session = await _new_database()
    _, scan_ids = await _seed_workspace_and_scans(Session, 1)

    async with Session() as db:
        org = Organization(name="Other Org", slug="other-lifecycle-org")
        db.add(org)
        await db.flush()
        workspace_b = Workspace(
            org_id=org.id,
            name="other",
            slug="other",
            provider=CloudProvider.AWS,
            region="us-east-1",
        )
        db.add(workspace_b)
        await db.commit()
        workspace_b_id = workspace_b.id

    try:
        async with Session() as db:
            with pytest.raises(LifecycleReconcileError, match="does not belong"):
                await reconcile_evidence_bundle(
                    db,
                    workspace_id=workspace_b_id,
                    scan_id=scan_ids[0],
                    bundle=_bundle(_finding()),
                )
            await db.rollback()

        async with Session() as db:
            incident_count = await db.scalar(
                select(func.count()).select_from(FindingIncident)
            )
            assert incident_count == 0
    finally:
        await engine.dispose()
