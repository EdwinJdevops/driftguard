from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.evidence.lifecycle import (
    INCIDENT_OPEN,
    INCIDENT_RESOLVED,
    LifecycleReconcileError,
    finding_fingerprint,
    reconcile_evidence_bundle,
    remediation_branch_for_fingerprint,
)
from backend.evidence.models import DriftEvidence, EvidenceBundle
from backend.models.base import Base
from backend.models.incidents import (
    EvidenceCursor,
    EvidenceReconciliation,
    FindingIncident,
    FindingOccurrence,
)
from backend.models.models import (
    CloudProvider,
    DriftScan,
    Organization,
    ScanStatus,
    Workspace,
)


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
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine, session_factory


async def _seed_workspace_and_scans(session_factory, scan_count: int):
    async with session_factory() as db:
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


def test_fingerprint_normalizes_paths_but_preserves_incident_boundaries():
    base = _finding(changed_paths=["/tags", "/instance_type", "/tags"])
    normalized = _finding(changed_paths=["/instance_type", "/tags"])
    masks_changed = _finding(
        changed_paths=["/instance_type", "/tags"],
        sensitive_paths=["/tags"],
        unknown_paths=["/instance_type"],
    )

    fingerprint = finding_fingerprint(base)
    assert fingerprint == finding_fingerprint(normalized)
    assert fingerprint == finding_fingerprint(masks_changed)
    assert len(fingerprint) == 64
    assert fingerprint != finding_fingerprint(_finding(address="aws_instance.other"))
    assert fingerprint != finding_fingerprint(_finding(deposed_key="deadbeef"))
    assert fingerprint != finding_fingerprint(_finding(actions=["delete", "create"]))
    assert fingerprint != finding_fingerprint(_finding(changed_paths=["/ami"]))
    assert remediation_branch_for_fingerprint(fingerprint) == f"driftguard/fix-{fingerprint}"


@pytest.mark.asyncio
async def test_create_repeat_resolve_and_reopen_lifecycle():
    engine, sessions = await _new_database()
    workspace_id, scan_ids = await _seed_workspace_and_scans(sessions, 4)
    finding = _finding()
    fingerprint = finding_fingerprint(finding)
    t0 = datetime(2026, 9, 14, 13, 0, tzinfo=UTC)

    try:
        async with sessions() as db:
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

        async with sessions() as db:
            repeated = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[1],
                bundle=_bundle(finding),
                observed_at=t0 + timedelta(hours=1),
            )
            await db.commit()
            assert repeated.observed_existing == 1

        async with sessions() as db:
            resolved = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[2],
                bundle=_bundle(),
                observed_at=t0 + timedelta(hours=2),
            )
            await db.commit()
            assert resolved.resolved == 1

        async with sessions() as db:
            reopened = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[3],
                bundle=_bundle(finding),
                observed_at=t0 + timedelta(hours=3),
            )
            await db.commit()
            assert reopened.reopened == 1

        async with sessions() as db:
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
            assert await db.scalar(select(func.count()).select_from(FindingOccurrence)) == 3
            assert await db.scalar(select(func.count()).select_from(EvidenceReconciliation)) == 4
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_incomplete_plan_cannot_resolve_missing_incident():
    engine, sessions = await _new_database()
    workspace_id, scan_ids = await _seed_workspace_and_scans(sessions, 2)
    finding = _finding()
    t0 = datetime(2026, 9, 14, 13, 0, tzinfo=UTC)

    try:
        async with sessions() as db:
            await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[0],
                bundle=_bundle(finding),
                observed_at=t0,
            )
            await db.commit()

        async with sessions() as db:
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

        async with sessions() as db:
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
async def test_scan_replay_is_exactly_once_and_inconsistent_replay_fails_closed():
    engine, sessions = await _new_database()
    workspace_id, scan_ids = await _seed_workspace_and_scans(sessions, 1)
    observed_at = datetime(2026, 9, 14, 13, 0, tzinfo=UTC)

    try:
        async with sessions() as db:
            await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[0],
                bundle=_bundle(),
                observed_at=observed_at,
            )
            await db.commit()

        async with sessions() as db:
            replay = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[0],
                bundle=_bundle(),
                observed_at=observed_at,
            )
            await db.commit()
            assert replay.already_reconciled is True

        async with sessions() as db:
            with pytest.raises(LifecycleReconcileError, match="Scan replay differs"):
                await reconcile_evidence_bundle(
                    db,
                    workspace_id=workspace_id,
                    scan_id=scan_ids[0],
                    bundle=_bundle(_finding()),
                    observed_at=observed_at + timedelta(minutes=1),
                )
            await db.rollback()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_scan_workspace_mismatch_fails_before_mutation():
    engine, sessions = await _new_database()
    _, scan_ids = await _seed_workspace_and_scans(sessions, 1)

    async with sessions() as db:
        org = Organization(name="Other Org", slug="other-lifecycle-org")
        db.add(org)
        await db.flush()
        workspace = Workspace(
            org_id=org.id,
            name="other",
            slug="other",
            provider=CloudProvider.AWS,
            region="us-east-1",
        )
        db.add(workspace)
        await db.commit()
        wrong_workspace_id = workspace.id

    try:
        async with sessions() as db:
            with pytest.raises(LifecycleReconcileError, match="does not belong"):
                await reconcile_evidence_bundle(
                    db,
                    workspace_id=wrong_workspace_id,
                    scan_id=scan_ids[0],
                    bundle=_bundle(_finding()),
                    observed_at=datetime(2026, 9, 14, 13, 0, tzinfo=UTC),
                )
            await db.rollback()

        async with sessions() as db:
            assert await db.scalar(select(func.count()).select_from(FindingIncident)) == 0
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_out_of_order_scan_cannot_roll_back_newer_lifecycle_state():
    engine, sessions = await _new_database()
    workspace_id, scan_ids = await _seed_workspace_and_scans(sessions, 3)
    finding = _finding()
    t0 = datetime(2026, 9, 14, 13, 0, tzinfo=UTC)

    try:
        async with sessions() as db:
            await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[0],
                bundle=_bundle(finding),
                observed_at=t0,
            )
            await db.commit()

        async with sessions() as db:
            result = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[2],
                bundle=_bundle(),
                observed_at=t0 + timedelta(hours=2),
            )
            await db.commit()
            assert result.resolved == 1

        async with sessions() as db:
            stale = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[1],
                bundle=_bundle(finding),
                observed_at=t0 + timedelta(hours=1),
            )
            await db.commit()
            assert stale.stale_ignored is True
            assert stale.reopened == 0

        async with sessions() as db:
            incident = (
                await db.execute(
                    select(FindingIncident).where(FindingIncident.workspace_id == workspace_id)
                )
            ).scalar_one()
            assert incident.status == INCIDENT_RESOLVED
            assert incident.occurrence_count == 1
            assert incident.reopen_count == 0

            marker = (
                await db.execute(
                    select(EvidenceReconciliation).where(
                        EvidenceReconciliation.scan_id == scan_ids[1]
                    )
                )
            ).scalar_one()
            assert marker.applied_to_lifecycle is False

            cursor = (
                await db.execute(
                    select(EvidenceCursor).where(EvidenceCursor.workspace_id == workspace_id)
                )
            ).scalar_one()
            assert cursor.latest_scan_id == scan_ids[2]

        async with sessions() as db:
            replay = await reconcile_evidence_bundle(
                db,
                workspace_id=workspace_id,
                scan_id=scan_ids[1],
                bundle=_bundle(finding),
                observed_at=t0 + timedelta(hours=1),
            )
            await db.commit()
            assert replay.already_reconciled is True
            assert replay.stale_ignored is True
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_timezone_naive_observation_is_rejected():
    engine, sessions = await _new_database()
    workspace_id, scan_ids = await _seed_workspace_and_scans(sessions, 1)
    naive_observed_at = datetime(2026, 9, 14, 13, 0, tzinfo=UTC).replace(tzinfo=None)

    try:
        async with sessions() as db:
            with pytest.raises(LifecycleReconcileError, match="timezone-aware"):
                await reconcile_evidence_bundle(
                    db,
                    workspace_id=workspace_id,
                    scan_id=scan_ids[0],
                    bundle=_bundle(_finding()),
                    observed_at=naive_observed_at,
                )
            await db.rollback()
    finally:
        await engine.dispose()
