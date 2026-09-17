from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.incidents import EvidenceSubmission
from ..models.models import DriftScan, ScanStatus, Workspace
from .lifecycle import LifecycleResult, reconcile_evidence_bundle
from .models import EvidenceBundle


class EvidenceIngestConflictError(ValueError):
    """Raised when one idempotency key is reused for different evidence."""


@dataclass(frozen=True, slots=True)
class EvidenceIngestResult:
    scan_id: str
    submission_id: str
    bundle_digest: str
    replayed: bool
    lifecycle: LifecycleResult


def evidence_bundle_digest(bundle: EvidenceBundle) -> str:
    """Canonical SHA-256 over the already-redacted Evidence Bundle."""
    payload = bundle.model_dump(mode="json")
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


async def ingest_evidence_bundle(
    db: AsyncSession,
    *,
    workspace_id: str,
    submission_id: str,
    bundle: EvidenceBundle,
    received_at: datetime | None = None,
) -> EvidenceIngestResult:
    """Persist redacted provenance and reconcile lifecycle atomically.

    The surrounding transaction belongs to the caller. A workspace row lock
    serializes same-workspace submissions on PostgreSQL. Idempotency is scoped
    to ``(workspace_id, submission_id)``: an exact replay is safe, while reuse
    of the same key for different evidence fails closed.
    """
    if not submission_id or not submission_id.strip():
        raise ValueError("submission_id must contain a non-whitespace character.")
    if len(submission_id) > 255:
        raise ValueError("submission_id must not exceed 255 characters.")

    received_at = (received_at or datetime.now(UTC)).astimezone(UTC)
    digest = evidence_bundle_digest(bundle)

    workspace_result = await db.execute(
        select(Workspace.id).where(Workspace.id == workspace_id).with_for_update()
    )
    if workspace_result.scalar_one_or_none() is None:
        raise ValueError(f"Workspace {workspace_id} does not exist.")

    existing_result = await db.execute(
        select(EvidenceSubmission).where(
            EvidenceSubmission.workspace_id == workspace_id,
            EvidenceSubmission.submission_id == submission_id,
        )
    )
    existing = existing_result.scalar_one_or_none()
    if existing is not None:
        if existing.bundle_digest != digest:
            raise EvidenceIngestConflictError(
                "submission_id was already used with different evidence."
            )
        lifecycle = await reconcile_evidence_bundle(
            db,
            workspace_id=workspace_id,
            scan_id=existing.scan_id,
            bundle=bundle,
            observed_at=_as_utc(existing.received_at),
        )
        return EvidenceIngestResult(
            scan_id=existing.scan_id,
            submission_id=submission_id,
            bundle_digest=digest,
            replayed=True,
            lifecycle=lifecycle,
        )

    scan = DriftScan(
        workspace_id=workspace_id,
        status=ScanStatus.RUNNING,
        triggered_by="evidence",
        total_resources_checked=0,
        drift_count=bundle.finding_count,
        started_at=received_at,
    )
    db.add(scan)
    await db.flush()

    submission = EvidenceSubmission(
        workspace_id=workspace_id,
        scan_id=scan.id,
        submission_id=submission_id,
        bundle_digest=digest,
        schema_version=bundle.schema_version,
        iac_engine=bundle.iac_engine,
        iac_engine_version=bundle.iac_engine_version,
        source_format_version=bundle.source_format_version,
        plan_timestamp=bundle.plan_timestamp,
        plan_applyable=bundle.plan_applyable,
        plan_complete=bundle.plan_complete,
        redaction_policy=bundle.redaction_policy,
        finding_count=bundle.finding_count,
        skipped_nonmanaged=bundle.skipped_nonmanaged,
        received_at=received_at,
    )
    db.add(submission)
    await db.flush()

    lifecycle = await reconcile_evidence_bundle(
        db,
        workspace_id=workspace_id,
        scan_id=scan.id,
        bundle=bundle,
        observed_at=received_at,
    )

    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.now(UTC)
    await db.flush()

    return EvidenceIngestResult(
        scan_id=scan.id,
        submission_id=submission_id,
        bundle_digest=digest,
        replayed=False,
        lifecycle=lifecycle,
    )
