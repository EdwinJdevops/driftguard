from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.auth import verify_api_key
from ..database import get_db
from ..evidence.ingest import EvidenceIngestConflictError, ingest_evidence_bundle
from ..evidence.lifecycle import LifecycleReconcileError
from ..evidence.models import EvidenceBundle
from ..models.models import Organization, Workspace

router = APIRouter(tags=["evidence"])


class EvidenceIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    submission_id: str = Field(min_length=1, max_length=255)
    bundle: EvidenceBundle


class EvidenceLifecycleResponse(BaseModel):
    created: int
    observed_existing: int
    reopened: int
    resolved: int
    already_reconciled: bool
    stale_ignored: bool
    resolution_performed: bool


class EvidenceIngestResponse(BaseModel):
    workspace_id: str
    scan_id: str
    submission_id: str
    bundle_digest: str
    replayed: bool
    finding_count: int
    skipped_nonmanaged: int
    lifecycle: EvidenceLifecycleResponse


def evidence_ingest_enabled() -> bool:
    return os.getenv("DRIFTGUARD_EVIDENCE_INGEST_ENABLED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


@router.post(
    "/workspaces/{workspace_id}/evidence",
    response_model=EvidenceIngestResponse,
)
async def ingest_workspace_evidence(
    workspace_id: str,
    body: EvidenceIngestRequest,
    org: Organization = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db),
):
    if not evidence_ingest_enabled():
        raise HTTPException(
            status_code=503,
            detail="Provider-native evidence ingestion is disabled.",
        )

    workspace_result = await db.execute(
        select(Workspace.id).where(
            Workspace.id == workspace_id,
            Workspace.org_id == org.id,
        )
    )
    if workspace_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Workspace not found.")

    try:
        result = await ingest_evidence_bundle(
            db,
            workspace_id=workspace_id,
            submission_id=body.submission_id,
            bundle=body.bundle,
        )
    except EvidenceIngestConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (LifecycleReconcileError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return EvidenceIngestResponse(
        workspace_id=workspace_id,
        scan_id=result.scan_id,
        submission_id=result.submission_id,
        bundle_digest=result.bundle_digest,
        replayed=result.replayed,
        finding_count=body.bundle.finding_count,
        skipped_nonmanaged=body.bundle.skipped_nonmanaged,
        lifecycle=EvidenceLifecycleResponse(
            created=result.lifecycle.created,
            observed_existing=result.lifecycle.observed_existing,
            reopened=result.lifecycle.reopened,
            resolved=result.lifecycle.resolved,
            already_reconciled=result.lifecycle.already_reconciled,
            stale_ignored=result.lifecycle.stale_ignored,
            resolution_performed=result.lifecycle.resolution_performed,
        ),
    )
