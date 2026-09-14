from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.incidents import (
    EvidenceReconciliation,
    FindingIncident,
    FindingOccurrence,
)
from ..models.models import DriftScan, Workspace
from .models import DriftEvidence, EvidenceBundle

IDENTITY_VERSION = "1"
INCIDENT_OPEN = "open"
INCIDENT_RESOLVED = "resolved"
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


class LifecycleReconcileError(ValueError):
    """Raised when evidence cannot be reconciled without ambiguity."""


@dataclass(frozen=True, slots=True)
class LifecycleResult:
    created: int = 0
    observed_existing: int = 0
    reopened: int = 0
    resolved: int = 0
    already_reconciled: bool = False
    resolution_performed: bool = False


def finding_fingerprint(finding: DriftEvidence) -> str:
    """Return the deterministic v1 incident identity for one evidence record.

    Identity deliberately includes the ordered provider-native action sequence
    and the normalized changed-path surface. Sensitive/unknown masks describe
    observation quality, not incident identity, so they do not split one drift
    incident when only masking/knownness changes between scans.
    """
    payload = {
        "identity_version": IDENTITY_VERSION,
        "resource_address": finding.resource_address,
        "deposed_key": finding.deposed_key,
        "resource_type": finding.resource_type,
        "provider_name": finding.provider_name,
        "actions": list(finding.actions),
        "changed_paths": sorted(set(finding.changed_paths)),
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def remediation_branch_for_fingerprint(fingerprint: str) -> str:
    """Return the stable GitHub branch reserved for one incident identity."""
    if not _FINGERPRINT_RE.fullmatch(fingerprint):
        raise LifecycleReconcileError("Incident fingerprint must be a 64-character lowercase SHA-256 hex digest.")
    return f"driftguard/fix-{fingerprint}"


def _observation_set_digest(fingerprints: set[str]) -> str:
    canonical = "\n".join(sorted(fingerprints)).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


async def reconcile_evidence_bundle(
    db: AsyncSession,
    *,
    workspace_id: str,
    scan_id: str,
    bundle: EvidenceBundle,
    observed_at: datetime | None = None,
) -> LifecycleResult:
    """Reconcile one redacted Evidence Bundle into workspace incident state.

    The caller owns the surrounding transaction. Reconciliation is exactly-once
    per scan ID: replays with byte-equivalent incident identity are no-ops, and
    a replay whose evidence set or completeness differs fails closed.

    Missing incidents are resolved only when ``bundle.plan_complete is True``.
    Terraform/OpenTofu may emit incomplete/deferred plans; absence from such a
    plan is not proof that previously observed drift disappeared.
    """
    observed_at = observed_at or datetime.now(UTC)
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise LifecycleReconcileError("observed_at must be timezone-aware.")

    observations: dict[str, DriftEvidence] = {}
    for finding in bundle.findings:
        fingerprint = finding_fingerprint(finding)
        if fingerprint in observations:
            raise LifecycleReconcileError(
                f"Evidence bundle contains duplicate incident identity {fingerprint}."
            )
        observations[fingerprint] = finding

    observation_digest = _observation_set_digest(set(observations))

    # Serialize lifecycle mutation per workspace on databases that support row
    # locks. SQLite ignores FOR UPDATE, which is sufficient for deterministic
    # single-process tests; PostgreSQL production receives the real lock.
    workspace_result = await db.execute(
        select(Workspace.id).where(Workspace.id == workspace_id).with_for_update()
    )
    if workspace_result.scalar_one_or_none() is None:
        raise LifecycleReconcileError(f"Workspace {workspace_id} does not exist.")

    scan_result = await db.execute(
        select(DriftScan.id).where(
            DriftScan.id == scan_id,
            DriftScan.workspace_id == workspace_id,
        )
    )
    if scan_result.scalar_one_or_none() is None:
        raise LifecycleReconcileError(
            f"Scan {scan_id} does not belong to workspace {workspace_id}."
        )

    marker_result = await db.execute(
        select(EvidenceReconciliation).where(EvidenceReconciliation.scan_id == scan_id)
    )
    marker = marker_result.scalar_one_or_none()
    if marker is not None:
        if (
            marker.workspace_id != workspace_id
            or marker.observation_set_digest != observation_digest
            or marker.finding_count != len(observations)
            or marker.plan_complete is not bundle.plan_complete
        ):
            raise LifecycleReconcileError(
                "Scan replay differs from the evidence already reconciled for this scan ID."
            )
        return LifecycleResult(already_reconciled=True)

    incidents_result = await db.execute(
        select(FindingIncident).where(
            FindingIncident.workspace_id == workspace_id,
            FindingIncident.identity_version == IDENTITY_VERSION,
        )
    )
    incidents = {incident.fingerprint: incident for incident in incidents_result.scalars().all()}

    created = 0
    observed_existing = 0
    reopened = 0

    for fingerprint, finding in observations.items():
        incident = incidents.get(fingerprint)
        if incident is None:
            incident = FindingIncident(
                workspace_id=workspace_id,
                fingerprint=fingerprint,
                identity_version=IDENTITY_VERSION,
                resource_address=finding.resource_address,
                deposed_key=finding.deposed_key,
                resource_type=finding.resource_type,
                provider_name=finding.provider_name,
                actions=list(finding.actions),
                changed_paths=sorted(set(finding.changed_paths)),
                status=INCIDENT_OPEN,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                last_scan_id=scan_id,
                occurrence_count=1,
                reopen_count=0,
                remediation_branch=remediation_branch_for_fingerprint(fingerprint),
            )
            db.add(incident)
            await db.flush()
            incidents[fingerprint] = incident
            created += 1
        else:
            incident.last_seen_at = observed_at
            incident.last_scan_id = scan_id
            incident.occurrence_count += 1
            if incident.status == INCIDENT_RESOLVED:
                incident.status = INCIDENT_OPEN
                incident.resolved_at = None
                incident.reopened_at = observed_at
                incident.reopen_count += 1
                reopened += 1
            elif incident.status == INCIDENT_OPEN:
                observed_existing += 1
            else:
                raise LifecycleReconcileError(
                    f"Incident {incident.id} has unsupported lifecycle status {incident.status!r}."
                )

        db.add(
            FindingOccurrence(
                incident_id=incident.id,
                workspace_id=workspace_id,
                scan_id=scan_id,
                observed_at=observed_at,
                evidence_schema_version=bundle.schema_version,
                sensitive_paths=sorted(set(finding.sensitive_paths)),
                unknown_paths=sorted(set(finding.unknown_paths)),
            )
        )

    resolved = 0
    resolution_performed = bundle.plan_complete is True
    if resolution_performed:
        observed_fingerprints = set(observations)
        for fingerprint, incident in incidents.items():
            if fingerprint in observed_fingerprints:
                continue
            if incident.status == INCIDENT_OPEN:
                incident.status = INCIDENT_RESOLVED
                incident.resolved_at = observed_at
                resolved += 1

    db.add(
        EvidenceReconciliation(
            scan_id=scan_id,
            workspace_id=workspace_id,
            observation_set_digest=observation_digest,
            finding_count=len(observations),
            plan_complete=bundle.plan_complete,
            reconciled_at=observed_at,
        )
    )
    await db.flush()

    return LifecycleResult(
        created=created,
        observed_existing=observed_existing,
        reopened=reopened,
        resolved=resolved,
        resolution_performed=resolution_performed,
    )
