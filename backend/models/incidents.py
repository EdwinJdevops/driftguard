from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, generate_id


class FindingIncident(Base, TimestampMixin):
    """Workspace-scoped lifecycle record for one deterministic drift identity."""

    __tablename__ = "finding_incidents"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "fingerprint",
            name="uq_finding_incidents_workspace_fingerprint",
        ),
        CheckConstraint(
            "status IN ('open', 'resolved')",
            name="ck_finding_incidents_status",
        ),
        CheckConstraint(
            "occurrence_count >= 1",
            name="ck_finding_incidents_occurrence_count",
        ),
        CheckConstraint(
            "reopen_count >= 0",
            name="ck_finding_incidents_reopen_count",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_id)
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id"), nullable=False, index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    identity_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1")

    resource_address: Mapped[str] = mapped_column(String(1000), nullable=False)
    deposed_key: Mapped[str | None] = mapped_column(String(255))
    resource_type: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_name: Mapped[str | None] = mapped_column(String(500))
    actions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    changed_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False)

    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open", index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_scan_id: Mapped[str] = mapped_column(ForeignKey("drift_scans.id"), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    reopen_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reopened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Stable future GitHub idempotency key. The evidence path does not open PRs
    # yet, but every recurrence of the same incident receives the same branch.
    remediation_branch: Mapped[str] = mapped_column(String(255), nullable=False)
    remediation_pr_url: Mapped[str | None] = mapped_column(String(500))
    remediation_pr_number: Mapped[int | None] = mapped_column(Integer)


class FindingOccurrence(Base, TimestampMixin):
    """Redacted audit record that an incident was observed in a specific scan."""

    __tablename__ = "finding_occurrences"
    __table_args__ = (
        UniqueConstraint(
            "incident_id",
            "scan_id",
            name="uq_finding_occurrences_incident_scan",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_id)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("finding_incidents.id"), nullable=False, index=True
    )
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id"), nullable=False, index=True
    )
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("drift_scans.id"), nullable=False, index=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    sensitive_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    unknown_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False)


class EvidenceReconciliation(Base, TimestampMixin):
    """Exactly-once marker for lifecycle reconciliation of one scan."""

    __tablename__ = "evidence_reconciliations"
    __table_args__ = (
        CheckConstraint(
            "finding_count >= 0",
            name="ck_evidence_reconciliations_finding_count",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("drift_scans.id"), nullable=False, unique=True, index=True
    )
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id"), nullable=False, index=True
    )
    observation_set_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False)
    plan_complete: Mapped[bool | None] = mapped_column(Boolean)
    reconciled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
