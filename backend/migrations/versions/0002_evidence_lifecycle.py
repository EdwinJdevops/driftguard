"""Add Evidence Core incident lifecycle persistence.

Revision ID: 0002_evidence_lifecycle
Revises: 0001_legacy_baseline
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_evidence_lifecycle"
down_revision: str | Sequence[str] | None = "0001_legacy_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "finding_incidents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("identity_version", sa.String(length=16), nullable=False),
        sa.Column("resource_address", sa.String(length=1000), nullable=False),
        sa.Column("deposed_key", sa.String(length=255), nullable=True),
        sa.Column("resource_type", sa.String(length=255), nullable=False),
        sa.Column("provider_name", sa.String(length=500), nullable=True),
        sa.Column("actions", sa.JSON(), nullable=False),
        sa.Column("changed_paths", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_scan_id", sa.String(length=36), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("reopen_count", sa.Integer(), nullable=False),
        sa.Column("reopened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("remediation_branch", sa.String(length=255), nullable=False),
        sa.Column("remediation_pr_url", sa.String(length=500), nullable=True),
        sa.Column("remediation_pr_number", sa.Integer(), nullable=True),
        *_timestamps(),
        sa.CheckConstraint("occurrence_count >= 1", name="ck_finding_incidents_occurrence_count"),
        sa.CheckConstraint("reopen_count >= 0", name="ck_finding_incidents_reopen_count"),
        sa.CheckConstraint("status IN ('open', 'resolved')", name="ck_finding_incidents_status"),
        sa.ForeignKeyConstraint(["last_scan_id"], ["drift_scans.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("workspace_id", "fingerprint", name="uq_finding_incidents_workspace_fingerprint"),
    )
    op.create_index(op.f("ix_finding_incidents_fingerprint"), "finding_incidents", ["fingerprint"], unique=False)
    op.create_index(op.f("ix_finding_incidents_status"), "finding_incidents", ["status"], unique=False)
    op.create_index(op.f("ix_finding_incidents_workspace_id"), "finding_incidents", ["workspace_id"], unique=False)

    op.create_table(
        "finding_occurrences",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_schema_version", sa.String(length=16), nullable=False),
        sa.Column("sensitive_paths", sa.JSON(), nullable=False),
        sa.Column("unknown_paths", sa.JSON(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["incident_id"], ["finding_incidents.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["drift_scans.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "scan_id", name="uq_finding_occurrences_incident_scan"),
    )
    op.create_index(op.f("ix_finding_occurrences_incident_id"), "finding_occurrences", ["incident_id"], unique=False)
    op.create_index(op.f("ix_finding_occurrences_scan_id"), "finding_occurrences", ["scan_id"], unique=False)
    op.create_index(op.f("ix_finding_occurrences_workspace_id"), "finding_occurrences", ["workspace_id"], unique=False)

    op.create_table(
        "evidence_cursors",
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("latest_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("latest_scan_id", sa.String(length=36), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["latest_scan_id"], ["drift_scans.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("workspace_id"),
    )

    op.create_table(
        "evidence_reconciliations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("observation_set_digest", sa.String(length=64), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("plan_complete", sa.Boolean(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_to_lifecycle", sa.Boolean(), nullable=False),
        sa.Column("reconciled_at", sa.DateTime(timezone=True), nullable=False),
        *_timestamps(),
        sa.CheckConstraint("finding_count >= 0", name="ck_evidence_reconciliations_finding_count"),
        sa.ForeignKeyConstraint(["scan_id"], ["drift_scans.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_evidence_reconciliations_scan_id"), "evidence_reconciliations", ["scan_id"], unique=True)
    op.create_index(op.f("ix_evidence_reconciliations_workspace_id"), "evidence_reconciliations", ["workspace_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_evidence_reconciliations_workspace_id"), table_name="evidence_reconciliations")
    op.drop_index(op.f("ix_evidence_reconciliations_scan_id"), table_name="evidence_reconciliations")
    op.drop_table("evidence_reconciliations")
    op.drop_table("evidence_cursors")
    op.drop_index(op.f("ix_finding_occurrences_workspace_id"), table_name="finding_occurrences")
    op.drop_index(op.f("ix_finding_occurrences_scan_id"), table_name="finding_occurrences")
    op.drop_index(op.f("ix_finding_occurrences_incident_id"), table_name="finding_occurrences")
    op.drop_table("finding_occurrences")
    op.drop_index(op.f("ix_finding_incidents_workspace_id"), table_name="finding_incidents")
    op.drop_index(op.f("ix_finding_incidents_status"), table_name="finding_incidents")
    op.drop_index(op.f("ix_finding_incidents_fingerprint"), table_name="finding_incidents")
    op.drop_table("finding_incidents")
