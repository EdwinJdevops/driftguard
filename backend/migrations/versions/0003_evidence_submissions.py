"""Add redacted provider-native evidence submission provenance.

Revision ID: 0003_evidence_submissions
Revises: 0002_evidence_lifecycle
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_evidence_submissions"
down_revision: str | Sequence[str] | None = "0002_evidence_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_submissions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("submission_id", sa.String(length=255), nullable=False),
        sa.Column("bundle_digest", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("iac_engine", sa.String(length=20), nullable=False),
        sa.Column("iac_engine_version", sa.String(length=64), nullable=True),
        sa.Column("source_format_version", sa.String(length=32), nullable=False),
        sa.Column("plan_timestamp", sa.String(length=64), nullable=True),
        sa.Column("plan_applyable", sa.Boolean(), nullable=True),
        sa.Column("plan_complete", sa.Boolean(), nullable=True),
        sa.Column("redaction_policy", sa.String(length=64), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("skipped_nonmanaged", sa.Integer(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("finding_count >= 0", name="ck_evidence_submissions_finding_count"),
        sa.CheckConstraint("skipped_nonmanaged >= 0", name="ck_evidence_submissions_skipped_nonmanaged"),
        sa.ForeignKeyConstraint(["scan_id"], ["drift_scans.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("workspace_id", "submission_id", name="uq_evidence_submissions_workspace_submission"),
    )
    op.create_index(op.f("ix_evidence_submissions_scan_id"), "evidence_submissions", ["scan_id"], unique=True)
    op.create_index(op.f("ix_evidence_submissions_workspace_id"), "evidence_submissions", ["workspace_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_evidence_submissions_workspace_id"), table_name="evidence_submissions")
    op.drop_index(op.f("ix_evidence_submissions_scan_id"), table_name="evidence_submissions")
    op.drop_table("evidence_submissions")
