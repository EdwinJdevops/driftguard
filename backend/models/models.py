from __future__ import annotations
from sqlalchemy import String, Text, Boolean, Integer, Float, JSON, ForeignKey, Enum as SAEnum, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from .base import Base, TimestampMixin, generate_id
import enum


class PlanTier(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    TEAM = "team"
    ENTERPRISE = "enterprise"


class CloudProvider(str, enum.Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class StateBackend(str, enum.Enum):
    UPLOAD = "upload"        # state pasted/uploaded directly per-scan
    S3 = "s3"                 # Terraform S3 backend
    TERRAFORM_CLOUD = "terraform_cloud"


class DriftStatus(str, enum.Enum):
    OPEN = "open"
    PR_OPENED = "pr_opened"
    RESOLVED = "resolved"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_id)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    plan: Mapped[PlanTier] = mapped_column(SAEnum(PlanTier), default=PlanTier.FREE, nullable=False)
    github_org: Mapped[str | None] = mapped_column(String(255))
    stripe_customer_id: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    max_workspaces: Mapped[int] = mapped_column(Integer, default=1)
    max_resources: Mapped[int] = mapped_column(Integer, default=50)

    workspaces: Mapped[list["Workspace"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    api_keys: Mapped[list["APIKey"]] = relationship(back_populates="organization", cascade="all, delete-orphan")


class APIKey(Base, TimestampMixin):
    """
    API key authentication. Key format: dg_live_<32 random chars>
    Only the SHA-256 hash is stored — the raw key is shown once at creation
    and cannot be retrieved again, same pattern as Stripe/GitHub tokens.
    """
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)  # shown in UI e.g. "dg_live_8f2a"
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization] = relationship(back_populates="api_keys")


class Workspace(Base, TimestampMixin):
    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    provider: Mapped[CloudProvider] = mapped_column(SAEnum(CloudProvider), nullable=False)
    region: Mapped[str] = mapped_column(String(100), nullable=False)

    # State source configuration
    state_backend: Mapped[StateBackend] = mapped_column(SAEnum(StateBackend), default=StateBackend.UPLOAD)
    s3_bucket: Mapped[str | None] = mapped_column(String(255))
    s3_key: Mapped[str | None] = mapped_column(String(500))
    s3_region: Mapped[str | None] = mapped_column(String(100))

    # GitHub integration
    github_repo: Mapped[str | None] = mapped_column(String(500))
    github_branch: Mapped[str] = mapped_column(String(255), default="main")
    terraform_dir: Mapped[str] = mapped_column(String(500), default=".")
    # ID of the GitHub App installation covering github_repo. A GitHub App
    # installation token is scoped only to repos that installation covers —
    # this is what makes per-tenant isolation possible instead of one PAT
    # with access to every customer's repo.
    github_app_installation_id: Mapped[str | None] = mapped_column(String(100))

    # Cross-account access via STS AssumeRole — DriftGuard never stores or
    # receives raw AWS access keys. The customer creates an IAM role in
    # their account trusting DriftGuard's account, gated by external_id.
    # If aws_role_arn is null, the scan falls back to the ambient credential
    # chain (single-account self-hosted deployments running inside the
    # target account already).
    aws_role_arn: Mapped[str | None] = mapped_column(String(500))
    aws_external_id: Mapped[str | None] = mapped_column(String(255))

    scan_interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    auto_pr_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notifications_slack_webhook: Mapped[str | None] = mapped_column(String(500))
    notifications_email: Mapped[str | None] = mapped_column(String(255))

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization] = relationship(back_populates="workspaces")
    scans: Mapped[list["DriftScan"]] = relationship(back_populates="workspace", cascade="all, delete-orphan")
    findings: Mapped[list["DriftFinding"]] = relationship(back_populates="workspace", cascade="all, delete-orphan")


class DriftScan(Base, TimestampMixin):
    __tablename__ = "drift_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    triggered_by: Mapped[str] = mapped_column(String(100), default="manual")

    total_resources_checked: Mapped[int] = mapped_column(Integer, default=0)
    drift_count: Mapped[int] = mapped_column(Integer, default=0)
    security_findings_count: Mapped[int] = mapped_column(Integer, default=0)
    cost_delta_monthly: Mapped[float | None] = mapped_column(Float)
    posture_score: Mapped[float | None] = mapped_column(Float)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)

    workspace: Mapped[Workspace] = relationship(back_populates="scans")
    findings: Mapped[list["DriftFinding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class DriftFinding(Base, TimestampMixin):
    __tablename__ = "drift_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    scan_id: Mapped[str] = mapped_column(ForeignKey("drift_scans.id"), nullable=False)

    resource_type: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(500), nullable=False)
    resource_name: Mapped[str | None] = mapped_column(String(500))
    region: Mapped[str | None] = mapped_column(String(100))

    status: Mapped[DriftStatus] = mapped_column(SAEnum(DriftStatus), default=DriftStatus.OPEN)
    severity: Mapped[SeverityLevel] = mapped_column(SAEnum(SeverityLevel), default=SeverityLevel.MEDIUM)
    drift_type: Mapped[str] = mapped_column(String(20), default="modified")

    expected_state: Mapped[dict | None] = mapped_column(JSON)
    actual_state: Mapped[dict | None] = mapped_column(JSON)
    diff_summary: Mapped[str | None] = mapped_column(Text)

    security_impact: Mapped[list | None] = mapped_column(JSON)
    compliance_violations: Mapped[list | None] = mapped_column(JSON)

    cost_delta_monthly: Mapped[float | None] = mapped_column(Float)

    terraform_patch: Mapped[str | None] = mapped_column(Text)
    github_pr_url: Mapped[str | None] = mapped_column(String(500))
    github_pr_number: Mapped[int | None] = mapped_column(Integer)

    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[str | None] = mapped_column(String(255))

    workspace: Mapped[Workspace] = relationship(back_populates="findings")
    scan: Mapped[DriftScan] = relationship(back_populates="findings")
