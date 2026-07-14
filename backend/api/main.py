"""
DriftGuard API — Production Application

Wires together: persistent DB, API key auth, rate limiting,
S3 remote state, async scan execution.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import structlog
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import init_db, get_db, db_session
from ..core.auth import verify_api_key, generate_api_key
from ..models.models import (
    Organization, Workspace, DriftScan, DriftFinding, APIKey,
    CloudProvider, ScanStatus, DriftStatus, SeverityLevel, StateBackend,
)
from ..engines.drift import TerraformStateParser, AWSStateCollector, DriftAnalyzer, PostureScorer
from ..integrations.s3_state import S3StateReader
from ..integrations.aws_auth import generate_external_id, resolve_scan_session, check_role_misconfigured
from ..integrations.github_pr import open_remediation_pr

log = structlog.get_logger(__name__)

limiter = Limiter(key_func=get_remote_address)

GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_APP_PRIVATE_KEY = os.getenv("GITHUB_APP_PRIVATE_KEY")


# ── SCHEMAS ──────────────────────────────────────────────────────────────

class SignupRequest(BaseModel):
    org_name: str = Field(..., min_length=2, max_length=255)
    org_slug: str = Field(..., min_length=2, max_length=100, pattern="^[a-z0-9-]+$")


class SignupResponse(BaseModel):
    org_id: str
    org_name: str
    api_key: str
    warning: str = "Store this API key now. It cannot be retrieved again."


class WorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    provider: str = Field(default="aws", pattern="^(aws|azure|gcp)$")
    region: str = Field(..., min_length=1)
    state_backend: str = Field(default="upload", pattern="^(upload|s3|terraform_cloud)$")
    s3_bucket: str | None = None
    s3_key: str | None = None
    s3_region: str | None = None
    github_repo: str | None = None
    github_branch: str = "main"
    github_app_installation_id: str | None = Field(
        default=None,
        description="GitHub App installation ID covering github_repo. Required for PR automation.",
    )
    scan_interval_minutes: int = Field(default=60, ge=5, le=1440)
    auto_pr_enabled: bool = True
    aws_role_arn: str | None = Field(
        default=None,
        description=(
            "IAM role ARN in the target AWS account for DriftGuard to assume "
            "via STS. Omit for self-hosted single-account deployments where "
            "DriftGuard already runs with an IAM role scoped to this account."
        ),
    )


class WorkspaceCreateResponse(BaseModel):
    id: str
    name: str
    provider: str
    region: str
    state_backend: str
    created_at: str
    aws_external_id: str | None = None
    trust_policy_setup: dict | None = None


class ScanTriggerRequest(BaseModel):
    state_file_content: dict | None = None


# ── APP FACTORY ──────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    log.info("DriftGuard API started", db_ready=True)
    yield
    log.info("DriftGuard API shutting down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="DriftGuard",
        description="Detect drift. Fix it. Keep your cloud honest.",
        version="2.0.0",
        lifespan=lifespan,
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_routes(app)
    return app


def register_routes(app: FastAPI):

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": "2.0.0", "timestamp": datetime.now(timezone.utc).isoformat()}

    @app.get("/api")
    async def api_info():
        return {
            "name": "DriftGuard",
            "tagline": "Detect drift. Fix it. Keep your cloud honest.",
            "docs": "/docs",
            "version": "2.0.0",
        }

    @app.post("/signup", response_model=SignupResponse, status_code=201)
    @limiter.limit("5/hour")
    async def signup(request: Request, body: SignupRequest, db: AsyncSession = Depends(get_db)):
        existing = await db.execute(select(Organization).where(Organization.slug == body.org_slug))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Organization slug already taken.")

        org = Organization(name=body.org_name, slug=body.org_slug)
        db.add(org)
        await db.flush()

        raw_key, key_hash, prefix = generate_api_key()
        api_key = APIKey(org_id=org.id, name="Default Key", key_hash=key_hash, key_prefix=prefix)
        db.add(api_key)
        await db.flush()

        log.info("New organization signup", org_id=org.id, slug=org.slug)
        return SignupResponse(org_id=org.id, org_name=org.name, api_key=raw_key)

    @app.post("/workspaces", status_code=201)
    @limiter.limit("30/minute")
    async def create_workspace(
        request: Request,
        body: WorkspaceCreate,
        org: Organization = Depends(verify_api_key),
        db: AsyncSession = Depends(get_db),
    ):
        count_result = await db.execute(select(Workspace).where(Workspace.org_id == org.id))
        existing_count = len(count_result.scalars().all())
        if existing_count >= org.max_workspaces:
            raise HTTPException(
                status_code=403,
                detail=f"Workspace limit reached ({org.max_workspaces}). Upgrade plan to add more.",
            )

        external_id = generate_external_id() if body.aws_role_arn else None

        ws = Workspace(
            org_id=org.id,
            name=body.name,
            slug=body.name.lower().replace(" ", "-"),
            provider=CloudProvider(body.provider),
            region=body.region,
            state_backend=StateBackend(body.state_backend),
            s3_bucket=body.s3_bucket,
            s3_key=body.s3_key,
            s3_region=body.s3_region or body.region,
            github_repo=body.github_repo,
            github_branch=body.github_branch,
            github_app_installation_id=body.github_app_installation_id,
            scan_interval_minutes=body.scan_interval_minutes,
            auto_pr_enabled=body.auto_pr_enabled,
            aws_role_arn=body.aws_role_arn,
            aws_external_id=external_id,
        )
        db.add(ws)
        await db.flush()

        trust_policy_setup = None
        if body.aws_role_arn:
            trust_policy_setup = {
                "instructions": (
                    "Add this trust policy to the IAM role so DriftGuard can "
                    "assume it. The external_id is required."
                ),
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": os.getenv("DRIFTGUARD_AWS_ACCOUNT_ID", "<driftguard-account-id>")},
                            "Action": "sts:AssumeRole",
                            "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
                        }
                    ],
                },
            }

        return WorkspaceCreateResponse(
            id=ws.id, name=ws.name, provider=ws.provider.value,
            region=ws.region, state_backend=ws.state_backend.value,
            created_at=ws.created_at.isoformat(),
            aws_external_id=external_id,
            trust_policy_setup=trust_policy_setup,
        )

    @app.post("/workspaces/{workspace_id}/verify-role")
    @limiter.limit("20/minute")
    async def verify_role(
        request: Request,
        workspace_id: str,
        org: Organization = Depends(verify_api_key),
        db: AsyncSession = Depends(get_db),
    ):
        """
        Called after the customer has created the IAM role in AWS. Confirms:
          1. The role is actually assumable with the correct external ID.
          2. The trust policy enforces the external ID condition — i.e. it
             does NOT also accept a wrong/blank external ID.
        A workspace with a role_arn is not usable for scanning until this
        passes; failing closed here is deliberate — an unverified role could
        mean either a broken setup (scans fail) or a misconfigured trust
        policy open to any AWS account (a real, exploitable hole).
        """
        ws_result = await db.execute(
            select(Workspace).where(Workspace.id == workspace_id, Workspace.org_id == org.id)
        )
        workspace = ws_result.scalar_one_or_none()
        if not workspace:
            raise HTTPException(status_code=404, detail="Workspace not found.")
        if not workspace.aws_role_arn or not workspace.aws_external_id:
            raise HTTPException(status_code=400, detail="Workspace has no aws_role_arn configured.")

        assume_result = resolve_scan_session(workspace.aws_role_arn, workspace.aws_external_id, workspace.region)
        if not assume_result.success:
            raise HTTPException(
                status_code=422,
                detail=f"Role is not assumable with the configured external ID: {assume_result.error}",
            )

        try:
            is_misconfigured = check_role_misconfigured(workspace.aws_role_arn, workspace.region)
        except Exception as e:
            raise HTTPException(
                status_code=422,
                detail=f"Could not verify trust policy safety: {e}",
            )

        if is_misconfigured:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Role is assumable WITHOUT the correct external ID — the trust policy "
                    "does not enforce sts:ExternalId. This role is exploitable by any AWS "
                    "account that guesses the ARN. Fix the trust policy Condition block before retrying."
                ),
            )

        return {
            "workspace_id": workspace.id,
            "verified": True,
            "expiration": assume_result.expiration,
        }

    @app.get("/workspaces")
    @limiter.limit("60/minute")
    async def list_workspaces(
        request: Request,
        org: Organization = Depends(verify_api_key),
        db: AsyncSession = Depends(get_db),
    ):
        result = await db.execute(select(Workspace).where(Workspace.org_id == org.id))
        workspaces = result.scalars().all()
        return {
            "workspaces": [
                {
                    "id": w.id, "name": w.name, "provider": w.provider.value,
                    "region": w.region, "is_active": w.is_active,
                    "last_scanned_at": w.last_scanned_at.isoformat() if w.last_scanned_at else None,
                }
                for w in workspaces
            ]
        }

    @app.post("/workspaces/{workspace_id}/scan")
    @limiter.limit("10/minute")
    async def trigger_scan(
        request: Request,
        workspace_id: str,
        body: ScanTriggerRequest,
        background_tasks: BackgroundTasks,
        org: Organization = Depends(verify_api_key),
        db: AsyncSession = Depends(get_db),
    ):
        ws_result = await db.execute(
            select(Workspace).where(Workspace.id == workspace_id, Workspace.org_id == org.id)
        )
        workspace = ws_result.scalar_one_or_none()
        if not workspace:
            raise HTTPException(status_code=404, detail="Workspace not found.")

        scan = DriftScan(workspace_id=workspace.id, status=ScanStatus.PENDING, triggered_by="api")
        db.add(scan)
        await db.flush()
        scan_id = scan.id

        # Explicit commit required: BackgroundTasks execute in a separate DB
        # session/transaction. Without committing now, the background task
        # cannot see this row — it was only flushed in the request-scoped
        # transaction, not committed. Relying on get_db's post-yield commit
        # timing relative to background task execution is not guaranteed.
        await db.commit()

        background_tasks.add_task(
            run_scan_pipeline,
            workspace_id=workspace.id,
            scan_id=scan_id,
            state_content=body.state_file_content,
            state_backend=workspace.state_backend,
            s3_bucket=workspace.s3_bucket,
            s3_key=workspace.s3_key,
            s3_region=workspace.s3_region,
            region=workspace.region,
            aws_role_arn=workspace.aws_role_arn,
            aws_external_id=workspace.aws_external_id,
        )

        return {"scan_id": scan_id, "workspace_id": workspace.id, "status": "pending"}

    @app.get("/scans/{scan_id}")
    @limiter.limit("60/minute")
    async def get_scan(
        request: Request,
        scan_id: str,
        org: Organization = Depends(verify_api_key),
        db: AsyncSession = Depends(get_db),
    ):
        result = await db.execute(select(DriftScan).where(DriftScan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")

        findings_result = await db.execute(select(DriftFinding).where(DriftFinding.scan_id == scan_id))
        findings = findings_result.scalars().all()

        return {
            "id": scan.id, "status": scan.status.value,
            "total_resources_checked": scan.total_resources_checked,
            "drift_count": scan.drift_count,
            "posture_score": scan.posture_score,
            "cost_delta_monthly": scan.cost_delta_monthly,
            "error_message": scan.error_message,
            "findings": [
                {
                    "id": f.id, "resource_type": f.resource_type, "resource_id": f.resource_id,
                    "severity": f.severity.value, "drift_type": f.drift_type,
                    "diff_summary": f.diff_summary, "security_impact": f.security_impact,
                    "compliance_violations": f.compliance_violations,
                    "cost_delta_monthly": f.cost_delta_monthly,
                    "terraform_patch": f.terraform_patch,
                    "status": f.status.value,
                    "github_pr_url": f.github_pr_url,
                    "github_pr_number": f.github_pr_number,
                }
                for f in findings
            ],
        }

    @app.get("/findings")
    @limiter.limit("60/minute")
    async def list_findings(
        request: Request,
        severity: str | None = None,
        org: Organization = Depends(verify_api_key),
        db: AsyncSession = Depends(get_db),
    ):
        ws_result = await db.execute(select(Workspace.id).where(Workspace.org_id == org.id))
        workspace_ids = [w[0] for w in ws_result.all()]

        if not workspace_ids:
            return {"findings": [], "total": 0}

        query = select(DriftFinding).where(
            DriftFinding.workspace_id.in_(workspace_ids),
            DriftFinding.status == DriftStatus.OPEN,
        )
        if severity:
            query = query.where(DriftFinding.severity == SeverityLevel(severity))

        result = await db.execute(query)
        findings = result.scalars().all()

        return {
            "findings": [
                {
                    "id": f.id, "resource_type": f.resource_type, "resource_id": f.resource_id,
                    "severity": f.severity.value, "drift_type": f.drift_type,
                    "cost_delta_monthly": f.cost_delta_monthly,
                    "github_pr_url": f.github_pr_url,
                    "github_pr_number": f.github_pr_number,
                }
                for f in findings
            ],
            "total": len(findings),
        }

    # ── DASHBOARD (static files) ──────────────────────────────────────
    # Mounted last and deliberately: Starlette matches explicit routes
    # registered above (health, signup, workspaces, scans, findings, docs)
    # before falling through to this mount. Any path not matched by an
    # explicit route above is served from frontend/, with "/" resolving
    # to index.html. This makes one deployment serve both the API and
    # the dashboard — no separate frontend host required.
    frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
    if frontend_dir.exists():
        app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="dashboard")
    else:
        log.warning("Frontend directory not found, dashboard will not be served", path=str(frontend_dir))


async def run_scan_pipeline(
    workspace_id: str,
    scan_id: str,
    state_content: dict | None,
    state_backend: StateBackend,
    s3_bucket: str | None,
    s3_key: str | None,
    s3_region: str | None,
    region: str,
    aws_role_arn: str | None,
    aws_external_id: str | None,
):
    """Background task: full scan pipeline with DB persistence."""
    log.info("Starting scan pipeline", scan_id=scan_id, workspace_id=workspace_id)

    async with db_session() as db:
        scan_result = await db.execute(select(DriftScan).where(DriftScan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        if not scan:
            log.error("Scan record not found", scan_id=scan_id)
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await db.flush()

        try:
            auth_result = resolve_scan_session(aws_role_arn, aws_external_id, region)
            if not auth_result.success:
                raise RuntimeError(f"AWS authentication failed: {auth_result.error}")
            session = auth_result.session

            if state_backend == StateBackend.S3 and s3_bucket and s3_key:
                reader = S3StateReader(session)
                state_read = reader.read_state(s3_bucket, s3_key, s3_region or region)
                if not state_read.success:
                    raise RuntimeError(f"Failed to read S3 state: {state_read.error}")
                resolved_state = state_read.state
            elif state_content:
                resolved_state = state_content
            else:
                raise RuntimeError("No state source provided.")

            parser = TerraformStateParser()
            tf_resources = parser.parse(resolved_state)

            collector = AWSStateCollector(session, region)
            live_resources = collector.collect_all()

            analyzer = DriftAnalyzer()
            findings = analyzer.analyze(tf_resources, live_resources, region)

            total_live = sum(len(v) for v in live_resources.values())
            scorer = PostureScorer()
            score = scorer.score(findings, max(total_live, len(tf_resources), 1))

            db_findings = []
            for f in findings:
                db_finding = DriftFinding(
                    workspace_id=workspace_id,
                    scan_id=scan_id,
                    resource_type=f.resource_type,
                    resource_id=f.resource_id,
                    resource_name=f.resource_name,
                    region=f.region,
                    severity=SeverityLevel(f.severity.value),
                    drift_type=f.drift_type.value,
                    expected_state=f.expected_state,
                    actual_state=f.actual_state,
                    diff_summary=f.diff_summary,
                    security_impact=f.security_impact,
                    compliance_violations=f.compliance_violations,
                    cost_delta_monthly=f.cost_delta_monthly,
                    terraform_patch=f.terraform_patch,
                )
                db.add(db_finding)
                db_findings.append(db_finding)

            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.total_resources_checked = total_live
            scan.drift_count = len(findings)
            scan.posture_score = score
            scan.cost_delta_monthly = sum(f.cost_delta_monthly or 0 for f in findings)

            ws_result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
            workspace = ws_result.scalar_one_or_none()
            if workspace:
                workspace.last_scanned_at = datetime.now(timezone.utc)

            await db.flush()  # populate generated finding IDs before PR automation

            if (
                workspace
                and workspace.auto_pr_enabled
                and workspace.github_repo
                and workspace.github_app_installation_id
                and GITHUB_APP_ID
                and GITHUB_APP_PRIVATE_KEY
            ):
                owner, _, repo_name = workspace.github_repo.partition("/")
                for db_finding in db_findings:
                    if not db_finding.terraform_patch:
                        continue
                    pr_result = await open_remediation_pr(
                        app_id=GITHUB_APP_ID,
                        private_key_pem=GITHUB_APP_PRIVATE_KEY,
                        installation_id=workspace.github_app_installation_id,
                        owner=owner,
                        repo=repo_name,
                        base_branch=workspace.github_branch,
                        terraform_dir=workspace.terraform_dir,
                        finding=db_finding,
                    )
                    if pr_result.success:
                        db_finding.github_pr_url = pr_result.pr_url
                        db_finding.github_pr_number = pr_result.pr_number
                        db_finding.status = DriftStatus.PR_OPENED
                    else:
                        log.error(
                            "GitHub PR automation failed for finding",
                            finding_id=db_finding.id,
                            error=pr_result.error,
                        )
                await db.flush()

            log.info("Scan completed", scan_id=scan_id, findings=len(findings), score=score)

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            await db.flush()
            log.error("Scan failed", scan_id=scan_id, error=str(e))


app = create_app()
