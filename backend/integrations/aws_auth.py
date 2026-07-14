"""
DriftGuard — Cross-Account AWS Authentication

Replaces raw long-lived credential handling with STS AssumeRole.
DriftGuard never receives, transmits, or stores a customer's AWS
access key or secret key. Instead:

  1. Customer creates an IAM role in their account with a trust
     policy that allows DriftGuard's own AWS account to assume it,
     conditioned on a per-workspace external ID (confused-deputy
     protection — see https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html).
  2. DriftGuard stores only the role ARN + external ID (both
     non-sensitive; the external ID is not a secret, it's a
     correlation token).
  3. Each scan calls sts:AssumeRole to get temporary credentials
     (max 1 hour TTL, auto-expiring, never persisted).

For self-hosted single-account deployments where DriftGuard already
runs inside the target AWS account (e.g. an ECS task role scoped to
that account), no role_arn is required — boto3's default credential
chain (task role / instance profile / env vars) is used directly.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import boto3
import structlog
from botocore.exceptions import ClientError

log = structlog.get_logger(__name__)

ASSUME_ROLE_SESSION_NAME = "driftguard-scan"
ASSUME_ROLE_DURATION_SECONDS = 3600  # 1 hour; shortest practical TTL for a scan


def generate_external_id() -> str:
    """
    Generates a per-workspace external ID for the IAM trust policy.
    Not a secret — it's a correlation token that prevents the confused
    deputy problem, so URL-safe and displayable in the dashboard is fine.
    """
    return f"dg-ext-{secrets.token_urlsafe(24)}"


@dataclass
class AssumeRoleResult:
    success: bool
    session: boto3.Session | None = None
    error: str | None = None
    expiration: str | None = None


def check_role_misconfigured(role_arn: str, region: str) -> bool:
    """
    Validates that a customer's IAM role actually enforces the external ID
    condition, rather than trusting our external_id blindly.

    Attempts sts:AssumeRole with a deliberately wrong external ID. If AWS
    rejects it (AccessDenied), the role's trust policy correctly conditions
    on sts:ExternalId. If it unexpectedly succeeds, the customer's trust
    policy has no external ID condition at all — the role is open to any
    party that knows the account ID, and DriftGuard should refuse to use it.

    This mirrors the validation pattern documented by Datadog Security Labs
    for multi-tenant SaaS integrations assuming customer-owned roles.
    """
    probe_external_id = f"probe-{secrets.token_urlsafe(16)}"
    try:
        sts = boto3.client("sts", region_name=region)
        sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="driftguard-misconfig-check",
            ExternalId=probe_external_id,
            DurationSeconds=900,  # minimum allowed; this session is discarded immediately
        )
        # If assume_role succeeded with a made-up external ID, the trust
        # policy isn't enforcing sts:ExternalId at all. Vulnerable.
        log.warning(
            "Role has no enforced external ID condition — confused deputy risk",
            role_arn=role_arn,
        )
        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "AccessDenied":
            return False  # correctly rejected the wrong external ID — properly configured
        # Any other error (bad ARN, role doesn't exist, etc.) isn't a
        # confused-deputy signal — surface it separately, don't claim "safe".
        log.error("Could not evaluate role trust policy", role_arn=role_arn, error=str(e))
        raise


def assume_workspace_role(
    role_arn: str,
    external_id: str,
    region: str,
) -> AssumeRoleResult:
    """
    Assumes the customer-provided IAM role using the workspace's external ID.
    Returns a boto3.Session backed by short-lived temporary credentials.

    The base credentials used to call sts:AssumeRole are DriftGuard's own
    (from the ambient environment — task role / instance profile / env),
    NOT the customer's. This is the STS layer, not a passthrough.
    """
    try:
        sts = boto3.client("sts", region_name=region)
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=ASSUME_ROLE_SESSION_NAME,
            ExternalId=external_id,
            DurationSeconds=ASSUME_ROLE_DURATION_SECONDS,
        )
        creds = response["Credentials"]

        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )

        log.info(
            "Assumed workspace role",
            role_arn=role_arn,
            expiration=creds["Expiration"].isoformat(),
        )

        return AssumeRoleResult(
            success=True,
            session=session,
            expiration=creds["Expiration"].isoformat(),
        )

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDenied":
            msg = (
                f"Could not assume role {role_arn}. Verify the trust policy "
                f"allows DriftGuard's AWS account and the external ID matches."
            )
        else:
            msg = f"AssumeRole failed ({error_code}): {e.response.get('Error', {}).get('Message', str(e))}"
        log.error("AssumeRole failed", role_arn=role_arn, error=msg)
        return AssumeRoleResult(success=False, error=msg)

    except Exception as e:
        log.error("Unexpected error during AssumeRole", role_arn=role_arn, error=str(e))
        return AssumeRoleResult(success=False, error=f"Unexpected error: {e}")


def resolve_scan_session(
    role_arn: str | None,
    external_id: str | None,
    region: str,
) -> AssumeRoleResult:
    """
    Resolves the boto3 session to use for a scan.

    - If the workspace has a role_arn configured (multi-account / SaaS mode):
      assume that role via STS.
    - Otherwise (single-account self-hosted mode): fall back to the ambient
      default credential chain — DriftGuard is assumed to already be running
      with an IAM role scoped to the account it's scanning.

    Either path returns a session backed by temporary or role-scoped
    credentials. Neither path accepts or requires a raw access key/secret
    from the caller.
    """
    if role_arn:
        if not external_id:
            return AssumeRoleResult(
                success=False,
                error="Workspace has a role_arn configured but no external_id — refusing to assume role.",
            )
        return assume_workspace_role(role_arn, external_id, region)

    try:
        session = boto3.Session(region_name=region)
        # Force credential resolution now so failures surface here, not
        # deep inside the scan pipeline.
        session.client("sts").get_caller_identity()
        return AssumeRoleResult(success=True, session=session)
    except Exception as e:
        return AssumeRoleResult(
            success=False,
            error=(
                "No role_arn configured for this workspace and no ambient "
                f"AWS credentials available in the DriftGuard environment: {e}"
            ),
        )
