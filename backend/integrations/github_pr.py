"""
DriftGuard — GitHub PR Remediation Automation

Authenticates as a GitHub App (not a static PAT). Same reasoning as the
AWS cross-account fix: a single token with access to every customer's repo
is a standing liability. A GitHub App installation token is scoped to only
the repos the customer installed it on, and expires in ~1 hour.

Flow per GitHub's own docs (verified against docs.github.com, not memory):
  1. Sign a JWT with the App's private key (RS256). iat is set 60s in the
     past to tolerate clock drift, exp is capped at GitHub's 10-minute max.
  2. Exchange the JWT for a short-lived installation access token via
     POST /app/installations/{installation_id}/access_tokens.
  3. Use that installation token for all subsequent repo operations.

Design choice — what a PR actually contains:
DriftGuard does NOT attempt to splice a patch into a customer's existing
.tf files. Locating the correct block inside arbitrary existing HCL and
rewriting it in place is an HCL-aware-parsing problem; getting it wrong
silently corrupts a customer's real infrastructure code, which is a far
worse failure than "the PR needs one manual step." Instead, each finding
gets a new file under <terraform_dir>/driftguard-remediations/, and the PR
description explains what changed and why. A human merges it, same as any
other GitOps change — this is a proposal for review, not an auto-apply.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass

import httpx
import structlog
from jose import jwt as jose_jwt

log = structlog.get_logger(__name__)

GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
JWT_CLOCK_DRIFT_BUFFER_SECONDS = 60
JWT_MAX_LIFETIME_SECONDS = 600  # GitHub's hard maximum


def generate_app_jwt(app_id: str, private_key_pem: str) -> str:
    now = int(time.time())
    payload = {
        "iat": now - JWT_CLOCK_DRIFT_BUFFER_SECONDS,
        "exp": now + JWT_MAX_LIFETIME_SECONDS - JWT_CLOCK_DRIFT_BUFFER_SECONDS,
        "iss": app_id,
    }
    return jose_jwt.encode(payload, private_key_pem, algorithm="RS256")


@dataclass
class InstallationTokenResult:
    success: bool
    token: str | None = None
    expires_at: str | None = None
    error: str | None = None


async def get_installation_token(
    app_jwt: str,
    installation_id: str,
    client: httpx.AsyncClient,
) -> InstallationTokenResult:
    try:
        response = await client.post(
            f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
        )
        if response.status_code != 201:
            return InstallationTokenResult(
                success=False,
                error=f"Installation token request failed ({response.status_code}): {response.text}",
            )
        body = response.json()
        return InstallationTokenResult(success=True, token=body["token"], expires_at=body.get("expires_at"))
    except httpx.HTTPError as e:
        return InstallationTokenResult(success=False, error=f"Network error requesting installation token: {e}")


@dataclass
class PRResult:
    success: bool
    pr_number: int | None = None
    pr_url: str | None = None
    branch: str | None = None
    error: str | None = None


class GitHubPRClient:
    """Thin wrapper around the subset of the GitHub REST API DriftGuard needs."""

    def __init__(self, installation_token: str, client: httpx.AsyncClient):
        self._client = client
        self._headers = {
            "Authorization": f"Bearer {installation_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }

    async def get_branch_sha(self, owner: str, repo: str, branch: str) -> str | None:
        response = await self._client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{branch}",
            headers=self._headers,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()["object"]["sha"]

    async def create_branch(self, owner: str, repo: str, new_branch: str, base_sha: str) -> bool:
        response = await self._client.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/refs",
            headers=self._headers,
            json={"ref": f"refs/heads/{new_branch}", "sha": base_sha},
        )
        if response.status_code == 201:
            return True
        if response.status_code == 422 and "already exists" in response.text.lower():
            return True  # idempotent retry — branch is already there
        response.raise_for_status()
        return False

    async def put_file(
        self, owner: str, repo: str, path: str, branch: str, content: str, message: str
    ) -> None:
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")

        existing_sha = None
        existing = await self._client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
            headers=self._headers,
            params={"ref": branch},
        )
        if existing.status_code == 200:
            existing_sha = existing.json().get("sha")

        payload = {"message": message, "content": encoded, "branch": branch}
        if existing_sha:
            payload["sha"] = existing_sha

        response = await self._client.put(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
            headers=self._headers,
            json=payload,
        )
        response.raise_for_status()

    async def open_pull_request(
        self, owner: str, repo: str, head: str, base: str, title: str, body: str
    ) -> PRResult:
        response = await self._client.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/pulls",
            headers=self._headers,
            json={"title": title, "head": head, "base": base, "body": body},
        )
        if response.status_code == 201:
            pr = response.json()
            return PRResult(success=True, pr_number=pr["number"], pr_url=pr["html_url"], branch=head)
        if response.status_code == 422 and "already exists" in response.text.lower():
            # A PR for this branch already exists — look it up instead of failing.
            existing = await self._client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/pulls",
                headers=self._headers,
                params={"head": f"{owner}:{head}", "state": "open"},
            )
            existing.raise_for_status()
            matches = existing.json()
            if matches:
                pr = matches[0]
                return PRResult(success=True, pr_number=pr["number"], pr_url=pr["html_url"], branch=head)
        return PRResult(success=False, error=f"PR creation failed ({response.status_code}): {response.text}")


def _safe_filename(resource_type: str, resource_id: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_." else "-" for c in f"{resource_type}-{resource_id}")
    return f"{safe}.tf"


def _pr_body(finding) -> str:
    lines = [
        "**DriftGuard detected infrastructure drift.**",
        "",
        f"- **Resource:** `{finding.resource_type}` / `{finding.resource_id}`",
        f"- **Severity:** {finding.severity.value if hasattr(finding.severity, 'value') else finding.severity}",
        f"- **Drift type:** {finding.drift_type}",
    ]
    if finding.cost_delta_monthly:
        lines.append(f"- **Monthly cost impact:** ${finding.cost_delta_monthly:,.2f}")
    if finding.compliance_violations:
        lines.append(f"- **Compliance violations:** {', '.join(finding.compliance_violations)}")
    if finding.security_impact:
        lines.append(f"- **Security impact:** {', '.join(finding.security_impact)}")
    if finding.diff_summary:
        lines += ["", "**What changed:**", finding.diff_summary]
    lines += [
        "",
        "---",
        "This PR adds the suggested Terraform patch as a new file under "
        "`driftguard-remediations/` for review. DriftGuard does not modify "
        "your existing `.tf` files automatically — merge this manually into "
        "the correct location after review, or close this PR if the drift "
        "was intentional.",
    ]
    return "\n".join(lines)


async def open_remediation_pr(
    app_id: str,
    private_key_pem: str,
    installation_id: str,
    owner: str,
    repo: str,
    base_branch: str,
    terraform_dir: str,
    finding,
    client: httpx.AsyncClient | None = None,
) -> PRResult:
    """
    High-level orchestration: JWT -> installation token -> branch -> file -> PR.
    `finding` is a DriftFinding ORM row (duck-typed here to keep this module
    free of a hard dependency on the models module).

    `client` is injectable for testing via httpx.MockTransport; production
    callers omit it and get a real network-backed client.
    """
    if not finding.terraform_patch:
        return PRResult(success=False, error="Finding has no terraform_patch to open a PR for.")

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(timeout=30.0)

    try:
        app_jwt = generate_app_jwt(app_id, private_key_pem)
        token_result = await get_installation_token(app_jwt, installation_id, client)
        if not token_result.success:
            return PRResult(success=False, error=token_result.error)

        gh = GitHubPRClient(token_result.token, client)
        branch = f"driftguard/fix-{finding.id[:8]}"

        try:
            base_sha = await gh.get_branch_sha(owner, repo, base_branch)
            if base_sha is None:
                return PRResult(success=False, error=f"Base branch '{base_branch}' not found in {owner}/{repo}.")

            await gh.create_branch(owner, repo, branch, base_sha)

            file_path = f"{terraform_dir.rstrip('/')}/driftguard-remediations/{_safe_filename(finding.resource_type, finding.resource_id)}"
            content = (
                f"# DriftGuard remediation suggestion — review before merging.\n"
                f"# Finding ID: {finding.id}\n"
                f"# Detected: {finding.resource_type} / {finding.resource_id}\n\n"
                f"{finding.terraform_patch}\n"
            )
            await gh.put_file(
                owner, repo, file_path, branch, content,
                message=f"DriftGuard: suggested fix for {finding.resource_type} {finding.resource_id}",
            )

            title = f"DriftGuard: drift detected in {finding.resource_type} {finding.resource_name or finding.resource_id}"
            result = await gh.open_pull_request(owner, repo, head=branch, base=base_branch, title=title, body=_pr_body(finding))
            return result

        except httpx.HTTPStatusError as e:
            log.error("GitHub PR automation failed", finding_id=finding.id, error=str(e))
            return PRResult(success=False, error=f"GitHub API error: {e.response.status_code} {e.response.text}")
        except httpx.HTTPError as e:
            log.error("GitHub PR automation network error", finding_id=finding.id, error=str(e))
            return PRResult(success=False, error=f"Network error: {e}")
    finally:
        if owns_client:
            await client.aclose()
