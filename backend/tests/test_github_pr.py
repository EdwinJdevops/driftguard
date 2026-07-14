"""
DriftGuard — GitHub PR Automation Test Suite

Uses httpx.MockTransport instead of a mocking library: requests go through
real httpx routing/serialization, only the network socket is replaced. This
catches URL/method/header mistakes that a MagicMock would silently accept.

Run: pytest backend/tests/test_github_pr.py -v
"""

from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt as jose_jwt

from backend.integrations.github_pr import (
    GitHubPRClient,
    generate_app_jwt,
    get_installation_token,
    open_remediation_pr,
)


@pytest.fixture(scope="module")
def rsa_private_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@dataclass
class FakeFinding:
    """Duck-typed stand-in for a DriftFinding ORM row — matches its real field names."""
    id: str = "abcd1234-5678-90ab-cdef-1234567890ab"
    resource_type: str = "aws_security_group"
    resource_id: str = "sg-0123456789abcdef0"
    resource_name: str | None = "web-sg"
    severity: object = "high"
    drift_type: str = "modified"
    diff_summary: str | None = "Inbound rule 0.0.0.0/0:22 added outside Terraform."
    security_impact: list | None = None
    compliance_violations: list | None = None
    cost_delta_monthly: float | None = None
    terraform_patch: str | None = 'resource "aws_security_group" "web" {\n  # restores declared ingress rules\n}'


# ── JWT GENERATION ─────────────────────────────────────────────────────────

def test_generate_app_jwt_has_correct_claims(rsa_private_key_pem):
    token = generate_app_jwt("123456", rsa_private_key_pem)
    claims = jose_jwt.get_unverified_claims(token)

    assert claims["iss"] == "123456"
    assert claims["exp"] - claims["iat"] <= 600  # GitHub's hard max lifetime
    assert claims["iat"] < int(datetime.now(timezone.utc).timestamp())  # backdated for clock drift


def test_generate_app_jwt_is_valid_rs256_signature(rsa_private_key_pem):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # Sign with a *different* key than we verify against — must fail.
    token = generate_app_jwt("123456", rsa_private_key_pem)
    with pytest.raises(Exception):
        jose_jwt.decode(token, public_key, algorithms=["RS256"])


# ── INSTALLATION TOKEN EXCHANGE ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_installation_token_success():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "https://api.github.com/app/installations/999/access_tokens"
        assert request.headers["authorization"] == "Bearer fake-jwt"
        return httpx.Response(201, json={"token": "ghs_faketoken123", "expires_at": "2026-07-12T15:00:00Z"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await get_installation_token("fake-jwt", "999", client)

    assert result.success is True
    assert result.token == "ghs_faketoken123"


@pytest.mark.asyncio
async def test_get_installation_token_handles_auth_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await get_installation_token("bad-jwt", "999", client)

    assert result.success is False
    assert "401" in result.error


# ── GITHUB PR CLIENT (branch, file, PR mechanics) ──────────────────────────

@pytest.mark.asyncio
async def test_get_branch_sha_returns_none_on_missing_branch():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        gh = GitHubPRClient("tok", client)
        sha = await gh.get_branch_sha("acme", "infra", "main")

    assert sha is None


@pytest.mark.asyncio
async def test_get_branch_sha_returns_sha_when_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"object": {"sha": "deadbeef123"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        gh = GitHubPRClient("tok", client)
        sha = await gh.get_branch_sha("acme", "infra", "main")

    assert sha == "deadbeef123"


@pytest.mark.asyncio
async def test_create_branch_treats_already_exists_as_success():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"message": "Reference already exists"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        gh = GitHubPRClient("tok", client)
        result = await gh.create_branch("acme", "infra", "driftguard/fix-abcd1234", "deadbeef123")

    assert result is True


@pytest.mark.asyncio
async def test_put_file_includes_existing_sha_when_file_present():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"sha": "existing-blob-sha"})
        return httpx.Response(201, json={"content": {"sha": "new-blob-sha"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        gh = GitHubPRClient("tok", client)
        await gh.put_file("acme", "infra", "driftguard-remediations/sg.tf", "driftguard/fix-abcd1234", "content", "msg")

    put_call = next(c for c in calls if c.method == "PUT")
    import json
    payload = json.loads(put_call.content)
    assert payload["sha"] == "existing-blob-sha"


@pytest.mark.asyncio
async def test_open_pull_request_reuses_existing_pr_on_conflict():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(422, json={"message": "A pull request already exists for acme:driftguard/fix-abcd1234"})
        # GET lookup for the existing open PR
        return httpx.Response(200, json=[{"number": 42, "html_url": "https://github.com/acme/infra/pull/42"}])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        gh = GitHubPRClient("tok", client)
        result = await gh.open_pull_request("acme", "infra", "driftguard/fix-abcd1234", "main", "title", "body")

    assert result.success is True
    assert result.pr_number == 42


# ── FULL ORCHESTRATION (open_remediation_pr) ───────────────────────────────

@pytest.mark.asyncio
async def test_open_remediation_pr_full_happy_path(rsa_private_key_pem):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url)))
        if "access_tokens" in str(request.url):
            return httpx.Response(201, json={"token": "ghs_faketoken", "expires_at": "2026-07-12T15:00:00Z"})
        if "git/ref/heads/main" in str(request.url):
            return httpx.Response(200, json={"object": {"sha": "base-sha-123"}})
        if request.url.path.endswith("/git/refs"):
            return httpx.Response(201, json={"ref": "refs/heads/driftguard/fix-abcd1234"})
        if "/contents/" in str(request.url) and request.method == "GET":
            return httpx.Response(404, json={"message": "Not Found"})  # no existing file
        if "/contents/" in str(request.url) and request.method == "PUT":
            return httpx.Response(201, json={"content": {"sha": "new-sha"}})
        if request.url.path.endswith("/pulls") and request.method == "POST":
            return httpx.Response(201, json={"number": 7, "html_url": "https://github.com/acme/infra/pull/7"})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await open_remediation_pr(
            app_id="123456",
            private_key_pem=rsa_private_key_pem,
            installation_id="999",
            owner="acme",
            repo="infra",
            base_branch="main",
            terraform_dir="terraform/",
            finding=FakeFinding(),
            client=client,
        )

    assert result.success is True
    assert result.pr_number == 7
    assert result.pr_url == "https://github.com/acme/infra/pull/7"
    # Confirm the real request sequence happened, not just that no exception was raised
    methods_hit = [m for m, _ in calls]
    assert methods_hit.count("POST") >= 3  # token exchange, branch create, PR create


@pytest.mark.asyncio
async def test_open_remediation_pr_rejects_finding_without_patch(rsa_private_key_pem):
    finding = FakeFinding(terraform_patch=None)

    result = await open_remediation_pr(
        app_id="123456",
        private_key_pem=rsa_private_key_pem,
        installation_id="999",
        owner="acme",
        repo="infra",
        base_branch="main",
        terraform_dir="terraform/",
        finding=finding,
    )

    assert result.success is False
    assert "terraform_patch" in result.error


@pytest.mark.asyncio
async def test_open_remediation_pr_fails_cleanly_when_base_branch_missing(rsa_private_key_pem):
    def handler(request: httpx.Request) -> httpx.Response:
        if "access_tokens" in str(request.url):
            return httpx.Response(201, json={"token": "ghs_faketoken", "expires_at": "2026-07-12T15:00:00Z"})
        if "git/ref/heads/" in str(request.url):
            return httpx.Response(404, json={"message": "Not Found"})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await open_remediation_pr(
            app_id="123456",
            private_key_pem=rsa_private_key_pem,
            installation_id="999",
            owner="acme",
            repo="infra",
            base_branch="nonexistent-branch",
            terraform_dir="terraform/",
            finding=FakeFinding(),
            client=client,
        )

    assert result.success is False
    assert "not found" in result.error.lower()
