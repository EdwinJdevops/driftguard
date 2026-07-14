"""
DriftGuard — Cross-Account Auth Test Suite

Run: pytest backend/tests/test_aws_auth.py -v
"""

import pytest
from unittest.mock import MagicMock, patch

from moto import mock_aws

from backend.integrations.aws_auth import (
    assume_workspace_role,
    check_role_misconfigured,
    generate_external_id,
    resolve_scan_session,
)

TEST_ROLE_ARN = "arn:aws:iam::123456789012:role/driftguard-scan-role"


# ── EXTERNAL ID GENERATION ────────────────────────────────────────────────

def test_external_id_has_expected_prefix():
    ext_id = generate_external_id()
    assert ext_id.startswith("dg-ext-")


def test_external_id_is_unique_per_call():
    ids = {generate_external_id() for _ in range(50)}
    assert len(ids) == 50


# ── ASSUME ROLE (moto-mocked STS) ─────────────────────────────────────────

@mock_aws
def test_assume_workspace_role_succeeds_with_valid_role_and_external_id():
    result = assume_workspace_role(TEST_ROLE_ARN, "dg-ext-abc123", "us-east-1")

    assert result.success is True
    assert result.session is not None
    assert result.error is None
    assert result.expiration is not None


@mock_aws
def test_assume_workspace_role_session_has_temporary_credentials():
    result = assume_workspace_role(TEST_ROLE_ARN, "dg-ext-abc123", "us-east-1")

    creds = result.session.get_credentials()
    assert creds.access_key is not None
    assert creds.secret_key is not None
    assert creds.token is not None  # session token present = temporary, not long-lived


@mock_aws
def test_assume_workspace_role_rejects_malformed_role_arn():
    result = assume_workspace_role("not-a-valid-arn", "dg-ext-abc123", "us-east-1")

    assert result.success is False
    assert result.session is None
    assert result.error is not None


# ── SESSION RESOLUTION (the actual decision point used by the scan pipeline) ──

@mock_aws
def test_resolve_scan_session_uses_assume_role_when_role_arn_present():
    result = resolve_scan_session(TEST_ROLE_ARN, "dg-ext-abc123", "us-east-1")

    assert result.success is True
    creds = result.session.get_credentials()
    assert creds.token is not None  # confirms STS path was taken, not passthrough


def test_resolve_scan_session_rejects_role_arn_without_external_id():
    """
    Refusing to assume a role without an external ID is a deliberate safety
    check, not an oversight — it's the confused-deputy guard. This must
    fail closed, not silently omit the condition.
    """
    result = resolve_scan_session(TEST_ROLE_ARN, None, "us-east-1")

    assert result.success is False
    assert result.session is None
    assert "external_id" in result.error.lower()


def test_resolve_scan_session_falls_back_to_ambient_chain_when_no_role_arn(monkeypatch):
    """
    Single-account self-hosted mode: no role_arn configured means DriftGuard
    is expected to already be running with credentials scoped to the target
    account. With no ambient credentials in this test environment, this
    must fail with a clear error rather than silently using an unrelated
    default session.
    """
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    result = resolve_scan_session(None, None, "us-east-1")

    assert result.success is False
    assert "no role_arn configured" in result.error.lower()


@mock_aws
def test_resolve_scan_session_ambient_chain_succeeds_when_credentials_present(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")

    result = resolve_scan_session(None, None, "us-east-1")

    assert result.success is True
    assert result.session is not None


# ── CONFUSED-DEPUTY MISCONFIGURATION CHECK ────────────────────────────────
#
# moto does not enforce IAM trust-policy conditions on sts:AssumeRole — it
# accepts any ExternalId regardless of the role's actual trust policy. Using
# it here would make the "properly configured" branch untestable (moto would
# always report "vulnerable"). We mock the boto3 client response directly so
# both real AWS behaviors are exercised deliberately.

def test_check_role_misconfigured_returns_false_when_access_denied():
    """AWS correctly rejecting a wrong external ID = properly configured role."""
    mock_client = MagicMock()
    mock_client.assume_role.side_effect = _client_error("AccessDenied")

    with patch("backend.integrations.aws_auth.boto3.client", return_value=mock_client):
        result = check_role_misconfigured(TEST_ROLE_ARN, "us-east-1")

    assert result is False


def test_check_role_misconfigured_returns_true_when_assume_unexpectedly_succeeds():
    """AWS accepting a deliberately wrong external ID = vulnerable trust policy."""
    mock_client = MagicMock()
    mock_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIAFAKE",
            "SecretAccessKey": "fake",
            "SessionToken": "fake-token",
            "Expiration": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        }
    }

    with patch("backend.integrations.aws_auth.boto3.client", return_value=mock_client):
        result = check_role_misconfigured(TEST_ROLE_ARN, "us-east-1")

    assert result is True


def test_check_role_misconfigured_reraises_non_access_denied_errors():
    """A bad ARN or missing role is a different failure mode — not a safety signal either way."""
    mock_client = MagicMock()
    mock_client.assume_role.side_effect = _client_error("ValidationError")

    with patch("backend.integrations.aws_auth.boto3.client", return_value=mock_client):
        with pytest.raises(Exception):
            check_role_misconfigured(TEST_ROLE_ARN, "us-east-1")


def _client_error(code: str):
    from botocore.exceptions import ClientError

    return ClientError(
        error_response={"Error": {"Code": code, "Message": f"Simulated {code}"}},
        operation_name="AssumeRole",
    )
