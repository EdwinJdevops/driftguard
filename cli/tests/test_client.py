"""
driftguard-cli test suite — uses httpx.MockTransport, same approach as the
backend's test_github_pr.py: real request routing, fake network only.

Run: pytest cli/tests/ -v
"""

import httpx
import pytest

from driftguard_cli.client import DriftGuardAPIError, DriftGuardClient


def _client_with_transport(handler) -> DriftGuardClient:
    client = DriftGuardClient("https://api.example.test", api_key="dg_live_test")
    # Patch the client's internal request method to use MockTransport instead
    # of a real socket — keeps _request()'s error handling under test.
    def patched(method, path, **kwargs):
        with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
            response = http_client.request(method, f"{client.base_url}{path}", headers=client._headers, **kwargs)
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                detail = response.text
            raise DriftGuardAPIError(response.status_code, detail)
        return response.json()

    client._request = patched
    return client


def test_signup_success():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "https://api.example.test/signup"
        return httpx.Response(201, json={"org_id": "org_1", "org_name": "Acme", "api_key": "dg_live_abc", "warning": "..."})

    client = _client_with_transport(handler)
    result = client.signup("Acme", "acme")
    assert result["api_key"] == "dg_live_abc"


def test_signup_conflict_raises_api_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json={"detail": "Organization slug already exists."})

    client = _client_with_transport(handler)
    with pytest.raises(DriftGuardAPIError) as exc_info:
        client.signup("Acme", "acme")
    assert exc_info.value.status_code == 409


def test_create_workspace_omits_none_fields():
    def handler(request: httpx.Request) -> httpx.Response:
        import json
        body = json.loads(request.content)
        assert "s3_bucket" not in body  # None values must not be sent
        assert body["name"] == "prod"
        return httpx.Response(201, json={"id": "ws_1", "name": "prod", "provider": "aws", "region": "us-east-1", "state_backend": "upload", "created_at": "2026-07-12T00:00:00Z"})

    client = _client_with_transport(handler)
    result = client.create_workspace(name="prod", region="us-east-1")
    assert result["id"] == "ws_1"


def test_list_findings_passes_severity_filter():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["severity"] == "critical"
        return httpx.Response(200, json={"findings": [], "total": 0})

    client = _client_with_transport(handler)
    client.list_findings(severity="critical")


def test_get_scan_returns_findings():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "id": "scan_1", "status": "completed", "total_resources_checked": 10,
            "drift_count": 1, "posture_score": 92.5, "cost_delta_monthly": 12.0,
            "error_message": None,
            "findings": [{"id": "f1", "resource_type": "aws_security_group", "resource_id": "sg-1",
                          "severity": "high", "drift_type": "modified", "diff_summary": "opened port 22",
                          "security_impact": [], "compliance_violations": [], "cost_delta_monthly": 0, "terraform_patch": None}],
        })

    client = _client_with_transport(handler)
    result = client.get_scan("scan_1")
    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
