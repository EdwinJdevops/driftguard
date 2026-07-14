"""
Thin HTTP client for the DriftGuard API. Every method here maps 1:1 to a
real endpoint in backend/api/main.py — field names match the actual
request/response schemas, not an idealized guess.
"""

from __future__ import annotations

import httpx


class DriftGuardAPIError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"API error {status_code}: {detail}")


class DriftGuardClient:
    def __init__(self, base_url: str, api_key: str | None = None, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._timeout = timeout

    def _request(self, method: str, path: str, **kwargs) -> dict:
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.request(method, f"{self.base_url}{path}", headers=self._headers, **kwargs)
        except httpx.ConnectError as e:
            raise DriftGuardAPIError(0, f"Could not reach {self.base_url} — is the API URL correct and the server running? ({e})")
        except httpx.TimeoutException as e:
            raise DriftGuardAPIError(0, f"Request to {self.base_url} timed out after {self._timeout}s ({e})")
        except httpx.HTTPError as e:
            raise DriftGuardAPIError(0, f"Network error contacting {self.base_url}: {e}")

        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                detail = response.text
            raise DriftGuardAPIError(response.status_code, detail)
        return response.json()

    def signup(self, org_name: str, org_slug: str) -> dict:
        return self._request("POST", "/signup", json={"org_name": org_name, "org_slug": org_slug})

    def create_workspace(
        self,
        name: str,
        provider: str = "aws",
        region: str = "us-east-1",
        state_backend: str = "upload",
        s3_bucket: str | None = None,
        s3_key: str | None = None,
        github_repo: str | None = None,
        aws_role_arn: str | None = None,
    ) -> dict:
        payload = {
            "name": name, "provider": provider, "region": region,
            "state_backend": state_backend, "s3_bucket": s3_bucket, "s3_key": s3_key,
            "github_repo": github_repo, "aws_role_arn": aws_role_arn,
        }
        clean_payload = {k: v for k, v in payload.items() if v is not None}
        return self._request("POST", "/workspaces", json=clean_payload)

    def list_workspaces(self) -> dict:
        return self._request("GET", "/workspaces")

    def verify_role(self, workspace_id: str) -> dict:
        return self._request("POST", f"/workspaces/{workspace_id}/verify-role")

    def trigger_scan(self, workspace_id: str, state_file_content: dict | None = None) -> dict:
        return self._request(
            "POST", f"/workspaces/{workspace_id}/scan",
            json={"state_file_content": state_file_content},
        )

    def get_scan(self, scan_id: str) -> dict:
        return self._request("GET", f"/scans/{scan_id}")

    def list_findings(self, severity: str | None = None) -> dict:
        params = {"severity": severity} if severity else {}
        return self._request("GET", "/findings", params=params)

    def health(self) -> dict:
        return self._request("GET", "/health")
