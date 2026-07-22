export interface Finding {
  id: string;
  resource_type: string;
  resource_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  drift_type: string;
  cost_delta_monthly: number | null;
  github_pr_url: string | null;
  github_pr_number: number | null;
}

export interface ScanFinding extends Finding {
  diff_summary: string | null;
  security_impact: string[] | null;
  compliance_violations: string[] | null;
  terraform_patch: string | null;
  status: string;
}

export interface ScanResult {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  total_resources_checked: number;
  drift_count: number;
  posture_score: number | null;
  cost_delta_monthly: number | null;
  error_message: string | null;
  findings: ScanFinding[];
}

export interface Workspace {
  id: string;
  name: string;
  provider: string;
  region: string;
  is_active: boolean;
  last_scanned_at: string | null;
}

export interface SignupResult {
  org_id: string;
  org_name: string;
  api_key: string;
  warning: string;
}

export class ApiError extends Error {
  statusCode: number;
  detail: string;

  constructor(statusCode: number, detail: string) {
    super(`API error ${statusCode}: ${detail}`);
    this.statusCode = statusCode;
    this.detail = detail;
  }
}

const API_URL = import.meta.env.VITE_API_URL ?? 'https://driftguard-endm.onrender.com';

async function request<T>(method: string, path: string, apiKey?: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;

  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, `Could not reach ${API_URL} — check your connection or the API URL.`);
  }

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const data = await response.json();
      detail = data.detail ?? detail;
    } catch {
      /* response body wasn't JSON — fall back to statusText */
    }
    throw new ApiError(response.status, detail);
  }
  return response.json();
}

export const api = {
  health: () => request<{ status: string; version: string }>('GET', '/health'),

  signup: (orgName: string, orgSlug: string) =>
    request<SignupResult>('POST', '/signup', undefined, { org_name: orgName, org_slug: orgSlug }),

  listWorkspaces: (apiKey: string) => request<{ workspaces: Workspace[] }>('GET', '/workspaces', apiKey),

  createWorkspace: (
    apiKey: string,
    params: { name: string; provider: string; region: string; s3_bucket?: string; s3_key?: string; github_repo?: string; aws_role_arn?: string }
  ) =>
    request<{ id: string; name: string; aws_external_id: string | null; trust_policy_setup: unknown }>(
      'POST',
      '/workspaces',
      apiKey,
      { ...params, state_backend: params.s3_bucket ? 's3' : 'upload' }
    ),

  triggerScan: (apiKey: string, workspaceId: string, stateFileContent: unknown = null) =>
    request<{ scan_id: string; workspace_id: string; status: string }>(
      'POST',
      `/workspaces/${workspaceId}/scan`,
      apiKey,
      { state_file_content: stateFileContent }
    ),

  getScan: (apiKey: string, scanId: string) => request<ScanResult>('GET', `/scans/${scanId}`, apiKey),

  listFindings: (apiKey: string, severity?: string) =>
    request<{ findings: Finding[]; total: number }>(
      'GET',
      `/findings${severity ? `?severity=${encodeURIComponent(severity)}` : ''}`,
      apiKey
    ),
};
