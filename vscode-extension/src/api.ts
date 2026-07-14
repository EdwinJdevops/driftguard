import axios, { AxiosInstance } from 'axios';

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

export interface ScanResult {
  id: string;
  status: string;
  total_resources_checked: number;
  drift_count: number;
  posture_score: number | null;
  cost_delta_monthly: number | null;
  error_message: string | null;
  findings: Array<Finding & { diff_summary: string | null; terraform_patch: string | null }>;
}

export interface Workspace {
  id: string;
  name: string;
  provider: string;
  region: string;
  is_active: boolean;
  last_scanned_at: string | null;
}

export class DriftGuardApiError extends Error {
  constructor(public statusCode: number, public detail: string) {
    super(`DriftGuard API error ${statusCode}: ${detail}`);
  }
}

export class DriftGuardClient {
  private http: AxiosInstance;

  constructor(baseUrl: string, apiKey: string) {
    this.http = axios.create({
      baseURL: baseUrl.replace(/\/$/, ''),
      headers: { Authorization: `Bearer ${apiKey}` },
      timeout: 15000,
    });
  }

  private async request<T>(method: 'get' | 'post', path: string, data?: unknown): Promise<T> {
    try {
      const response = await this.http.request<T>({ method, url: path, data });
      return response.data;
    } catch (err: any) {
      if (err.response) {
        const detail = err.response.data?.detail ?? err.response.statusText;
        throw new DriftGuardApiError(err.response.status, detail);
      }
      if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND') {
        throw new DriftGuardApiError(0, `Could not reach ${this.http.defaults.baseURL} — check driftguard.apiUrl in settings.`);
      }
      throw new DriftGuardApiError(0, err.message ?? 'Unknown network error');
    }
  }

  listWorkspaces(): Promise<{ workspaces: Workspace[] }> {
    return this.request('get', '/workspaces');
  }

  listFindings(severity?: string): Promise<{ findings: Finding[]; total: number }> {
    const query = severity ? `?severity=${encodeURIComponent(severity)}` : '';
    return this.request('get', `/findings${query}`);
  }

  triggerScan(workspaceId: string): Promise<{ scan_id: string; workspace_id: string; status: string }> {
    return this.request('post', `/workspaces/${workspaceId}/scan`, { state_file_content: null });
  }

  getScan(scanId: string): Promise<ScanResult> {
    return this.request('get', `/scans/${scanId}`);
  }

  health(): Promise<{ status: string; version: string }> {
    return this.request('get', '/health');
  }
}
