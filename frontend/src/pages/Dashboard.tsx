import { useEffect, useState } from 'react';
import { api, ApiError, type Workspace, type ScanResult, type Finding } from '../lib/api';
import { Gauge } from '../components/Gauge';

const STORAGE_KEY = 'driftguard_api_key';

const SEV_COLOR: Record<string, string> = {
  critical: 'text-critical border-critical/40 bg-critical/10',
  high: 'text-high border-high/40 bg-high/10',
  medium: 'text-medium border-medium/40 bg-medium/10',
  low: 'text-low border-low/40 bg-low/10',
};

function LoginPanel({ onAuthenticated }: { onAuthenticated: (key: string) => void }) {
  const [mode, setMode] = useState<'signin' | 'signup'>('signin');
  const [apiKey, setApiKey] = useState('');
  const [orgName, setOrgName] = useState('');
  const [orgSlug, setOrgSlug] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [signupResult, setSignupResult] = useState<{ api_key: string; warning: string } | null>(null);

  async function handleSignIn(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await api.listWorkspaces(apiKey);
      onAuthenticated(apiKey);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Could not connect.');
    } finally {
      setLoading(false);
    }
  }

  async function handleSignUp(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = await api.signup(orgName, orgSlug);
      setSignupResult(result);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Could not create organization.');
    } finally {
      setLoading(false);
    }
  }

  if (signupResult) {
    return (
      <div className="max-w-md mx-auto mt-24 rounded-xl border border-good/40 bg-good/5 p-6">
        <h2 className="font-mono font-bold text-good mb-3">Organization created</h2>
        <p className="text-sm text-text-dim mb-3">{signupResult.warning}</p>
        <div className="font-mono text-xs bg-black/40 border border-panel-border rounded p-3 break-all mb-4">
          {signupResult.api_key}
        </div>
        <button
          onClick={() => onAuthenticated(signupResult.api_key)}
          className="w-full font-mono text-sm px-4 py-2.5 rounded-md bg-good text-black font-semibold hover:bg-good/90 transition-colors"
        >
          Continue to dashboard →
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-md mx-auto mt-24">
      <div className="flex gap-2 mb-6 font-mono text-sm">
        <button
          onClick={() => setMode('signin')}
          className={`px-4 py-2 rounded-md border ${mode === 'signin' ? 'border-brand/40 bg-brand/10 text-brand' : 'border-panel-border text-text-dim'}`}
        >
          Sign in
        </button>
        <button
          onClick={() => setMode('signup')}
          className={`px-4 py-2 rounded-md border ${mode === 'signup' ? 'border-brand/40 bg-brand/10 text-brand' : 'border-panel-border text-text-dim'}`}
        >
          New organization
        </button>
      </div>

      {mode === 'signin' ? (
        <form onSubmit={handleSignIn} className="rounded-xl border border-panel-border bg-panel p-6">
          <label className="block font-mono text-xs text-text-dim mb-2 uppercase tracking-wide">API key</label>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="dg_live_..."
            required
            className="w-full font-mono text-sm bg-black/40 border border-panel-border rounded-md px-3 py-2.5 mb-4 focus:border-brand/60 outline-none"
          />
          {error && <p className="text-critical text-xs mb-4">{error}</p>}
          <button
            type="submit"
            disabled={loading}
            className="w-full font-mono text-sm px-4 py-2.5 rounded-md bg-brand text-black font-semibold hover:bg-brand/90 transition-colors disabled:opacity-50"
          >
            {loading ? 'Connecting…' : 'Sign in'}
          </button>
        </form>
      ) : (
        <form onSubmit={handleSignUp} className="rounded-xl border border-panel-border bg-panel p-6">
          <label className="block font-mono text-xs text-text-dim mb-2 uppercase tracking-wide">Organization name</label>
          <input
            value={orgName}
            onChange={(e) => setOrgName(e.target.value)}
            required
            className="w-full font-mono text-sm bg-black/40 border border-panel-border rounded-md px-3 py-2.5 mb-4 focus:border-brand/60 outline-none"
          />
          <label className="block font-mono text-xs text-text-dim mb-2 uppercase tracking-wide">Slug (lowercase, hyphens)</label>
          <input
            value={orgSlug}
            onChange={(e) => setOrgSlug(e.target.value)}
            pattern="[a-z0-9-]+"
            required
            className="w-full font-mono text-sm bg-black/40 border border-panel-border rounded-md px-3 py-2.5 mb-4 focus:border-brand/60 outline-none"
          />
          {error && <p className="text-critical text-xs mb-4">{error}</p>}
          <button
            type="submit"
            disabled={loading}
            className="w-full font-mono text-sm px-4 py-2.5 rounded-md bg-good text-black font-semibold hover:bg-good/90 transition-colors disabled:opacity-50"
          >
            {loading ? 'Creating…' : 'Create organization'}
          </button>
        </form>
      )}
    </div>
  );
}

function FindingRow({ f }: { f: Finding }) {
  return (
    <div className="flex items-center gap-4 px-5 py-3.5 border-b border-panel-border last:border-0 hover:bg-panel-hover transition-colors">
      <span className={`font-mono text-[11px] font-bold uppercase px-2 py-0.5 rounded border ${SEV_COLOR[f.severity] ?? ''}`}>
        {f.severity}
      </span>
      <div className="flex-1 min-w-0">
        <div className="font-mono text-sm truncate">{f.resource_type} / {f.resource_id}</div>
        <div className="text-xs text-text-dim">{f.drift_type}</div>
      </div>
      <div className="font-mono text-xs text-medium text-right w-24 shrink-0">
        {f.cost_delta_monthly ? `$${f.cost_delta_monthly.toFixed(2)}/mo` : '—'}
      </div>
      {f.github_pr_url ? (
        <a
          href={f.github_pr_url}
          target="_blank"
          rel="noopener noreferrer"
          className="font-mono text-xs text-good border border-good/40 bg-good/10 px-2.5 py-1 rounded shrink-0"
        >
          PR #{f.github_pr_number}
        </a>
      ) : (
        <span className="font-mono text-xs text-text-dim shrink-0">no PR</span>
      )}
    </div>
  );
}

function DashboardHome({ apiKey, onSignOut }: { apiKey: string; onSignOut: () => void }) {
  const [workspaces, setWorkspaces] = useState<Workspace[] | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [scanning, setScanning] = useState<string | null>(null);
  const [lastScan, setLastScan] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadAll() {
    try {
      const [ws, fs] = await Promise.all([api.listWorkspaces(apiKey), api.listFindings(apiKey)]);
      setWorkspaces(ws.workspaces);
      setFindings(fs.findings);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Could not load dashboard.');
    }
  }

  useEffect(() => {
    loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiKey]);

  async function triggerScan(workspaceId: string) {
    setScanning(workspaceId);
    setError(null);
    try {
      const { scan_id } = await api.triggerScan(apiKey, workspaceId);
      await pollScan(scan_id);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Scan failed to trigger.');
      setScanning(null);
    }
  }

  async function pollScan(scanId: string, attempts = 0) {
    if (attempts > 40) {
      setError('Scan is taking longer than expected.');
      setScanning(null);
      return;
    }
    const scan = await api.getScan(apiKey, scanId);
    if (scan.status === 'completed' || scan.status === 'failed') {
      setLastScan(scan);
      setScanning(null);
      loadAll();
      return;
    }
    setTimeout(() => pollScan(scanId, attempts + 1), 3000);
  }

  return (
    <div className="max-w-5xl mx-auto px-6 py-10">
      <div className="flex justify-between items-center mb-8">
        <h1 className="font-mono text-xl font-bold">Dashboard</h1>
        <button onClick={onSignOut} className="font-mono text-xs text-text-dim hover:text-text">
          Sign out
        </button>
      </div>

      {error && (
        <div className="mb-6 rounded-md border border-critical/40 bg-critical/10 text-critical text-sm px-4 py-3">
          {error}
        </div>
      )}

      {lastScan && (
        <div className="mb-8 rounded-xl border border-panel-border bg-panel p-6 flex items-center gap-8 flex-wrap">
          <Gauge score={Math.round(lastScan.posture_score ?? 0)} />
          <div className="flex gap-8 font-mono text-sm">
            <div>
              <div className="text-text-dim text-xs mb-1">Resources checked</div>
              <div className="text-lg">{lastScan.total_resources_checked}</div>
            </div>
            <div>
              <div className="text-text-dim text-xs mb-1">Drift found</div>
              <div className="text-lg text-critical">{lastScan.drift_count}</div>
            </div>
            <div>
              <div className="text-text-dim text-xs mb-1">Cost impact</div>
              <div className="text-lg text-medium">${(lastScan.cost_delta_monthly ?? 0).toFixed(2)}/mo</div>
            </div>
          </div>
        </div>
      )}

      <div className="mb-10">
        <h2 className="font-mono text-sm text-text-dim uppercase tracking-wide mb-3">Workspaces</h2>
        {workspaces === null ? (
          <p className="text-text-dim text-sm font-mono">Loading…</p>
        ) : workspaces.length === 0 ? (
          <p className="text-text-dim text-sm">
            No workspaces yet. Create one with the CLI: <code className="font-mono text-drift">driftguard workspace create</code>
          </p>
        ) : (
          <div className="rounded-xl border border-panel-border overflow-hidden">
            {workspaces.map((w) => (
              <div key={w.id} className="flex items-center justify-between px-5 py-3.5 border-b border-panel-border last:border-0">
                <div>
                  <div className="font-mono text-sm">{w.name}</div>
                  <div className="text-xs text-text-dim">
                    {w.provider} · {w.region} · last scanned {w.last_scanned_at ?? 'never'}
                  </div>
                </div>
                <button
                  onClick={() => triggerScan(w.id)}
                  disabled={scanning === w.id}
                  className="font-mono text-xs px-3 py-1.5 rounded-md bg-good/15 border border-good/40 text-good hover:bg-good/25 transition-colors disabled:opacity-50"
                >
                  {scanning === w.id ? 'Scanning…' : 'Trigger scan'}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      <div>
        <h2 className="font-mono text-sm text-text-dim uppercase tracking-wide mb-3">Open findings</h2>
        {findings === null ? (
          <p className="text-text-dim text-sm font-mono">Loading…</p>
        ) : findings.length === 0 ? (
          <p className="text-text-dim text-sm">No open findings.</p>
        ) : (
          <div className="rounded-xl border border-panel-border overflow-hidden">
            {findings.map((f) => (
              <FindingRow key={f.id} f={f} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function Dashboard() {
  const [apiKey, setApiKey] = useState<string | null>(() => localStorage.getItem(STORAGE_KEY));

  function handleAuthenticated(key: string) {
    localStorage.setItem(STORAGE_KEY, key);
    setApiKey(key);
  }

  function handleSignOut() {
    localStorage.removeItem(STORAGE_KEY);
    setApiKey(null);
  }

  if (!apiKey) {
    return <LoginPanel onAuthenticated={handleAuthenticated} />;
  }
  return <DashboardHome apiKey={apiKey} onSignOut={handleSignOut} />;
}
