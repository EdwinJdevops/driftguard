import { useEffect, useState } from 'react';
import { DriftDiff } from '../components/DriftDiff';

interface RepoStats {
  stargazers_count: number;
  forks_count: number;
  open_issues_count: number;
}

const RESOURCE_COVERAGE = [
  { resource: 'aws_instance', tracked: 'instance_type, vpc_security_group_ids, iam_instance_profile' },
  { resource: 'aws_s3_bucket', tracked: 'versioning, server_side_encryption_configuration, acl' },
  { resource: 'aws_security_group', tracked: 'ingress, egress' },
  { resource: 'aws_db_instance', tracked: 'instance_class, publicly_accessible, storage_encrypted' },
  { resource: 'aws_iam_role', tracked: 'assume_role_policy' },
  { resource: 'aws_iam_policy', tracked: 'policy document' },
];

const SECURITY_ROWS = [
  {
    concern: 'AWS access',
    naive: 'Accept access_key_id/secret over HTTP',
    actual: 'STS AssumeRole + per-workspace external ID, confused-deputy validated',
  },
  {
    concern: 'GitHub access',
    naive: 'One static PAT with access to every repo',
    actual: 'GitHub App installation tokens — scoped, expire in ~1 hour',
  },
  {
    concern: 'Remediation',
    naive: 'Auto-apply patches into existing .tf files',
    actual: 'New file under driftguard-remediations/, opened as a PR for human review',
  },
];

const STEPS = [
  {
    n: '01',
    title: 'Connect',
    body: 'Point DriftGuard at a workspace: an S3-backed state file, or upload one directly. Cross-account AWS access uses STS AssumeRole with an external ID your team controls — no long-lived keys ever leave your account.',
  },
  {
    n: '02',
    title: 'Scan',
    body: 'The engine parses declared state, collects live AWS state for the same resources, and diffs them. Every finding is scored against CIS AWS Benchmarks and mapped to MITRE ATT&CK where relevant, then priced against current monthly cost.',
  },
  {
    n: '03',
    title: 'Remediate',
    body: 'Findings with a generated patch get a GitHub PR — a new file under driftguard-remediations/, never spliced into your existing .tf files. A human reviews and merges, same as any other change.',
  },
];

export function Landing({ onNavigate }: { onNavigate: (path: string) => void }) {
  const [stats, setStats] = useState<RepoStats | null>(null);

  useEffect(() => {
    fetch('https://api.github.com/repos/EdwinJdevops/driftguard')
      .then((r) => (r.ok ? r.json() : null))
      .then(setStats)
      .catch(() => setStats(null));
  }, []);

  return (
    <div>
      {/* ── Hero ─────────────────────────────────────────── */}
      <section className="max-w-6xl mx-auto px-6 pt-20 pb-24 grid md:grid-cols-2 gap-14 items-center">
        <div>
          <div className="font-mono text-xs text-drift mb-4 uppercase tracking-wider">Terraform drift detection</div>
          <h1 className="font-mono text-4xl sm:text-5xl font-bold leading-[1.1] tracking-tight mb-6">
            Your state file says one thing.
            <br />
            <span className="text-drift">Your infrastructure says another.</span>
          </h1>
          <p className="text-text-dim text-lg leading-relaxed mb-8 max-w-lg">
            DriftGuard diffs Terraform state against live AWS, scores every gap against CIS and MITRE ATT&CK,
            prices the monthly cost impact, and opens a reviewable PR with the fix.
          </p>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => onNavigate('/dashboard')}
              className="font-mono text-sm px-5 py-3 rounded-md bg-good text-black font-semibold hover:bg-good/90 transition-colors"
            >
              Open dashboard →
            </button>
            <a
              href="https://github.com/EdwinJdevops/driftguard"
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-sm px-5 py-3 rounded-md border border-panel-border hover:border-brand/40 hover:text-brand transition-colors"
            >
              View source
            </a>
          </div>
          {stats && (
            <div className="flex gap-5 mt-6 font-mono text-xs text-text-dim">
              <span>★ {stats.stargazers_count} stars</span>
              <span>⑂ {stats.forks_count} forks</span>
              <span>{stats.open_issues_count} open issues</span>
            </div>
          )}
        </div>
        <DriftDiff />
      </section>

      {/* ── Problem ──────────────────────────────────────── */}
      <section className="max-w-6xl mx-auto px-6 py-20 border-t border-panel-border/60">
        <div className="max-w-2xl">
          <h2 className="font-mono text-2xl font-bold mb-4">Plan doesn't catch this.</h2>
          <p className="text-text-dim leading-relaxed text-lg">
            <span className="font-mono text-text">terraform plan</span> tells you what{' '}
            <em className="text-text not-italic font-medium">will</em> change if you apply. It has no opinion about
            what already changed outside your control — a security group rule added through the console, an S3
            bucket with encryption disabled mid-incident, an RDS instance flipped to publicly accessible. Nothing
            surfaces until someone re-applies against that exact resource, or an auditor asks a question you can't
            answer.
          </p>
        </div>
      </section>

      {/* ── Coverage ─────────────────────────────────────── */}
      <section id="platform" className="max-w-6xl mx-auto px-6 py-20 border-t border-panel-border/60">
        <h2 className="font-mono text-2xl font-bold mb-2">Resource coverage</h2>
        <p className="text-text-dim mb-8">AWS only, today. Extending coverage is a collector method plus a rule entry — not a rewrite.</p>
        <div className="rounded-xl border border-panel-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-panel border-b border-panel-border text-left text-text-dim font-mono text-xs uppercase tracking-wide">
                <th className="px-5 py-3 font-medium">Resource</th>
                <th className="px-5 py-3 font-medium">Tracked attributes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-panel-border">
              {RESOURCE_COVERAGE.map((r) => (
                <tr key={r.resource} className="hover:bg-panel-hover transition-colors">
                  <td className="px-5 py-3 font-mono text-drift">{r.resource}</td>
                  <td className="px-5 py-3 text-text-dim font-mono text-xs">{r.tracked}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* ── How it works ─────────────────────────────────── */}
      <section className="max-w-6xl mx-auto px-6 py-20 border-t border-panel-border/60">
        <h2 className="font-mono text-2xl font-bold mb-10">How it works</h2>
        <div className="grid md:grid-cols-3 gap-8">
          {STEPS.map((s) => (
            <div key={s.n}>
              <div className="font-mono text-drift text-sm mb-3">{s.n}</div>
              <h3 className="font-mono font-bold text-lg mb-2">{s.title}</h3>
              <p className="text-text-dim text-sm leading-relaxed">{s.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Security model ───────────────────────────────── */}
      <section id="security" className="max-w-6xl mx-auto px-6 py-20 border-t border-panel-border/60">
        <h2 className="font-mono text-2xl font-bold mb-2">Security model</h2>
        <p className="text-text-dim mb-8 max-w-2xl">
          Any tool that touches a customer's cloud account and repo has to answer the same question twice.
          DriftGuard answers it the same way both times: short-lived, scoped, per-tenant identity — never a
          static secret with broad access.
        </p>
        <div className="rounded-xl border border-panel-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-panel border-b border-panel-border text-left text-text-dim font-mono text-xs uppercase tracking-wide">
                <th className="px-5 py-3 font-medium">Concern</th>
                <th className="px-5 py-3 font-medium">Naive approach (rejected)</th>
                <th className="px-5 py-3 font-medium">What DriftGuard does</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-panel-border">
              {SECURITY_ROWS.map((r) => (
                <tr key={r.concern} className="hover:bg-panel-hover transition-colors align-top">
                  <td className="px-5 py-3 font-mono text-text">{r.concern}</td>
                  <td className="px-5 py-3 text-critical/80 text-xs">{r.naive}</td>
                  <td className="px-5 py-3 text-good text-xs">{r.actual}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* ── Install ──────────────────────────────────────── */}
      <section className="max-w-6xl mx-auto px-6 py-20 border-t border-panel-border/60">
        <div className="rounded-xl border border-panel-border bg-panel p-8">
          <h2 className="font-mono text-2xl font-bold mb-2">Self-host it. It's yours.</h2>
          <p className="text-text-dim mb-6 max-w-lg">
            MIT licensed. No account required to run it, no feature gates. Bring your own Postgres.
          </p>
          <div className="font-mono text-sm bg-black/40 border border-panel-border rounded-lg p-4 text-text-dim">
            <div className="text-text">$ git clone https://github.com/EdwinJdevops/driftguard.git</div>
            <div className="text-text">$ pip install -r requirements-dev.txt</div>
            <div className="text-text">$ pytest backend/tests/ -v</div>
            <div className="text-good mt-1"># 45 tests, no AWS account required</div>
          </div>
        </div>
      </section>
    </div>
  );
}
