import { useEffect, useState } from 'react';

const SCENARIOS = [
  {
    resource: 'aws_security_group.web',
    declared: 'ingress = []',
    actual: 'ingress = [{ cidr: "0.0.0.0/0", port: 22 }]',
    label: 'CIS 5.2 violation',
  },
  {
    resource: 'aws_db_instance.orders',
    declared: 'publicly_accessible = false',
    actual: 'publicly_accessible = true',
    label: 'critical exposure',
  },
  {
    resource: 'aws_s3_bucket.uploads',
    declared: 'encryption { sse_algorithm = "AES256" }',
    actual: '(encryption block removed)',
    label: 'compliance gap',
  },
];

/**
 * The signature element: literalizes "drift" as a live divergence between
 * two states, re-cycling through real severity scenarios drawn from the
 * actual rule set in backend/engines/drift.py — not decorative, not a
 * stock dashboard screenshot.
 */
export function DriftDiff() {
  const [index, setIndex] = useState(0);
  const [phase, setPhase] = useState<'stable' | 'drifting'>('stable');

  useEffect(() => {
    const cycle = setInterval(() => {
      setPhase('drifting');
      setTimeout(() => {
        setIndex((i) => (i + 1) % SCENARIOS.length);
        setPhase('stable');
      }, 900);
    }, 3400);
    return () => clearInterval(cycle);
  }, []);

  const scenario = SCENARIOS[index];

  return (
    <div className="rounded-xl border border-panel-border bg-panel/60 backdrop-blur-sm overflow-hidden font-mono text-sm shadow-2xl shadow-black/40">
      <div className="flex items-center justify-between border-b border-panel-border px-4 py-2.5 bg-black/20">
        <span className="text-text-dim text-xs">{scenario.resource}</span>
        <span
          className={`text-xs px-2 py-0.5 rounded transition-colors duration-500 ${
            phase === 'drifting'
              ? 'bg-drift/15 text-drift border border-drift/40'
              : 'bg-panel-border/60 text-text-dim border border-transparent'
          }`}
        >
          {phase === 'drifting' ? scenario.label : 'in sync'}
        </span>
      </div>
      <div className="grid grid-cols-2 divide-x divide-panel-border">
        <div className="p-4">
          <div className="text-text-dim text-xs mb-2 uppercase tracking-wide">Declared</div>
          <div className="text-text/90 leading-relaxed">{scenario.declared}</div>
        </div>
        <div className="p-4">
          <div className="text-text-dim text-xs mb-2 uppercase tracking-wide">Actual</div>
          <div
            className={`leading-relaxed transition-colors duration-500 ${
              phase === 'drifting' ? 'text-drift' : 'text-text/90'
            }`}
          >
            {phase === 'drifting' ? scenario.actual : scenario.declared}
          </div>
        </div>
      </div>
    </div>
  );
}
