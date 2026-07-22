export function Gauge({ score }: { score: number | null }) {
  const value = score ?? 0;
  const circumference = 169.6;
  const offset = circumference - (circumference * value) / 100;
  const color = value >= 80 ? 'var(--color-good)' : value >= 60 ? 'var(--color-medium)' : 'var(--color-critical)';

  return (
    <svg width="64" height="64" viewBox="0 0 64 64">
      <circle cx="32" cy="32" r="27" stroke="var(--color-panel-border)" strokeWidth="7" fill="none" />
      <circle
        cx="32"
        cy="32"
        r="27"
        stroke={color}
        strokeWidth="7"
        fill="none"
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={score === null ? circumference : offset}
        transform="rotate(-90 32 32)"
        style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.3s ease' }}
      />
      <text x="32" y="37" textAnchor="middle" fontFamily="var(--font-mono)" fontSize="15" fill="var(--color-text)">
        {score === null ? '--' : Math.round(score)}
      </text>
    </svg>
  );
}
