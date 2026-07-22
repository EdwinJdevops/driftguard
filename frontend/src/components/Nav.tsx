interface NavProps {
  onNavigate: (path: string) => void;
  current: string;
}

export function Nav({ onNavigate, current }: NavProps) {
  return (
    <header className="border-b border-panel-border/60">
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
        <button
          onClick={() => onNavigate('/')}
          className="flex items-center gap-2.5 font-mono font-bold text-lg tracking-tight"
        >
          <svg viewBox="0 0 40 40" className="w-7 h-7" fill="none">
            <rect width="40" height="40" rx="9" fill="#111820" stroke="#1E2A38" />
            <path d="M20 8 L30 13 V20 C30 27 25.5 31 20 33 C14.5 31 10 27 10 20 V13 Z" stroke="#58A6FF" strokeWidth="1.6" fill="none" />
            <path d="M20 15 V25 M15 20 H25" stroke="#F0883E" strokeWidth="1.6" strokeLinecap="round" />
          </svg>
          DriftGuard
        </button>

        <nav className="flex items-center gap-6 text-sm">
          <a href="#platform" className="text-text-dim hover:text-text transition-colors hidden sm:inline">
            Platform
          </a>
          <a href="#security" className="text-text-dim hover:text-text transition-colors hidden sm:inline">
            Security
          </a>
          <a
            href="https://github.com/EdwinJdevops/driftguard"
            target="_blank"
            rel="noopener noreferrer"
            className="text-text-dim hover:text-text transition-colors hidden sm:inline"
          >
            GitHub
          </a>
          <button
            onClick={() => onNavigate('/dashboard')}
            className={`font-mono text-xs px-4 py-2 rounded-md border transition-colors ${
              current === '/dashboard'
                ? 'bg-brand/15 border-brand/40 text-brand'
                : 'border-panel-border hover:border-brand/40 hover:text-brand'
            }`}
          >
            Dashboard →
          </button>
        </nav>
      </div>
    </header>
  );
}
