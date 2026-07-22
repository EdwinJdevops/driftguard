export function Footer() {
  return (
    <footer className="border-t border-panel-border/60 mt-24">
      <div className="max-w-6xl mx-auto px-6 py-10 flex flex-col sm:flex-row justify-between gap-4 text-sm text-text-dim">
        <div>
          <span className="font-mono text-text">DriftGuard</span> · MIT License · Terraform drift detection
        </div>
        <div className="flex gap-5">
          <a href="https://github.com/EdwinJdevops/driftguard" target="_blank" rel="noopener noreferrer" className="hover:text-text transition-colors">
            GitHub
          </a>
          <a href="https://github.com/EdwinJdevops/driftguard/tree/main/cli" target="_blank" rel="noopener noreferrer" className="hover:text-text transition-colors">
            CLI
          </a>
          <a href="https://github.com/EdwinJdevops/driftguard/tree/main/vscode-extension" target="_blank" rel="noopener noreferrer" className="hover:text-text transition-colors">
            VS Code
          </a>
          <a href="https://github.com/EdwinJdevops/driftguard/blob/main/README.md#api" target="_blank" rel="noopener noreferrer" className="hover:text-text transition-colors">
            API docs
          </a>
        </div>
      </div>
    </footer>
  );
}
