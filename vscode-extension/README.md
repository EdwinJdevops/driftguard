# DriftGuard for VS Code

Terraform drift findings, scan triggers, and remediation PRs — without leaving your editor.

## Features

- **Findings sidebar** — open drift findings from your DriftGuard org, severity-colored, in the activity bar.
- **Trigger scans** — pick a workspace, kick off a scan, get notified when it completes.
- **Jump to remediation PRs** — click a finding with an open PR to view it on GitHub.

## Setup

1. Run **DriftGuard: Configure API Connection** (Cmd/Ctrl+Shift+P).
2. Enter your API URL and API key (`dg_live_...` from `driftguard signup` or the dashboard).
3. Your key is stored in VS Code's `SecretStorage` — not in `settings.json`, not in plaintext.

## Status

Built and type-checked (`tsc --strict` passes against the real `@types/vscode` API surface).
**Not yet published to the VS Code Marketplace** — that requires a publisher account and
`vsce publish` token, which is a decision for you to make, not something I can do on your
behalf. To try it locally: `vsce package` produces a `.vsix` you can install via
"Extensions: Install from VSIX..." in VS Code.
