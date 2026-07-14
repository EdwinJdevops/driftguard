import * as vscode from 'vscode';
import { DriftGuardClient, DriftGuardApiError } from './api';
import { FindingsProvider, FindingItem } from './findingsProvider';

const SECRET_KEY = 'driftguard.apiKey';

let cachedClient: DriftGuardClient | undefined;

async function getClient(context: vscode.ExtensionContext): Promise<DriftGuardClient | undefined> {
  if (cachedClient) {
    return cachedClient;
  }
  const apiKey = await context.secrets.get(SECRET_KEY);
  if (!apiKey) {
    return undefined;
  }
  const apiUrl = vscode.workspace.getConfiguration('driftguard').get<string>('apiUrl')!;
  cachedClient = new DriftGuardClient(apiUrl, apiKey);
  return cachedClient;
}

export function activate(context: vscode.ExtensionContext): void {
  const findingsProvider = new FindingsProvider(() => cachedClient);
  vscode.window.registerTreeDataProvider('driftguardFindings', findingsProvider);

  // Populate the client from stored secrets on startup, if already configured.
  getClient(context).then(() => findingsProvider.refresh());

  context.subscriptions.push(
    vscode.commands.registerCommand('driftguard.configure', async () => {
      const apiUrl = await vscode.window.showInputBox({
        prompt: 'DriftGuard API URL',
        value: vscode.workspace.getConfiguration('driftguard').get<string>('apiUrl'),
      });
      if (apiUrl === undefined) {
        return; // user cancelled
      }
      await vscode.workspace.getConfiguration('driftguard').update('apiUrl', apiUrl, vscode.ConfigurationTarget.Global);

      const apiKey = await vscode.window.showInputBox({
        prompt: 'DriftGuard API key (dg_live_...)',
        password: true,
      });
      if (!apiKey) {
        return;
      }
      await context.secrets.store(SECRET_KEY, apiKey);
      cachedClient = new DriftGuardClient(apiUrl, apiKey);

      try {
        await cachedClient.health();
        vscode.window.showInformationMessage('DriftGuard: connected successfully.');
        findingsProvider.refresh();
      } catch (err) {
        const detail = err instanceof DriftGuardApiError ? err.detail : String(err);
        vscode.window.showErrorMessage(`DriftGuard: could not connect — ${detail}`);
      }
    }),

    vscode.commands.registerCommand('driftguard.refreshFindings', () => {
      findingsProvider.refresh();
    }),

    vscode.commands.registerCommand('driftguard.triggerScan', async () => {
      const client = await getClient(context);
      if (!client) {
        vscode.window.showWarningMessage('DriftGuard: run "DriftGuard: Configure API Connection" first.');
        return;
      }
      try {
        const { workspaces } = await client.listWorkspaces();
        if (workspaces.length === 0) {
          vscode.window.showInformationMessage('DriftGuard: no workspaces found for this organization.');
          return;
        }
        const picked = await vscode.window.showQuickPick(
          workspaces.map((w) => ({ label: w.name, description: w.region, id: w.id })),
          { placeHolder: 'Select a workspace to scan' }
        );
        if (!picked) {
          return;
        }
        const { scan_id } = await client.triggerScan(picked.id);
        vscode.window.showInformationMessage(`DriftGuard: scan ${scan_id.slice(0, 8)} triggered.`);

        await pollScanAndNotify(client, scan_id, findingsProvider);
      } catch (err) {
        const detail = err instanceof DriftGuardApiError ? err.detail : String(err);
        vscode.window.showErrorMessage(`DriftGuard: ${detail}`);
      }
    }),

    vscode.commands.registerCommand('driftguard.openPullRequest', async (item: FindingItem) => {
      if (item?.finding.github_pr_url) {
        vscode.env.openExternal(vscode.Uri.parse(item.finding.github_pr_url));
      } else {
        vscode.window.showInformationMessage('DriftGuard: this finding has no remediation PR yet.');
      }
    })
  );
}

async function pollScanAndNotify(
  client: DriftGuardClient,
  scanId: string,
  findingsProvider: FindingsProvider,
  maxAttempts = 40,
  intervalMs = 3000
): Promise<void> {
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
    const scan = await client.getScan(scanId);
    if (scan.status === 'completed') {
      vscode.window.showInformationMessage(
        `DriftGuard: scan complete — ${scan.drift_count} finding(s), posture score ${scan.posture_score ?? 'N/A'}/100.`
      );
      findingsProvider.refresh();
      return;
    }
    if (scan.status === 'failed') {
      vscode.window.showErrorMessage(`DriftGuard: scan failed — ${scan.error_message}`);
      return;
    }
  }
  vscode.window.showWarningMessage('DriftGuard: scan is taking longer than expected — check status manually.');
}

export function deactivate(): void {
  cachedClient = undefined;
}
