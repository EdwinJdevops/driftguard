import * as vscode from 'vscode';
import { DriftGuardClient, Finding, DriftGuardApiError } from './api';

const SEVERITY_ICONS: Record<string, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '⚪',
};

export class FindingItem extends vscode.TreeItem {
  constructor(public readonly finding: Finding) {
    super(`${SEVERITY_ICONS[finding.severity] ?? ''} ${finding.resource_type}`, vscode.TreeItemCollapsibleState.None);
    this.description = finding.resource_id;
    this.tooltip = [
      `Severity: ${finding.severity}`,
      `Drift type: ${finding.drift_type}`,
      finding.cost_delta_monthly ? `Monthly cost impact: $${finding.cost_delta_monthly.toFixed(2)}` : undefined,
      finding.github_pr_url ? `PR: ${finding.github_pr_url}` : 'No PR opened yet',
    ]
      .filter(Boolean)
      .join('\n');
    this.contextValue = finding.github_pr_url ? 'findingWithPR' : 'finding';
  }
}

export class FindingsProvider implements vscode.TreeDataProvider<FindingItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<FindingItem | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findings: Finding[] = [];

  constructor(private getClient: () => DriftGuardClient | undefined) {}

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FindingItem): vscode.TreeItem {
    return element;
  }

  async getChildren(): Promise<FindingItem[]> {
    const client = this.getClient();
    if (!client) {
      return [];
    }
    try {
      const result = await client.listFindings();
      this.findings = result.findings;
      return this.findings.map((f) => new FindingItem(f));
    } catch (err) {
      if (err instanceof DriftGuardApiError) {
        vscode.window.showErrorMessage(`DriftGuard: ${err.detail}`);
      }
      return [];
    }
  }
}
