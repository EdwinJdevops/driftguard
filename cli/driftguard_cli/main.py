"""
DriftGuard CLI — entry point.

Install: pip install driftguard-cli
Usage:   driftguard --help
"""

from __future__ import annotations

import time

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .client import DriftGuardAPIError, DriftGuardClient
from .config import Config

app = typer.Typer(
    name="driftguard",
    help="Detect and remediate Terraform drift from your terminal.",
    no_args_is_help=True,
)
workspace_app = typer.Typer(help="Manage workspaces.")
scan_app = typer.Typer(help="Trigger and inspect scans.")
findings_app = typer.Typer(help="List open drift findings.")
app.add_typer(workspace_app, name="workspace")
app.add_typer(scan_app, name="scan")
app.add_typer(findings_app, name="findings")

console = Console()
SEVERITY_COLORS = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}


def _client() -> DriftGuardClient:
    cfg = Config.load()
    if not cfg.api_key:
        console.print("[red]Not authenticated.[/red] Run [bold]driftguard login[/bold] first.")
        raise typer.Exit(code=1)
    return DriftGuardClient(cfg.api_url, cfg.api_key)


def _handle_api_error(e: DriftGuardAPIError) -> None:
    console.print(f"[red]API error {e.status_code}:[/red] {e.detail}")
    raise typer.Exit(code=1)


@app.command()
def login(
    api_key: str = typer.Option(..., prompt=True, hide_input=True, help="Your DriftGuard API key (dg_live_...)."),
    api_url: str = typer.Option(None, help="Override the API base URL (defaults to the hosted instance, or DRIFTGUARD_API_URL)."),
):
    """Store your API key locally (~/.driftguard/config.json, mode 0600)."""
    cfg = Config.load()
    cfg.api_key = api_key
    if api_url:
        cfg.api_url = api_url
    try:
        DriftGuardClient(cfg.api_url, cfg.api_key).list_workspaces()
    except DriftGuardAPIError as e:
        console.print(f"[red]Could not authenticate:[/red] {e.detail}")
        raise typer.Exit(code=1)
    cfg.save()
    console.print("[green]Authenticated.[/green] Config saved to ~/.driftguard/config.json")


@app.command()
def signup(
    org_name: str = typer.Option(..., prompt=True),
    org_slug: str = typer.Option(..., prompt=True, help="Lowercase, hyphens only, e.g. 'acme-corp'."),
    api_url: str = typer.Option(None),
):
    """Create a new organization and save the returned API key."""
    cfg = Config.load()
    if api_url:
        cfg.api_url = api_url
    client = DriftGuardClient(cfg.api_url)
    try:
        result = client.signup(org_name, org_slug)
    except DriftGuardAPIError as e:
        _handle_api_error(e)
        return
    cfg.api_key = result["api_key"]
    cfg.save()
    console.print(Panel(
        f"[bold green]Organization created:[/bold green] {result['org_name']}\n"
        f"[yellow]{result['warning']}[/yellow]\n\n"
        f"API key saved to ~/.driftguard/config.json",
        title="Signup complete",
    ))


@workspace_app.command("create")
def workspace_create(
    name: str,
    provider: str = typer.Option("aws"),
    region: str = typer.Option(...),
    s3_bucket: str = typer.Option(None, help="Required if reading state from S3."),
    s3_key: str = typer.Option(None),
    github_repo: str = typer.Option(None, help="owner/repo for PR automation."),
    aws_role_arn: str = typer.Option(None, help="Omit for self-hosted single-account mode."),
):
    """Create a workspace."""
    client = _client()
    state_backend = "s3" if s3_bucket else "upload"
    try:
        result = client.create_workspace(
            name=name, provider=provider, region=region, state_backend=state_backend,
            s3_bucket=s3_bucket, s3_key=s3_key, github_repo=github_repo, aws_role_arn=aws_role_arn,
        )
    except DriftGuardAPIError as e:
        _handle_api_error(e)
        return

    console.print(f"[green]Workspace created:[/green] {result['id']}")
    if result.get("trust_policy_setup"):
        console.print(Panel(
            f"External ID: [bold]{result['aws_external_id']}[/bold]\n\n"
            "Add this trust policy to your IAM role, then run:\n"
            f"  driftguard workspace verify-role {result['id']}",
            title="AWS cross-account setup required",
        ))


@workspace_app.command("list")
def workspace_list():
    """List all workspaces in your organization."""
    client = _client()
    try:
        result = client.list_workspaces()
    except DriftGuardAPIError as e:
        _handle_api_error(e)
        return

    table = Table(title="Workspaces")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Provider")
    table.add_column("Region")
    table.add_column("Active")
    table.add_column("Last scanned")
    for w in result["workspaces"]:
        table.add_row(w["id"][:8], w["name"], w["provider"], w["region"], str(w["is_active"]), w["last_scanned_at"] or "never")
    console.print(table)


@workspace_app.command("verify-role")
def workspace_verify_role(workspace_id: str):
    """Verify a configured aws_role_arn is assumable and safely conditioned on external_id."""
    client = _client()
    try:
        result = client.verify_role(workspace_id)
    except DriftGuardAPIError as e:
        _handle_api_error(e)
        return
    console.print(f"[green]Role verified.[/green] Session expires {result['expiration']}")


@scan_app.command("trigger")
def scan_trigger(
    workspace_id: str,
    state_file: str = typer.Option(None, help="Path to a local terraform.tfstate JSON file, if not using S3 backend."),
    wait: bool = typer.Option(False, help="Poll until the scan completes."),
):
    """Trigger a drift scan on a workspace."""
    import json as jsonlib

    client = _client()
    state_content = None
    if state_file:
        with open(state_file) as f:
            state_content = jsonlib.load(f)

    try:
        result = client.trigger_scan(workspace_id, state_file_content=state_content)
    except DriftGuardAPIError as e:
        _handle_api_error(e)
        return

    console.print(f"[green]Scan triggered:[/green] {result['scan_id']}")

    if wait:
        _poll_scan(client, result["scan_id"])


def _poll_scan(client: DriftGuardClient, scan_id: str, interval: float = 3.0, max_attempts: int = 40):
    with console.status("[bold]Scanning...[/bold]"):
        for _ in range(max_attempts):
            scan = client.get_scan(scan_id)
            if scan["status"] in ("completed", "failed"):
                break
            time.sleep(interval)
        else:
            console.print("[yellow]Timed out waiting for scan to complete. Check status with:[/yellow]")
            console.print(f"  driftguard scan status {scan_id}")
            return

    _print_scan_result(scan)


@scan_app.command("status")
def scan_status(scan_id: str):
    """Check the status and results of a scan."""
    client = _client()
    try:
        scan = client.get_scan(scan_id)
    except DriftGuardAPIError as e:
        _handle_api_error(e)
        return
    _print_scan_result(scan)


def _print_scan_result(scan: dict):
    if scan["status"] == "failed":
        console.print(f"[red]Scan failed:[/red] {scan['error_message']}")
        return

    console.print(Panel(
        f"Status: [bold]{scan['status']}[/bold]  |  "
        f"Resources checked: {scan['total_resources_checked']}  |  "
        f"Drift found: {scan['drift_count']}  |  "
        f"Posture score: {scan['posture_score']}/100  |  "
        f"Monthly cost impact: ${scan['cost_delta_monthly'] or 0:,.2f}",
        title=f"Scan {scan['id'][:8]}",
    ))

    if not scan["findings"]:
        return

    table = Table(title="Findings")
    table.add_column("Severity")
    table.add_column("Resource")
    table.add_column("Drift type")
    table.add_column("Summary")
    for f in scan["findings"]:
        color = SEVERITY_COLORS.get(f["severity"], "white")
        table.add_row(
            f"[{color}]{f['severity']}[/{color}]",
            f"{f['resource_type']}\n{f['resource_id']}",
            f["drift_type"],
            (f["diff_summary"] or "")[:80],
        )
    console.print(table)


@findings_app.command("list")
def findings_list(severity: str = typer.Option(None, help="Filter: critical, high, medium, low.")):
    """List all open findings across every workspace."""
    client = _client()
    try:
        result = client.list_findings(severity=severity)
    except DriftGuardAPIError as e:
        _handle_api_error(e)
        return

    if not result["findings"]:
        console.print("[green]No open findings.[/green]")
        return

    table = Table(title=f"Open findings ({result['total']})")
    table.add_column("Severity")
    table.add_column("Resource")
    table.add_column("Drift type")
    table.add_column("Monthly cost impact")
    for f in result["findings"]:
        color = SEVERITY_COLORS.get(f["severity"], "white")
        table.add_row(
            f"[{color}]{f['severity']}[/{color}]",
            f"{f['resource_type']} / {f['resource_id']}",
            f["drift_type"],
            f"${f['cost_delta_monthly']:,.2f}" if f["cost_delta_monthly"] else "-",
        )
    console.print(table)


@app.command()
def status():
    """Check API connectivity and configured endpoint."""
    cfg = Config.load()
    try:
        DriftGuardClient(cfg.api_url).health()
        console.print(f"[green]Connected:[/green] {cfg.api_url}")
    except DriftGuardAPIError as e:
        console.print(f"[red]Unreachable ({cfg.api_url}):[/red] {e.detail}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
