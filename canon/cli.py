"""
Canon CLI.
canon fetch    - fetch all sources, produce evidence packages
canon review   - interactive human review of pending evidence
canon verify   - verify ledger and approval integrity
canon status   - show current state of all sources
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import click
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from canon.approval.gate import ApprovalGate
from canon.models import EvidencePackage, SourceState
from canon.monitor.monitor import CanonMonitor

app = typer.Typer(name="canon", help="Canon - Deterministic governance knowledge integrity engine.")
console = Console()


@app.command()
def fetch(
    canon_dir: str = typer.Option(".canon"),
    github_token: str = typer.Option(None, envvar="GITHUB_TOKEN"),
):
    """Fetch all governance sources and produce evidence packages."""
    monitor = CanonMonitor(canon_dir=Path(canon_dir))
    console.print("[bold blue]Canon[/bold blue] - Fetching governance sources...\n")
    packages = asyncio.run(monitor.run(github_token=github_token))

    pending = [p for p in packages if p.change_count > 0]
    if not pending:
        console.print("[green]All sources match baseline. No changes detected.[/green]")
        return

    for pkg in pending:
        colour = "red" if pkg.critical_changes else "yellow"
        console.print(Panel(
            f"[bold]{pkg.source_name}[/bold]\n"
            f"Changes: {pkg.change_count}  |  Critical: {len(pkg.critical_changes)}\n"
            f"Evidence ID: {pkg.evidence_id[:8]}...",
            border_style=colour,
        ))
        for diff in pkg.diffs[:5]:
            console.print(f"  [{diff.change_type.value}] {diff.rule_id}: {diff.description[:80]}")
            if diff.severity_delta:
                console.print(f"    Severity: [bold red]{diff.severity_delta}[/bold red]")

    if pending:
        console.print(f"\n[yellow]{len(pending)} evidence package(s) pending review.[/yellow]")
        console.print("Run [bold]canon review[/bold] to inspect and approve.")


@app.command()
def review(
    canon_dir: str = typer.Option(".canon"),
    approver: str = typer.Option(..., prompt="Your name/ID for audit record"),
):
    """Interactive human review of pending evidence packages."""
    monitor = CanonMonitor(canon_dir=Path(canon_dir))
    gate = ApprovalGate(canon_dir=Path(canon_dir))
    pending = monitor.load_pending_evidence()

    if not pending:
        console.print("[green]No pending evidence packages.[/green]")
        return

    for pkg in pending:
        console.print(Panel(
            f"[bold]Source:[/bold] {pkg.source_name}\n"
            f"[bold]Evidence ID:[/bold] {pkg.evidence_id}\n"
            f"[bold]Changes:[/bold] {pkg.change_count} "
            f"([red]{len(pkg.critical_changes)} critical[/red])\n"
            f"[bold]Evidence Hash:[/bold] {pkg.evidence_hash}",
            title="Evidence Package", border_style="blue",
        ))

        table = Table(show_lines=True)
        table.add_column("Rule ID")
        table.add_column("Change")
        table.add_column("Severity Delta")
        table.add_column("Description")
        for diff in pkg.diffs:
            sev = diff.severity_delta or "-"
            sev_style = "red" if diff.severity_delta and "CRITICAL" in diff.severity_delta else "white"
            table.add_row(
                diff.rule_id, diff.change_type.value,
                f"[{sev_style}]{sev}[/{sev_style}]",
                diff.description[:60],
            )
        console.print(table)

        decision = typer.prompt(
            "Decision", default="deferred",
            type=click.Choice(["approved", "rejected", "deferred"]),
        )
        justification = typer.prompt("Justification (required for audit trail)")
        record = gate.record_decision(pkg, approver, decision, justification)
        colour = {"approved": "green", "rejected": "red", "deferred": "yellow"}[decision]
        console.print(f"[{colour}]Recorded: {decision.upper()}[/{colour}] (id: {record.approval_id})\n")


@app.command()
def verify(canon_dir: str = typer.Option(".canon")):
    """Verify integrity of Canon approval records."""
    gate = ApprovalGate(canon_dir=Path(canon_dir))
    tampered = gate.verify_integrity()
    if tampered:
        console.print(f"[bold red]INTEGRITY VIOLATION: {len(tampered)} tampered record(s)[/bold red]")
        for r in tampered:
            console.print(f"  - {r}")
        raise typer.Exit(1)
    console.print("[bold green]INTEGRITY VERIFIED: All approval records intact.[/bold green]")


@app.command()
def status(canon_dir: str = typer.Option(".canon")):
    """Show current state of all tracked governance sources."""
    states_dir = Path(canon_dir) / "states"
    if not states_dir.exists() or not list(states_dir.glob("*.json")):
        console.print("[yellow]No source states found. Run [bold]canon fetch[/bold] first.[/yellow]")
        return

    table = Table(title="Canon Source Status", show_lines=True)
    table.add_column("Source", style="bold")
    table.add_column("Version/Commit")
    table.add_column("Rules")
    table.add_column("Hash (8 chars)")
    table.add_column("Last Fetched")

    for state_file in sorted(states_dir.glob("*.json")):
        state = SourceState.model_validate_json(state_file.read_text())
        version = state.version_tag or (state.commit_sha[:8] if state.commit_sha else "unknown")
        table.add_row(
            state.source_name, version, str(len(state.rules)),
            state.raw_hash[:8], state.fetched_at.strftime("%Y-%m-%d %H:%M UTC"),
        )
    console.print(table)


if __name__ == "__main__":
    app()