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

def _report_run(monitor: CanonMonitor) -> bool:
    """Print source warnings and failures. Return True if any source failed."""
    for warning in monitor.warnings:
        console.print(f"[yellow]WARNING:[/yellow] {warning}")
    for source_id, message in monitor.errors.items():
        console.print(f"[red]FAILED {source_id}:[/red] {message}")
    return bool(monitor.errors)


app = typer.Typer(name="canon", help="Canon - Deterministic governance knowledge integrity engine.")
console = Console()



@app.command()
def sync(
    anchor_root: str = typer.Option(..., help="Path to the Anchor repository root"),
    canon_dir: str = typer.Option(".canon", help="Canon state directory"),
    github_token: str = typer.Option(None, envvar="GITHUB_TOKEN"),
):
    """Fetch sources, diff, and generate proposals in an Anchor repository."""
    anchor_path = Path(anchor_root).resolve()
    if not anchor_path.exists():
        console.print(f"[red]Anchor root not found: {anchor_path}[/red]")
        raise typer.Exit(1)

    # Default canon_dir to inside the Anchor repo
    canon_path = (
        Path(canon_dir)
        if canon_dir != ".canon"
        else anchor_path / ".canon"
    )

    monitor = CanonMonitor(
        canon_dir=canon_path,
        anchor_repo_root=anchor_path,
    )
    console.print(
        f"[bold blue]Canon Sync[/bold blue] - Anchor root: {anchor_path}\n"
    )
    packages = asyncio.run(monitor.run(
        github_token=github_token,
        generate_proposals=True,
    ))

    failed = _report_run(monitor)
    pending = [p for p in packages if p.change_count > 0]
    if not pending:
        if not failed:
            console.print(
                "[green]Sources checked successfully. No proposals generated.[/green]"
            )
        raise typer.Exit(1 if failed else 0)

    console.print(f"\n[yellow]{len(pending)} proposal(s) generated.[/yellow]")
    console.print(
        f"Run [bold]canon review --canon-dir {canon_path}[/bold] to review."
    )

    if failed:
        raise typer.Exit(1)



@app.command()
def fetch(
    canon_dir: str = typer.Option(".canon"),
    github_token: str = typer.Option(None, envvar="GITHUB_TOKEN"),
):
    """Fetch all governance sources and produce evidence packages."""
    monitor = CanonMonitor(canon_dir=Path(canon_dir))
    console.print("[bold blue]Canon[/bold blue] - Fetching governance sources...\n")
    packages = asyncio.run(monitor.run(github_token=github_token))

    failed = _report_run(monitor)
    pending = [p for p in packages if p.change_count > 0]
    if not pending:
        if not failed:
            console.print("[green]Sources checked successfully. No changes detected.[/green]")
        raise typer.Exit(1 if failed else 0)

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

    if failed:
        raise typer.Exit(1)


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
    """Verify the ledger hash chain and the integrity of approval records."""
    gate = ApprovalGate(canon_dir=Path(canon_dir))
    tampered = gate.verify_integrity()
    chain_problems = gate.ledger.verify()
    binding_problems = gate.verify_ledger_binding()

    if tampered or chain_problems or binding_problems:
        console.print("[bold red]INTEGRITY VIOLATION[/bold red]")
        for r in tampered:
            console.print(f"  - tampered approval record: {r}")
        for p in chain_problems:
            console.print(f"  - ledger: {p}")
        for p in binding_problems:
            console.print(f"  - ledger/approval mismatch: {p}")
        raise typer.Exit(1)
    console.print(
        "[bold green]INTEGRITY VERIFIED: ledger chain and approval records intact.[/bold green]"
    )


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
    table.add_column("Fetched via")
    table.add_column("Hash (8 chars)")
    table.add_column("Last Fetched")

    for state_file in sorted(states_dir.glob("*.json")):
        state = SourceState.model_validate_json(state_file.read_text(encoding="utf-8"))
        version = state.version_tag or (state.commit_sha[:8] if state.commit_sha else "unknown")
        method = state.fetch_method or "unknown"
        if state.degraded:
            method += " (degraded)"
        table.add_row(
            state.source_name, version, str(len(state.rules)), method,
            state.raw_hash[:8], state.fetched_at.strftime("%Y-%m-%d %H:%M UTC"),
        )
    console.print(table)


if __name__ == "__main__":
    app()
