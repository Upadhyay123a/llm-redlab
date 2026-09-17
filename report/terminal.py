"""Terminal report using rich: a findings summary table, then one grouped
remediation panel per attack type (so fixes aren't repeated per payload).
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from core.finding import Finding

_SEV_COLOR = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def render(target_name: str, findings: list[Finding]) -> None:
    console = Console()
    succeeded = [f for f in findings if f.succeeded]

    console.print()
    console.print(Panel.fit(
        f"[bold]llm-redlab[/bold]  -  target: [cyan]{target_name}[/cyan]\n"
        f"{len(succeeded)}/{len(findings)} attacks succeeded",
        border_style="red" if succeeded else "green",
    ))

    # Findings table.
    table = Table(box=box.SIMPLE_HEAVY, show_lines=False)
    table.add_column("Result", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Risk", justify="right")
    table.add_column("Payload ID", no_wrap=True)
    table.add_column("Category")
    for f in findings:
        result = "[green]SUCCESS[/green]" if f.succeeded else "[dim]blocked[/dim]"
        sev = f"[{_SEV_COLOR.get(f.severity, '')}]{f.severity}[/]"
        risk = f"{f.risk_score:.1f}" if f.succeeded else "-"
        table.add_row(result, sev, risk, f.payload_id, f.category)
    console.print(table)

    # One remediation panel per attack type that succeeded.
    seen: set[str] = set()
    for f in succeeded:
        if f.attack_id in seen:
            continue
        seen.add(f.attack_id)
        console.print(Panel(
            f.remediation,
            title=f"[bold]Remediation - {f.attack_id}[/bold]",
            border_style="green",
            box=box.ROUNDED,
        ))
