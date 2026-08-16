"""
cli/display.py

All rich-based rendering lives here so menu.py stays focused on flow logic.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text

console = Console()


def banner():
    console.print(Panel.fit(
        "[bold cyan]ADVANCED APK CLONER[/bold cyan] [dim]v1.0[/dim]",
        border_style="cyan",
    ))


def section(title: str):
    console.rule(f"[bold]{title}[/bold]")


def error_panel(stage: str, reason: str, original_safe: bool, suggestion: str = ""):
    body = (
        f"[bold]Stage:[/bold] {stage}\n\n"
        f"[bold]Reason:[/bold]\n{reason}\n\n"
        f"[bold]Original APK:[/bold] {'[green]Safe ✓[/green]' if original_safe else '[red]AT RISK[/red]'}\n"
    )
    if suggestion:
        body += f"\n[bold]Suggested action:[/bold]\n{suggestion}"
    console.print(Panel(body, title="[bold red]CLONING FAILED[/bold red]", border_style="red"))


def success_panel(output_path: str, checks: dict[str, bool]):
    table = Table(show_header=False, box=None)
    for name, ok in checks.items():
        mark = "[green]✓[/green]" if ok else "[red]✕[/red]"
        table.add_row(name.replace("_", " ").title(), mark)
    console.print(Panel(table, title="[bold green]FINAL VALIDATION[/bold green]", border_style="green"))
    console.print(Panel(f"[bold]{output_path}[/bold]", title="[bold green]Clone successful ✓[/bold green]", border_style="green"))


def profile_table(profile):
    table = Table(title="APK ANALYSIS", show_lines=False)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("App Name", profile.app_name)
    table.add_row("Package ID", profile.package_id)
    table.add_row("Version", f"{profile.version_name} ({profile.version_code})")
    table.add_row("Min SDK", str(profile.min_sdk))
    table.add_row("Target SDK", str(profile.target_sdk))
    table.add_row("Activities", str(len(profile.activities)))
    table.add_row("Services", str(len(profile.services)))
    table.add_row("Receivers", str(len(profile.receivers)))
    table.add_row("Providers", str(len(profile.providers)))
    table.add_row("Permissions", str(len(profile.permissions)))
    table.add_row("Native ABIs", ", ".join(profile.native_abis) or "none")
    table.add_row("DEX Files", str(len(profile.dex_files)))
    table.add_row("Signature", ", ".join(profile.signing_schemes) or "None detected")
    table.add_row("Split APK", "Yes" if profile.is_split_apk else "No")
    table.add_row("Obfuscation", "Detected" if profile.obfuscation_detected else "Not detected")
    color = {"FULL": "green", "GOOD": "green", "LIMITED": "yellow", "HIGH RISK": "red", "UNSUPPORTED": "red"}.get(profile.cloneability, "white")
    table.add_row("Cloneability", f"[{color}]{profile.cloneability}[/{color}]")
    console.print(table)
    if profile.risks:
        console.print(Panel("\n".join(f"⚠ {r}" for r in profile.risks), title="Potential issues detected", border_style="yellow"))


def env_table(statuses: dict):
    table = Table(title="ENVIRONMENT CHECK")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Details")
    for name, st in statuses.items():
        mark = "[green]✓[/green]" if st.found else ("[yellow]⚠ Not detected[/yellow]" if not st.required else "[red]✕ Missing[/red]")
        table.add_row(name, mark, st.version or st.install_hint if not st.found else (st.version or ""))
    console.print(table)
