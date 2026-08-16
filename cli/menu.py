"""
cli/menu.py

Ties every module together into the user-facing flow described in the
spec: Detect -> Analyze -> Configure -> Clone -> Modify -> Rebuild ->
Align -> Sign -> Verify -> Save.
"""

from __future__ import annotations

from pathlib import Path

from rich.prompt import Prompt, IntPrompt

from cli import display, prompts
from core.analyzer import ApkAnalyzer, AnalysisError
from core.clone_engine import CloneEngine, CloneConfig
from platforms.detection import detect_mode, RunMode
from platforms.android import AndroidAppSource, AndroidAppSourceUnavailable
from platforms import windows as win_platform
from storage.config import AppConfig
from storage.history import CloneHistory
from tools.tool_manager import ToolManager


def run():
    display.banner()
    config = AppConfig()
    history = CloneHistory(config.history_file)
    tools = ToolManager()

    display.section("Environment Check")
    statuses = tools.check_all()
    display.env_table(statuses)
    if not tools.environment_ready():
        display.console.print(
            "[red]Required dependency missing.[/red] Install the tool(s) marked above, then re-run."
        )
        return

    mode = detect_mode()
    display.console.print(f"Detected platform mode: [bold]{mode.value}[/bold]\n")

    while True:
        choice = Prompt.ask(
            "\n[bold]Choose mode[/bold]\n"
            "1. Installed Android Apps\n"
            "2. Select APK File\n"
            "3. Clone History\n"
            "4. Exit\n> ",
            choices=["1", "2", "3", "4"],
            default="2",
        )
        if choice == "1":
            apk_path = _select_installed_app()
        elif choice == "2":
            apk_path = _select_apk_file(mode)
        elif choice == "3":
            _show_history(history)
            continue
        else:
            return

        if apk_path is None:
            continue

        _run_clone_flow(apk_path, config, history)


def _select_installed_app() -> Path | None:
    source = AndroidAppSource()
    try:
        apps = source.list_installed_apps()
    except AndroidAppSourceUnavailable as e:
        display.console.print(f"[yellow]{e}[/yellow]")
        return None

    if not apps:
        display.console.print("[yellow]No installed applications were found.[/yellow]")
        return None

    for i, app in enumerate(apps[:50], 1):
        display.console.print(f"{i}. {app.package_id}  (v{app.version_name})")
    idx = IntPrompt.ask("Select application", default=0)
    if idx < 1 or idx > len(apps[:50]):
        return None
    chosen = apps[idx - 1]
    try:
        return source.copy_apk_to_workspace(chosen, Path.home() / ".apk_cloner" / "acquired")
    except AndroidAppSourceUnavailable as e:
        display.console.print(f"[red]{e}[/red]")
        return None


def _select_apk_file(mode: RunMode) -> Path | None:
    if win_platform.gui_picker_available() and prompts.confirm("Use graphical file picker?", default=False):
        path = win_platform.pick_apk_via_gui()
        if path is None:
            return None
        raw = str(path)
    else:
        raw = Prompt.ask("Enter APK file location")

    try:
        path = win_platform.validate_manual_path(raw)
    except Exception as e:
        display.console.print(f"[red]{e}[/red]")
        return None

    display.console.print("[green]✓[/green] APK found")
    display.console.print("[green]✓[/green] File readable")
    return path


def _run_clone_flow(apk_path: Path, app_config: AppConfig, history: CloneHistory):
    display.section("APK Analysis")
    analyzer = ApkAnalyzer()
    try:
        profile = analyzer.analyze(apk_path)
    except AnalysisError as e:
        display.error_panel("Analysis", str(e), original_safe=True)
        return

    display.profile_table(profile)

    if profile.cloneability in ("HIGH RISK", "LIMITED", "UNSUPPORTED"):
        if not prompts.confirm(
            f"Cloneability is {profile.cloneability}. Continue anyway?", default=False
        ):
            return

    display.section("Customization")
    clone_config = CloneConfig()
    clone_config.new_app_name = prompts.prompt_text("App name", profile.app_name)
    clone_config.new_package_id = prompts.prompt_package_id(profile.package_id)
    clone_config.new_version_name = prompts.prompt_text("Version name", profile.version_name)
    clone_config.new_version_code = prompts.prompt_text("Version code", profile.version_code)

    if prompts.confirm("Replace app icon?", default=False):
        icon_raw = Prompt.ask("Path to new icon (PNG/WebP)")
        icon_path = Path(icon_raw).expanduser()
        if icon_path.is_file():
            clone_config.new_icon_path = icon_path
        else:
            display.console.print("[yellow]Icon file not found - keeping original.[/yellow]")

    if profile.permissions and prompts.confirm("Review/remove permissions?", default=False):
        for perm in profile.permissions:
            if prompts.confirm(f"Remove {perm}?", default=False):
                clone_config.permissions_to_remove.append(perm)

    display.section("Cloning")
    engine = CloneEngine(log_fn=lambda line: display.console.print(f"[dim]{line}[/dim]"))
    output_name = (clone_config.new_app_name or profile.app_name or "clone").replace(" ", "_")
    destination = prompts.prompt_destination(app_config.default_output_dir / output_name)

    result = engine.run(apk_path, clone_config, destination, output_name)

    if not result.success:
        display.error_panel(
            result.stage_failed or "unknown",
            result.reason,
            original_safe=result.original_untouched,
            suggestion=_suggestion_for_stage(result.stage_failed),
        )
        history.record(
            app_name=clone_config.new_app_name or profile.app_name,
            package_id=clone_config.new_package_id or profile.package_id,
            output_path="",
            success=False,
            reason=result.reason,
        )
        return

    display.success_panel(str(result.output_apk), result.validation.checks)
    history.record(
        app_name=clone_config.new_app_name or profile.app_name,
        package_id=clone_config.new_package_id or profile.package_id,
        output_path=str(result.output_apk),
        success=True,
    )


def _suggestion_for_stage(stage: str | None) -> str:
    return {
        "decode": "The APK's resources may use an unsupported compile SDK. Try updating apktool's framework files.",
        "rebuild": "Check clone.log for the exact resource/manifest error and adjust the customization that triggered it.",
        "alignment": "Ensure zipalign is installed and the rebuilt APK isn't corrupted.",
        "signing": "Verify the keystore password/alias, or let the tool generate a new keystore.",
        "validation": "Review which specific check failed above; the clone was not saved.",
        "analysis": "Confirm the file is a valid, uncorrupted APK.",
    }.get(stage or "", "Review the log above for details.")


def _show_history(history: CloneHistory):
    display.section("Clone History")
    entries = history.list_all()
    if not entries:
        display.console.print("[dim]No clones yet.[/dim]")
        return
    for e in entries[:20]:
        status = "[green]✓ Successful[/green]" if e["success"] else "[red]✕ Failed[/red]"
        display.console.print(f"{e['app_name']}  {e['package_id']}  {e['timestamp']}  {status}")
