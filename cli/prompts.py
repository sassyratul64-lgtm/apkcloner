"""
cli/prompts.py

Input prompts with validation baked in - never hands invalid data
downstream to the modification/build pipeline.
"""

from __future__ import annotations

from pathlib import Path

from rich.prompt import Prompt, Confirm

from core.modifier import validate_package_id, InvalidPackageId


def prompt_package_id(current: str) -> str | None:
    while True:
        raw = Prompt.ask(f"Package ID (current: {current})", default=current)
        if raw == current:
            return None
        try:
            validate_package_id(raw)
            return raw
        except InvalidPackageId as e:
            from cli.display import console
            console.print(f"[red]{e}[/red]")


def prompt_text(label: str, default: str = "") -> str | None:
    raw = Prompt.ask(label, default=default)
    return raw if raw != default else None


def prompt_destination(default_dir: Path) -> Path:
    while True:
        raw = Prompt.ask("Destination directory", default=str(default_dir))
        path = Path(raw).expanduser()
        if path.exists() and not path.is_dir():
            from cli.display import console
            console.print("[red]That path exists and is not a directory.[/red]")
            continue
        if not path.exists():
            if Confirm.ask(f"Directory does not exist. Create {path}?", default=True):
                path.mkdir(parents=True, exist_ok=True)
            else:
                continue
        return path


def confirm(label: str, default: bool = True) -> bool:
    return Confirm.ask(label, default=default)
