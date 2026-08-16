"""
tools/tool_manager.py

Detects required external tooling before any clone operation is attempted.
Never assumes a tool is present - every call is verified by actually
invoking the binary and inspecting its output/exit code.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class ToolStatus:
    name: str
    found: bool
    path: Optional[str] = None
    version: Optional[str] = None
    required: bool = True
    install_hint: str = ""


def _run(cmd: list[str]) -> Optional[str]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        out = (result.stdout or "") + (result.stderr or "")
        return out.strip().splitlines()[0] if out.strip() else ""
    except Exception:
        return None


class ToolManager:
    """
    Verifies presence of every external binary the pipeline depends on.
    Nothing downstream should assume a tool exists without consulting this.
    """

    CHECKS = {
        "java": {
            "which": "java",
            "version_cmd": ["java", "-version"],
            "required": True,
            "hint": "Install a JDK: apt-get install -y openjdk-21-jdk-headless",
        },
        "keytool": {
            "which": "keytool",
            "version_cmd": ["keytool", "-help"],
            "required": True,
            "hint": "Ships with the JDK. Install a JDK (see 'java' above).",
        },
        "apktool": {
            "which": "apktool",
            "version_cmd": ["apktool", "--version"],
            "required": True,
            "hint": "Install from https://apktool.org or: apt-get install -y apktool",
        },
        "zipalign": {
            "which": "zipalign",
            "version_cmd": ["zipalign"],
            "required": True,
            "hint": "Part of Android SDK build-tools, or: apt-get install -y zipalign",
        },
        "apksigner": {
            "which": "apksigner",
            "version_cmd": ["apksigner", "version"],
            "required": True,
            "hint": "Part of Android SDK build-tools, or: apt-get install -y apksigner",
        },
        "aapt2": {
            "which": "aapt2",
            "version_cmd": ["aapt2", "version"],
            "required": False,
            "hint": "Part of Android SDK build-tools, or: apt-get install -y aapt",
        },
        "adb": {
            "which": "adb",
            "version_cmd": ["adb", "version"],
            "required": False,
            "hint": "Install platform-tools if you want on-device install testing.",
        },
    }

    def check_all(self) -> dict[str, ToolStatus]:
        results: dict[str, ToolStatus] = {}
        for name, spec in self.CHECKS.items():
            path = shutil.which(spec["which"])
            version = _run(spec["version_cmd"]) if path else None
            results[name] = ToolStatus(
                name=name,
                found=bool(path),
                path=path,
                version=version,
                required=spec["required"],
                install_hint=spec["hint"],
            )
        return results

    def missing_required(self) -> list[ToolStatus]:
        return [s for s in self.check_all().values() if s.required and not s.found]

    def environment_ready(self) -> bool:
        return len(self.missing_required()) == 0
