"""
core/builder.py

Wraps `apktool` to decode an APK into an editable directory tree and
rebuild it afterwards. This is the real decompile/recompile step - no
shortcuts.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class BuildError(Exception):
    def __init__(self, message: str, stage: str, raw_output: str = ""):
        super().__init__(message)
        self.stage = stage
        self.raw_output = raw_output


class ApkBuilder:
    def __init__(self, apktool_bin: str = "apktool"):
        self.apktool_bin = apktool_bin

    def decode(self, apk_path: Path, output_dir: Path) -> Path:
        cmd = [
            self.apktool_bin, "d", "-f", "-o", str(output_dir), str(apk_path)
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            raise BuildError(
                "apktool failed to decode the APK.", "decode",
                (result.stdout + result.stderr)[-4000:]
            )
        if not (output_dir / "AndroidManifest.xml").is_file():
            raise BuildError(
                "Decode completed but no AndroidManifest.xml was produced.",
                "decode",
            )
        return output_dir

    def build(self, decoded_dir: Path, output_apk: Path) -> Path:
        output_apk.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            self.apktool_bin, "b", str(decoded_dir), "-o", str(output_apk)
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        if result.returncode != 0:
            raise BuildError(
                "apktool failed to rebuild the APK.", "rebuild",
                (result.stdout + result.stderr)[-4000:]
            )
        if not output_apk.is_file():
            raise BuildError(
                "Rebuild reported success but no output APK was produced.",
                "rebuild",
            )
        return output_apk
