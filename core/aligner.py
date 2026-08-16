"""
core/aligner.py

Real zip alignment using the official `zipalign` tool (4-byte boundary,
required by Android for efficient mmap-based resource access).
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class AlignError(Exception):
    pass


class ApkAligner:
    def __init__(self, zipalign_bin: str = "zipalign"):
        self.zipalign_bin = zipalign_bin

    def align(self, input_apk: Path, output_apk: Path, alignment: int = 4) -> Path:
        output_apk.parent.mkdir(parents=True, exist_ok=True)
        cmd = [self.zipalign_bin, "-f", "-p", str(alignment), str(input_apk), str(output_apk)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            raise AlignError(f"zipalign failed: {(result.stdout + result.stderr).strip()[-2000:]}")
        if not output_apk.is_file():
            raise AlignError("zipalign reported success but produced no output file.")
        return output_apk

    def verify(self, apk_path: Path, alignment: int = 4) -> bool:
        cmd = [self.zipalign_bin, "-c", "-p", str(alignment), str(apk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode == 0
