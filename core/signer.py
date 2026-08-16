"""
core/signer.py

Real signing via the official `apksigner` tool. Never invents a "signed"
status - relies on apksigner's own exit code and verification pass.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from security.keystore import KeystoreHandle


class SignError(Exception):
    pass


class ApkSigner:
    def __init__(self, apksigner_bin: str = "apksigner"):
        self.apksigner_bin = apksigner_bin

    def sign(self, input_apk: Path, output_apk: Path, keystore: KeystoreHandle) -> Path:
        output_apk.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            self.apksigner_bin, "sign",
            "--ks", str(keystore.path),
            "--ks-key-alias", keystore.alias,
            "--ks-pass", f"pass:{keystore.password}",
            "--key-pass", f"pass:{keystore.password}",
            "--out", str(output_apk),
            str(input_apk),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            # Redact password from any echoed command in the error text.
            safe_err = result.stderr.replace(keystore.password, "****")
            raise SignError(f"apksigner failed to sign the APK: {safe_err.strip()[-2000:]}")
        if not output_apk.is_file():
            raise SignError("apksigner reported success but no signed APK was produced.")
        return output_apk

    def verify(self, apk_path: Path) -> tuple[bool, str]:
        cmd = [self.apksigner_bin, "verify", "--print-certs", str(apk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        ok = result.returncode == 0
        return ok, (result.stdout + result.stderr).strip()
