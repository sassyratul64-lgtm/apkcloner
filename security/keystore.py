"""
security/keystore.py

Generates and manages signing keystores via the JDK's `keytool`.
Passwords are handled only in-memory for the duration of the process
that needs them, are passed to subprocesses via argv (never echoed),
and are never written into logs, clone-info.json, or history.
"""

from __future__ import annotations

import secrets
import string
import subprocess
from dataclasses import dataclass
from pathlib import Path


class KeystoreError(Exception):
    pass


@dataclass
class KeystoreHandle:
    """Holds a reference to a keystore. The password is intentionally not
    a dataclass field with a repr - it's excluded so accidental print()/
    logging calls on this object can never leak it."""
    path: Path
    alias: str
    _password: str

    def __repr__(self):
        return f"KeystoreHandle(path={self.path}, alias={self.alias}, password=<redacted>)"

    @property
    def password(self) -> str:
        return self._password


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


class KeystoreManager:
    def __init__(self, keytool_bin: str = "keytool"):
        self.keytool_bin = keytool_bin

    def generate_new_keystore(
        self,
        dest_path: Path,
        alias: str = "clonekey",
        common_name: str = "APK Cloner",
        validity_days: int = 10000,
        password: str | None = None,
    ) -> KeystoreHandle:
        password = password or generate_password()
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            self.keytool_bin, "-genkeypair",
            "-v",
            "-keystore", str(dest_path),
            "-alias", alias,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", str(validity_days),
            "-storepass", password,
            "-keypass", password,
            "-dname", f"CN={common_name}, OU=Clone, O=Clone, L=Unknown, ST=Unknown, C=US",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0 or not dest_path.is_file():
            raise KeystoreError("Failed to generate signing keystore.")
        return KeystoreHandle(path=dest_path, alias=alias, _password=password)

    def load_existing(self, path: Path, alias: str, password: str) -> KeystoreHandle:
        if not path.is_file():
            raise KeystoreError(f"Keystore not found: {path}")
        # Validate credentials actually work before handing back the handle.
        cmd = [
            self.keytool_bin, "-list",
            "-keystore", str(path), "-alias", alias, "-storepass", password,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise KeystoreError("Could not open keystore - wrong password, alias, or corrupt file.")
        return KeystoreHandle(path=path, alias=alias, _password=password)
