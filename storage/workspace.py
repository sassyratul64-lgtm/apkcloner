"""
storage/workspace.py

Every clone operation happens inside an isolated, disposable workspace.
The original APK is copied in read-only fashion and never written to.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import uuid
from pathlib import Path


class Workspace:
    def __init__(self, base_dir: Path | None = None):
        self.root = Path(
            tempfile.mkdtemp(prefix=f"apkcloner_{uuid.uuid4().hex[:8]}_", dir=base_dir)
        )
        self.decode_dir = self.root / "decoded"
        self.original_copy: Path | None = None
        self.original_sha256: str | None = None

    def import_original(self, source_apk: Path) -> Path:
        """Copies the source APK into the workspace and records its hash so
        we can prove afterwards that the original file on disk was never
        modified."""
        if not source_apk.is_file():
            raise FileNotFoundError(f"APK not found: {source_apk}")
        self.original_sha256 = self._sha256(source_apk)
        dest = self.root / "original.apk"
        shutil.copy2(source_apk, dest)
        self.original_copy = dest
        return dest

    def verify_original_untouched(self, source_apk: Path) -> bool:
        """Re-hashes the user's original APK to prove it is byte-for-byte
        unchanged after the whole pipeline has run."""
        if self.original_sha256 is None:
            return False
        return self._sha256(source_apk) == self.original_sha256

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.cleanup()
