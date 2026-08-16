"""
storage/history.py

Persists a local record of past clone operations (never secrets).
"""

from __future__ import annotations

import json
import time
from pathlib import Path


class CloneHistory:
    def __init__(self, history_file: Path):
        self.history_file = history_file
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.history_file.exists():
            self.history_file.write_text("[]")

    def _load(self) -> list[dict]:
        try:
            return json.loads(self.history_file.read_text())
        except Exception:
            return []

    def _save(self, entries: list[dict]):
        self.history_file.write_text(json.dumps(entries, indent=2))

    def record(
        self,
        app_name: str,
        package_id: str,
        output_path: str,
        success: bool,
        reason: str = "",
    ):
        entries = self._load()
        entries.append({
            "app_name": app_name,
            "package_id": package_id,
            "output_path": output_path,
            "success": success,
            "reason": reason,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        self._save(entries)

    def list_all(self) -> list[dict]:
        return list(reversed(self._load()))
