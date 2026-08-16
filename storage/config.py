"""
storage/config.py

Simple persisted config: default output directory, history file location.
"""

from __future__ import annotations

import json
from pathlib import Path


class AppConfig:
    DEFAULT_HOME = Path.home() / ".apk_cloner"

    def __init__(self, home: Path | None = None):
        self.home = home or self.DEFAULT_HOME
        self.home.mkdir(parents=True, exist_ok=True)
        self.config_file = self.home / "config.json"
        self.history_file = self.home / "history.json"
        self._data = self._load()

    def _load(self) -> dict:
        if self.config_file.exists():
            try:
                return json.loads(self.config_file.read_text())
            except Exception:
                pass
        return {
            "default_output_dir": str(Path.home() / "ClonedApps"),
        }

    def save(self):
        self.config_file.write_text(json.dumps(self._data, indent=2))

    @property
    def default_output_dir(self) -> Path:
        return Path(self._data.get("default_output_dir", str(Path.home() / "ClonedApps")))

    @default_output_dir.setter
    def default_output_dir(self, value: Path):
        self._data["default_output_dir"] = str(value)
        self.save()
