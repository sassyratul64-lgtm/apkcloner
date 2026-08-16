"""
platform/android.py

Real installed-application discovery for Android/Termux, using the `pm`
package manager command that's available on-device. When it isn't
available (e.g. this tool running in a desktop sandbox, or Termux
without storage/shell access to `pm`), this module says so plainly
instead of fabricating a fake app list.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from platforms.detection import has_pm_command


@dataclass
class InstalledApp:
    package_id: str
    apk_path: str
    app_name: str = ""
    version_name: str = ""


class AndroidAppSourceUnavailable(Exception):
    pass


class AndroidAppSource:
    def list_installed_apps(self) -> list[InstalledApp]:
        if not has_pm_command():
            raise AndroidAppSourceUnavailable(
                "The Android package manager ('pm') is not available in this "
                "environment, so installed apps cannot be listed automatically. "
                "This happens when the tool isn't running on an actual Android "
                "device/Termux, or storage permission hasn't been granted. "
                "Use the manual APK file selection option instead."
            )
        try:
            result = subprocess.run(
                ["pm", "list", "packages", "-f"],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as e:
            raise AndroidAppSourceUnavailable(f"Failed to run 'pm list packages': {e}")

        if result.returncode != 0:
            raise AndroidAppSourceUnavailable(
                f"'pm list packages' failed: {result.stderr.strip()}"
            )

        apps: list[InstalledApp] = []
        # Format: package:/data/app/.../base.apk=com.example.app
        for line in result.stdout.splitlines():
            m = re.match(r"package:(.+)=([\w.]+)$", line.strip())
            if not m:
                continue
            apk_path, package_id = m.group(1), m.group(2)
            apps.append(InstalledApp(package_id=package_id, apk_path=apk_path))

        for app in apps:
            app.version_name = self._get_version_name(app.package_id)

        return apps

    @staticmethod
    def _get_version_name(package_id: str) -> str:
        try:
            result = subprocess.run(
                ["dumpsys", "package", package_id],
                capture_output=True, text=True, timeout=15,
            )
            m = re.search(r"versionName=(\S+)", result.stdout)
            return m.group(1) if m else "unknown"
        except Exception:
            return "unknown"

    def copy_apk_to_workspace(self, app: InstalledApp, dest_dir: Path) -> Path:
        """Copies (never moves/modifies) the installed APK out to a working
        location. Requires read access to /data/app/... which on stock
        Android is restricted; on Termux this typically needs root or the
        app to be debuggable/exported. Fails honestly if access is denied."""
        src = Path(app.apk_path)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"{app.package_id}.apk"
        try:
            shutil.copy2(src, dest)
        except PermissionError as e:
            raise AndroidAppSourceUnavailable(
                f"Permission denied reading {src}. Android restricts direct "
                "access to other apps' installed APKs on most devices. Use "
                "'adb shell pm path <package>' + 'adb pull', or manual APK "
                "file selection, instead."
            ) from e
        return dest
