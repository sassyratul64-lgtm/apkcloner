"""
core/permission_manager.py

Permissions are only ever removed on explicit user confirmation - never
silently. Every removal is logged and surfaced in the final report.
"""

from __future__ import annotations

from core.manifest_manager import ManifestManager

# Permissions that are almost always load-bearing; removing them is very
# likely to break basic app functionality (not exhaustive, just a warning aid).
HIGH_RISK_TO_REMOVE = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.FOREGROUND_SERVICE",
}


class PermissionManager:
    def __init__(self, manifest: ManifestManager):
        self.manifest = manifest

    def list_permissions(self) -> list[str]:
        return self.manifest.list_permissions()

    def risk_warning(self, permission_name: str) -> str | None:
        if permission_name in HIGH_RISK_TO_REMOVE:
            return (
                f"Removing {permission_name} may cause the application to "
                "malfunction or crash."
            )
        return None

    def remove(self, permission_name: str, removal_log: list[str]) -> bool:
        removed = self.manifest.remove_permission(permission_name)
        if removed:
            removal_log.append(permission_name)
        return removed
