"""
core/manifest_manager.py

Operates on the human-readable AndroidManifest.xml produced by
`apktool decode` (not the compiled binary AXML). All edits go through
ElementTree with the proper Android namespace so the file stays valid.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ET.register_namespace("android", ANDROID_NS)


def _a(tag: str) -> str:
    return f"{{{ANDROID_NS}}}{tag}"


class ManifestManager:
    def __init__(self, manifest_path: Path):
        self.path = manifest_path
        if not manifest_path.is_file():
            raise FileNotFoundError(f"AndroidManifest.xml not found at {manifest_path}")
        self.tree = ET.parse(manifest_path)
        self.root = self.tree.getroot()

    # ---- package / version ----

    def get_package(self) -> str:
        return self.root.get("package", "")

    def set_package(self, new_package: str):
        old_package = self.get_package()
        self.root.set("package", new_package)
        # Rewrite provider authorities and any component names expressed as
        # ".ClassName" style relative references remain valid automatically;
        # fully-qualified names that literally embed the old package string
        # (rare, but seen in some manifests) are best-effort updated too.
        for elem in self.root.iter():
            for attr in (_a("name"), _a("authorities")):
                val = elem.get(attr)
                if val and old_package and old_package in val:
                    elem.set(attr, val.replace(old_package, new_package))

    def set_version(self, version_name: str | None, version_code: str | None):
        if version_name:
            self.root.set(_a("versionName"), version_name)
        if version_code:
            self.root.set(_a("versionCode"), str(version_code))

    def get_version(self) -> tuple[str, str]:
        return (
            self.root.get(_a("versionName"), ""),
            self.root.get(_a("versionCode"), ""),
        )

    # ---- components ----

    def _application(self):
        app = self.root.find("application")
        if app is None:
            raise ValueError("No <application> element in manifest.")
        return app

    def _normalize_component_name(self, name: str) -> str:
        """apktool/aapt often store component names in the manifest as a
        package-relative form (e.g. '.MainActivity') rather than fully
        qualified. Normalizes both the stored and looked-up name to fully
        qualified form so lookups work regardless of which style is used."""
        if name.startswith("."):
            return self.get_package() + name
        return name

    def list_components(self, tag: str) -> list[str]:
        app = self._application()
        return [
            self._normalize_component_name(c.get(_a("name"), ""))
            for c in app.findall(tag)
        ]

    def set_component_enabled(self, tag: str, name: str, enabled: bool) -> bool:
        app = self._application()
        target = self._normalize_component_name(name)
        for c in app.findall(tag):
            if self._normalize_component_name(c.get(_a("name"), "")) == target:
                c.set(_a("enabled"), "true" if enabled else "false")
                return True
        return False

    def is_component_exported_or_main(self, tag: str, name: str) -> bool:
        """Flags components that look essential (exported launcher activity,
        or has intent-filters) so the UI can warn before disabling them."""
        app = self._application()
        target = self._normalize_component_name(name)
        for c in app.findall(tag):
            if self._normalize_component_name(c.get(_a("name"), "")) == target:
                has_filter = c.find("intent-filter") is not None
                is_main = any(
                    action.get(_a("name")) == "android.intent.action.MAIN"
                    for f in c.findall("intent-filter")
                    for action in f.findall("action")
                )
                return has_filter or is_main
        return False

    # ---- permissions ----

    def list_permissions(self) -> list[str]:
        return [
            p.get(_a("name"), "")
            for p in self.root.findall("uses-permission")
        ]

    def remove_permission(self, permission_name: str) -> bool:
        removed = False
        for p in list(self.root.findall("uses-permission")):
            if p.get(_a("name")) == permission_name:
                self.root.remove(p)
                removed = True
        return removed

    # ---- app label ----

    def get_label_ref(self) -> str:
        return self._application().get(_a("label"), "")

    def set_label_literal(self, literal_name: str):
        """Points the app label directly at a literal string instead of a
        @string/... resource reference, for a simple, safe rename."""
        self._application().set(_a("label"), literal_name)

    def save(self):
        self.tree.write(self.path, encoding="utf-8", xml_declaration=True)
