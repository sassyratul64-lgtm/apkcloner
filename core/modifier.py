"""
core/modifier.py

Applies a validated CloneConfig to a decoded (apktool) APK directory.
Every change is applied through the dedicated manager for that surface
(manifest, resources, components, permissions) - this module just
sequences them and collects a change log for clone-info.json.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from core.manifest_manager import ManifestManager
from core.resource_manager import ResourceManager
from core.component_manager import ComponentManager
from core.permission_manager import PermissionManager

PACKAGE_ID_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$"
)

RESERVED_JAVA_WORDS = {
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char",
    "class", "const", "continue", "default", "do", "double", "else", "enum",
    "extends", "final", "finally", "float", "for", "goto", "if", "implements",
    "import", "instanceof", "int", "interface", "long", "native", "new",
    "package", "private", "protected", "public", "return", "short", "static",
    "strictfp", "super", "switch", "synchronized", "this", "throw", "throws",
    "transient", "try", "void", "volatile", "while",
}


class InvalidPackageId(Exception):
    pass


def validate_package_id(package_id: str) -> None:
    if not PACKAGE_ID_RE.match(package_id):
        raise InvalidPackageId(
            f"'{package_id}' is not a valid package/application ID. "
            "Expected a reverse-domain form like com.example.app (letters, "
            "digits, underscores; at least two segments; no leading digits)."
        )
    for segment in package_id.split("."):
        if segment.lower() in RESERVED_JAVA_WORDS:
            raise InvalidPackageId(
                f"Segment '{segment}' in '{package_id}' is a reserved Java keyword."
            )


@dataclass
class CloneConfig:
    new_app_name: str | None = None
    new_package_id: str | None = None
    new_version_name: str | None = None
    new_version_code: str | None = None
    new_icon_path: Path | None = None
    permissions_to_remove: list[str] = field(default_factory=list)
    components_to_disable: list[tuple[str, str]] = field(default_factory=list)  # (kind, name)
    keep_original_resources: bool = True


@dataclass
class ModificationReport:
    applied: list[str] = field(default_factory=list)
    skipped_unsupported: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ApkModifier:
    def __init__(self, decoded_dir: Path):
        self.decoded_dir = decoded_dir
        self.manifest = ManifestManager(decoded_dir / "AndroidManifest.xml")
        self.resources = ResourceManager(decoded_dir)
        self.components = ComponentManager(self.manifest)
        self.permissions = PermissionManager(self.manifest)

    def apply(self, config: CloneConfig) -> ModificationReport:
        report = ModificationReport()

        if config.new_package_id:
            validate_package_id(config.new_package_id)
            old_pkg = self.manifest.get_package()
            self.manifest.set_package(config.new_package_id)
            report.applied.append(f"Package ID changed: {old_pkg} -> {config.new_package_id}")
            report.warnings.append(
                "Internal code/string references that hard-code the original "
                "package name (if any) may not resolve after this rename."
            )

        if config.new_version_name or config.new_version_code:
            self.manifest.set_version(config.new_version_name, config.new_version_code)
            report.applied.append(
                f"Version set to name={config.new_version_name or '(unchanged)'} "
                f"code={config.new_version_code or '(unchanged)'}"
            )

        if config.new_app_name:
            self.manifest.set_label_literal(config.new_app_name)
            report.applied.append(f"App label set to literal '{config.new_app_name}'")

        if config.new_icon_path:
            try:
                changed = self.resources.replace_app_icon(config.new_icon_path)
                if changed:
                    report.applied.append(f"App icon replaced ({len(changed)} density variants)")
                else:
                    report.skipped_unsupported.append(
                        "App icon: no ic_launcher assets found to replace in this APK."
                    )
            except Exception as e:
                report.skipped_unsupported.append(f"App icon: {e}")

        for perm in config.permissions_to_remove:
            warn = self.permissions.risk_warning(perm)
            if warn:
                report.warnings.append(warn)
            _removed_log: list[str] = []
            if self.permissions.remove(perm, _removed_log):
                report.applied.append(f"Permission removed: {perm}")
            else:
                report.skipped_unsupported.append(f"Permission not found (not removed): {perm}")

        for kind, name in config.components_to_disable:
            warn = self.components.warn_if_essential(kind, name)
            if warn:
                report.warnings.append(warn)
            if self.components.disable(kind, name):
                report.applied.append(f"Component disabled: {kind} {name}")
            else:
                report.skipped_unsupported.append(f"Component not found (not disabled): {kind} {name}")

        self.manifest.save()
        return report
