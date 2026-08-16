"""
core/component_manager.py

Thin, purpose-specific layer over ManifestManager for enabling/disabling
activities, services, receivers and providers, with essential-component
warnings so the CLI can flag risky choices before they're applied.
"""

from __future__ import annotations

from core.manifest_manager import ManifestManager

COMPONENT_TAGS = {
    "activity": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


class ComponentManager:
    def __init__(self, manifest: ManifestManager):
        self.manifest = manifest

    def list_all(self) -> dict[str, list[str]]:
        return {
            kind: self.manifest.list_components(tag)
            for kind, tag in COMPONENT_TAGS.items()
        }

    def warn_if_essential(self, kind: str, name: str) -> str | None:
        tag = COMPONENT_TAGS.get(kind)
        if not tag:
            return None
        if self.manifest.is_component_exported_or_main(tag, name):
            return (
                f"{name} has an intent-filter (may be the launcher activity or a "
                "required entry point). Disabling it may break the app."
            )
        return None

    def disable(self, kind: str, name: str) -> bool:
        tag = COMPONENT_TAGS.get(kind)
        if not tag:
            raise ValueError(f"Unknown component kind: {kind}")
        return self.manifest.set_component_enabled(tag, name, enabled=False)
