"""
core/resource_manager.py

Operates on the decoded resource tree produced by apktool. Only ever
touches files inside the workspace's decode directory - never the
original APK.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from PIL import Image

from security.secrets import sanitize_filename, SecurityError

ICON_DIRS = [
    "mipmap-mdpi", "mipmap-hdpi", "mipmap-xhdpi", "mipmap-xxhdpi", "mipmap-xxxhdpi",
    "mipmap-anydpi-v26",
    "drawable-mdpi", "drawable-hdpi", "drawable-xhdpi", "drawable-xxhdpi", "drawable-xxxhdpi",
]


class ResourceManager:
    def __init__(self, decode_dir: Path):
        self.decode_dir = decode_dir
        self.res_dir = decode_dir / "res"

    def search(self, query: str) -> list[Path]:
        if not self.res_dir.is_dir():
            return []
        query_lower = query.lower()
        return [
            p for p in self.res_dir.rglob("*")
            if p.is_file() and query_lower in p.name.lower()
        ]

    def find_launcher_icon_names(self) -> set[str]:
        """Finds the icon base filenames (without extension/density suffix)
        referenced as mipmap/ic_launcher in the manifest's application icon
        attribute, falling back to the conventional 'ic_launcher' name."""
        return {"ic_launcher", "ic_launcher_round"}

    def replace_app_icon(self, new_icon_path: Path) -> list[Path]:
        """Validates the supplied image and writes it into every density
        bucket that currently holds an ic_launcher asset. Returns the list
        of files actually replaced."""
        if not new_icon_path.is_file():
            raise FileNotFoundError(f"Icon file not found: {new_icon_path}")

        try:
            with Image.open(new_icon_path) as img:
                img.verify()
            with Image.open(new_icon_path) as img:
                fmt = img.format
                w, h = img.size
        except Exception as e:
            raise ValueError(f"Not a valid image file: {e}")

        if fmt not in ("PNG", "WEBP"):
            raise ValueError(f"Unsupported icon format '{fmt}'. Use PNG or WebP.")
        if w < 48 or h < 48:
            raise ValueError(f"Icon too small ({w}x{h}). Minimum 48x48 recommended.")

        replaced = []
        icon_names = self.find_launcher_icon_names()
        for density_dir in ICON_DIRS:
            d = self.res_dir / density_dir
            if not d.is_dir():
                continue
            for existing in d.iterdir():
                stem = existing.stem
                if stem in icon_names and existing.is_file():
                    # Generate a density-appropriate resize rather than a raw copy.
                    target_size = self._target_size_for_density(density_dir)
                    with Image.open(new_icon_path) as src:
                        src = src.convert("RGBA")
                        resized = src.resize((target_size, target_size), Image.LANCZOS)
                        out_path = existing.with_suffix(".png")
                        resized.save(out_path)
                        if out_path != existing:
                            existing.unlink(missing_ok=True)
                        replaced.append(out_path)
        return replaced

    @staticmethod
    def _target_size_for_density(density_dir: str) -> int:
        table = {
            "mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192,
        }
        for key, size in table.items():
            if key in density_dir:
                return size
        return 96

    def set_string_value(self, name: str, new_value: str, values_dir: str = "values") -> bool:
        """Edits res/values/strings.xml (or a specific values-* folder) in
        place. Returns False rather than silently no-op-ing if the key
        wasn't found, so callers know it's unsupported for this APK."""
        import xml.etree.ElementTree as ET

        strings_xml = self.res_dir / values_dir / "strings.xml"
        if not strings_xml.is_file():
            return False
        tree = ET.parse(strings_xml)
        root = tree.getroot()
        found = False
        for el in root.findall("string"):
            if el.get("name") == name:
                el.text = new_value
                found = True
        if found:
            tree.write(strings_xml, encoding="utf-8", xml_declaration=True)
        return found
