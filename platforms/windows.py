"""
platform/windows.py

Desktop APK acquisition. Manual path entry always works; a graphical
file picker is offered only when a display/tkinter is actually usable -
never assumed.
"""

from __future__ import annotations

from pathlib import Path


def gui_picker_available() -> bool:
    try:
        import tkinter  # noqa: F401
        # Actually try to init a root window - tkinter import alone doesn't
        # guarantee a usable display (e.g. headless Linux without X).
        root = tkinter.Tk()
        root.withdraw()
        root.destroy()
        return True
    except Exception:
        return False


def pick_apk_via_gui() -> Path | None:
    import tkinter
    from tkinter import filedialog

    root = tkinter.Tk()
    root.withdraw()
    path = filedialog.askopenfilename(
        title="Select APK file",
        filetypes=[("Android Package", "*.apk"), ("All files", "*.*")],
    )
    root.destroy()
    return Path(path) if path else None


def validate_manual_path(raw_path: str) -> Path:
    path = Path(raw_path.strip().strip('"'))
    if not path.exists():
        raise FileNotFoundError(f"No file at: {path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {path}")
    if path.suffix.lower() != ".apk":
        raise ValueError(f"Expected a .apk file, got: {path.suffix}")
    try:
        with open(path, "rb") as f:
            f.read(4)
    except Exception as e:
        raise PermissionError(f"File is not readable: {e}")
    return path
