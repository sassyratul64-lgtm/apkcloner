"""
platform/detection.py

Determines which acquisition/UX mode to use. Detection is based on real
environment signals, not guesses - and every branch degrades honestly
when a signal is absent instead of pretending to be a platform it isn't.
"""

from __future__ import annotations

import os
import platform as py_platform
import shutil
from enum import Enum


class RunMode(Enum):
    TERMUX_ANDROID = "termux_android"
    WINDOWS = "windows"
    GENERIC_DESKTOP = "generic_desktop"


def detect_mode() -> RunMode:
    # Termux sets $PREFIX to something like /data/data/com.termux/files/usr
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix or shutil.which("termux-info"):
        return RunMode.TERMUX_ANDROID
    if py_platform.system() == "Windows":
        return RunMode.WINDOWS
    return RunMode.GENERIC_DESKTOP


def has_pm_command() -> bool:
    """`pm` (package manager) is only available on-device (Android/Termux
    with appropriate permissions), never on a desktop Linux sandbox."""
    return shutil.which("pm") is not None


def has_adb() -> bool:
    return shutil.which("adb") is not None
