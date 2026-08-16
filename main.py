#!/usr/bin/env python3
"""
Advanced APK App Cloner - entry point.

Usage:
    python3 main.py            # interactive CLI
    python3 main.py --debug    # interactive CLI with full tracebacks on error
"""

from __future__ import annotations

import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])

from cli import menu  # noqa: E402


def main():
    debug = "--debug" in sys.argv
    try:
        menu.run()
    except KeyboardInterrupt:
        print("\nCancelled.")
    except Exception as e:
        if debug:
            raise
        print(f"\nUnexpected error: {e}\nRun with --debug for a full traceback.")


if __name__ == "__main__":
    main()
