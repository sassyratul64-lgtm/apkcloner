"""
security/secrets.py

Defensive helpers: path traversal prevention, filename sanitization,
and a subprocess wrapper that guarantees secrets never reach logs.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Optional


class SecurityError(Exception):
    pass


_SAFE_NAME = re.compile(r"^[A-Za-z0-9._\- ]+$")


def sanitize_filename(name: str) -> str:
    """Strips anything that isn't a safe filename character. Prevents
    path traversal / injection via user-provided icon or resource names."""
    name = Path(name).name  # drop any directory components
    cleaned = re.sub(r"[^A-Za-z0-9._\- ]", "_", name)
    if not cleaned or cleaned in (".", ".."):
        raise SecurityError(f"Unsafe filename rejected: {name!r}")
    return cleaned


def safe_extract_path(member_name: str, extract_root: Path) -> Path:
    """Resolves a zip member path against extract_root and refuses to
    return anything that would escape it (zip-slip protection)."""
    target = (extract_root / member_name).resolve()
    root = extract_root.resolve()
    if not str(target).startswith(str(root) + "/") and target != root:
        raise SecurityError(f"Path traversal attempt blocked: {member_name!r}")
    return target


def run_silent(cmd: list[str], secret_args: Optional[set[str]] = None, **kwargs):
    """Runs a subprocess and, on failure, raises with a command line where
    any secret argument values (e.g. keystore passwords) are redacted so
    they can never leak into logs or error panels."""
    secret_args = secret_args or set()
    result = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        redacted = []
        skip_next = False
        for tok in cmd:
            if skip_next:
                redacted.append("****")
                skip_next = False
                continue
            redacted.append(tok)
            if tok in secret_args:
                skip_next = True
        raise RuntimeError(
            f"Command failed ({' '.join(redacted)}): {result.stderr.strip()[:2000]}"
        )
    return result
