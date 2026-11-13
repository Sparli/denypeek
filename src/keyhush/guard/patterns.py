"""The secret-file pattern list, ~/.keyhush/secretfiles. Defaults live in guard.py."""

from __future__ import annotations

from pathlib import Path

from ..fsutil import ensure_private_dir, write_new_private
from ..sources import Home
from .guard import DEFAULT_PATTERNS


def patterns_path(home: Home) -> Path:
    return home.keyhush_dir / "secretfiles"


def ensure_patterns(home: Home) -> bool:
    """Write the default list if there is none. Returns True if it was created."""
    path = patterns_path(home)
    if path.exists():
        return False
    ensure_private_dir(home.keyhush_dir)
    write_new_private(path, DEFAULT_PATTERNS.encode())
    return True
