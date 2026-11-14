"""File helpers: owner-only folders and files, atomic replace."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

BINARY = getattr(os, "O_BINARY", 0)


def ensure_private_dir(path: Path) -> None:
    """Create a folder with owner-only access (0700) at creation, not fixed afterwards."""
    path = Path(path)
    if path.is_symlink():
        raise OSError(f"{path} is a symlink; refusing to use it")
    if path.is_dir():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mkdir(str(path), 0o700)
    except FileExistsError:
        if not path.is_dir() or path.is_symlink():
            raise


def write_new_private(path: Path, data: bytes) -> None:
    """Create a new owner-only file (0600). Fails if it already exists."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | BINARY, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    """Write next to the target, fsync, then rename over it. A crash leaves the old file."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=".denypeek-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
