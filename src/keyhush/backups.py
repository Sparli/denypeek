"""Backups for redact and undo, under ~/.keyhush/backups/ with owner-only access.

Each redact run makes one backup set: a folder holding a copy of every file before it was
changed (blob-0001, ...) and manifest.json. The copies still contain the secrets until
`keyhush backups purge` deletes them.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .fsutil import atomic_write, ensure_private_dir, write_new_private
from .sources import Home

MANIFEST = "manifest.json"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def backups_dir(home: Home) -> Path:
    return home.keyhush_dir / "backups"


@dataclass
class BackupSet:
    path: Path
    manifest: dict

    @property
    def name(self) -> str:
        return self.path.name

    def add(self, original: Path, data: bytes, mode: int) -> dict:
        n = len(self.manifest["files"]) + 1
        blob = f"blob-{n:04d}"
        write_new_private(self.path / blob, data)
        entry = {
            "path": str(original),
            "blob": blob,
            "sha256_before": sha256(data),
            "sha256_after": None,
            "mode": mode,
        }
        self.manifest["files"].append(entry)
        self.save()
        return entry

    def save(self) -> None:
        payload = json.dumps(self.manifest, indent=2).encode()
        target = self.path / MANIFEST
        if not target.exists():
            write_new_private(target, payload)
        else:
            atomic_write(target, payload, mode=0o600)


def new_set(home: Home) -> BackupSet:
    ensure_private_dir(home.keyhush_dir)
    ensure_private_dir(backups_dir(home))
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = backups_dir(home) / f"{stamp}-{secrets.token_hex(3)}"
    os.mkdir(str(path), 0o700)
    bs = BackupSet(path, {"tool": "keyhush", "version": __version__, "created": stamp,
                          "home": str(home.root), "undone": False, "files": []})
    bs.save()
    return bs


def list_sets(home: Home) -> list[BackupSet]:
    base = backups_dir(home)
    if not base.is_dir():
        return []
    out = []
    for p in sorted(base.iterdir()):
        if not p.is_dir() or p.is_symlink():
            continue
        try:
            manifest = json.loads((p / MANIFEST).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            manifest = {"files": [], "broken": True}
        out.append(BackupSet(p, manifest))
    return out


def size_of(path: Path) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += (Path(dirpath) / f).stat().st_size
            except OSError:
                pass
    return total


def purge(home: Home) -> int:
    """Delete every backup set. Returns how many were deleted."""
    sets = list_sets(home)
    for bs in sets:
        shutil.rmtree(bs.path)
    return len(sets)
