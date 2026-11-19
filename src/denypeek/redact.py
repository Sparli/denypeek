"""Redact secrets in JSONL and JSON history files, verify, and undo.

Safety rules:
- Only files inside the known history folders; symlinks that lead elsewhere and files with
  more than one hard link are skipped.
- Files changed in the last 10 minutes are skipped unless include_active (an agent may be
  writing to them).
- A backup is written before any change. The change is written to a temporary file and
  renamed over the original, so a crash leaves the original intact.
- Just before the rename the file is read again; if it changed, the file is skipped.
- Untouched lines stay byte-identical. A changed line must still be valid JSON, or that
  line is left alone and listed.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import backups
from .fsutil import atomic_write
from .scan import Problem, find_secrets, fingerprint, inside, preview, salt, scan
from .sources import Home

ACTIVE_SECONDS = 10 * 60


@dataclass
class Rotation:
    rule: str
    preview: Optional[str]
    length: int
    fingerprint: str


@dataclass
class RedactResult:
    planned_files: int = 0
    changed: list[Path] = field(default_factory=list)
    redacted: int = 0
    skipped: list[Problem] = field(default_factory=list)
    leftover: list[Problem] = field(default_factory=list)  # found again after redaction
    rotate: dict[str, Rotation] = field(default_factory=dict)
    backup: Optional[backups.BackupSet] = None

    @property
    def exit_code(self) -> int:
        if self.leftover:
            return 2
        return 1 if self.skipped else 0


def marker(rule: str, fp: str) -> str:
    return f"[REDACTED:{rule}:{fp}]"


def _valid_json(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except ValueError:
        return False


def _replace(text: str, hits, key: bytes, result: RedactResult):
    new = text
    for h in sorted(hits, key=lambda h: h.start, reverse=True):
        fp = fingerprint(h.secret, key)
        new = new[: h.start] + marker(h.rule, fp) + new[h.end :]
        result.rotate.setdefault(fp, Rotation(h.rule, preview(h.rule, h.secret), len(h.secret), fp))
    return new


def redact_bytes(data: bytes, kind: str, path: Path, key: bytes, result: RedactResult):
    """Return (new_bytes, count). Lines that would break stay unchanged and are listed."""
    if kind == "json":
        text = data.decode("utf-8")
        hits = find_secrets(text)
        if not hits:
            return data, 0
        new = _replace(text, hits, key, result)
        if _valid_json(text) and not _valid_json(new):
            result.skipped.append(Problem(path, "", "redaction would break the JSON; left as is"))
            return data, 0
        return new.encode("utf-8"), len(hits)

    lines = data.split(b"\n")
    count = 0
    for i, raw in enumerate(lines):
        if not raw.strip():
            continue
        line = raw.decode("utf-8")
        hits = find_secrets(line)
        if not hits:
            continue
        new = _replace(line, hits, key, result)
        if not _valid_json(new):
            why = (
                "line is not valid JSON"
                if not _valid_json(line)
                else "redaction would break the JSON"
            )
            result.skipped.append(Problem(path, str(i + 1), f"{why}; left as is"))
            continue
        lines[i] = new.encode("utf-8")
        count += len(hits)
    return b"\n".join(lines), count


def _skip_reason(path: Path, roots: list[Path], include_active: bool, now: float) -> Optional[str]:
    if not inside(path, roots):
        return "symlink or path leads outside the history folders"
    try:
        st = os.stat(path)
    except OSError as exc:
        return f"cannot read: {exc.strerror or exc}"
    if st.st_nlink > 1:
        return "file has other hard links"
    if not include_active and now - st.st_mtime < ACTIVE_SECONDS:
        return "changed in the last 10 minutes (an agent may be using it); use --include-active"
    return None


def redact(home: Home, include_active: bool = False) -> RedactResult:
    result = RedactResult()
    found = scan(home, kinds={"jsonl", "json"})
    if found.stopped:  # Ctrl-C: change nothing on a partial scan
        raise KeyboardInterrupt
    files = {}
    for f in found.findings:
        files.setdefault(f.path, None)
    kinds = {s.path: s.kind for s in found.files}
    for p in found.incomplete:
        if p.path in files and not p.where:
            result.skipped.append(
                Problem(p.path, "", f"not fully readable ({p.reason}); left as is")
            )
            files.pop(p.path)
    for p in found.notes:
        if "symlink" in p.reason:
            result.skipped.append(Problem(p.path, "", "symlink leads outside the history folders"))
    result.planned_files = len(files)
    roots = home.history_roots()
    now = time.time()
    key = salt(home)

    for path in files:
        reason = _skip_reason(path, roots, include_active, now)
        if reason:
            result.skipped.append(Problem(path, "", reason))
            continue
        try:
            data = path.read_bytes()
            st = os.stat(path)
            mode = st.st_mode & 0o777
            new, count = redact_bytes(data, kinds[path], path, key, result)
        except (OSError, UnicodeDecodeError) as exc:
            result.skipped.append(Problem(path, "", f"cannot redact: {exc}"))
            continue
        if count == 0:
            continue
        if result.backup is None:
            result.backup = backups.new_set(home)
        entry = result.backup.add(path, data, mode, (st.st_atime_ns, st.st_mtime_ns))
        if path.read_bytes() != data:  # changed while we worked
            result.skipped.append(Problem(path, "", "file changed while redacting; left as is"))
            continue
        atomic_write(path, new, mode=mode)
        # keep the file's times: agents order sessions by them, and a later redact would
        # otherwise skip the file as recently changed
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
        entry["sha256_after"] = backups.sha256(new)
        result.backup.save()
        result.changed.append(path)
        result.redacted += count

    # Prove it: rescan every changed file.
    for path in result.changed:
        text = path.read_bytes().decode("utf-8")
        units = [text] if kinds[path] == "json" else text.split("\n")
        skipped_lines = {p.where for p in result.skipped if p.path == path}
        for n, unit in enumerate(units, start=1):
            if kinds[path] == "jsonl" and str(n) in skipped_lines:
                continue
            for hit in find_secrets(unit):
                where = "" if kinds[path] == "json" else str(n)
                result.leftover.append(
                    Problem(path, where, f"{hit.rule} still present after redaction")
                )
    return result


@dataclass
class UndoResult:
    backup: Optional[backups.BackupSet] = None
    restored: list[Path] = field(default_factory=list)
    skipped: list[Problem] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        if self.backup is None:
            return 2
        return 1 if self.skipped else 0


def undo(home: Home, set_name: Optional[str] = None) -> UndoResult:
    result = UndoResult()
    sets = [s for s in backups.list_sets(home) if not s.manifest.get("broken")]
    if set_name:
        sets = [s for s in sets if s.name == set_name]
    else:
        sets = [s for s in sets if not s.manifest.get("undone")]
    if not sets:
        return result
    bs = sets[-1]
    result.backup = bs
    roots = home.history_roots()
    for entry in bs.manifest["files"]:
        path = Path(entry["path"])
        if entry.get("sha256_after") is None:
            result.skipped.append(Problem(path, "", "was never changed by this redact run"))
            continue
        if path.is_symlink() or not inside(path, roots):
            result.skipped.append(Problem(path, "", "outside the history folders; not restored"))
            continue
        try:
            current = path.read_bytes()
        except OSError as exc:
            result.skipped.append(Problem(path, "", f"cannot read: {exc.strerror or exc}"))
            continue
        if backups.sha256(current) == entry["sha256_before"]:
            result.skipped.append(Problem(path, "", "already restored"))
            continue
        if backups.sha256(current) != entry["sha256_after"]:
            result.skipped.append(Problem(path, "", "changed since redact; not restored"))
            continue
        original = (bs.path / entry["blob"]).read_bytes()
        if backups.sha256(original) != entry["sha256_before"]:
            result.skipped.append(Problem(path, "", "backup copy is damaged; not restored"))
            continue
        atomic_write(path, original, mode=entry.get("mode", 0o600))
        if entry.get("mtime_ns") is not None:
            os.utime(path, ns=(entry.get("atime_ns", entry["mtime_ns"]), entry["mtime_ns"]))
        result.restored.append(path)
    bs.manifest["undone"] = True
    bs.save()
    return result
