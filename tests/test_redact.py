"""A6, A7, A8, A9 and redaction safety."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import time
from pathlib import Path

import pytest

from keyhush.redact import redact
from keyhush.sources import resolve_home

from .conftest import fake_github, jl, run_cli, write

MARKER = re.compile(r"\[REDACTED:[a-z0-9-]+:[0-9a-f]{8}\]")


def history_files(home: Path) -> dict[Path, bytes]:
    out = {}
    for sub in (".claude", ".codex", ".gemini"):
        for p in (home / sub).rglob("*"):
            if p.is_file() and p.suffix in (".jsonl", ".json"):
                out[p] = p.read_bytes()
    return out


def test_a6_redact_then_scan_finds_nothing(four_store_home, keys):
    home = four_store_home
    before = history_files(home)
    code, out, _ = run_cli("redact", "--home", str(home), "--yes")
    assert code == 0, out
    assert "Redacted 3 secret(s) in 3 file(s)." in out
    assert "Verified: a rescan of the changed files finds no known key shapes." in out
    for k in keys.values():
        assert k not in out

    code, out, _ = run_cli("scan", "--home", str(home), "--json")
    data = json.loads(out)
    remaining = [f for f in data["findings"] if f["agent"] != "cursor"]
    assert remaining == []  # Cursor's database is never redacted

    after = history_files(home)
    for path, old in before.items():
        new = after[path]
        assert MARKER.search(new.decode()), path
        if path.suffix == ".jsonl":
            old_lines, new_lines = old.split(b"\n"), new.split(b"\n")
            assert len(old_lines) == len(new_lines)
            for a, b in zip(old_lines, new_lines):
                if a != b:
                    json.loads(b)  # changed line is still valid JSON
                    assert MARKER.search(b.decode())
        else:
            json.loads(new)
        for k in keys.values():
            assert k.encode() not in new


def test_a7_undo_restores_byte_identical(four_store_home):
    home = four_store_home
    before = history_files(home)
    run_cli("redact", "--home", str(home), "--yes")
    assert history_files(home) != before
    code, out, _ = run_cli("undo", "--home", str(home))
    assert code == 0, out
    assert "Restored 3 file(s)" in out
    assert history_files(home) == before
    code, out, _ = run_cli("undo", "--home", str(home))
    assert code == 2 and "No backup to undo" in out + _


def test_a8_backup_location_permissions_and_warning(four_store_home):
    home = four_store_home
    code, out, _ = run_cli("redact", "--home", str(home), "--yes")
    assert "WARNING: the backup still holds the secrets" in out
    assert "keyhush backups purge" in out
    base = home / ".keyhush" / "backups"
    sets = [p for p in base.iterdir() if p.is_dir()]
    assert len(sets) == 1
    blobs = sorted(sets[0].glob("blob-*"))
    assert len(blobs) == 3
    if sys.platform != "win32":
        for d in (home / ".keyhush", base, sets[0]):
            assert stat.S_IMODE(d.stat().st_mode) == 0o700, d
        for f in [*blobs, sets[0] / "manifest.json"]:
            assert stat.S_IMODE(f.stat().st_mode) == 0o600, f
    for path in history_files(home):
        siblings = [p.name for p in path.parent.iterdir()]
        assert all(not n.startswith((".keyhush", path.name + ".")) for n in siblings), siblings

    code, out, _ = run_cli("backups", "purge", "--home", str(home), "--yes")
    assert code == 0 and "Deleted 1 backup set(s)." in out
    assert list(base.iterdir()) == []


def test_a8_backup_created_owner_only_even_with_loose_umask(four_store_home):
    if sys.platform == "win32":
        pytest.skip("POSIX permissions")
    old = os.umask(0)
    try:
        run_cli("redact", "--home", str(four_store_home), "--yes")
    finally:
        os.umask(old)
    for p in (four_store_home / ".keyhush").rglob("*"):
        mode = stat.S_IMODE(p.stat().st_mode)
        assert mode & 0o077 == 0, (p, oct(mode))


def test_a9_recent_file_and_outside_symlink_are_skipped(isolated, tmp_path):
    home = isolated
    recent = write(
        home / ".claude/projects/p/recent.jsonl", jl({"t": fake_github()}), mtime=time.time() - 60
    )
    linked = False
    if sys.platform != "win32":
        outside = write(tmp_path / "outside/other.jsonl", jl({"t": fake_github()}))
        (home / ".claude/projects/p/link.jsonl").symlink_to(outside)
        linked = True
    original = recent.read_bytes()
    code, out, _ = run_cli("redact", "--home", str(home), "--yes")
    assert code == 1, out
    assert "recent.jsonl: changed in the last 10 minutes" in out
    assert recent.read_bytes() == original
    if linked:
        assert "link.jsonl: symlink leads outside the history folders" in out
        assert outside.read_bytes().count(b"[REDACTED") == 0

    code, out, _ = run_cli("redact", "--home", str(home), "--yes", "--include-active")
    assert "Redacted 1 secret(s) in 1 file(s)." in out
    assert b"[REDACTED:github-pat:" in recent.read_bytes()


def test_hard_linked_file_is_skipped(isolated, tmp_path):
    f = write(isolated / ".claude/projects/p/a.jsonl", jl({"t": fake_github()}))
    os.link(f, tmp_path / "elsewhere.jsonl")
    code, out, _ = run_cli("redact", "--home", str(isolated), "--yes")
    assert code == 1 and "other hard links" in out


def test_redact_refuses_without_yes_when_not_interactive(four_store_home, monkeypatch):
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    before = history_files(four_store_home)
    code, _out, err = run_cli("redact", "--home", str(four_store_home))
    assert code == 2 and "--yes" in err
    assert history_files(four_store_home) == before


def test_file_changed_during_redact_is_left_alone(isolated, monkeypatch):
    f = write(isolated / ".claude/projects/p/a.jsonl", jl({"t": fake_github()}))
    import keyhush.backups as backups

    real_add = backups.BackupSet.add

    def add_and_simulate_agent_write(self, original, data, mode):
        entry = real_add(self, original, data, mode)
        with open(original, "ab") as fh:
            fh.write(b'{"new": "line"}\n')
        return entry

    monkeypatch.setattr(backups.BackupSet, "add", add_and_simulate_agent_write)
    res = redact(resolve_home(str(isolated)))
    assert res.changed == []
    assert any("changed while redacting" in p.reason for p in res.skipped)
    assert f.read_bytes().endswith(b'{"new": "line"}\n')


def test_line_that_would_break_json_is_left_alone(isolated):
    key = fake_github()
    bad = '{"t": "' + key + '"'  # not valid JSON to begin with
    f = write(isolated / ".claude/projects/p/a.jsonl", '{"ok": 1}\n' + bad + "\n")
    code, out, _ = run_cli("redact", "--home", str(isolated), "--yes")
    assert "line is not valid JSON; left as is" in out
    assert key.encode() in f.read_bytes()
    assert code != 0
