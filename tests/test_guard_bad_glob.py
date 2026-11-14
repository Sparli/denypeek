"""Python 3.9: a word that is not a valid glob crashed the hook, which then blocked.

`["z-a"]` in a written settings file made fnmatch raise `re.error` (bad character range) on 3.9,
so an ordinary settings edit was denied with "guard error". The first fix compared such a word
as plain text, which let `cat .en[!z-a]` through on 3.9 (the review's L1). Now every bracket
expression is turned into `?` before matching (see test_guard_glob_syntax.py), so fnmatch never
sees a bracket, and a pattern that still fails to compile counts as a match. Real hook errors
still block (see test_guard_hook.py, A14).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from denypeek.guard import blocked
from denypeek.guard import guard as g

GUARD = Path(__file__).resolve().parents[1] / "src" / "denypeek" / "guard" / "guard.py"


def run_hook(payload: dict, home: Path, cwd: Path):
    proc = subprocess.run(
        [sys.executable, "-I", "-S", str(GUARD), "--agent", "claude", "--home", str(home)],
        input=json.dumps(payload).encode(),
        capture_output=True,
        timeout=60,
        cwd=str(cwd),
        env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
    )
    out = proc.stdout.decode() + proc.stderr.decode()
    return blocked("claude", proc.stdout.decode(), proc.returncode), out


def write_event(path: Path, content: str) -> dict:
    return {
        "cwd": str(path.parent.parent),
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(path), "content": content},
    }


def test_a_pattern_that_fails_to_compile_counts_as_a_match(monkeypatch):
    def broken(name, pattern):
        raise re.error("bad character range z-a")

    monkeypatch.setattr(g.fnmatch, "fnmatchcase", broken)
    assert g.name_matches("notes.md", "anything") is True


def test_brackets_never_reach_fnmatch():
    assert g.shell_glob(".en[!z-a]") == ".en?"
    assert g.name_matches(".env", ".en[!z-a]")
    assert g.name_matches(".env", ".en[^x]")


def test_name_matches_still_globs_ignoring_case():
    assert g.name_matches(".env", "*.ENV")
    assert g.name_matches("a", "[z-a]") in (True, False)  # never raises, on any Python


def test_settings_write_with_a_reversed_range_is_allowed(isolated, tmp_path):
    path = tmp_path / "proj" / ".gemini" / "settings.json"
    path.parent.mkdir(parents=True)
    denied, out = run_hook(write_event(path, '{"theme": ["z-a"]}'), isolated, path.parent.parent)
    assert not denied, out
    assert "guard error" not in out


def test_settings_write_that_turns_hooks_off_is_still_denied(isolated, tmp_path):
    path = tmp_path / "proj" / ".gemini" / "settings.json"
    path.parent.mkdir(parents=True)
    content = '{"theme": ["z-a"], "hooksConfig": {"enabled": false}}'
    denied, out = run_hook(write_event(path, content), isolated, path.parent.parent)
    assert denied and "hooks off" in out, out


def test_a_real_hook_error_still_blocks(isolated, tmp_path):
    proc = subprocess.run(
        [sys.executable, "-I", "-S", str(GUARD), "--agent", "claude", "--home", str(isolated)],
        input=b"{not json",
        capture_output=True,
        timeout=60,
        cwd=str(tmp_path),
        env={"HOME": str(isolated), "PATH": "/usr/bin:/bin"},
    )
    assert blocked("claude", proc.stdout.decode(), proc.returncode)
