"""G2 (inputs that hang the hook) and G3 (strings too long to check are denied, not skipped)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from keyhush.guard import blocked

GUARD = Path(__file__).resolve().parents[1] / "src" / "keyhush" / "guard" / "guard.py"


def run(agent, payload, cwd, raw=None):
    data = raw if raw is not None else json.dumps(payload).encode()
    start = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-I", "-S", str(GUARD), "--agent", agent],
        input=data,
        capture_output=True,
        timeout=60,
        cwd=str(cwd),
        env=dict(os.environ),
    )
    return proc, time.monotonic() - start


def bash(command, cwd):
    return {
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


LIMIT = 4.0  # the agents' timeout is 10 s; the hook must answer well inside it


def test_g2_many_newlines_answer_fast(tmp_path):
    proc, secs = run("codex", bash("cat .env" + "\n" * 40000, tmp_path), tmp_path)
    assert secs < LIMIT, secs
    assert blocked("codex", proc.stdout.decode(), proc.returncode)


def test_g2_wide_globs_answer_fast(tmp_path):
    wide = tmp_path / "wide"
    for a in range(14):
        for b in range(14):
            for c in range(14):
                (wide / str(a) / str(b) / str(c)).mkdir(parents=True)
    proc, secs = run("claude", bash(" ".join(["cat"] + ["wide/*/*/*/*"] * 10), tmp_path), tmp_path)
    assert secs < LIMIT, secs
    assert proc.returncode in (0, 2)
    out = proc.stdout.decode()
    assert out.strip(), "the hook must always answer"


def test_g2_many_brace_groups_answer_fast(tmp_path):
    token = "{a,b}" * 8
    proc, secs = run("claude", bash(" ".join(["cat"] + [token] * 300), tmp_path), tmp_path)
    assert secs < LIMIT, secs
    assert proc.stdout.decode().strip()


def test_g2_timeout_denies_and_says_why(tmp_path, monkeypatch):
    from keyhush.guard import guard as g

    monkeypatch.setattr(g, "HOOK_SECONDS", 0.0)
    out, code, msg = g.run(["--agent", "claude"], json.dumps(bash("cat x", tmp_path)).encode())
    assert code == 2 and "too long" in msg
