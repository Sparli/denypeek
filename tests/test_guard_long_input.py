"""G3: strings too long to check are denied, not skipped."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from denypeek.guard import blocked

GUARD = Path(__file__).resolve().parents[1] / "src" / "denypeek" / "guard" / "guard.py"


def run(agent, payload, cwd, raw=None):
    data = raw if raw is not None else json.dumps(payload).encode()
    start = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-I", "-S", str(GUARD), "--agent", agent, "--home", os.environ["HOME"]],
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


@pytest.mark.parametrize("agent", ["claude", "codex", "gemini"])
def test_g3_overlong_shell_string_is_denied(agent, tmp_path):
    proc, _ = run(
        agent,
        bash("cat .env # " + "x" * 100_001, tmp_path)
        if agent != "gemini"
        else {
            "cwd": str(tmp_path),
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "cat .env # " + "x" * 100_001},
        },
        tmp_path,
    )
    assert blocked(agent, proc.stdout.decode(), proc.returncode)
    assert "too long to check" in proc.stdout.decode()


def test_g3_overlong_path_is_denied(tmp_path):
    path = str(tmp_path) + "/" + "./" * 2100 + ".env"
    payload = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": path},
    }
    proc, _ = run("claude", payload, tmp_path)
    assert blocked("claude", proc.stdout.decode(), proc.returncode)


def test_g3_path_with_newline_is_checked(tmp_path):
    payload = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(tmp_path / ".env") + "\n"},
    }
    proc, _ = run("claude", payload, tmp_path)
    assert blocked("claude", proc.stdout.decode(), proc.returncode)


def test_g3_long_file_content_is_still_allowed(tmp_path):
    payload = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(tmp_path / "big.txt"), "content": "hello world\n" * 20000},
    }
    proc, _ = run("claude", payload, tmp_path)
    assert not blocked("claude", proc.stdout.decode(), proc.returncode)
