"""A12, A13, A14 and bypass attempts against guard.py, in each agent's input format."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from keyhush.guard import ALLOW_CASES, DENY_CASES, blocked, sample_inputs
from keyhush.sources import resolve_home

from .conftest import symlink_or_skip

GUARD = Path(__file__).resolve().parents[1] / "src" / "keyhush" / "guard" / "guard.py"
AGENTS = ["claude", "codex", "cursor", "gemini"]


@pytest.fixture
def project(tmp_path):
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    for name in (".env", ".env.example", ".dev.vars"):
        (proj / name).write_text("PLACEHOLDER=1\n")
    (proj / "src" / "app.py").write_text("print('hi')\n")
    return proj


def run_guard(agent: str, payload, cwd: Path, python: str = sys.executable, raw: bytes = None):
    data = raw if raw is not None else json.dumps(payload).encode()
    start = time.monotonic()
    proc = subprocess.run(
        [python, str(GUARD), "--agent", agent],
        input=data,
        capture_output=True,
        timeout=20,
        cwd=str(cwd),
        env=dict(os.environ),
    )
    return proc, time.monotonic() - start


@pytest.mark.parametrize("agent", AGENTS)
def test_a12_denies_in_each_agents_format(agent, project, isolated):
    cases = sample_inputs(agent, project, resolve_home(str(isolated)))
    for case in DENY_CASES:
        proc, _ = run_guard(agent, cases[case], project)
        out = proc.stdout.decode()
        assert blocked(agent, out, proc.returncode), (agent, case, out, proc.stderr)
        data = json.loads(out)
        if agent == "cursor":
            assert data["permission"] == "deny" and "keyhush blocked" in data["user_message"]
        elif agent == "gemini":
            assert data["decision"] == "deny" and "keyhush blocked" in data["reason"]
        else:
            hso = data["hookSpecificOutput"]
            assert hso["permissionDecision"] == "deny"
            assert hso["hookEventName"] == "PreToolUse"
            assert "keyhush blocked" in hso["permissionDecisionReason"]


@pytest.mark.parametrize("agent", AGENTS)
def test_a13_allows_harmless_calls_without_approving_them(agent, project, isolated):
    cases = sample_inputs(agent, project, resolve_home(str(isolated)))
    for case in ALLOW_CASES:
        proc, _ = run_guard(agent, cases[case], project)
        out = proc.stdout.decode()
        assert proc.returncode == 0 and not blocked(agent, out, 0), (agent, case, out)
        if agent == "cursor":
            assert json.loads(out) == {"permission": "allow"}  # Cursor needs an explicit answer
        else:
            assert out == ""  # no "allow": the agent's own permission prompts still apply


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize(
    "raw", [b"", b"{not json", b"x" * 5_000_000], ids=["empty", "broken", "5MB"]
)
def test_a14_bad_input_blocks_fast_and_names_uninstall(agent, raw, project):
    proc, seconds = run_guard(agent, None, project, raw=raw)
    assert blocked(agent, proc.stdout.decode(), proc.returncode)
    assert proc.returncode == 2
    assert "keyhush guard uninstall" in proc.stderr.decode()
    assert "keyhush guard uninstall" in proc.stdout.decode()
    assert seconds < 1.0, seconds


def claude_bash(command, cwd):
    return {
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


@pytest.mark.parametrize(
    "command",
    [
        "cat .env",
        "cat ./.env",
        "cat '.env'",
        'cat ".ENV"',
        "cat .En[v]",
        "cat${IFS}.env",
        "cat $IFS.env",
        "cat .e*",
        "cat .en?",
        "less < .env",
        "echo ok && cat .env",
        "true; head -n1 .env | base64",
        "source .env",
        "cp .env /tmp/x",
        "cat src/../.env",
        "cat $HOME/.ssh/id_rsa",
        "cat ~/.ssh/id_ed25519",
        "cat ~/.aws/credentials",
        "python3 -m json.tool --file=.env",
        "grep -rn KEY .",
        "grep -R KEY",
        "rg KEY",
        "git grep KEY",
        "cat .dev.vars",
        "cat server.pem",
        "sh -c 'cat .env'",
        'bash -lc "head .env"',
        'eval "cat .env"',
    ],
)
def test_bypass_attempts_are_blocked(command, project, isolated):
    (project / "server.pem").write_text("x")
    proc, _ = run_guard("claude", claude_bash(command, project), project)
    assert blocked("claude", proc.stdout.decode(), proc.returncode), command


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "cat .env.example",
        "grep -r KEY src/",
        "grep KEY src/app.py",
        "git status",
        "cat src/app.py",
        "ssh-keygen -y -f id.pub",
    ],
)
def test_normal_commands_are_allowed(command, project):
    proc, _ = run_guard("claude", claude_bash(command, project), project)
    assert not blocked("claude", proc.stdout.decode(), proc.returncode), command


def test_symlink_to_secret_file_is_blocked(project):
    symlink_or_skip(project / "notes.txt", project / ".env")
    payload = {
        "cwd": str(project),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(project / "notes.txt")},
    }
    proc, _ = run_guard("claude", payload, project)
    assert blocked("claude", proc.stdout.decode(), proc.returncode)


def test_claude_grep_tool_over_folder_with_secret_is_blocked(project):
    payload = {
        "cwd": str(project),
        "hook_event_name": "PreToolUse",
        "tool_name": "Grep",
        "tool_input": {"pattern": "KEY", "path": str(project)},
    }
    proc, _ = run_guard("claude", payload, project)
    assert blocked("claude", proc.stdout.decode(), proc.returncode)
    payload["tool_input"]["path"] = str(project / "src")
    proc, _ = run_guard("claude", payload, project)
    assert not blocked("claude", proc.stdout.decode(), proc.returncode)


def test_codex_array_command_is_checked(project):
    payload = {
        "cwd": str(project),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": ["bash", "-lc", "cat .env"]},
    }
    proc, _ = run_guard("codex", payload, project)
    assert blocked("codex", proc.stdout.decode(), proc.returncode)


def test_user_patterns_file_is_used(project, isolated):
    (isolated / ".keyhush").mkdir()
    (isolated / ".keyhush" / "secretfiles").write_text("config/prod.yml\n")
    (project / "config").mkdir()
    payload = {
        "cwd": str(project),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(project / "config" / "prod.yml")},
    }
    proc, _ = run_guard("claude", payload, project)
    assert blocked("claude", proc.stdout.decode(), proc.returncode)
    payload["tool_input"]["file_path"] = str(project / ".env")  # defaults replaced
    proc, _ = run_guard("claude", payload, project)
    assert not blocked("claude", proc.stdout.decode(), proc.returncode)


def test_unknown_agent_fails_closed(project):
    proc, _ = run_guard("nope", {"tool_name": "Read"}, project)
    assert proc.returncode == 2 and "keyhush guard uninstall" in proc.stderr.decode()


def _python39():
    for cand in ("python3.9", "/usr/bin/python3"):
        path = shutil.which(cand) or (cand if os.path.exists(cand) else None)
        if not path:
            continue
        try:
            out = subprocess.run(
                [path, "-c", "import sys;print(sys.version_info[:2])"],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
        except OSError:
            continue
        if out.strip() == "(3, 9)":
            return path
    return None


def test_guard_runs_on_python_39_if_available(project, isolated):
    py = _python39()
    if not py:
        pytest.skip("no Python 3.9 on this machine")
    cases = sample_inputs("claude", project, resolve_home(str(isolated)))
    for case in DENY_CASES + ALLOW_CASES:
        proc, _ = run_guard("claude", cases[case], project, python=py)
        assert blocked("claude", proc.stdout.decode(), proc.returncode) == (case in DENY_CASES), (
            case
        )
