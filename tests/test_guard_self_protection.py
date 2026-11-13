"""A19: an agent cannot switch the guard off."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from keyhush.guard import blocked

GUARD = Path(__file__).resolve().parents[1] / "src" / "keyhush" / "guard" / "guard.py"
AGENTS = ["claude", "codex", "cursor", "gemini"]


def protected_files(home: Path) -> list[Path]:
    return [
        home / ".keyhush" / "secretfiles",
        home / ".keyhush" / "guard.py",
        home / ".keyhush" / "guard-state.json",
        home / ".keyhush" / "backups" / "20261113T000000Z-abc123" / "blob-0001",
        home / ".keyhush" / "config-backups" / "x-.claude-settings.json",
        home / ".claude" / "settings.json",
        home / ".codex" / "hooks.json",
        home / ".codex" / "config.toml",
        home / ".cursor" / "hooks.json",
        home / ".gemini" / "settings.json",
    ]


def event(agent: str, kind: str, value: str, cwd: Path) -> dict:
    """A tool call in the agent's own hook format. kind: read, edit or shell."""
    if agent in ("claude", "codex"):
        if kind == "shell":
            tool, ti = "Bash", {"command": value}
        elif agent == "codex":  # Codex reads through the shell and edits through apply_patch
            if kind == "read":
                tool, ti = "Bash", {"command": f"cat '{value}'"}
            else:
                patch = f"*** Begin Patch\n*** Update File: {value}\n@@\n-a\n+b\n*** End Patch\n"
                tool, ti = "apply_patch", {"command": patch}
        else:
            tool = "Read" if kind == "read" else "Edit"
            ti = {"file_path": value, "old_string": "a", "new_string": "b"}
        return {
            "cwd": str(cwd),
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": ti,
        }
    if agent == "cursor":
        base = {"hook_event_name": "", "workspace_roots": [str(cwd)], "conversation_id": "t"}
        if kind == "read":
            return {**base, "hook_event_name": "beforeReadFile", "file_path": value, "content": ""}
        if kind == "shell":
            return {
                **base,
                "hook_event_name": "beforeShellExecution",
                "command": value,
                "cwd": str(cwd),
            }
        return {
            **base,
            "hook_event_name": "preToolUse",
            "tool_name": "Write",
            "cwd": str(cwd),
            "tool_input": {"file_path": value, "content": "{}"},
        }
    tool = {"read": "read_file", "edit": "write_file", "shell": "run_shell_command"}[kind]
    ti = {"command": value} if kind == "shell" else {"file_path": value, "content": "{}"}
    return {"cwd": str(cwd), "hook_event_name": "BeforeTool", "tool_name": tool, "tool_input": ti}


def run(agent: str, payload: dict, cwd: Path, home: Path):
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
    env.pop("CLAUDE_CONFIG_DIR", None)
    env.pop("CODEX_HOME", None)
    proc = subprocess.run(
        [sys.executable, str(GUARD), "--agent", agent],
        input=json.dumps(payload).encode(),
        capture_output=True,
        timeout=60,
        cwd=str(cwd),
        env=env,
    )
    return blocked(agent, proc.stdout.decode(), proc.returncode), proc.stdout.decode()


@pytest.fixture
def project(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    return proj


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("kind", ["read", "edit"])
def test_a19_tool_access_to_protected_files_is_denied(agent, kind, project, isolated):
    for path in protected_files(isolated):
        denied, out = run(agent, event(agent, kind, str(path), project), project, isolated)
        assert denied, (agent, kind, path, out)
        if agent != "cursor" or kind != "read":
            assert "switch the guard off" in out or "protects" in out, out


SHELL_ATTACKS = [
    "echo x > ~/.keyhush/secretfiles",
    "printf '' >| $HOME/.keyhush/secretfiles",
    "rm ~/.keyhush/guard.py",
    "rm -rf ~/.keyhush",
    "cat ~/.keyhush/secretfiles",
    "cp /dev/null ~/.codex/hooks.json",
    "sed -i '' 's/keyhush//' ~/.claude/settings.json",
    "python3 -c 'print(1)' > ~/.gemini/settings.json",
    "mv ~/.cursor/hooks.json /tmp/x",
    "echo '[features]' >> ~/.codex/config.toml",
    "cd ~ && rm .keyhush/guard.py",
    "keyhush guard uninstall",
    "uv run keyhush guard uninstall --agent claude",
    "python -m keyhush.cli guard uninstall",
    "keyhush guard install --python /bin/true",
    "bash -c 'keyhush guard uninstall'",
]


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("command", SHELL_ATTACKS)
def test_a19_shell_commands_on_protected_files_are_denied(agent, command, project, isolated):
    (isolated / ".keyhush").mkdir(exist_ok=True)
    payload = event(agent, "shell", command, project)
    denied, out = run(agent, payload, project, isolated)
    assert denied, (agent, command, out)


@pytest.mark.parametrize(
    "command",
    ["keyhush scan --json", "keyhush guard status", "keyhush guard test", "ls ~", "cat README.md"],
)
def test_keyhush_read_only_commands_still_allowed(command, project, isolated):
    denied, out = run("claude", event("claude", "shell", command, project), project, isolated)
    assert not denied, (command, out)


def test_symlinked_config_is_protected_at_its_target(project, isolated, tmp_path):
    dotfiles = tmp_path / "dotfiles"
    dotfiles.mkdir()
    target = dotfiles / "claude-settings.json"
    target.write_text("{}")
    (isolated / ".claude").mkdir()
    try:
        (isolated / ".claude" / "settings.json").symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create symlinks here: {exc}")
    denied, _ = run("claude", event("claude", "edit", str(target), project), project, isolated)
    assert denied


def test_custom_config_dirs_are_protected(project, isolated, tmp_path):
    custom = tmp_path / "claude-config"
    payload = event("claude", "edit", str(custom / "settings.json"), project)
    env = {**os.environ, "HOME": str(isolated), "CLAUDE_CONFIG_DIR": str(custom)}
    proc = subprocess.run(
        [sys.executable, str(GUARD), "--agent", "claude"],
        input=json.dumps(payload).encode(),
        capture_output=True,
        timeout=60,
        cwd=str(project),
        env=env,
    )
    assert blocked("claude", proc.stdout.decode(), proc.returncode)


def test_user_pattern_list_cannot_unprotect(project, isolated):
    (isolated / ".keyhush").mkdir()
    (isolated / ".keyhush" / "secretfiles").write_text("!**\n!~/.keyhush/**\n")
    denied, _ = run(
        "claude",
        event("claude", "edit", str(isolated / ".keyhush" / "guard.py"), project),
        project,
        isolated,
    )
    assert denied
