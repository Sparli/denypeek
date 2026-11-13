"""QA pass 2, should-fix 1: agents cannot move, delete or rewrite the agent folders that
hold the hook settings (~/.claude, ~/.codex, ~/.cursor, ~/.gemini)."""

from __future__ import annotations

import pytest

from keyhush.guard import guard as g


@pytest.fixture
def rules():
    return g.parse_patterns(g.DEFAULT_PATTERNS)


def shell(command, cwd):
    return {
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


@pytest.mark.parametrize(
    "command",
    [
        "mv ~/.claude ~/.claude_old",
        "rm -rf ~/.claude",
        "rm -rf ~/.cursor ~/.codex",
        "mv ~/.codex x",
        "chmod 000 ~/.claude",
        "rm -rf ~/.gemini",
        "chown root ~/.claude/",
        "cp -r /tmp/evil/ ~/.claude",
        "rsync -a --delete /tmp/x/ ~/.codex/",
        "find ~/.claude -delete",
        "find ~/.gemini -exec rm {} +",
        "cd ~ && rm -rf .claude",
        "ln -sfn /tmp/x ~/.cursor",
        "tar -xf x.tar -C ~/.claude",
    ],
)
def test_agent_folders_cannot_be_moved_or_changed(command, rules, tmp_path, isolated):
    assert g.decide(shell(command, tmp_path), rules), command


@pytest.mark.parametrize(
    "command",
    [
        "ls ~/.claude",
        "ls -la ~/.codex/",
        "du -sh ~/.cursor",
        "find ~/.claude -name '*.md'",
        "cd ~/.gemini && ls",
        "cp notes.txt ~",
        "cat ~/.claude/CLAUDE.md",
    ],
)
def test_reading_agent_folders_is_allowed(command, rules, tmp_path, isolated):
    assert g.decide(shell(command, tmp_path), rules) is None, command


def test_cursor_delete_tool_on_agent_folder_is_denied(rules, tmp_path, isolated):
    event = {
        "cwd": str(tmp_path),
        "hook_event_name": "preToolUse",
        "tool_name": "Delete",
        "tool_input": {"path": str(isolated / ".claude")},
    }
    assert g.decide(event, rules)
