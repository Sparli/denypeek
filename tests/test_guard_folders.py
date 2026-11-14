"""QA pass 2, should-fix 1: agents cannot move, delete or rewrite the agent folders that
hold the hook settings (~/.claude, ~/.codex, ~/.cursor, ~/.gemini)."""

from __future__ import annotations

import pytest

from denypeek.guard import guard as g


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


# --- R3: through globs and find ----------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf ~/.cl*",
        "rm -rf ~/.c?aude",
        "mv ~/.[c]laude /tmp/x",
        "rm -rf ~/.{claude,codex}",
        "find ~ -maxdepth 1 -name .claude -exec rm -rf {} +",
        "find ~ -name '.c*' -delete",
        "find $HOME -maxdepth 1 -type d -name '.gemini' -delete",
        "git rm -r ~/.claude",
    ],
)
def test_r3_agent_folders_through_globs_and_find_are_denied(command, rules, tmp_path, isolated):
    for d in (".claude", ".codex", ".gemini", ".cursor"):
        (isolated / d).mkdir(exist_ok=True)
    assert g.decide(shell(command, tmp_path), rules), command


@pytest.mark.parametrize(
    "command",
    [
        "ls -d ~/.c*",
        "find ~ -maxdepth 1 -name '.c*'",
        "rm -rf build/*",
        "find build -name '*.o' -delete",
    ],
)
def test_r3_harmless_globs_and_find_are_allowed(command, rules, tmp_path, isolated):
    for d in (".claude", ".codex"):
        (isolated / d).mkdir(exist_ok=True)
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "a.o").write_text("x")
    assert g.decide(shell(command, tmp_path), rules) is None, command
