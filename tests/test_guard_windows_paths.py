"""Windows path forms, tested on every platform by calling the guard's parser directly.

CI on Windows found that `cat C:\\Users\\...\\.env` was allowed: POSIX-style splitting read the
backslashes as escapes. These tests feed Windows-style strings to the same code on any OS, with
Windows mode switched on or off, so the logic does not depend on CI alone.
"""

from __future__ import annotations

import pytest

from denypeek.guard import guard as g


@pytest.fixture
def rules():
    return g.parse_patterns(g.DEFAULT_PATTERNS)


def decide_shell(command, cwd, rules):
    event = {
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    return g.decide(event, rules)


@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize(
    "command",
    [
        r"cat C:\Users\runneradmin\proj\.env",
        r"type C:\Users\me\proj\.env",
        r'cat "C:\Users\me\proj\.env"',
        r"cat 'C:\Users\me\proj\.env'",
        r"Get-Content -Path C:\proj\.ENV",
        r"Get-Content -LiteralPath 'D:\work\app\.dev.vars'",
        r"cat C:/Users/me\proj/.env",
        r"cat c:\PROJ\.Env",
        r"cat \\fileserver\share\app\.env",
        r"copy C:\proj\.env C:\temp\x",
        r"cat C:\Users\me\.ssh\id_rsa",
    ],
)
def test_windows_absolute_paths_are_denied(command, windows, rules, tmp_path, monkeypatch):
    monkeypatch.setattr(g, "WINDOWS", windows)
    assert decide_shell(command, tmp_path, rules), command


@pytest.mark.parametrize(
    "command",
    [
        r"Get-Content %USERPROFILE%\.ssh\id_rsa",
        r"type %HOMEDRIVE%%HOMEPATH%\.aws\credentials",
        r"gc $env:USERPROFILE\.aws\credentials",
        r"gc ${env:USERPROFILE}\.ssh\id_ed25519",
        r"type %userprofile%\.denypeek\secretfiles",
    ],
)
def test_windows_home_variables_are_expanded(command, rules, tmp_path, monkeypatch, isolated):
    monkeypatch.setattr(g, "WINDOWS", False)
    assert decide_shell(command, tmp_path, rules), command


@pytest.mark.parametrize("command", [r"type .\.env", r"cat src\..\.env", r"more .\config\..\.env"])
def test_windows_relative_backslash_paths_on_windows(command, rules, tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "config").mkdir()
    monkeypatch.setattr(g, "WINDOWS", True)
    assert decide_shell(command, tmp_path, rules), command


@pytest.mark.parametrize(
    "command",
    [
        r"echo a\ b",
        r"printf 'x\n'",
        r"grep -r 'foo\.bar' src/",
        r"cat my\ notes.txt",
        r"type .\.env",  # in bash this means "..env", not .env
    ],
)
def test_posix_backslash_escapes_are_kept(command, rules, tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    monkeypatch.setattr(g, "WINDOWS", False)
    assert decide_shell(command, tmp_path, rules) is None, command


@pytest.mark.parametrize(
    "command", [r"type C:\proj\.env.example", r"dir C:\proj\src", r"Get-Content C:\proj\README.md"]
)
def test_windows_paths_to_normal_files_are_allowed(command, rules, tmp_path, monkeypatch):
    for windows in (False, True):
        monkeypatch.setattr(g, "WINDOWS", windows)
        assert decide_shell(command, tmp_path, rules) is None, (command, windows)


def test_windows_tool_paths_are_matched(rules, tmp_path):
    event = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": r"C:\project\src\..\.env"},
    }
    assert g.decide(event, rules)


def test_windows_patch_paths_are_matched(rules, tmp_path):
    patch = "*** Begin Patch\n*** Update File: C:\\proj\\.dev.vars\n@@\n-a\n+b\n*** End Patch\n"
    event = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "tool_input": {"command": patch},
    }
    assert g.decide(event, rules)
