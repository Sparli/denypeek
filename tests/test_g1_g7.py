"""SPEC 3a, revised 2026-11-17: G1 text the shell reads again, and G7 ancestors.

the spec's "Open at 5b03394" list, each confirmed in a real shell, plus G7's must-allow list,
through the real hook script. The fixture home is tmp/home and the project tmp/proj, so the
project's parent folder is an ancestor of the home folder.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from denypeek.guard import blocked
from denypeek.guard import guard as g

GUARD = Path(__file__).resolve().parents[1] / "src" / "denypeek" / "guard" / "guard.py"


@pytest.fixture
def lab(isolated, tmp_path):
    home = isolated
    for d in (".claude", ".denypeek", "bin", "proj/build", "empty"):
        (home / d).mkdir(parents=True)
    (home / "bin" / "tool").write_text("#!/bin/sh\n")
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / ".pytest_cache").mkdir()
    (proj / ".env").write_text("X=1\n")
    (proj / "notes.txt").write_text("n\n")
    (proj / "x").write_text("x\n")
    return home, proj


def run_hook(command: str, home: Path, cwd: Path, tool="Bash", tool_input=None):
    payload = {
        "session_id": "t",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input or {"command": command},
    }
    proc = subprocess.run(
        [sys.executable, "-I", "-S", str(GUARD), "--agent", "claude", "--home", str(home)],
        input=json.dumps(payload).encode(),
        capture_output=True,
        timeout=60,
        cwd=str(cwd),
        env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
    )
    return blocked("claude", proc.stdout.decode(), proc.returncode), proc.stdout.decode()


# G1: a quoted or escaped literal stays live when the shell reads it again
G1_DENY = [
    "for f in '.e*'; do cat $f; done",
    "for f in a '.e?v' b; do cat $f; done",
    "set -- '.e*'; cat $1",
    "set -- x '.e*'; cat $@",
    "a=('.e*'); cat ${a[0]}",
    "a=(x '.e[!x]v'); cat ${a[1]}",
    "sh -c 'cat $0' '.e*'",
    "bash -c 'cat $1' x '.e?v'",
    "eval cat '.e*'",
    "eval cat .e\\*",
    "eval 'cat .e*'",
    "echo 'cat .e*' | sh",
    "printf '%s\\n' 'cat .e?v' | bash",
    "bash <<< 'cat .e*'",
    "sudo sh -c 'cat .e*'",
    "env bash -c 'cat .e*'",
]


@pytest.mark.parametrize("command", G1_DENY)
def test_g1_text_read_again_is_live(command, lab):
    home, proj = lab
    denied, out = run_hook(command, home, proj)
    assert denied, (command, out)


G1_ALLOW = [
    "grep -o '[a-z]*' notes.txt",
    "find . -name '*.py'",
    "echo '*' | wc -c",
    "printf '%s' '.e*' | cat",
    "a='.e*'; echo \"$a\"",
    "for f in a b; do echo $f; done",
]


@pytest.mark.parametrize("command", G1_ALLOW)
def test_g1_quoted_patterns_given_to_a_program_stay_literal(command, lab):
    home, proj = lab
    denied, out = run_hook(command, home, proj)
    assert not denied, (command, out)


# G7: delete, move or lock the home folder or a folder above it
G7_DENY_FROM_PROJ = [
    "rm -rf ..",
    "rm -rf .?",
    "rm -rf ~",
    "rm -rf ~/",
    "rm -rf $HOME",
    'rm -rf "$HOME"',
    "sudo rm -rf ~",
    "env rm -rf ~",
    "/bin/rm -rf ~",
    "\\rm -rf ~",
    "mv ~ /tmp/x",
    "mv -t /tmp ~",
    "chmod -R 000 ~",
    "chown -R nobody ~",
    "rsync -a --delete empty/ ~/",
    "rsync -a --remove-source-files ~/ /tmp/x",
    "cd ~ && rm -rf .",
    "bash -c 'rm -rf ~'",
    "unlink ~",
    "rmdir ..",
]


@pytest.mark.parametrize("command", G7_DENY_FROM_PROJ)
def test_g7_ancestor_delete_move_or_lock_is_denied(command, lab):
    home, proj = lab
    denied, out = run_hook(command, home, proj)
    assert denied, (command, out)


@pytest.mark.parametrize("command", ["git clean -fdx", "rm -rf ~+", "rm -rf ."])
def test_g7_from_the_home_folder(command, lab):
    home, _ = lab
    denied, out = run_hook(command, home, home)
    assert denied, (command, out)


G7_ALLOW = [
    "mv notes.txt ~",
    "cp x ~",
    "ls ..",
    "cd ~ && ls",
    "chmod +x ~/bin/tool",
    "rm -rf ~/proj/build",
    "rm -rf .*_cache",
    "git clean -fd",
    "find ~ -name x",
]


@pytest.mark.parametrize("command", G7_ALLOW)
def test_g7_must_allow(command, lab):
    home, proj = lab
    denied, out = run_hook(command, home, proj)
    assert not denied, (command, out)


@pytest.mark.parametrize("command", ["chmod 700 ~", "grep -r rm ~"])
def test_g7_listed_costs_are_denied(command, lab):
    home, proj = lab
    denied, out = run_hook(command, home, proj)
    assert denied, (command, out)


def test_g7_agent_delete_tool_on_the_home_folder_is_denied(lab):
    home, proj = lab
    event = {
        "cwd": str(proj),
        "hook_event_name": "PreToolUse",
        "tool_name": "Delete",
        "tool_input": {"path": str(home)},
    }
    assert g.decide(event, g.parse_patterns(g.DEFAULT_PATTERNS))
    event["tool_input"] = {"path": str(home / "proj" / "build")}
    assert not g.decide(event, g.parse_patterns(g.DEFAULT_PATTERNS))
