"""L1, L2 (the review's launch check) and related shell glob forms, through the real hook script.

The shell decides what a word expands to, so the guard must never match less than the shell:
- `[!…]` and `[^…]` are negation in bash, zsh and sh; Python's fnmatch reads `[^x]` as a literal
  `^` or `x`, and Python 3.9 raises on a reversed range such as `[z-a]` (L1, L2).
- POSIX classes such as `[[:alpha:]]` are one character to the shell.
- zsh (the macOS default shell) expands `(a|b)` groups and recursive `**/` with default options.
- bash and zsh expand brace sequences such as `{m..o}`.

These run on whatever Python runs the suite; CI runs the whole suite on Python 3.9 too.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from denypeek.guard import blocked

GUARD = Path(__file__).resolve().parents[1] / "src" / "denypeek" / "guard" / "guard.py"


@pytest.fixture
def lab(isolated, tmp_path):
    (isolated / ".claude").mkdir()
    (isolated / ".denypeek").mkdir()
    proj = tmp_path / "proj"
    (proj / "sub" / "deep").mkdir(parents=True)
    (proj / ".env").write_text("X=1\n")
    (proj / "sub" / "deep" / ".env").write_text("X=1\n")
    (proj / "app.py").write_text("print(1)\n")
    return isolated, proj


def run_hook(command: str, home: Path, cwd: Path):
    payload = {
        "session_id": "t",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
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


NEGATED = ["[!z-a]", "[^z-a]", "[^x]", "[!x]"]


@pytest.mark.parametrize("bracket", NEGATED)
def test_l1_l2_negated_brackets_on_env_are_denied(bracket, lab):
    home, proj = lab
    for word in (f".en{bracket}", f".e{bracket}v", f".{bracket}nv"):
        denied, out = run_hook(f"cat {word}", home, proj)
        assert denied, (word, out)


@pytest.mark.parametrize("bracket", NEGATED)
@pytest.mark.parametrize("folder", [".denype{}k", ".clau{}e"])
def test_l1_l2_negated_brackets_on_protected_folders_are_denied(bracket, folder, lab):
    home, proj = lab
    word = "~/" + folder.format(bracket)
    for cwd in (home, proj):
        denied, out = run_hook(f"rm -rf {word}", home, cwd)
        assert denied, (word, cwd, out)


@pytest.mark.parametrize(
    "word",
    [
        ".en[[:alpha:]]",
        ".e[[:lower:]]v",
        ".e[[:alpha:][:digit:]]v",
        ".en[]v]",
        ".en[!]x]",
        ".e[n][v]",
        "'.e'[n]v",
        ".e[n-n]v",
        "{.en,x}[^x]",
        ".e{m..o}v",
        ".e{l..p..2}v",
        ".(env|x)",
        "(.env|x)",
        ".e(n)v",
        ".e(n|x)v",
        "'.e'(n)v",
        ".e((n))v",
        "**/.en?",
        "**/.en[^x]",
    ],
)
def test_other_shell_forms_that_expand_to_env_are_denied(word, lab):
    home, proj = lab
    denied, out = run_hook(f"cat {word}", home, proj)
    assert denied, (word, out)


@pytest.mark.parametrize(
    "command",
    [
        # bash extglob and zsh kshglob, which an agent can switch on in the same command
        "bash -O extglob -c 'cat .e@(n)v'",
        "shopt -s extglob; cat .e+(n)v",
        "shopt -s extglob; cat .e!(x)v",
        "zsh -o kshglob -c 'cat .e@(n)v'",
        # zsh EXTENDED_GLOB
        "setopt extendedglob; cat .e^xv",
        "setopt extendedglob; cat .en#v",
        "setopt extendedglob; cat .e(n|x)##v",
        "setopt extendedglob; cat (#i).ENV",
        "setopt extendedglob; cat .env~x",
    ],
)
def test_opt_in_glob_modes_that_expand_to_env_are_denied(command, lab):
    home, proj = lab
    denied, out = run_hook(command, home, proj)
    assert denied, (command, out)


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf ~/.(claude|x)",
        "rm -rf ~/.denype(e)k",
        "rm -rf ~/.clau[[:alpha:]]e",
        "rm -rf ~/.cl{a..b}ude",
        "mv ~/.denype[^x]k /tmp/x",
    ],
)
def test_other_shell_forms_on_protected_folders_are_denied(command, lab):
    home, proj = lab
    denied, out = run_hook(command, home, proj)
    assert denied, (command, out)


@pytest.mark.parametrize(
    "command",
    [
        "cat app.py",
        "ls",
        "cat .en[v",  # unclosed bracket: the shell reads a literal `[`; no such file
        "cat app.[p]y",
        "ls [a-z]*.py",
        "(cd sub && ls)",
        "echo $((1+2))",
        "arr=(a b); echo ${arr[0]}",
        "x=(foo)",
        "ls ~/.claude",
        "grep -E '(API|KEY)' app.py",
        'grep -E "^(foo|bar)$" app.py',
        "grep '^.env' app.py",
        "ls  # list files (a|b) ^x",
        "git diff HEAD^ -- app.py",
        "echo a#b",
        "f() { ls; }; f",
        "(ls|wc)",
        "diff <(ls) <(ls -a)",
    ],
)
def test_ordinary_commands_are_still_allowed(command, lab):
    home, proj = lab
    denied, out = run_hook(command, home, proj)
    assert not denied, (command, out)
