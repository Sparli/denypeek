"""SPEC 3a G8: hidden names, the `always` and `auto` settings, through the real hook script.

The setting is `hidden_names` in ~/.denypeek/guard-state.json. `auto`: a `*`, `?` or bracket
written at the start of a path part does not match a hidden name, as in every covered shell
without dotglob, globdots or GLOBIGNORE. Anything else counts hidden names, and in `auto`
anything that turns hidden-name matching on is denied. The conftest fixture keeps every test
away from the real /etc startup files.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from denypeek.guard import blocked, install_base
from denypeek.guard import guard as g
from denypeek.sources import resolve_home

from .conftest import run_cli

GUARD = Path(__file__).resolve().parents[1] / "src" / "denypeek" / "guard" / "guard.py"


def set_hidden(home: Path, value):
    (home / ".denypeek").mkdir(exist_ok=True)
    state = home / ".denypeek" / "guard-state.json"
    state.write_text(json.dumps({} if value is None else {"hidden_names": value}))


@pytest.fixture
def lab(isolated, tmp_path):
    home = isolated
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / ".env").write_text("X=1\n")
    (proj / "README.md").write_text("x\n")
    (proj / "src" / "app.py").write_text("x\n")
    deep = tmp_path / "deep"  # a secret only in a subfolder
    (deep / "sub").mkdir(parents=True)
    (deep / "sub" / ".env").write_text("X=1\n")
    (deep / "notes.md").write_text("x\n")
    return home, proj, deep


def run_hook(command, home, cwd):
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


AUTO_ALLOW = [
    "x=1; export PATH=$PATH:/x; declare -i n=2; printf -v out '%s' a; read -r line <<< x",
    "du -sh *",
    "cat *",
    "wc -l *",
    "grep foo *",
    "rm -rf ./*",
    "set -euo pipefail; ls *",
    "shopt -s nullglob; ls *.py",
    "setopt extendedglob; ls *.md",
    "ls ?EADME.md",
    "cat [R]EADME.md",
    "cat **/*.py",
]


@pytest.mark.parametrize("command", AUTO_ALLOW)
def test_auto_must_allow(command, lab):
    home, proj, _ = lab
    set_hidden(home, "auto")
    denied, out = run_hook(command, home, proj)
    assert not denied, (command, out)


AUTO_DENY = [
    "cat .e*",  # starts with a literal dot
    "cat @(.env)",  # widened text counts hidden names
    "cat *(D)",
    "cat !(x)",
    "x=.; cat $x*",  # a resolved value
    "cat $y*",  # an expansion the guard cannot resolve
    "cat $(echo .)*",
    "cat .en[v]",
]


@pytest.mark.parametrize("command", AUTO_DENY)
def test_auto_still_counts_hidden_names_where_the_shell_may(command, lab):
    home, proj, _ = lab
    set_hidden(home, "auto")
    denied, out = run_hook(command, home, proj)
    assert denied, (command, out)


def test_auto_still_runs_the_recursive_search_check(lab):
    home, _, deep = lab
    set_hidden(home, "auto")
    denied, out = run_hook("grep -r foo *", home, deep)
    assert denied, out
    denied, out = run_hook("grep foo *", home, deep)
    assert not denied, out


def test_auto_still_runs_g7(lab, tmp_path):
    home, _, _ = lab
    set_hidden(home, "auto")
    denied, out = run_hook("rm -rf *", home, tmp_path)  # tmp_path holds the home folder
    assert denied, out


SWITCHES = [
    "shopt -s dotglob; cat *",
    "bash -O dotglob -c 'cat *'",
    "BASHOPTS=dotglob bash -c 'cat *'",
    "setopt globdots; cat *",
    "setopt g_lObd_ots; cat *",
    "unsetopt noglobdots",
    "set -o globdots",
    "set +o noglobdots",
    "zsh -o globdots -c 'cat *'",
    "zsh --globdots -c 'cat *'",
    "emulate zsh -o globdots",
    "options[globdots]=on",
    "options+=(globdots on)",
    "GLOBIGNORE=x; cat *",
    "export GLOBIGNORE=.",
    "zsh -4 -c 'cat *'",
    "zsh -f4c 'cat *'",
    "set -4",
    "setopt -4",
    "shopt -s $o; cat *",
    "o=dotglob; shopt -s $o",
    "setopt $(echo x)",
    "set -o $x",
    "options[$k]=on",
    "eval 'shopt -s dotglob'",
    "sh -c 'shopt -s dot\"\"glob'",
    # the review's evasion forms: continuation, $'...', a split name, braces, declare, printf -v
    "shopt -s dot\\\nglob; cat *",
    "shopt -s $'dot\\x67lob'; cat *",
    "o=dot; shopt -s ${o}glob; cat *",
    "shopt -s {dot,x}glob 2>/dev/null; cat *",
    "n=GLOB; declare ${n}IGNORE=zz; cat *",
    "n=GLOB; printf -v ${n}IGNORE zz; cat *",
    "o=dot; bash -O ${o}glob -c 'cat *'",
    "unsetopt +4; cat *",
    "o=glob; setopt ${o}dots; cat *",
    # the spec (3): a variable whose name is not a readable literal could be GLOBIGNORE
    "${n}IGNORE=x; cat *",
    "declare ${n}IGNORE=zz; cat *",
    "typeset $(echo GLOB)IGNORE=1",
    "export ${n}=x",
    "readonly ${n}IGNORE=x",
    "local ${n}=x",
    "printf -v $n zz; cat *",
    "read $n <<< x",
]


@pytest.mark.parametrize("command", SWITCHES)
def test_auto_denies_turning_hidden_names_on(command, lab):
    home, proj, _ = lab
    (proj / ".env").unlink()  # the switch itself is denied, whatever is in the folder
    set_hidden(home, "auto")
    denied, out = run_hook(command, home, proj)
    assert denied, (command, out)
    assert "hidden" in out, out


def test_always_does_not_deny_the_switch_but_counts_hidden_names(lab):
    home, proj, _ = lab
    set_hidden(home, "always")
    assert not run_hook("shopt -s nullglob; setopt globdots", home, proj)[0]
    assert run_hook("cat *", home, proj)[0]


@pytest.mark.parametrize("value", [None, "", "AUTO", "on", 1, ["auto"]])
def test_missing_or_unknown_setting_means_always(value, lab):
    home, proj, _ = lab
    if value is None:
        (home / ".denypeek").mkdir(exist_ok=True)
    else:
        (home / ".denypeek").mkdir(exist_ok=True)
        (home / ".denypeek" / "guard-state.json").write_text(json.dumps({"hidden_names": value}))
    denied, out = run_hook("cat *", home, proj)
    assert denied, (value, out)


def test_unreadable_state_means_always(lab):
    home, proj, _ = lab
    (home / ".denypeek").mkdir(exist_ok=True)
    (home / ".denypeek" / "guard-state.json").write_text("{not json")
    assert run_hook("cat *", home, proj)[0]


def test_windows_is_always(isolated, monkeypatch):
    set_hidden(isolated, "auto")
    monkeypatch.setattr(g, "WINDOWS", True)
    assert g.hidden_names() == "always"
    monkeypatch.setattr(g, "WINDOWS", False)
    assert g.hidden_names() == "auto"


# --- install and status ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,text",
    [
        (".zshrc", "setopt GLOB_DOTS\n"),
        (".bashrc", "shopt -s dotglob\n"),
        (".bash_profile", "export GLOBIGNORE=.:..\n"),
        (".zshenv", "setopt glob_dots\n"),
    ],
)
def test_install_picks_always_when_a_startup_file_names_a_switch(name, text, isolated):
    (isolated / name).write_text(text)
    code, out, _ = run_cli("guard", "install", "--home", str(isolated), "--agent", "claude")
    assert "Hidden files: always" in out and name in out, out
    state = json.loads((isolated / ".denypeek" / "guard-state.json").read_text())
    assert state["hidden_names"] == "always"


def test_install_picks_auto_and_says_why(isolated):
    (isolated / ".zshrc").write_text("setopt extendedglob\n")
    code, out, _ = run_cli("guard", "install", "--home", str(isolated), "--agent", "claude")
    assert "Hidden files: auto (no bash or zsh startup file" in out, out


def test_a_system_startup_file_counts(isolated, tmp_path, monkeypatch):
    etc = tmp_path / "etc-zshrc"
    etc.write_text("setopt globdots\n")
    monkeypatch.setattr(install_base, "SYSTEM_STARTUP_FILES", (str(etc),))
    value, reason = install_base.detect_hidden(resolve_home(str(isolated)))
    assert value == "always" and "globdots" in reason


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs POSIX file modes")
def test_an_unreadable_startup_file_means_always(isolated):
    rc = isolated / ".zshrc"
    rc.write_text("x\n")
    os.chmod(rc, 0)
    try:
        value, reason = install_base.detect_hidden(resolve_home(str(isolated)))
    finally:
        os.chmod(rc, 0o600)
    assert value == "always" and "cannot be read" in reason


def test_hidden_always_forces_and_survives_reinstall(isolated):
    run_cli("guard", "install", "--home", str(isolated), "--agent", "claude", "--hidden", "always")
    run_cli("guard", "install", "--home", str(isolated), "--agent", "claude")
    state = json.loads((isolated / ".denypeek" / "guard-state.json").read_text())
    assert state["hidden_names"] == "always" and state["hidden_names_forced"] is True


def test_status_reports_a_change_in_the_startup_files(isolated):
    run_cli("guard", "install", "--home", str(isolated), "--agent", "claude")
    _, out, _ = run_cli("guard", "status", "--home", str(isolated), "--agent", "claude")
    assert "Hidden files: auto" in out and "CHANGED" not in out, out
    (isolated / ".bashrc").write_text("shopt -s dotglob\n")
    _, out, _ = run_cli("guard", "status", "--home", str(isolated), "--agent", "claude")
    assert "CHANGED" in out and "always" in out, out


def test_uninstall_removes_the_state_file_when_no_agent_is_left(isolated):
    run_cli("guard", "install", "--home", str(isolated), "--agent", "claude")
    run_cli("guard", "uninstall", "--home", str(isolated), "--agent", "claude")
    assert not (isolated / ".denypeek" / "guard-state.json").exists()
