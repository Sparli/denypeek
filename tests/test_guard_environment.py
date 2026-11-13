"""R1: the hook's environment cannot switch it off (DEVELOPER_DIR, HOME, settings env)."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from keyhush.guard import SPECS, blocked, sample_inputs
from keyhush.guard import guard as g
from keyhush.guard.install_base import ours_commands, stable_python
from keyhush.sources import resolve_home

from .conftest import run_cli

posix_only = pytest.mark.skipif(os.name != "posix", reason="the /bin/sh wrapper is POSIX only")
mac_launcher = pytest.mark.skipif(
    sys.platform != "darwin" or not os.path.exists("/usr/bin/python3"),
    reason="needs macOS with /usr/bin/python3",
)


@pytest.fixture
def proj(tmp_path):
    p = tmp_path / "proj"
    (p / "src").mkdir(parents=True)
    (p / ".env").write_text("PLACEHOLDER=1\n")
    (p / "src" / "app.py").write_text("x\n")
    return p


def installed_run(home, proj, case, env_extra):
    h = resolve_home(str(home))
    command = ours_commands(SPECS["claude"], h)[0]
    payload = sample_inputs("claude", proj, h)[case]
    env = {**os.environ, **env_extra}
    return subprocess.run(
        shlex.split(command),
        input=json.dumps(payload).encode(),
        capture_output=True,
        timeout=60,
        cwd=str(proj),
        env=env,
    )


@posix_only
def test_r1_home_from_the_environment_is_ignored(isolated, tmp_path, proj):
    run_cli("guard", "install", "--home", str(isolated), "--python", sys.executable)
    evil = tmp_path / "evil-home"
    (evil / ".keyhush").mkdir(parents=True)
    (evil / ".keyhush" / "secretfiles").write_text("!*\n!**\n")
    proc = installed_run(isolated, proj, "cat .env", {"HOME": str(evil)})
    assert blocked("claude", proc.stdout.decode(), proc.returncode)


@posix_only
@mac_launcher
def test_r1_developer_dir_cannot_replace_python(isolated, tmp_path, proj):
    run_cli("guard", "install", "--home", str(isolated), "--python", "/usr/bin/python3")
    fake = tmp_path / "fakedev" / "usr" / "bin"
    fake.mkdir(parents=True)
    xcrun = fake / "xcrun"
    xcrun.write_text("#!/bin/sh\necho '{}'\nexit 0\n")
    xcrun.chmod(0o755)
    proc = installed_run(isolated, proj, "cat .env", {"DEVELOPER_DIR": str(tmp_path / "fakedev")})
    assert blocked("claude", proc.stdout.decode(), proc.returncode)


@mac_launcher
def test_r1_installer_writes_the_real_python_not_the_xcrun_launcher():
    python, _warning = stable_python("/usr/bin/python3")
    assert python != "/usr/bin/python3"
    assert os.path.isfile(python) and os.stat(python).st_uid == 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX account database")
def test_r1_guard_home_comes_from_the_account_not_HOME(monkeypatch):
    import pwd

    monkeypatch.setattr(g, "_home", [None])
    monkeypatch.setenv("HOME", "/tmp/not-the-real-home")
    assert g.home_dir() == pwd.getpwuid(os.getuid()).pw_dir


def test_r1_guard_home_comes_from_the_command_line(monkeypatch, tmp_path):
    monkeypatch.setattr(g, "_home", [None])
    g.run(["--agent", "claude", "--home", str(tmp_path)], b"{}")
    assert g.home_dir() == str(tmp_path)


@pytest.mark.parametrize("var", ["PYTHONPATH", "HOME", "DEVELOPER_DIR", "PATH", "USERPROFILE"])
def test_r1_project_settings_env_that_reaches_the_hook_is_denied(var):
    content = json.dumps({"env": {var: "/tmp/evil"}})
    assert g.settings_problem("claude", content)


def test_r1_ordinary_settings_env_is_allowed():
    assert g.settings_problem("claude", json.dumps({"env": {"NODE_ENV": "test"}})) is None


@posix_only
def test_r1_old_wrapper_without_clean_environment_is_out_of_date(isolated):
    run_cli("guard", "install", "--home", str(isolated), "--python", sys.executable)
    w = isolated / ".keyhush" / "guard.sh"
    w.write_text(w.read_text().replace("/usr/bin/env -i", "/usr/bin/env"))
    code, out, _ = run_cli("guard", "status", "--home", str(isolated))
    assert code == 1 and "out of date" in out


def test_r1_tests_never_reach_the_real_home():
    assert Path(os.environ["HOME"]).name == "home"  # the conftest fixture home
