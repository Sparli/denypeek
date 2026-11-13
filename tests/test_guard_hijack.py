"""G1: the hook's Python must not be hijackable by files or variables an agent can set."""

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
from keyhush.guard.install_base import ours_commands
from keyhush.sources import resolve_home

from .conftest import run_cli

posix_only = pytest.mark.skipif(os.name != "posix", reason="the /bin/sh wrapper is POSIX only")


def installed_run(home: Path, proj: Path, case: str, extra_env: dict):
    h = resolve_home(str(home))
    command = ours_commands(SPECS["claude"], h)[0]
    payload = sample_inputs("claude", proj, h)[case]
    env = {**os.environ, "HOME": str(home), **extra_env}
    return subprocess.run(
        shlex.split(command),
        input=json.dumps(payload).encode(),
        capture_output=True,
        timeout=60,
        cwd=str(proj),
        env=env,
    )


@pytest.fixture
def proj(tmp_path):
    p = tmp_path / "proj"
    (p / "src").mkdir(parents=True)
    for name in (".env", ".env.example", ".dev.vars"):
        (p / name).write_text("PLACEHOLDER=1\n")
    (p / "src" / "app.py").write_text("x\n")
    return p


@posix_only
def test_pythonpath_cannot_hijack_the_hook(isolated, tmp_path, proj):
    run_cli("guard", "install", "--home", str(isolated), "--python", sys.executable)
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "json.py").write_text("import os\nos._exit(0)\n")
    for var in ("PYTHONPATH", "PYTHONSTARTUP"):
        target = str(evil) if var == "PYTHONPATH" else str(evil / "json.py")
        proc = installed_run(isolated, proj, "cat .env", {var: target})
        assert blocked("claude", proc.stdout.decode(), proc.returncode), var


@posix_only
def test_user_site_cannot_hijack_the_hook(isolated, proj):
    run_cli("guard", "install", "--home", str(isolated), "--python", sys.executable)
    code = "import site, sys; print(site.getusersitepackages())"
    site_dir = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={**os.environ, "HOME": str(isolated)},
    ).stdout.strip()
    Path(site_dir).mkdir(parents=True)
    (Path(site_dir) / "usercustomize.py").write_text("import os\nos._exit(0)\n")
    (Path(site_dir) / "evil.pth").write_text("import os; os._exit(0)\n")
    proc = installed_run(isolated, proj, "cat .env", {})
    assert blocked("claude", proc.stdout.decode(), proc.returncode)


@posix_only
def test_silent_exit_zero_is_treated_as_failure(isolated, proj):
    run_cli("guard", "install", "--home", str(isolated), "--python", sys.executable)
    (isolated / ".keyhush" / "guard.py").write_text("import sys\nsys.exit(0)\n")
    proc = installed_run(isolated, proj, "ls", {})
    assert proc.returncode == 2 and "no answer" in proc.stderr.decode()


def test_agent_cannot_write_python_startup_files(isolated, tmp_path):
    rules = g.parse_patterns(g.DEFAULT_PATTERNS)
    targets = [
        isolated / "Library/Python/3.9/lib/python/site-packages/usercustomize.py",
        isolated / ".local/lib/python3.12/site-packages/sitecustomize.py",
        isolated / ".local/lib/python3.12/site-packages/x.pth",
    ]
    for t in targets:
        event = {
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": str(t), "content": "import os"},
        }
        assert g.decide(event, rules), t


def test_allow_always_prints_a_reply():
    out, code = g.allow_output("claude")
    assert code == 0 and json.loads(out) == {}


def test_install_and_status_warn_about_a_writable_python(isolated, monkeypatch):
    import keyhush.guard as guard_pkg
    import keyhush.guard.install_base as base

    monkeypatch.setattr(base, "writable_parts", lambda py: ["/fake/lib/python3.x"])
    monkeypatch.setattr(guard_pkg, "writable_parts", lambda py: ["/fake/lib/python3.x"])
    python = getattr(sys, "_base_executable", None) or sys.executable  # not inside a venv
    if base._fragile(python):
        pytest.skip("no Python outside a virtualenv or temp folder to test with")
    code, out, _ = run_cli("guard", "install", "--home", str(isolated), "--python", python)
    assert code == 0 and "can be modified by your user account" in out
    code, out, _ = run_cli("guard", "status", "--home", str(isolated))
    assert "WARNING: your user account can modify the hook's Python" in out


def test_default_choice_prefers_a_python_the_user_cannot_modify():
    from keyhush.guard.install_base import stable_python, writable_parts

    python, warning = stable_python()
    assert not writable_parts(python) or warning


@posix_only
def test_old_wrapper_without_isolation_is_reported_out_of_date(isolated):
    run_cli("guard", "install", "--home", str(isolated), "--python", sys.executable)
    w = isolated / ".keyhush" / "guard.sh"
    w.write_text(w.read_text().replace("-I -S ", ""))
    code, out, _ = run_cli("guard", "status", "--home", str(isolated))
    assert code == 1 and "out of date" in out
