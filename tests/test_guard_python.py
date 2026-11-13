"""The hook must not fail open when its Python goes away (QA finding 4)."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from keyhush.guard import SPECS, blocked, sample_inputs
from keyhush.guard.install_base import ours_commands, stable_python
from keyhush.sources import resolve_home

from .conftest import run_cli

posix_only = pytest.mark.skipif(os.name != "posix", reason="the /bin/sh wrapper is POSIX only")


def install_with_python(home: Path, python: str) -> None:
    code, out, err = run_cli("guard", "install", "--home", str(home), "--python", python)
    assert code == 0, out + err


def run_installed(home: Path, agent: str, case: str, proj: Path):
    h = resolve_home(str(home))
    command = ours_commands(SPECS[agent], h)[0]
    payload = sample_inputs(agent, proj, h)[case]
    env = {**os.environ, "HOME": str(home)}
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
@pytest.mark.parametrize("agent", list(SPECS))
def test_missing_python_blocks_every_call(agent, isolated, tmp_path, proj):
    gone = tmp_path / "py" / "python3"
    gone.parent.mkdir()
    gone.symlink_to(os.path.realpath(sys.executable))
    install_with_python(isolated, str(gone))
    assert not run_installed(isolated, agent, "ls", proj).returncode  # works while present
    gone.unlink()
    for case in ("ls", "read src/app.py", "cat .env"):
        proc = run_installed(isolated, agent, case, proj)
        assert proc.returncode == 2, (agent, case, proc.returncode)
        assert blocked(agent, proc.stdout.decode(), proc.returncode)
        assert "keyhush guard" in proc.stderr.decode()


@posix_only
def test_guard_that_cannot_load_blocks(isolated, proj):
    install_with_python(isolated, sys.executable)
    (isolated / ".keyhush" / "guard.py").write_text("def broken(:\n")
    proc = run_installed(isolated, "claude", "ls", proj)
    assert proc.returncode == 2 and "Blocked to be safe" in proc.stderr.decode()


@posix_only
def test_status_reports_missing_python(isolated, tmp_path):
    gone = tmp_path / "py" / "python3"
    gone.parent.mkdir()
    gone.symlink_to(os.path.realpath(sys.executable))
    install_with_python(isolated, str(gone))
    code, out, _ = run_cli("guard", "status", "--home", str(isolated))
    assert code == 0, out
    gone.unlink()
    code, out, _ = run_cli("guard", "status", "--home", str(isolated))
    assert code == 1
    assert "BROKEN" in out and "Python is missing" in out
    code, out, _ = run_cli("guard", "status", "--home", str(isolated), "--json")
    data = json.loads(out)
    assert code == 1 and not any(a["working"] for a in data["agents"])


def test_install_warns_about_a_virtualenv_python(isolated):
    venv_python = sys.executable
    if not (Path(sys.prefix) / "pyvenv.cfg").exists():
        pytest.skip("tests are not running in a virtualenv")
    code, out, _ = run_cli("guard", "install", "--home", str(isolated), "--python", venv_python)
    assert code == 0
    assert "WARNING" in out and "virtual environment" in out


def test_default_choice_avoids_virtualenvs_or_warns():
    python, warning = stable_python()
    from keyhush.guard.install_base import in_virtualenv

    assert in_virtualenv(python) is None or warning
