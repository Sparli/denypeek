"""R1: the hook's environment cannot switch it off (DEVELOPER_DIR, HOME, settings env)."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from denypeek.guard import SPECS, blocked, sample_inputs
from denypeek.guard import guard as g
from denypeek.guard.install_base import ours_commands, stable_python
from denypeek.sources import resolve_home

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
    (evil / ".denypeek").mkdir(parents=True)
    (evil / ".denypeek" / "secretfiles").write_text("!*\n!**\n")
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
def test_r1_installer_resolves_the_launcher_only_to_a_root_owned_interpreter():
    """Two developer-tool layouts: a root-owned interpreter behind the launcher (Command Line
    Tools, App Store Xcode) is used directly; otherwise the launcher is kept, which is safe
    because the wrapper clears the environment (see the next test). Either way, a user-writable
    interpreter gets the G1 warning."""
    real = subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            "-S",
            "-c",
            "import os, sys; print(os.path.realpath(sys.executable))",
        ],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
    ).stdout.strip()
    owner = os.stat(real).st_uid if real and os.path.exists(real) else None
    python, warning = stable_python("/usr/bin/python3")
    detail = f"real={real!r} owner_uid={owner} chosen={python!r} warning={warning!r}"
    if owner == 0:
        assert python == real, detail
    else:
        assert python == "/usr/bin/python3", detail
    from denypeek.guard.install_base import writable_parts

    if writable_parts(python):
        assert warning, detail


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
    w = isolated / ".denypeek" / "guard.sh"
    w.write_text(w.read_text().replace("/usr/bin/env -i", "/usr/bin/env"))
    code, out, _ = run_cli("guard", "status", "--home", str(isolated))
    assert code == 1 and "out of date" in out


def test_r1_tests_never_reach_the_real_home():
    assert Path(os.environ["HOME"]).name == "home"  # the conftest fixture home


@posix_only
@mac_launcher
def test_r1_launcher_kept_in_the_wrapper_still_ignores_developer_dir(
    isolated, tmp_path, proj, monkeypatch
):
    """When no root-owned interpreter is found behind /usr/bin/python3 (for example a full Xcode
    owned by the user, as on CI runners), the installer keeps the xcrun launcher. That is safe
    only because the wrapper starts it with env -i, so DEVELOPER_DIR never reaches it. Prove it
    with the launcher forced into the wrapper."""
    import denypeek.guard.install_base as base

    monkeypatch.setattr(base, "resolve_launcher", lambda python: python)
    code, out, err = run_cli(
        "guard", "install", "--home", str(isolated), "--python", "/usr/bin/python3"
    )
    assert code == 0, out + err
    wrapper = (isolated / ".denypeek" / "guard.sh").read_text()
    assert "PY='/usr/bin/python3'" in wrapper and "/usr/bin/env -i" in wrapper
    fake = tmp_path / "fakedev" / "usr" / "bin"
    fake.mkdir(parents=True)
    for name in ("xcrun", "python3"):
        (fake / name).write_text("#!/bin/sh\necho '{}'\nexit 0\n")
        (fake / name).chmod(0o755)
    for extra in (
        {"DEVELOPER_DIR": str(tmp_path / "fakedev")},
        {"SDKROOT": str(tmp_path / "fakedev")},
        {"PATH": f"{fake}:/usr/bin:/bin"},
    ):
        proc = installed_run(isolated, proj, "cat .env", extra)
        assert blocked("claude", proc.stdout.decode(), proc.returncode), extra


# --- F1: exported shell functions and shell variables -------------------------------------

BASH_FUNC = {"BASH_FUNC_printf%%": '() { echo "{}"; }', "BASH_FUNC_echo%%": "() { :; }"}


@posix_only
def test_f1_exported_functions_cannot_rewrite_the_answer(isolated, proj):
    """the review's reproduction: run the installed command through sh -c, as agents do, with an
    exported printf function. macOS /bin/sh is bash and imports it; the answer must stay deny."""
    run_cli("guard", "install", "--home", str(isolated), "--python", sys.executable)
    h = resolve_home(str(isolated))
    command = ours_commands(SPECS["claude"], h)[0]
    payload = json.dumps(sample_inputs("claude", proj, h)["cat .env"]).encode()
    for shell in ("/bin/sh", "/bin/bash"):
        if not os.path.exists(shell):
            continue
        env = {**os.environ, **BASH_FUNC, "BASH_ENV": "/dev/null", "SHELLOPTS": "xtrace"}
        proc = subprocess.run(
            [shell, "-c", command],
            input=payload,
            capture_output=True,
            timeout=60,
            cwd=str(proj),
            env=env,
        )
        assert blocked("claude", proc.stdout.decode(), proc.returncode), (shell, proc.stdout)


@posix_only
def test_f1_hook_command_starts_with_a_clean_environment(isolated):
    run_cli("guard", "install", "--home", str(isolated), "--python", sys.executable)
    for spec in SPECS.values():
        for command in ours_commands(spec, resolve_home(str(isolated))):
            assert command.startswith("/usr/bin/env -i /bin/sh "), command


@posix_only
def test_f1_old_hook_command_is_reported_out_of_date(isolated):
    run_cli("guard", "install", "--home", str(isolated), "--python", sys.executable)
    cfg = isolated / ".claude" / "settings.json"
    cfg.write_text(cfg.read_text().replace("/usr/bin/env -i /bin/sh", "/bin/sh"))
    code, out, _ = run_cli("guard", "status", "--home", str(isolated))
    assert code == 1 and "out of date" in out


@pytest.mark.parametrize(
    "var",
    [
        "BASH_FUNC_printf%%",
        "BASH_FUNC_x()",
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "BASHOPTS",
        "IFS",
        "CDPATH",
        "GLOBIGNORE",
        "PROMPT_COMMAND",
        "PS4",
    ],
)
def test_f1_project_settings_shell_variables_are_denied(var):
    assert g.settings_problem("claude", json.dumps({"env": {var: "() { :; }"}})), var
