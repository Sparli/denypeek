"""guard install | status | uninstall | test, for all four agents."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..fsutil import atomic_write, ensure_private_dir
from ..sources import Home
from . import install_claude, install_codex, install_cursor, install_gemini
from .install_base import (
    USE_WRAPPER,
    Change,
    ConfigError,
    guard_path,
    hook_command,
    hook_python,
    install,
    installed,
    load_state,
    ours_commands,
    save_state,
    stable_python,
    state_path,
    uninstall,
    wrapper_path,
    writable_parts,
    write_wrapper,
)
from .patterns import ensure_patterns, patterns_path

SPECS = {
    s.name: s
    for s in (install_claude.SPEC, install_codex.SPEC, install_cursor.SPEC, install_gemini.SPEC)
}
GUARD_SOURCE = Path(__file__).with_name("guard.py")


def pick(agents: Optional[list[str]]) -> list:
    names = agents or list(SPECS)
    unknown = [a for a in names if a not in SPECS]
    if unknown:
        raise ConfigError(f"unknown agent(s): {', '.join(unknown)}; use {', '.join(SPECS)}")
    return [SPECS[a] for a in names]


def _digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def copy_guard(home: Home) -> None:
    ensure_private_dir(home.keyhush_dir)
    atomic_write(guard_path(home), GUARD_SOURCE.read_bytes(), mode=0o600)


def do_install(home: Home, agents=None, python: Optional[str] = None):
    """Returns (changes, warning about the chosen Python or None)."""
    py, warning = stable_python(python)
    copy_guard(home)
    if USE_WRAPPER:
        write_wrapper(home, py)
    ensure_patterns(home)
    state = load_state(home)
    changes = [
        install(spec, home, hook_command(py, home, spec.name), state) for spec in pick(agents)
    ]
    save_state(home, state)
    return changes, warning


def do_uninstall(home: Home, agents=None) -> list[Change]:
    state = load_state(home)
    changes = [uninstall(spec, home, state) for spec in pick(agents)]
    if state:
        save_state(home, state)
    else:  # nothing of ours is installed any more
        try:
            os.remove(state_path(home))
        except FileNotFoundError:
            pass
    if not any(installed(s, home)[0] for s in SPECS.values()):
        for path in (guard_path(home), wrapper_path(home)):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
    return changes


@dataclass
class Status:
    agent: str
    label: str
    config: Path
    installed: bool
    error: Optional[str]
    notes: list
    health: Optional[str] = None  # None if the hook runs and blocks; else why not


def do_status(home: Home, agents=None) -> tuple[list[Status], dict]:
    rows = []
    for spec in pick(agents):
        ok, err = installed(spec, home)
        health = hook_health(spec, home) if ok else None
        rows.append(Status(spec.name, spec.label, spec.config(home), ok, err, spec.notes, health))
    python = None
    for spec in pick(agents):
        commands = ours_commands(spec, home)
        if commands:
            python = hook_python(commands[0], home)
            break
    info = {
        "python": python,
        "python_writable": writable_parts(python) if python and os.path.exists(python) else [],
        "guard": str(guard_path(home)),
        "guard_present": guard_path(home).exists(),
        "guard_current": _digest(guard_path(home)) == _digest(GUARD_SOURCE)
        and (
            not USE_WRAPPER
            or not wrapper_path(home).exists()
            or all(
                x in wrapper_path(home).read_text(encoding="utf-8")
                for x in ("-I -S", "/usr/bin/env -i", "--home")
            )
        ),
        "patterns": str(patterns_path(home)),
        "patterns_present": patterns_path(home).exists(),
    }
    return rows, info


# --- guard test: real hook input formats --------------------------------------------

DENY_CASES = [
    "read .env",
    "cat .env",
    "grep -r KEY . (folder holds .env)",
    "edit .dev.vars",
    "read ~/.ssh/id_rsa",
    "overwrite ~/.keyhush/secretfiles",
]
ALLOW_CASES = ["read .env.example", "read src/app.py", "ls", "grep -r KEY src/ (no secret file)"]


def sample_inputs(agent: str, proj: Path, home: Home) -> dict[str, dict]:
    """One hook input per case, in the agent's documented format."""
    p = lambda *parts: str(proj.joinpath(*parts))  # noqa: E731
    ssh = str(home.root / ".ssh" / "id_rsa")
    base = {"session_id": "keyhush-test", "transcript_path": None, "cwd": str(proj)}

    if agent in ("claude", "codex"):

        def tool(name, ti):
            ev = {
                **base,
                "hook_event_name": "PreToolUse",
                "tool_name": name,
                "tool_input": ti,
                "tool_use_id": "keyhush-test",
            }
            if agent == "claude":
                ev["permission_mode"] = "default"
            else:
                ev.update(turn_id="keyhush-test", model="test", permission_mode="default")
            return ev

        if agent == "claude":
            reads = lambda f: tool("Read", {"file_path": f})  # noqa: E731
            edit = tool("Edit", {"file_path": p(".dev.vars"), "old_string": "A", "new_string": "B"})
        else:  # Codex reads through the shell and edits through apply_patch
            reads = lambda f: tool("Bash", {"command": f"sed -n '1,200p' {shlex.quote(f)}"})  # noqa: E731
            patch = "*** Begin Patch\n*** Update File: .dev.vars\n@@\n-A=1\n+A=2\n*** End Patch\n"
            edit = tool("apply_patch", {"command": patch})
        sh = lambda c: tool("Bash", {"command": c})  # noqa: E731
    elif agent == "cursor":
        cbase = {
            "conversation_id": "keyhush-test",
            "generation_id": "g",
            "model": "test",
            "cursor_version": "test",
            "workspace_roots": [str(proj)],
            "user_email": None,
            "transcript_path": None,
        }

        def reads(f):
            return {
                **cbase,
                "hook_event_name": "beforeReadFile",
                "file_path": f,
                "content": "",
                "attachments": [],
            }

        def sh(c):
            return {
                **cbase,
                "hook_event_name": "beforeShellExecution",
                "command": c,
                "cwd": str(proj),
                "sandbox": False,
            }

        edit = {
            **cbase,
            "hook_event_name": "preToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": p(".dev.vars"), "content": "A=2"},
            "tool_use_id": "keyhush-test",
            "cwd": str(proj),
        }
    else:  # gemini

        def tool(name, ti):
            return {
                **base,
                "hook_event_name": "BeforeTool",
                "timestamp": "2026-01-01T00:00:00Z",
                "tool_name": name,
                "tool_input": ti,
            }

        reads = lambda f: tool("read_file", {"file_path": f})  # noqa: E731
        sh = lambda c: tool("run_shell_command", {"command": c, "dir_path": str(proj)})  # noqa: E731
        edit = tool("replace", {"file_path": p(".dev.vars"), "old_string": "A", "new_string": "B"})

    return {
        "read .env": reads(p(".env")),
        "cat .env": sh("cat .env"),
        "grep -r KEY . (folder holds .env)": sh("grep -r KEY ."),
        "edit .dev.vars": edit,
        "read ~/.ssh/id_rsa": reads(ssh),
        "overwrite ~/.keyhush/secretfiles": sh("echo '!*' > ~/.keyhush/secretfiles"),
        "read .env.example": reads(p(".env.example")),
        "read src/app.py": reads(p("src", "app.py")),
        "ls": sh("ls"),
        "grep -r KEY src/ (no secret file)": sh("grep -r KEY src/"),
    }


def blocked(agent: str, stdout: str, code: int) -> bool:
    if code == 2:
        return True
    try:
        data = json.loads(stdout) if stdout.strip() else {}
    except ValueError:
        return agent == "cursor"  # Cursor blocks on invalid output
    if agent == "cursor":
        return data.get("permission") != "allow"
    if agent == "gemini":
        return data.get("decision") in ("deny", "block")
    hso = data.get("hookSpecificOutput") or {}
    return hso.get("permissionDecision") == "deny" or data.get("decision") == "block"


@dataclass
class TestRow:
    agent: str
    case: str
    expected: str
    got: str

    @property
    def ok(self) -> bool:
        return self.expected == self.got


def _argv(command: str) -> list[str] | str:
    return command if sys.platform == "win32" else shlex.split(command)


def do_test(home: Home, agents=None) -> list[TestRow]:
    rows: list[TestRow] = []
    proj = Path(tempfile.mkdtemp(prefix="keyhush-test-"))
    try:
        (proj / "src").mkdir()
        for name in (".env", ".env.example", ".dev.vars"):
            (proj / name).write_text("PLACEHOLDER=not-a-secret\n")
        (proj / "src" / "app.py").write_text("print('hi')\n")
        env = {**os.environ, "HOME": str(home.root), "USERPROFILE": str(home.root)}
        for spec in pick(agents):
            commands = ours_commands(spec, home)
            ok, _err = installed(spec, home)
            cases = sample_inputs(spec.name, proj, home)
            for case, payload in cases.items():
                expected = "blocked" if case in DENY_CASES else "allowed"
                if not ok or not commands:
                    rows.append(TestRow(spec.name, case, expected, "not installed"))
                    continue
                try:
                    proc = subprocess.run(
                        _argv(commands[0]),
                        input=json.dumps(payload).encode(),
                        capture_output=True,
                        timeout=10,
                        cwd=str(proj),
                        env=env,
                    )
                    got = (
                        "blocked"
                        if blocked(spec.name, proc.stdout.decode(errors="replace"), proc.returncode)
                        else "allowed"
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    got = f"error: {type(exc).__name__}"
                rows.append(TestRow(spec.name, case, expected, got))
    finally:
        shutil.rmtree(proj, ignore_errors=True)
    return rows


def hook_health(spec, home: Home) -> Optional[str]:
    """Run the installed hook once on a deny case and an allow case. None means healthy."""
    commands = ours_commands(spec, home)
    if not commands:
        return "no keyhush hook command found"
    python = hook_python(commands[0], home)
    if not python or not os.path.exists(python):
        return f"the hook's Python is missing ({python or 'unknown'}); run keyhush guard install"
    proj = Path(tempfile.mkdtemp(prefix="keyhush-status-"))
    try:
        (proj / "src").mkdir()
        (proj / "src" / "app.py").write_text("x\n")
        (proj / ".env").write_text("PLACEHOLDER=1\n")
        (proj / ".env.example").write_text("PLACEHOLDER=1\n")
        (proj / ".dev.vars").write_text("PLACEHOLDER=1\n")
        cases = sample_inputs(spec.name, proj, home)
        env = {**os.environ, "HOME": str(home.root), "USERPROFILE": str(home.root)}
        for case, want in (("cat .env", True), ("ls", False)):
            try:
                proc = subprocess.run(
                    _argv(commands[0]),
                    input=json.dumps(cases[case]).encode(),
                    capture_output=True,
                    timeout=15,
                    cwd=str(proj),
                    env=env,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                return f"the hook command does not run ({type(exc).__name__})"
            if want and not blocked(
                spec.name, proc.stdout.decode(errors="replace"), proc.returncode
            ):
                return "the hook ran but did not block a .env read"
            if not want and proc.returncode not in (0,):
                msg = proc.stderr.decode(errors="replace").strip().splitlines()[-1:] or [""]
                return f"the hook fails on a harmless call (exit {proc.returncode}): {msg[0]}"
    finally:
        shutil.rmtree(proj, ignore_errors=True)
    return None
