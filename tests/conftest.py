"""Test safety harness (spec section 7) and fixture homes.

- Every test runs with HOME, USERPROFILE, CLAUDE_CONFIG_DIR and CODEX_HOME pointing at a
  temp folder.
- An audit hook fails any test that touches a path under the real home folder, outside the
  repo and the Python install.
- socket.socket is patched to raise, so no test can reach the network (A2).
- Fake keys are assembled at run time from random characters. No key-shaped literal is in
  this repo.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import sqlite3
import string
import sys
import tempfile
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _real_home() -> str:
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError, AttributeError):
        return os.environ.get("USERPROFILE") or os.path.expanduser("~")


REAL_HOME = os.path.normcase(os.path.realpath(_real_home()))
ALLOWED_UNDER_HOME = [
    os.path.normcase(os.path.realpath(p))
    for p in {
        str(REPO),
        sys.prefix,
        sys.base_prefix,
        sys.exec_prefix,
        tempfile.gettempdir(),
        os.path.join(_real_home(), ".local", "share", "uv"),
        os.path.join(_real_home(), ".cache", "uv"),
        # Python's own bytecode cache (Apple's system Python puts it under ~/Library/Caches)
        getattr(sys, "pycache_prefix", None) or str(REPO),
    }
]
_state = {"active": False, "violations": []}
WATCHED = {
    "open",
    "os.listdir",
    "os.scandir",
    "os.remove",
    "os.rename",
    "os.replace",
    "os.mkdir",
    "os.rmdir",
    "shutil.rmtree",
    "shutil.copyfile",
    "sqlite3.connect",
    "os.chmod",
    "os.symlink",
    "os.truncate",
    "os.utime",
}


def _check_path(event: str, arg) -> None:
    if isinstance(arg, int) or arg is None:
        return
    try:
        raw = os.fsdecode(arg)
    except TypeError:
        return
    if raw.startswith("file:"):
        raw = raw[5:].split("?", 1)[0]
    if raw in ("", ":memory:"):
        return
    p = os.path.normcase(os.path.realpath(os.path.abspath(raw)))
    if p != REAL_HOME and not p.startswith(REAL_HOME + os.sep):
        return
    if any(p == a or p.startswith(a + os.sep) for a in ALLOWED_UNDER_HOME):
        return
    _state["violations"].append(f"{event}: {raw}")
    raise PermissionError(f"test touched the real home folder: {raw}")


def _audit(event: str, args) -> None:
    if not _state["active"] or event not in WATCHED or not args:
        return
    _check_path(event, args[0])
    if event in ("os.rename", "os.replace", "os.symlink") and len(args) > 1:
        _check_path(event, args[1])


sys.addaudithook(_audit)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Fake home for every test, no network, and the real-home tripwire on."""
    home = tmp_path / "home"
    home.mkdir()
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude"))
    monkeypatch.setenv("CODEX_HOME", str(home / ".codex"))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))

    def no_network(*a, **k):
        raise OSError("network disabled in tests")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket.socket, "__init__", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    _state["violations"].clear()
    _state["active"] = True
    yield home
    _state["active"] = False
    assert not _state["violations"], f"touched the real home: {_state['violations']}"


# --- fake keys -------------------------------------------------------------------------


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


ALNUM = string.ascii_letters + string.digits


def fake_github() -> str:
    return "gh" + "p_" + _rand(ALNUM, 36)


def fake_aws() -> str:
    return "AK" + "IA" + _rand(string.ascii_uppercase + "234567", 16)


def fake_stripe() -> str:
    return "sk" + "_live_" + _rand(ALNUM, 24)


def fake_slack() -> str:
    return (
        "xo"
        + "xb-"
        + _rand(string.digits, 12)
        + "-"
        + _rand(string.digits, 12)
        + "-"
        + _rand(ALNUM, 24)
    )


def fake_adobe() -> str:
    return "p8" + "e-" + _rand(string.ascii_letters + string.digits, 32)


# --- fixture homes ----------------------------------------------------------------------

OLD = time.time() - 3600  # an hour ago: not "active"


def jl(*records) -> str:
    return "".join(json.dumps(r) + "\n" for r in records)


def write(path: Path, text: str, mtime: float = OLD) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path


def make_cursor_db(path: Path, value: str, mtime: float = OLD) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
    conn.execute("INSERT INTO ItemTable VALUES (?, ?)", ("theme", "dark"))
    conn.execute("INSERT INTO ItemTable VALUES (?, ?)", ("composerData:1", value.encode()))
    conn.commit()
    conn.close()
    os.utime(path, (mtime, mtime))
    return path


@pytest.fixture
def keys():
    return {
        "claude": fake_github(),
        "codex": fake_aws(),
        "gemini": fake_stripe(),
        "cursor": fake_slack(),
    }


@pytest.fixture
def four_store_home(isolated, keys):
    """One fake key in each agent's store, at a known file and line."""
    home = isolated
    write(
        home / ".claude/projects/-work-app/s1.jsonl",
        jl(
            {"type": "user", "message": {"content": "hello"}},
            {"type": "user", "message": {"content": f"my token is {keys['claude']} ok"}},
            {"type": "assistant", "message": {"content": "noted"}},
        ),
    )
    write(
        home / ".codex/sessions/2026/11/13/rollout-1.jsonl",
        jl(
            {"type": "session_meta"},
            {"type": "message", "text": "run the build"},
            {"type": "function_call_output", "output": f"aws_access_key_id = {keys['codex']}"},
        ),
    )
    gemini = {
        "sessionId": "x",
        "messages": [
            {"type": "user", "content": "deploy"},
            {"type": "gemini", "content": f"Using STRIPE key {keys['gemini']} now"},
        ],
    }
    write(home / ".gemini/tmp/abc123/chats/session-1.json", json.dumps(gemini, indent=2))
    make_cursor_db(
        home / "Library/Application Support/Cursor/User/globalStorage/state.vscdb",
        json.dumps({"text": f"slack {keys['cursor']}"}),
    )
    return home


def run_cli(*args: str) -> tuple[int, str, str]:
    """Run the CLI in-process and capture output."""
    import contextlib
    import io

    from keyhush.cli import main

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


def symlink_or_skip(link: Path, target: Path) -> None:
    """Create a symlink, or skip the test where the OS refuses (Windows without the right)."""
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create symlinks here: {exc}")
