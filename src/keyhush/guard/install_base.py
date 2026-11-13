"""Shared logic for wiring the guard into an agent's JSON config.

Every edit: back the file up first, merge without touching other keys, write atomically,
recognise our own entries so uninstall removes only ours, and stay idempotent.
What we created or added is recorded in ~/.keyhush/guard-state.json.
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from ..fsutil import atomic_write, ensure_private_dir, write_new_private
from ..sources import Home

MAX_CONFIG_BYTES = 5_000_000
MARKER = "keyhush"


class ConfigError(Exception):
    """A config file we will not touch (malformed, too big, not an object)."""


OUR_HOOK = re.compile(r"[/\\]\.keyhush[/\\]guard\.(?:py|sh)\b")


def is_ours(command: str) -> bool:
    """Our hook command names ~/.keyhush/guard.sh or guard.py exactly (G12)."""
    return bool(OUR_HOOK.search(command or ""))


def remove_ours(entries: list) -> None:
    """Remove only our hook objects; drop a matcher group only if nothing else is left (G12)."""
    kept = []
    for e in entries:
        if isinstance(e, dict) and isinstance(e.get("hooks"), list):
            hooks = [
                h
                for h in e["hooks"]
                if not (isinstance(h, dict) and is_ours(str(h.get("command", ""))))
            ]
            if len(hooks) == len(e["hooks"]):
                kept.append(e)
            elif hooks:
                kept.append({**e, "hooks": hooks})
        elif isinstance(e, dict) and is_ours(str(e.get("command", ""))):
            continue
        else:
            kept.append(e)
    entries[:] = kept


def guard_path(home: Home) -> Path:
    return home.keyhush_dir / "guard.py"


def wrapper_path(home: Home) -> Path:
    return home.keyhush_dir / "guard.sh"


USE_WRAPPER = os.name == "posix"  # /bin/sh exists on macOS and Linux, not on Windows

WRAPPER = """#!/bin/sh
# keyhush guard wrapper, written by `keyhush guard install`.
# Exit 2 means "block this tool call" to every supported agent. It is used if the hook's Python
# or guard.py is missing, if Python fails, or if the hook gives no answer.
PY={py}
GUARD={guard}
# Nothing from the environment may change what Python loads (G1).
unset PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE PYTHONINSPECT PYTHONEXECUTABLE \
  PYTHONWARNINGS PYTHONSAFEPATH PYTHONPLATLIBDIR PYTHONNOUSERSITE
if [ ! -x "$PY" ] || [ ! -f "$GUARD" ]; then
  echo "keyhush guard cannot run: its Python or guard.py is missing. Blocked to be safe. \
Fix it in your own terminal: keyhush guard status (or keyhush guard uninstall)." >&2
  exit 2
fi
# -I: isolated (ignores PYTHON* variables, the user site folder and the script's folder).
# -S: no site module, so no site-packages and no .pth files. The hook needs only the stdlib.
OUT=$("$PY" -I -S "$GUARD" "$@")
rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
  echo "keyhush guard failed (exit $rc). Blocked to be safe. Run: keyhush guard status" >&2
  exit 2
fi
if [ "$rc" -eq 0 ] && [ -z "$OUT" ]; then
  echo "keyhush guard gave no answer. Blocked to be safe. Run: keyhush guard status" >&2
  exit 2
fi
printf '%s\n' "$OUT"
exit "$rc"
"""


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def write_wrapper(home: Home, python: str) -> None:
    text = WRAPPER.format(py=_sh_quote(python), guard=_sh_quote(str(guard_path(home))))
    atomic_write(wrapper_path(home), text.encode(), mode=0o600)


def wrapper_python(home: Home) -> Optional[str]:
    """The Python path written into guard.sh, if any."""
    try:
        for line in wrapper_path(home).read_text(encoding="utf-8").splitlines():
            if line.startswith("PY="):
                v = line[3:]
                return v[1:-1].replace("'\\''", "'") if v.startswith("'") else v
    except OSError:
        pass
    return None


def state_path(home: Home) -> Path:
    return home.keyhush_dir / "guard-state.json"


def load_state(home: Home) -> dict:
    try:
        return json.loads(state_path(home).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(home: Home, state: dict) -> None:
    ensure_private_dir(home.keyhush_dir)
    path = state_path(home)
    data = json.dumps(state, indent=2).encode()
    if path.exists():
        atomic_write(path, data, mode=0o600)
    else:
        write_new_private(path, data)


def _temporary(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    tmp = tempfile.gettempdir().replace("\\", "/").lower()
    return any(
        x in p for x in ("/.cache/uv/", "/uv/cache/", "archive-v", "/pipx/.cache/")
    ) or p.startswith(tmp)


# Root-owned system Python first: its files cannot be changed without admin rights.
SYSTEM_PYTHONS = ["/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3"]


def in_virtualenv(path: str) -> Optional[Path]:
    """The virtual environment folder a Python lives in, or None."""
    p = Path(path).absolute()
    for parent in list(p.parents)[:4]:
        if (parent / "pyvenv.cfg").exists():
            return parent
    return None


def _works(python: str) -> bool:
    """True if this Python runs and is 3.9 or newer."""
    if not python or not os.path.exists(python):
        return False
    try:
        proc = subprocess.run(
            [python, "-c", "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"],
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


WRITABLE_CHECK = (
    "import json, os, sys, sysconfig\n"
    "paths = [os.path.realpath(sys.executable), sysconfig.get_paths()['stdlib']]\n"
    "print(json.dumps([p for p in paths if os.access(p, os.W_OK)]))\n"
)


def writable_parts(python: str) -> list[str]:
    """The interpreter file or stdlib folder of this Python that the current user can write.

    If an agent can write there, it can make the hook run its code (G1). A system Python such
    as /usr/bin/python3 on macOS is root-owned; python.org and Homebrew Pythons often are not.
    """
    try:
        proc = subprocess.run(
            [python, "-I", "-S", "-c", WRITABLE_CHECK], capture_output=True, text=True, timeout=15
        )
        return list(json.loads(proc.stdout or "[]"))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []


def _fragile(python: str) -> Optional[str]:
    """Why this Python may disappear (a virtualenv or a temporary folder), or None."""
    venv = in_virtualenv(python)
    if venv:
        return f"it is inside the virtual environment {venv}"
    if _temporary(python):
        return "it is in a temporary or cache folder"
    return None


def stable_python(explicit: Optional[str] = None) -> tuple[str, Optional[str]]:
    """Pick the hook's Python. Returns (path, warning or None).

    Order: --python; a system Python; the Python this virtualenv was built from; python3 on
    PATH. A Python inside a virtualenv or a temporary folder is used only as a last resort,
    with a warning, because deleting that folder would break the guard.
    """
    if explicit:
        why = _fragile(explicit)
        if why:
            return explicit, f"the hook's Python {explicit} may disappear: {why}"
        return explicit, _writable_warning(explicit)
    base = getattr(sys, "_base_executable", None) or ""
    candidates = (SYSTEM_PYTHONS if os.name == "posix" else []) + [base]
    candidates += [shutil.which(n) or "" for n in ("python3", "python")]
    usable = [c for c in dict.fromkeys(candidates) if c and not _fragile(c) and _works(c)]
    for c in usable:  # first choice: one the user cannot modify
        if not writable_parts(c):
            return c, None
    if usable:
        return usable[0], _writable_warning(usable[0])
    if sys.executable and _works(sys.executable):
        why = _fragile(sys.executable) or "no system Python was found"
        return sys.executable, (
            f"no stable Python found, so the hook uses {sys.executable} ({why}). If that folder "
            "is moved or deleted, the guard stops working: run keyhush guard install again "
            "with --python /path/to/python3."
        )
    raise ConfigError("no working Python 3.9+ found; pass --python /path/to/python3")


def _writable_warning(python: str) -> Optional[str]:
    parts = writable_parts(python)
    if not parts:
        return None
    return (
        f"the hook's Python can be modified by your user account ({', '.join(parts)}). An agent "
        "allowed to write there could make the hook allow everything. Prefer a root-owned "
        "Python, for example --python /usr/bin/python3 on macOS."
    )


def hook_command(python: str, home: Home, agent: str) -> str:
    if USE_WRAPPER:
        return f'/bin/sh "{wrapper_path(home)}" --agent {agent}'
    return f'"{python}" -I -S "{guard_path(home)}" --agent {agent}'


def hook_python(command: str, home: Home) -> Optional[str]:
    """The Python an installed hook command will run."""
    if "guard.sh" in command.replace("\\", "/"):
        return wrapper_python(home)
    try:
        parts = shlex.split(command, posix=os.name == "posix")
    except ValueError:
        return None
    return parts[0].strip('"') if parts else None


def read_config(path: Path) -> tuple[dict, bool]:
    """Return (config, existed). Refuses malformed or huge files instead of overwriting them."""
    if not path.exists():
        return {}, False
    if path.is_symlink() and not Path(os.path.realpath(path)).exists():
        raise ConfigError(f"{path} is a broken symlink; not touched")
    size = path.stat().st_size
    if size > MAX_CONFIG_BYTES:
        raise ConfigError(f"{path} is {size} bytes, too big to edit safely; not touched")
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return {}, True
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ConfigError(f"{path} is not valid JSON ({exc}); not touched") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path} is not a JSON object; not touched")
    return data, True


def read_only_reason(path: Path) -> Optional[str]:
    """Why we must not write this file, or None. A rename would replace a read-only file, so
    the check is on the file itself, not only on its folder."""
    real = Path(os.path.realpath(path))
    if not real.exists():
        return None
    mode = real.stat().st_mode
    if not os.access(real, os.W_OK) or not (mode & stat.S_IWUSR):
        return (
            f"{path} is read-only; not touched. Make it writable yourself if you want "
            "keyhush to change it"
        )
    return None


def backup_config(home: Home, path: Path) -> Optional[Path]:
    if not path.exists():
        return None
    base = home.keyhush_dir / "config-backups"
    ensure_private_dir(home.keyhush_dir)
    ensure_private_dir(base)
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = base / f"{stamp}-{path.parent.name}-{path.name}"
    write_new_private(target, path.read_bytes())
    return target


def write_config(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    real = Path(os.path.realpath(path))
    mode = (real.stat().st_mode & 0o777) if real.exists() else 0o600
    atomic_write(real, (json.dumps(data, indent=2) + "\n").encode(), mode=mode)


def _container(data: dict, keys: list[str], created: list[list[str]], kind: type):
    node = data
    for i, k in enumerate(keys):
        last = i == len(keys) - 1
        if k not in node:
            node[k] = kind() if last else {}
            created.append(keys[: i + 1])
        node = node[k]
        expected = kind if last else dict
        if not isinstance(node, expected):
            raise ConfigError(f"'{'.'.join(keys[: i + 1])}' has an unexpected type; not touched")
    return node


@dataclass
class AgentSpec:
    name: str
    label: str
    config: Callable[[Home], Path]
    # Each hook list: (keys to the list, function(command) -> entry)
    hook_lists: list[tuple[list[str], Callable[[str], dict]]]
    entry_commands: Callable[[dict], list[str]]
    extra_values: list[tuple[list[str], list[str]]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Change:
    agent: str
    path: Path
    changed: bool
    backup: Optional[Path] = None
    error: Optional[str] = None


def install(spec: AgentSpec, home: Home, command: str, state: dict) -> Change:
    path = spec.config(home)
    try:
        data, existed = read_config(path)
    except (ConfigError, OSError, UnicodeDecodeError) as exc:
        return Change(spec.name, path, False, error=str(exc))
    before = copy.deepcopy(data)
    prior = copy.deepcopy(state.get(spec.name))
    st = state.setdefault(
        spec.name,
        {"config": str(path), "file_existed": existed, "created_keys": [], "added_values": {}},
    )
    created: list[list[str]] = []
    try:
        for keys, make in spec.hook_lists:
            lst = _container(data, keys, created, list)
            remove_ours(lst)
            lst.append(make(command))
        for keys, values in spec.extra_values:
            lst = _container(data, keys, created, list)
            added = st["added_values"].setdefault(".".join(keys), [])
            for v in values:
                if v not in lst:
                    lst.append(v)
                    if v not in added:
                        added.append(v)
    except ConfigError as exc:
        return Change(spec.name, path, False, error=str(exc))
    for c in created:
        if c not in st["created_keys"]:
            st["created_keys"].append(c)
    if data == before and existed:
        return Change(spec.name, path, False)
    reason = read_only_reason(path)
    if reason:
        if prior is None:  # nothing was written, so record nothing
            state.pop(spec.name, None)
        else:
            state[spec.name] = prior
        return Change(spec.name, path, False, error=reason)
    backup = backup_config(home, path)
    write_config(path, data)
    return Change(spec.name, path, True, backup)


def uninstall(spec: AgentSpec, home: Home, state: dict) -> Change:
    st = state.get(spec.name, {})
    path = Path(st.get("config") or spec.config(home))
    try:
        data, existed = read_config(path)
    except (ConfigError, OSError, UnicodeDecodeError) as exc:
        return Change(spec.name, path, False, error=str(exc))
    if not existed:
        state.pop(spec.name, None)
        return Change(spec.name, path, False)
    before = copy.deepcopy(data)
    for keys, _make in spec.hook_lists:
        node = _get(data, keys)
        if isinstance(node, list):
            remove_ours(node)
    for dotted, values in st.get("added_values", {}).items():
        node = _get(data, dotted.split("."))
        if isinstance(node, list):
            node[:] = [v for v in node if v not in values]
    for keys in sorted(st.get("created_keys", []), key=len, reverse=True):
        _prune(data, keys)
    if data == before:
        state.pop(spec.name, None)
        return Change(spec.name, path, False)
    reason = read_only_reason(path)
    if reason:
        return Change(spec.name, path, False, error=reason)
    state.pop(spec.name, None)
    backup = backup_config(home, path)
    if not data and st.get("file_existed") is False:
        os.remove(path)
    else:
        write_config(path, data)
    return Change(spec.name, path, True, backup)


def installed(spec: AgentSpec, home: Home) -> tuple[bool, Optional[str]]:
    """(our hook present in every expected list, error)."""
    try:
        data, existed = read_config(spec.config(home))
    except (ConfigError, OSError, UnicodeDecodeError) as exc:
        return False, str(exc)
    if not existed:
        return False, None
    for keys, _make in spec.hook_lists:
        node = _get(data, keys)
        if not isinstance(node, list) or not any(
            any(is_ours(c) for c in spec.entry_commands(e)) for e in node
        ):
            return False, None
    return True, None


def ours_commands(spec: AgentSpec, home: Home) -> list[str]:
    try:
        data, _ = read_config(spec.config(home))
    except (ConfigError, OSError, UnicodeDecodeError):
        return []
    out = []
    for keys, _make in spec.hook_lists:
        node = _get(data, keys)
        if isinstance(node, list):
            for e in node:
                out += [c for c in spec.entry_commands(e) if is_ours(c)]
    return out


def _get(data, keys):
    node = data
    for k in keys:
        if not isinstance(node, dict) or k not in node:
            return None
        node = node[k]
    return node


def _prune(data: dict, keys: list[str]) -> None:
    parent = _get(data, keys[:-1]) if len(keys) > 1 else data
    if isinstance(parent, dict) and keys[-1] in parent and parent[keys[-1]] in ({}, []):
        del parent[keys[-1]]
