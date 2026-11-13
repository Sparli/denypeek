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
import shutil
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


def is_ours(command: str) -> bool:
    c = command.replace("\\", "/")
    return MARKER in c and "guard.py" in c


def guard_path(home: Home) -> Path:
    return home.keyhush_dir / "guard.py"


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


def stable_python(explicit: Optional[str] = None) -> str:
    """A Python that will still exist tomorrow: never the temporary one `uvx` runs in."""
    if explicit:
        return explicit
    candidates = [sys.executable] + [shutil.which(n) or "" for n in ("python3", "python")]
    for c in candidates:
        if c and os.path.exists(c) and not _temporary(c):
            return c
    raise ConfigError("no stable Python found; pass --python /path/to/python3")


def hook_command(python: str, home: Home, agent: str) -> str:
    return f'"{python}" "{guard_path(home)}" --agent {agent}'


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
    st = state.setdefault(
        spec.name,
        {"config": str(path), "file_existed": existed, "created_keys": [], "added_values": {}},
    )
    created: list[list[str]] = []
    try:
        for keys, make in spec.hook_lists:
            lst = _container(data, keys, created, list)
            lst[:] = [e for e in lst if not any(is_ours(c) for c in spec.entry_commands(e))]
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
            node[:] = [e for e in node if not any(is_ours(c) for c in spec.entry_commands(e))]
    for dotted, values in st.get("added_values", {}).items():
        node = _get(data, dotted.split("."))
        if isinstance(node, list):
            node[:] = [v for v in node if v not in values]
    for keys in sorted(st.get("created_keys", []), key=len, reverse=True):
        _prune(data, keys)
    state.pop(spec.name, None)
    if data == before:
        return Change(spec.name, path, False)
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
