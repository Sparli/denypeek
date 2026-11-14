"""Codex CLI history.

SESSIONS: `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`
ARCHIVED: `~/.codex/archived_sessions/*.jsonl`
HISTORY:  `~/.codex/history.jsonl`
[U] community sources (ranwhat's path table, 2026-11). `CODEX_HOME` moves the folder.
"""

from __future__ import annotations

from pathlib import Path

from . import Home, Source, walk

SESSIONS = "sessions"
ARCHIVED = "archived_sessions"
HISTORY = "history.jsonl"


def roots(home: Home) -> list[Path]:
    return [home.codex_dir / SESSIONS, home.codex_dir / ARCHIVED, home.codex_dir / HISTORY]


def find(home: Home, errors: list) -> list[Source]:
    out = []
    for sub in (SESSIONS, ARCHIVED):
        out += [
            Source("codex", p, "jsonl") for p in walk(home.codex_dir / sub, (".jsonl",), errors)
        ]
    hist = home.codex_dir / HISTORY
    if hist.is_file() or hist.is_symlink():
        out.append(Source("codex", hist, "jsonl"))
    return out
