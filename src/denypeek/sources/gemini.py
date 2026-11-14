"""Gemini CLI history.

CHATS: `~/.gemini/tmp/<project>/chats/session-*.jsonl` (older versions: `.json`).
LOGS:  `~/.gemini/tmp/<project>/logs.json`, the prompt log.
[U] community sources (ranwhat's path table, 2026-11). On Windows the folder is
`%USERPROFILE%\\.gemini` [U].
"""

from __future__ import annotations

from pathlib import Path

from . import Home, Source, walk

TMP = "tmp"


def roots(home: Home) -> list[Path]:
    return [home.gemini_dir / TMP]


def find(home: Home, errors: list) -> list[Source]:
    out = []
    for p in walk(home.gemini_dir / TMP, (".jsonl", ".json"), errors):
        parts = p.parts
        in_chats = len(parts) >= 2 and parts[-2] == "chats"
        if in_chats or p.name == "logs.json":
            out.append(Source("gemini", p, "jsonl" if p.suffix == ".jsonl" else "json"))
    return out
