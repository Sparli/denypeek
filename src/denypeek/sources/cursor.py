"""Cursor history (SQLite). Scanned read-only; never redacted.

STATE_DB:  `<Cursor app dir>/User/globalStorage/state.vscdb` and
           `<Cursor app dir>/User/workspaceStorage/<id>/state.vscdb`, where the app dir is
           `~/Library/Application Support/Cursor` (macOS), `~/.config/Cursor` (Linux) or
           `%APPDATA%\\Cursor` (Windows).
CHATS_DB:  `~/.cursor/chats/<workspace>/<chat>/store.db`
[U] community sources (ranwhat's path table, 2026-11).
"""

from __future__ import annotations

from . import Home, Source, walk

STATE_DB = "state.vscdb"
CHATS_DB = "store.db"


def find(home: Home, errors: list) -> list[Source]:
    out = []
    for app in home.cursor_app_dirs:
        for p in walk(app / "User", (".vscdb",), errors):
            if p.name == STATE_DB:
                out.append(Source("cursor", p, "sqlite"))
    for p in walk(home.cursor_dot_dir / "chats", (".db",), errors):
        if p.name == CHATS_DB:
            out.append(Source("cursor", p, "sqlite"))
    return out
