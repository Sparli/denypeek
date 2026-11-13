"""Where each agent keeps its history. Paths are relative to a home folder.

With `--home <dir>`, every path is built from that folder and the CLAUDE_CONFIG_DIR and
CODEX_HOME variables are ignored, so a fixture home can never reach the real one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Source:
    agent: str
    path: Path
    kind: str  # "jsonl" | "json" | "sqlite"


@dataclass(frozen=True)
class Home:
    root: Path
    claude_dir: Path
    codex_dir: Path
    gemini_dir: Path
    cursor_dot_dir: Path
    cursor_app_dirs: tuple[Path, ...]

    @property
    def keyhush_dir(self) -> Path:
        return self.root / ".keyhush"

    def history_roots(self) -> list[Path]:
        """Folders that redact and undo may write inside."""
        from . import claude, codex, gemini

        return claude.roots(self) + codex.roots(self) + gemini.roots(self)

    def display(self, path: Path) -> str:
        """Show a path with the home folder as `~`."""
        try:
            rel = Path(path).relative_to(self.root)
        except ValueError:
            return str(path)
        return str(Path("~") / rel)


def resolve_home(home: Optional[str] = None, environ: Optional[dict] = None) -> Home:
    env = os.environ if environ is None else environ
    if home is not None:
        root = Path(home).expanduser().absolute()
        claude_dir = root / ".claude"
        codex_dir = root / ".codex"
        app_dirs = _cursor_app_dirs(root, None)
    else:
        root = Path.home()
        claude_dir = Path(env["CLAUDE_CONFIG_DIR"]) if env.get("CLAUDE_CONFIG_DIR") else root / ".claude"
        codex_dir = Path(env["CODEX_HOME"]) if env.get("CODEX_HOME") else root / ".codex"
        app_dirs = _cursor_app_dirs(root, env.get("APPDATA"))
    return Home(
        root=root,
        claude_dir=claude_dir.absolute(),
        codex_dir=codex_dir.absolute(),
        gemini_dir=root / ".gemini",
        cursor_dot_dir=root / ".cursor",
        cursor_app_dirs=app_dirs,
    )


def _cursor_app_dirs(root: Path, appdata: Optional[str]) -> tuple[Path, ...]:
    # [U] community sources (ranwhat's path table): macOS, Linux, Windows.
    dirs = [
        root / "Library" / "Application Support" / "Cursor",
        root / ".config" / "Cursor",
        root / "AppData" / "Roaming" / "Cursor",
    ]
    if appdata:
        dirs.append(Path(appdata) / "Cursor")
    seen, out = set(), []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return tuple(out)


def walk(base: Path, suffixes: tuple[str, ...], errors: list) -> list[Path]:
    """Files under base with one of the suffixes. Symlinked folders are not followed."""
    if not base.is_dir():
        return []
    found = []

    def onerror(exc: OSError) -> None:
        errors.append((Path(exc.filename or base), f"cannot list folder: {exc.strerror}"))

    for dirpath, _dirnames, filenames in os.walk(base, onerror=onerror, followlinks=False):
        for name in filenames:
            if name.endswith(suffixes):
                found.append(Path(dirpath) / name)
    return sorted(found)


def all_sources(home: Home, errors: list) -> list[Source]:
    from . import claude, codex, cursor, gemini

    out: list[Source] = []
    for mod in (claude, codex, gemini, cursor):
        out.extend(mod.find(home, errors))
    return out
