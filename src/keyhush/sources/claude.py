"""Claude Code history.

PROJECTS: `~/.claude/projects/<project>/<session>.jsonl` (and subagent files below it).
Source: official docs, https://code.claude.com/docs/en/claude-directory (the `projects/` folder).
HISTORY: `~/.claude/history.jsonl`, the prompt history. [U] community sources.
`CLAUDE_CONFIG_DIR` moves the whole folder (official docs, env-vars page).
"""

from __future__ import annotations

from pathlib import Path

from . import Home, Source, walk

PROJECTS = "projects"
HISTORY = "history.jsonl"


def roots(home: Home) -> list[Path]:
    return [home.claude_dir / PROJECTS, home.claude_dir / HISTORY]


def find(home: Home, errors: list) -> list[Source]:
    out = [Source("claude", p, "jsonl") for p in walk(home.claude_dir / PROJECTS, (".jsonl",), errors)]
    hist = home.claude_dir / HISTORY
    if hist.is_file() or hist.is_symlink():
        out.append(Source("claude", hist, "jsonl"))
    return out
