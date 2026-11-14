"""Cursor: ~/.cursor/hooks.json (version 1).

Docs: https://cursor.com/docs/hooks
- beforeReadFile and beforeShellExecution, as in the spec.
- preToolUse with matcher Read|Write|Grep|Delete|Shell is added too: it is the only hook
  that sees file writes and the Grep tool, which the spec's acceptance tests need.
- failClosed: true makes crashes and timeouts block. For these permission hooks Cursor also
  blocks on empty or invalid output, so the guard prints {"permission": "allow"} to allow.
"""

from __future__ import annotations

from .install_base import AgentSpec

TOOL_MATCHER = "Read|Write|Grep|Delete|Shell"


def _entry(matcher=None):
    def make(command: str) -> dict:
        e = {"command": command, "failClosed": True, "timeout": 10}
        if matcher:
            e["matcher"] = matcher
        return e

    return make


def _commands(entry) -> list[str]:
    return [entry.get("command", "")] if isinstance(entry, dict) else []


SPEC = AgentSpec(
    name="cursor",
    label="Cursor",
    config=lambda home: home.cursor_dot_dir / "hooks.json",
    hook_lists=[
        (["hooks", "beforeReadFile"], _entry()),
        (["hooks", "beforeShellExecution"], _entry()),
        (["hooks", "preToolUse"], _entry(TOOL_MATCHER)),
    ],
    entry_commands=_commands,
    notes=[
        "Cursor's docs say terminal and MCP protection is not guaranteed; see the README limits.",
    ],
)
