"""Gemini CLI: ~/.gemini/settings.json, hooks.BeforeTool.

Docs: https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md
- Deny with {"decision": "deny", "reason": ...} on exit 0, or exit 2 with stderr.
- timeout is in milliseconds. Tool names from docs/reference/tools.md.
"""

from __future__ import annotations

from .install_base import AgentSpec

MATCHER = (
    "read_file|read_many_files|run_shell_command|grep_search|search_file_content"
    "|glob|write_file|replace"
)


def _entry(command: str) -> dict:
    return {
        "matcher": MATCHER,
        "hooks": [
            {"name": "denypeek-guard", "type": "command", "command": command, "timeout": 10000}
        ],
    }


def _commands(entry) -> list[str]:
    if not isinstance(entry, dict):
        return []
    return [h.get("command", "") for h in entry.get("hooks", []) if isinstance(h, dict)]


SPEC = AgentSpec(
    name="gemini",
    label="Gemini CLI",
    config=lambda home: home.gemini_dir / "settings.json",
    hook_lists=[(["hooks", "BeforeTool"], _entry)],
    entry_commands=_commands,
)
