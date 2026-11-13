"""Codex CLI: ~/.codex/hooks.json, hooks.PreToolUse for Bash and apply_patch.

Docs: https://learn.chatgpt.com/docs/hooks.
- Deny with hookSpecificOutput.permissionDecision "deny", or exit 2.
- Hooks are on by default; `[features] hooks = false` in config.toml turns them off.
- Codex skips a new or changed hook until the user trusts it with /hooks.
- A hook error, timeout or malformed reply lets the tool run, so the guard always answers.
"""

from __future__ import annotations

from .install_base import AgentSpec

MATCHER = "Bash|apply_patch"


def _entry(command: str) -> dict:
    return {
        "matcher": MATCHER,
        "hooks": [
            {
                "type": "command",
                "command": command,
                "timeout": 10,
                "statusMessage": "keyhush: checking for secret files",
            }
        ],
    }


def _commands(entry) -> list[str]:
    if not isinstance(entry, dict):
        return []
    return [h.get("command", "") for h in entry.get("hooks", []) if isinstance(h, dict)]


SPEC = AgentSpec(
    name="codex",
    label="Codex CLI",
    config=lambda home: home.codex_dir / "hooks.json",
    hook_lists=[(["hooks", "PreToolUse"], _entry)],
    entry_commands=_commands,
    notes=[
        "Open Codex and run /hooks to trust the keyhush hook. Codex skips it until you do.",
        "Hooks are on by default. If you turned them off, set `[features] hooks = true` "
        "in ~/.codex/config.toml.",
        "Codex reads files through the shell, so the guard checks shell commands and patches.",
    ],
)
