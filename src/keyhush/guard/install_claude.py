"""Claude Code: ~/.claude/settings.json, hooks.PreToolUse, plus permissions.deny Read rules.

Docs: https://code.claude.com/docs/en/hooks (PreToolUse, deny via
hookSpecificOutput.permissionDecision) and https://code.claude.com/docs/en/permissions
(`//` anchors a rule at the filesystem root, `~/` at home).
`PowerShell` is in the matcher because on Windows Claude Code may route shell commands
through it and never register `Bash` (hooks docs, PowerShell tool section).
"""

from __future__ import annotations

from .install_base import AgentSpec

MATCHER = "Read|Edit|Write|Grep|Glob|Bash|PowerShell"
# Deny rules for Claude's own file tools; they also cover @-mentions, which skip hooks.
# `.env.*` is left to the hook, because a deny rule cannot allow `.env.example` back.
DENY_READ = [
    "Read(//**/.env)",
    "Read(//**/.dev.vars)",
    "Read(//**/*.pem)",
    "Read(//**/id_rsa*)",
    "Read(~/.ssh/**)",
    "Read(~/.aws/credentials)",
]


def _entry(command: str) -> dict:
    return {"matcher": MATCHER, "hooks": [{"type": "command", "command": command, "timeout": 10}]}


def _commands(entry) -> list[str]:
    if not isinstance(entry, dict):
        return []
    return [h.get("command", "") for h in entry.get("hooks", []) if isinstance(h, dict)]


SPEC = AgentSpec(
    name="claude",
    label="Claude Code",
    config=lambda home: home.claude_dir / "settings.json",
    hook_lists=[(["hooks", "PreToolUse"], _entry)],
    entry_commands=_commands,
    extra_values=[(["permissions", "deny"], DENY_READ)],
)
