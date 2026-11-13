# 01: The guard

## Goal
Stop coding agents reading secret files, on four agents, from one pattern list, with a test the
user can run to prove it. Users asked for a hard block that also covers shell, grep and edits,
not only the agent's file tool.

## Shape
- One file, `src/keyhush/guard/guard.py`, Python 3.9+ standard library only. `guard install`
  copies it to `~/.keyhush/guard.py` so it works whatever installed the CLI, and runs it with a
  stable Python, never the temporary one `uvx` uses.
- One pattern list, `~/.keyhush/secretfiles`, gitignore-style, case-insensitive. Built-in
  defaults apply when the file is missing.
- One installer module per agent (`install_claude.py`, `install_codex.py`, `install_cursor.py`,
  `install_gemini.py`), sharing `install_base.py`.

## Rules
- **Deny:** reads, edits and writes of a listed path; shell commands that name one; recursive
  search over a folder that holds one.
- **Allow without approving:** no decision on harmless calls, so the agent's own prompts still run.
  Cursor needs an explicit `allow` because it blocks empty output.
- **Fail closed:** on its own error the hook denies and names `keyhush guard uninstall`.
- **Field-agnostic:** every string in the tool input is checked, so renamed fields do not open
  holes.

## Config edits
Back up first, merge without touching other keys, write atomically, recognise our entries by the
hook command, record what was created in `~/.keyhush/guard-state.json`, and be idempotent.
Malformed, oversized or oddly typed configs are refused, never rewritten.

## Proof
`keyhush guard test` sends each agent's documented hook input for five deny cases and four allow
cases to the installed hook and prints a table.

## Out of scope (v0.1)
Scripts that open files themselves, MCP tools, OS-level sandboxing, editing Codex permission
profiles, agents beyond the four.
