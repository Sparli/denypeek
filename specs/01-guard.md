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

## How it starts
On macOS and Linux each agent runs `/bin/sh ~/.keyhush/guard.sh --agent NAME`. The wrapper holds
the absolute path of the hook's Python and exits 2 (block, for all four agents) if that Python or
`guard.py` is missing, or if Python exits with anything but 0 or 2. On Windows the command runs
Python directly, so a missing interpreter is a fail-open case there.

`guard install` prefers a system Python, then the virtualenv's base Python, then `python3` on
PATH, skipping anything inside a virtualenv or temporary folder, and warns if it must use one.
`guard status` checks the Python exists and runs the hook once on a deny and an allow case.

## Rules
- **Deny:** reads, edits and writes of a listed path; shell commands that name one; recursive
  search over a folder that holds one.
- **Allow without approving:** no decision on harmless calls, so the agent's own prompts still run.
  Cursor needs an explicit `allow` because it blocks empty output.
- **Fail closed:** on its own error the hook denies and names `keyhush guard uninstall`.
- **Field-agnostic:** every string in the tool input is checked, so renamed fields do not open
  holes.
- **Self-protection (A19):** any agent access to `~/.keyhush/**` and to the hook config files
  (`~/.claude/settings.json` or `$CLAUDE_CONFIG_DIR`, `~/.codex/hooks.json` and `config.toml` or
  `$CODEX_HOME`, `~/.cursor/hooks.json`, `~/.gemini/settings.json`, and their symlink targets) is
  denied, whatever the pattern list says. Agent-run `keyhush guard install|uninstall` is denied.
  Any call whose content contains `disableAllHooks` or a `hooks = false` line is denied, because a
  project's settings can turn the user's hooks off.
- **Shell normalisation (A18):** quotes and `$'...'` quoting, `~`, `$HOME`, `$PWD`, `$IFS`,
  `{a,b}` braces, redirections, globs (hidden files too), words after `:`, `=` and `@`, folders
  entered with `cd`, Unicode NFC, and nested `bash -c` or `eval` scripts.
- **Known misses:** names built at run time (`$(ls | grep env)`, base64), scripts that open files
  themselves, copies under other names, values already in the environment, MCP tools.

## Config edits
Back up first, merge without touching other keys, write atomically, recognise our entries by the
hook command, record what was created in `~/.keyhush/guard-state.json`, and be idempotent.
Malformed, oversized, oddly typed or read-only configs are refused, never rewritten. The state
file and the wrapper are removed once nothing is installed; `keyhush backups purge --config`
deletes the copies of earlier settings.

## Proof
`keyhush guard test` sends each agent's documented hook input for five deny cases and four allow
cases to the installed hook and prints a table.

## Out of scope (v0.1)
Scripts that open files themselves, MCP tools, OS-level sandboxing, editing Codex permission
profiles, agents beyond the four.
