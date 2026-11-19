# 01: The guard

## Goal
Stop coding agents reading secret files, on four agents, from one pattern list, with a test the
user can run to prove it. Users asked for a hard block that also covers shell, grep and edits,
not only the agent's file tool.

## Shape
- One file, `src/denypeek/guard/guard.py`, Python 3.9+ standard library only. `guard install`
  copies it to `~/.denypeek/guard.py` so it works whatever installed the CLI, and runs it with a
  stable Python, never the temporary one `uvx` uses.
- One pattern list, `~/.denypeek/secretfiles`, gitignore-style, case-insensitive. Built-in
  defaults apply when the file is missing.
- One installer module per agent (`install_claude.py`, `install_codex.py`, `install_cursor.py`,
  `install_gemini.py`), sharing `install_base.py`.

## How it starts
On macOS and Linux each agent runs `/usr/bin/env -i /bin/sh ~/.denypeek/guard.sh --agent NAME`, so
the wrapper's shell starts from an empty environment: no exported function (`BASH_FUNC_*`) or
variable can replace its builtins (F1). The wrapper holds
the absolute path of the hook's Python and the home folder at install time, and starts
`/usr/bin/env -i HOME=<home> PATH=/usr/bin:/bin python -I -S guard.py --home <home>` (R1: no
variable an agent can set reaches the hook; only CLAUDE_CONFIG_DIR and CODEX_HOME pass, and they
can only add protected folders). guard.py takes its home folder from --home or the account
record (pwd), never from HOME. On macOS the installer writes the root-owned interpreter behind
the /usr/bin/python3 xcrun launcher, which honours DEVELOPER_DIR. Python runs (isolated mode and no site module: no site-packages, `.pth`
files, user site or script-folder imports; both flags exist on 3.9). It exits 2 (block, for all
four agents) if that Python or `guard.py` is missing, if Python exits with anything but 0 or 2,
or if it exits 0 without a reply (the guard always replies, `{}` on allow). On Windows the
command runs `python -I -S` directly, so a missing interpreter is a fail-open case there.

`guard install` prefers a Python the user cannot modify: `/usr/bin/python3` first, then other
system Pythons, the virtualenv's base Python and `python3` on PATH, skipping anything inside a
virtualenv or temporary folder. A Python whose program file or stdlib folder the user can write
to is used only as a last resort, with a warning (G1). `guard status` checks the Python exists,
warns if it is user-writable, and runs the hook once on a deny and an allow case.

Every decision has a 2.5 s deadline checked in the token, brace and glob loops; past it the call
is denied. A watchdog at 3 s (interval timer and CPU limit on POSIX, timer thread on Windows)
covers a check stuck inside C code (G2).

## Rules
- **Deny:** reads, edits and writes of a listed path; shell commands that name one; a recursive
  search that, run as written, would read one (the tree rule, below).
- **Allow without approving:** no decision on harmless calls, so the agent's own prompts still run.
  Cursor needs an explicit `allow` because it blocks empty output.
- **Fail closed:** on its own error the hook denies and names `denypeek guard uninstall`.
- **Field-agnostic:** every string in the tool input is checked, so renamed fields do not open
  holes.
- **Over-limit input (G3):** commands over 100,000 characters and paths over 4,096 are denied as
  too long to check; path fields are trimmed of surrounding whitespace only.
- **Working folders (G4):** relative names are checked against the session cwd and the tool's
  `workdir`, `dir_path`, `directory`, `working_directory` or `cwd` fields, and any `cd` target.
- **Self-protection (A19):** any agent access to `~/.denypeek/**` and to the hook config files
  (`~/.claude/settings.json` or `$CLAUDE_CONFIG_DIR`, `~/.codex/hooks.json` and `config.toml` or
  `$CODEX_HOME`, `~/.cursor/hooks.json`, `~/.gemini/settings.json`, and their symlink targets) is
  denied, whatever the pattern list says. Agent-run `denypeek guard install|uninstall` is denied.
  Shell commands may only read `~/.claude`, `~/.codex`, `~/.cursor`, `~/.gemini`. The user's
  Python folders (`~/Library/Python`, `~/.local/lib/python*`, `%APPDATA%\Python`) are protected
  (G1). Agent settings files at any depth (G5): an edit or write is checked by parsing the file it
  would produce (JSON, comments stripped for Gemini; TOML via tomllib, or a text pattern on 3.9
  and 3.10) and denied if it turns hooks off or cannot be parsed; Codex patches may add but not
  update them; shell commands may only read them, and a command that is not read-only may not
  use a project `.claude`, `.codex`, `.gemini` or `.cursor` folder itself as source or target
  (R2; `git` is read-only only for status, log, diff, show, grep...). Edits that set
  hook-relevant `env` variables are denied (`PYTHON*`, `HOME`, `PATH`, `LD_*`, `DYLD_*`,
  `BASH_FUNC_*`, `BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`, `IFS` and similar shell variables). The text check also runs on JSON-unescaped text. Any text containing `disableAllHooks` or a
  `hooks = false` line is also denied.
- **Shell normalisation (A18):** quotes and `$'...'` quoting, `~`, `$HOME`, `$PWD`, `$IFS`,
  `{a,b}` braces, redirections, globs (hidden files too), words after `:`, `=` and `@`, folders
  entered with `cd`, Unicode NFC, and nested `bash -c` or `eval` scripts. Windows-shaped paths
  (drive letters, UNC shares, `%USERPROFILE%` and `$env:USERPROFILE` paths) get `/` separators
  before splitting; on Windows every backslash does, since cmd and PowerShell never use it as an
  escape. Elsewhere backslashes stay shell escapes.
- **Recursive reads, the tree rule (spec 3b):** `grep -r`, `-d recurse`, `--directories=recurse`,
  `rg`, `ag`, `ack`, `git grep`, the search tools and Gemini `read_many_files` trigger a walk of
  every folder the search reads (found through wrappers, `cd`, abbreviated options and both
  readings of an optional option value). The walk skips nothing, for any tool: no hidden names,
  no ignore files, no `node_modules`. Only grep's own `--include`, `--exclude` and
  `--exclude-dir`, as literal values without `/`, narrow it. The search is allowed only if no
  name under it matches the patterns; a regular file `cacert.pem` directly in a folder `certifi` under `site-packages` or
  `dist-packages` does not count.
  A search whose folders or files cannot be told (`xargs`, `git grep` over a revision, the index
  a pattern path or another git folder, a path that is not a literal) is denied. A search covering denypeek's folder, an agent folder or a hook
  config is denied without a walk. Only names that can match a pattern, and symbolic links, get
  the full check. Limits: 100,000 entries and 1 second (measurement in `specs/04-tree-walk.md`);
  past either, denied as too big to check (all start folders together). The deny message names
  up to two secret files and up to eight clear folders directly under the start, plain names
  only.
- **Agent folders (R3):** words are expanded (braces, globs) before the agent-folder check;
  `find -delete/-exec` starting at the home folder or above an agent folder is denied.
- **Variables (R4):** substitution stops and the call is denied once the text would pass
  100,000 characters, checked before any large string is built.
- **Known misses:** names built at run time (`$(ls | grep env)`, base64, command substitution in
  a variable), whole-tree dumps (`find -exec cat`, `tar`), programs that open files on their own,
  copies under other names, values already in the environment, `rm -rf ~`, MCP tools; variables
  set by `for`, `printf -v`, `set --` or `read` (R5); project settings written without naming
  the folder (`tar xf` in the project root, `git checkout .`, a program). Windows: no wrapper,
  so a missing Python fails open and the home folder comes from USERPROFILE.

## Config edits
Back up first, merge without touching other keys, write atomically, recognise our entries by the
hook command, record what was created in `~/.denypeek/guard-state.json`, and be idempotent.
Malformed, oversized, oddly typed or read-only configs are refused, never rewritten. The state
file and the wrapper are removed once nothing is installed; `denypeek backups purge --config`
deletes the copies of earlier settings.

## Proof
`denypeek guard test` sends each agent's documented hook input for five deny cases and four allow
cases to the installed hook and prints a table.

## Out of scope (v0.1)
Scripts that open files themselves, MCP tools, OS-level sandboxing, editing Codex permission
profiles, agents beyond the four.
