# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed (security final check of the guard, F1)
- The hook command starts with `/usr/bin/env -i`, so exported shell functions and variables
  cannot change the wrapper; project settings that set `BASH_FUNC_*`, `BASH_ENV`, `SHELLOPTS`,
  `IFS` and similar shell variables are denied.

### Fixed (security re-check of the guard, R1 to R7)
- The hook starts from a clean environment with a fixed home folder (`env -i`, `--home`), and on
  macOS from the real interpreter rather than the `xcrun` launcher; settings that set
  hook-relevant variables are denied.
- Project agent settings folders are protected as copy, move, link and extract targets; `git`
  counts as read-only only for read subcommands; JSON-escaped hooks-off text is caught.
- Agent folders cannot be deleted through globs, braces or `find -delete` from the home folder.
- Variable expansion is capped and denied past 100,000 characters.
- README states what the guard is and is not, and lists the remaining known misses.

### Fixed (security review of the guard, G1 to G14)
- The hook's Python runs isolated (`-I -S`, `PYTHON*` cleared); the installer prefers a
  root-owned Python and warns about one the user can modify; user Python folders are protected.
- The hook answers within about 3 seconds on any input (deadline plus watchdog).
- Over-long commands and paths are denied, not skipped.
- Relative names are checked against the tool's working folder.
- Settings that turn hooks off are found by parsing, in project settings too, including
  Gemini's `hooksConfig`.
- `grep -d recurse`, `node_modules` for `grep -r`, line continuations, Gemini `read_many_files`
  folders and simple same-command variables are handled.
- Agents cannot move, delete or rewrite `~/.claude`, `~/.codex`, `~/.cursor`, `~/.gemini`.
- Uninstall removes only keyhush's own hook objects.
- Install reports an unwritable config folder instead of crashing.
- CI pins actions to commit SHAs and runs the suite on Python 3.9.

### Fixed (after QA and security review)
- The guard protects itself: agents cannot read or change `~/.keyhush/**` or the hook config
  files, run `keyhush guard install|uninstall`, or write `disableAllHooks` / `hooks = false`.
- Blocked bypasses: `git show HEAD:.env`, `git cat-file`, brace expansion, `$'...'` quoting,
  `curl -F f=@.env`, `$PWD`, `cd dir && cat .env`, NFD Unicode names.
- The hook blocks instead of failing open when its Python or `guard.py` is missing (macOS, Linux);
  `guard install` avoids virtualenv Pythons and warns; `guard status` runs the hook.
- Read-only agent configs are left untouched.
- Install and uninstall headers say how many agents succeeded; the state file is removed after a
  full uninstall; `keyhush backups purge --config` deletes copies of earlier settings.

### Added
- `keyhush guard install | status | test | uninstall` for Claude Code, Codex CLI, Cursor and
  Gemini CLI, from one pattern list, with a fail-closed standard-library hook.
- `keyhush scan` of agent history (JSONL, JSON, Cursor SQLite read-only), with `--json` and exit
  codes 0, 1 and 2, listing every file or line it could not read.
- `keyhush redact`, `undo` and `backups list | purge`, with owner-only backups, atomic writes and a
  verification rescan.
- Detection rules generated from gitleaks v8.30.1.
- Agent skill file and `AGENTS.md` snippet.
- Diagrams, design notes in `specs/`, and a terminal capture made from a real fixture run.
