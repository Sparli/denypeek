# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
