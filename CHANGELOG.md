# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
