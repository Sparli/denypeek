# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-16

First release.

### Added
- `keyhush guard install | status | test | uninstall` for Claude Code, Codex CLI, Cursor and
  Gemini CLI, from one pattern list, with a standard-library hook that blocks when it cannot run
  (macOS, Linux).
- `keyhush scan` of agent history (JSONL, JSON, Cursor SQLite read-only), with `--json` and exit
  codes 0, 1 and 2, listing every file or line it could not read. Output shows no secret: only
  rule, length, a salted fingerprint and, for rules with a fixed public prefix such as `AKIA`, at
  most four characters of that prefix.
- `keyhush redact`, `undo` and `backups list | purge`, with owner-only backups, atomic writes, kept
  file times and a verification rescan.
- Detection rules generated from gitleaks v8.30.1.
- Agent skill file and `AGENTS.md` snippet.
- Diagrams, design notes in `specs/`, and a terminal capture made from a real fixture run.

### Security
Hardened before release through QA passes and security reviews of the guard, scan and redact:
- The hook runs from a clean environment (`/usr/bin/env -i`, isolated Python, fixed home folder)
  and answers within about 3 seconds on any input; over-long input is denied, not skipped.
- The guard protects itself and the agents' own folders: agents cannot read or change
  `~/.keyhush/**`, the hook configs or `~/.claude`, `~/.codex`, `~/.cursor`, `~/.gemini`, or turn
  hooks off in any settings file.
- Known bypasses are blocked (`git show HEAD:.env`, brace expansion, `$'...'` quoting, NFD names,
  `curl -F f=@.env` and others). The README lists the misses that remain.
- File names are escaped in all output, and a Cursor database with a non-empty `-wal` file is
  reported as not fully scanned.
- CI pins actions to commit SHAs and runs on Linux, macOS and Windows, and on Python 3.9.
