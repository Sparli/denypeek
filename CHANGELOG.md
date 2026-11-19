# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

First release. The project was renamed from keyhush before this release, because another
project already uses that name.

### Added
- `denypeek guard install | status | test | uninstall` for Claude Code, Codex CLI, Cursor and
  Gemini CLI, from one pattern list, with a standard-library hook that blocks when it cannot run
  (macOS, Linux).
- `denypeek scan` of agent history (JSONL, JSON, Cursor SQLite read-only), with `--json` and exit
  codes 0, 1 and 2, listing every file or line it could not read. Output shows no secret: only
  rule, length, a salted fingerprint and, for rules with a fixed public prefix such as `AKIA`, at
  most four characters of that prefix.
- `denypeek redact`, `undo` and `backups list | purge`, with owner-only backups, atomic writes, kept
  file times and a verification rescan.
- Detection rules generated from gitleaks v8.30.1.
- Agent skill file and `AGENTS.md` snippet.
- Diagrams, design notes in `specs/`, and a terminal capture made from a real fixture run.

### Security
- Recursive searches follow the tree rule: what the tool, run as written, can read decides,
  not the folder's size. `rg foo` beside a `.env` is allowed; `grep -r` over a big project is
  denied only past 100,000 entries, with a message saying how to narrow it. Installs made before
  this change have no record of a ripgrep config, so every `rg` beside a secret file stays
  denied until you run `denypeek guard install` again.
Hardened before release through QA passes and security reviews of the guard, scan and redact:
- The hook runs from a clean environment (`/usr/bin/env -i`, isolated Python, fixed home folder)
  and answers within about 3 seconds on any input; over-long input is denied, not skipped.
- The guard protects itself and the agents' own folders: agents cannot read or change
  `~/.denypeek/**`, the hook configs or `~/.claude`, `~/.codex`, `~/.cursor`, `~/.gemini`, or turn
  hooks off in any settings file.
- Known bypasses are blocked (`git show HEAD:.env`, brace expansion, `$'...'` quoting, NFD names,
  `curl -F f=@.env` and others). The README lists the misses that remain.
- The shell check follows one written rule for globs (the shell-word rule): if bash, zsh or sh,
  in any covered mode, can expand a word to a protected path, the command is denied. Real
  shells check it in CI (the glob oracle in `tests/oracle`). Quoted patterns are literal unless
  the shell reads them again (a bound value used unquoted, `-c` strings, `eval`, a pipe into a
  shell).
- Deleting, moving or locking the home folder or a folder above it (`rm -rf ~`, `rm -rf ..`,
  `mv ~ /tmp/x`, `chmod -R 000 ~`, `git clean` there) is denied, because it would remove the
  guard and every agent folder at once.
- Hidden file names: `guard install` picks a setting from your bash and zsh startup files.
  With `auto`, `cat *` passes beside a `.env`, as it does in the shell, and turning
  `dotglob` or `globdots` on is denied; with `always`, hidden names always count.
  `--hidden always` forces it.
- File names are escaped in all output, and a Cursor database with a non-empty `-wal` file is
  reported as not fully scanned.
- CI pins actions to commit SHAs and runs on Linux, macOS and Windows, and on Python 3.9.
