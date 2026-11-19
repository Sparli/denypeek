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
- `scan` shows what it will read and a progress line on a terminal, uses every CPU core and
  splits large history files, so a few GB take a few minutes. Ctrl-C stops it cleanly, lists
  what it found so far and exits with code 2; `redact` stops before changing any file.
- `redact` lists every key it found to rotate, including ones it did not redact (a key in
  Cursor's database), marked as such.

### Security
- Recursive searches follow the tree rule: `grep -r`, `rg`, `ag`, `ack`, `git grep` and the
  agents' own search tools are allowed only if nothing under the folders they read matches the
  pattern list, whatever the tool would skip. In a project with a `.env`, a search from the top
  is denied; the message names the secret files and lists the folders that are clear to search
  instead. The folders are found through wrappers (`env`, `timeout`, `sudo`), `cd`,
  redirections, pipes and abbreviated options; a search whose folders cannot be told, `git grep`
  over a revision or the index, a folder that cannot be listed, and a command that may write
  files before it searches are denied. A walk of more than 100,000 entries or a second is
  denied as too big. The public `certifi/cacert.pem` in Python virtualenvs does not count.
  Ignore-aware searches are planned for v0.2.
- A command denied only because a bare `*` could match a hidden secret file gets its own
  message, saying to name the files instead.
- A hook decision that runs out of time is a normal denial, shown by Claude Code as a block
  rather than a hook error.
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
- Hidden file names count for every pattern by default (`always`), so `cat *` beside a `.env` is
  denied. `guard install --hidden auto` is an experimental opt-in in which a bare `*` skips
  hidden files as your shell does; it has known gaps, listed in the README.
- File names are escaped in all output, and a Cursor database with a non-empty `-wal` file is
  reported as not fully scanned.
- CI pins actions to commit SHAs and runs on Linux, macOS and Windows, and on Python 3.9.
