# keyhush

**Keep API keys out of your coding agents.**

keyhush is one small tool for people who use Claude Code, Codex CLI, Cursor or Gemini CLI.

- **Block.** It stops agents reading secret files such as `.env`, `.dev.vars`, `*.pem` and
  `~/.ssh/*`. That covers the agent's file tools, shell commands that name the file, and
  recursive `grep` over a folder that holds one. One pattern list covers all four agents.
- **Find.** It scans the agents' local history for API keys that already leaked into it.
- **Scrub.** It replaces those keys with a marker, keeps a backup, and rescans to prove the
  scrub worked.

It runs offline, has no dependencies, and never prints a full secret.

> **Status: v0.1.0, not released yet.** It is tested on fixtures, not yet on live installs of
> each agent: **Claude Code, Codex CLI, Cursor and Gemini CLI are all "not live-tested" so far.**
> Detection is best effort: a clean scan is not proof that a machine is clean.

## Quick start (about 5 minutes)

You need Python 3.9 or newer and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
git clone <repository address> keyhush && cd keyhush
```

```bash
uv run keyhush scan
```

That is a read-only scan of your agent history. Exit code 0 means nothing found, 1 means
findings, 2 means something could not be read.

To block secret-file reads in your agents, then prove it works:

```bash
uv run keyhush guard install
```

```bash
uv run keyhush guard test
```

Once keyhush is on PyPI, `uvx keyhush scan` will work without cloning.
Until then: `uvx --from git+<repository address> keyhush scan`.

## Why

People asked for this, repeatedly:

- A hard block on secret-file reads that also covers shell, grep and edits, on every agent:
  Codex [#2847](https://github.com/openai/codex/issues/2847),
  Claude Code [#44868](https://github.com/anthropics/claude-code/issues/44868)
  (a user's own hook missed `grep` and `.dev.vars`), and Cursor's
  [forum](https://forum.cursor.com/t/dot-env-files-are-being-read-by-the-agent/153166)
  after its default ignores were removed.
- One ignore list across agents: Gemini CLI
  [#4688](https://github.com/google-gemini/gemini-cli/issues/4688).

Existing tools already scan and redact agent history well:
[AgentSweep](https://github.com/Ishannaik/agent-sweep),
[ranwhat](https://github.com/MatijaMiki/ranwhat) and
[Maskara](https://github.com/mrgoonie/maskara). keyhush does not claim scanning or redaction as
new. What it adds is the cross-agent **guard** with a built-in `guard test`, and a scan that lists
every file or line it could not read instead of skipping it silently.

## Commands

| Command | What it does |
|---|---|
| `keyhush scan [--json]` | Read-only scan of agent history. Shows rule, file, line, first four characters, length and a fingerprint. |
| `keyhush redact [--yes] [--include-active]` | Replaces each found key with `[REDACTED:<rule>:<fingerprint>]` in JSONL and JSON history, after a backup. Then rescans. |
| `keyhush undo [--set NAME]` | Restores the files changed by the last redact, byte for byte. |
| `keyhush backups list` / `purge --yes` | Lists or deletes redact backups. They still hold the keys. |
| `keyhush guard install [--agent NAME]` | Wires the guard into each agent's own pre-tool hook. |
| `keyhush guard status [--json]` | Shows where it is installed. Exit 0 only if all asked-for agents are covered. |
| `keyhush guard test` | Feeds each agent's real hook input format to the installed hook and prints blocked or allowed, per agent and case. |
| `keyhush guard uninstall [--agent NAME]` | Removes only keyhush's entries. |

Every command takes `--home DIR` to work on another home folder (used for testing).

## The guard

`guard install` copies one standard-library script to `~/.keyhush/guard.py`, writes a default
pattern list to `~/.keyhush/secretfiles` if there is none, and adds a hook entry to each agent.
Before each edit it backs the file up to `~/.keyhush/config-backups/`. It merges without touching
your other settings, writes atomically, and can run twice without duplicates.

| Agent | File it edits | Hook | Notes |
|---|---|---|---|
| Claude Code | `~/.claude/settings.json` | `PreToolUse` for `Read\|Edit\|Write\|Grep\|Glob\|Bash\|PowerShell`, plus `permissions.deny` `Read(...)` rules | Deny rules also cover `@` mentions, which skip hooks. [Hooks](https://code.claude.com/docs/en/hooks), [permissions](https://code.claude.com/docs/en/permissions) |
| Codex CLI | `~/.codex/hooks.json` | `PreToolUse` for `Bash\|apply_patch` | **Run `/hooks` in Codex and trust the hook. Codex skips it until you do.** Hooks are on by default; if you turned them off, set `[features] hooks = true` in `~/.codex/config.toml`. [Docs](https://learn.chatgpt.com/docs/hooks) |
| Cursor | `~/.cursor/hooks.json` | `beforeReadFile`, `beforeShellExecution`, and `preToolUse` for `Read\|Write\|Grep\|Delete\|Shell`, all with `failClosed: true` | [Docs](https://cursor.com/docs/hooks) |
| Gemini CLI | `~/.gemini/settings.json` | `BeforeTool` for its file, search and shell tools | [Docs](https://geminicli.com/docs/hooks/reference/) |

The hook denies:

- reading, editing or writing a path that matches the pattern list;
- a shell command that names such a path, after undoing quotes, `~`, `$HOME`, `$IFS`, globs,
  redirections and nested `bash -c` or `eval` scripts;
- a recursive `grep`, `rg`, `ag`, `ack` or `git grep`, or the agent's own search tool, over a
  folder that holds a secret file.

When it allows a call it says nothing (Cursor gets an explicit `allow`, because Cursor blocks on
empty output). So your agent's own permission prompts still apply. On any error of its own
(empty, broken or huge input) it **blocks**, and the message names `keyhush guard uninstall`.

### The pattern list

`~/.keyhush/secretfiles` uses gitignore-style lines. Case does not matter. A name with no slash
matches at any depth, `~/` means your home folder, and `!` allows a path again. The defaults
include `.env`, `.env.*` (but not `.env.example`, `.env.sample` or `.env.template`),
`.dev.vars`, `*.pem`, `*.key`, `id_rsa*` and other SSH keys (not `*.pub`), `.netrc`, `.npmrc`,
`.pypirc`, `credentials.json`, `~/.aws/credentials`, `~/.ssh/**`, `~/.docker/config.json`,
`~/.kube/config` and `~/.config/gcloud/**`. Edit the file, then run `keyhush guard test`.

## Scan

`scan` reads:

| Agent | Where | Format | Source |
|---|---|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` (or `$CLAUDE_CONFIG_DIR`) | JSONL | [Official docs](https://code.claude.com/docs/en/claude-directory) |
| Claude Code | `~/.claude/history.jsonl` | JSONL | **[unverified]** community sources |
| Codex CLI | `~/.codex/sessions/**`, `archived_sessions/`, `history.jsonl` (or `$CODEX_HOME`) | JSONL | **[unverified]** community sources |
| Gemini CLI | `~/.gemini/tmp/*/chats/*`, `logs.json` | JSONL, JSON | **[unverified]** community sources |
| Cursor | `state.vscdb` under Cursor's app folder (macOS, Linux, Windows), `~/.cursor/chats/**/store.db` | SQLite, read-only | **[unverified]** community sources |

It reads Cursor's database in immutable read-only mode: no locks, no journal, and it never
touches the `-wal` file. Every file or line it could not read (broken JSON, bad UTF-8, no
permission) is listed, and the exit code is 2. A line holding a U+2028 character is read as one
line, not split, and noted.

Fingerprints are a keyed hash with a random per-machine salt in `~/.keyhush/salt`, so a short key
cannot be worked back from its fingerprint.

### Detection rules

The rules come from [gitleaks](https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml)
v8.30.1 (MIT), converted to Python by `tools/gen_rules.py`, with gitleaks' keywords, entropy
thresholds and allowlists kept. 217 of its 222 rules are used. 26 were rewritten from Go-only
regex syntax.

These 5 rules are not used, because they match on the file's name or type, which does not apply to
agent history:

- `pkcs12-file` (matches file names only)
- `freemius-secret-key`, `hashicorp-tf-password`, `kubernetes-secret-yaml`,
  `nuget-config-password` (only apply to certain file types)

Very long history lines with many key-like words scan slowly (several seconds per megabyte in the
worst case).

## Redact, undo and backups

`redact` works on JSONL and JSON history only, never on Cursor's database.

- It asks first (or takes `--yes`) and never runs without confirmation in a non-interactive shell.
- It backs up each file to `~/.keyhush/backups/<time>-<id>/`. Those folders and files are created
  owner-only (0700 and 0600), not beside the original.
- It writes to a temporary file and renames it over the original, so a crash leaves the original
  intact. If the file changed while keyhush worked (an agent writing to it), that file is skipped.
- It skips files changed in the last 10 minutes unless you pass `--include-active`. It also skips
  symlinks that lead outside the history folders and files with other hard links.
- Untouched lines stay byte-identical. A changed line must still be valid JSON, or it is left
  alone and listed.
- It rescans the changed files and says whether anything is left.
- It lists the keys to rotate.

**The backups still hold the keys.** Check your history, then run `keyhush backups purge --yes`.

## Limits: what keyhush cannot do

- **The guard is a heuristic.** It cannot stop a script that opens a file itself
  (`python -c "open('.env')"`), MCP tools, or a user who approves a read the hook did not see. The
  shell check will miss some tricks.
- **Cursor:** Cursor's own docs say terminal and MCP protection is not guaranteed.
- **Codex:** the hook does nothing until you trust it with `/hooks`. Codex lets a tool run if a
  hook errors or times out; keyhush always answers to avoid that.
- **Grep:** the guard blocks a search over any folder that holds a secret file, including the
  agent's own search tool over your whole project. Narrow the path (for example `src/`) to search.
- Hook inputs over 4 MB are blocked rather than checked.
- **Paths:** history locations for Codex, Gemini CLI, Cursor and Claude's `history.jsonl` come
  from community sources, not vendor docs. Windows paths are unverified. Windows is tested on
  fixtures in CI only.
- Secrets with no known shape, and secrets split across messages, are not found.
- **Redaction changes your history files**, and the backups hold the secrets until you purge them.
- **A found key must be rotated**, whether or not you redact it. It may already have been sent to
  the agent's provider.
- Best-effort detection: a clean result is not proof that a machine is clean.

## Use from an agent

`skills/keyhush/SKILL.md` is a skill file for Claude Code, Codex, Cursor and Gemini CLI.
`AGENTS-snippet.md` is a block to paste into `AGENTS.md`. Both tell the agent to run
`keyhush scan --json` and `keyhush guard status`, and never `keyhush redact` without your yes.

## Privacy

keyhush has no network code and no dependencies. Nothing leaves your machine. Output shows only
the first four characters of a key, its length and a fingerprint.

## Development

```bash
uv sync
```

```bash
uv run pytest
```

```bash
uv run ruff check .
```

Tests build fixture homes in a temp folder, assemble fake keys at run time, disable the network,
and fail if anything touches your real home folder. `python tools/gen_rules.py --check` confirms
`rules.py` matches the pinned gitleaks file.

## Licence

MIT. The licence file will be added before the first release. Third-party notices are in
[THIRD_PARTY.md](THIRD_PARTY.md). Security reports: see [SECURITY.md](SECURITY.md).
