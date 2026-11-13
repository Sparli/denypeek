---
name: keyhush
description: Check whether API keys have leaked into coding-agent history and whether the keyhush guard is blocking secret-file reads. Use when the user asks about leaked keys, secrets in agent logs or transcripts, or protecting .env files from agents.
---

# keyhush

keyhush is a local, offline command-line tool. It finds API keys in the history of Claude Code,
Codex CLI, Cursor and Gemini CLI, and blocks agents from reading secret files such as `.env`.

## What you may run

- `keyhush scan --json` to look for leaked keys. It is read-only. Exit code 0 means nothing found,
  1 means findings, 2 means some files could not be read. The output never holds a full key.
- `keyhush guard status --json` to see which agents are protected.
- `keyhush guard test` to prove the guard blocks secret files.

## What you must not do

- **Never run `keyhush redact`, `keyhush undo`, `keyhush backups purge`, `keyhush guard install` or
  `keyhush guard uninstall` without the user's explicit yes for that command.** They change files.
- Never try to read, print or work around a file the guard blocks. Tell the user instead.
- Never ask the user to paste a key.

## How to report

Summarise the findings by agent, file and rule. Remind the user that a found key must be rotated
at its provider even if it is redacted, and that a clean scan is not proof the machine is clean.
