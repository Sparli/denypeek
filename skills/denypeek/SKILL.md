---
name: denypeek
description: Check whether API keys have leaked into coding-agent history and whether the denypeek guard is blocking secret-file reads. Use when the user asks about leaked keys, secrets in agent logs or transcripts, or protecting .env files from agents.
---

# denypeek

denypeek is a local, offline command-line tool. It finds API keys in the history of Claude Code,
Codex CLI, Cursor and Gemini CLI, and blocks agents from reading secret files such as `.env`.

## What you may run

- `denypeek scan --json` to look for leaked keys. It is read-only. Exit code 0 means nothing found,
  1 means findings, 2 means some files could not be read. The output never holds a full key.
- `denypeek guard status --json` to see which agents are protected.
- `denypeek guard test` to prove the guard blocks secret files.

## What you must not do

- **Never run `denypeek redact`, `denypeek undo`, `denypeek backups purge`, `denypeek guard install` or
  `denypeek guard uninstall` without the user's explicit yes for that command.** They change files.
- Never try to read, print or work around a file the guard blocks. Tell the user instead.
- Never ask the user to paste a key.

## How to report

Summarise the findings by agent, file and rule. Remind the user that a found key must be rotated
at its provider even if it is redacted, and that a clean scan is not proof the machine is clean.
