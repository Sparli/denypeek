# 02: Scan and redact

## Scan
- Offline, read-only. Sources per agent live in `src/keyhush/sources/`, each path a named constant
  with its source in a comment. `--home DIR` replaces the home folder and ignores
  `CLAUDE_CONFIG_DIR` and `CODEX_HOME`, so a fixture home cannot reach the real one.
- JSONL is split on `\n` only (U+2028 inside a JSON string is valid and does not end a line).
  JSON files are read whole. Cursor's SQLite is opened `mode=ro&immutable=1`, reading only known
  tables with fixed SQL.
- Output shows rule, file, line, first four characters, length and an 8-character HMAC fingerprint
  keyed by a random per-machine salt. Never the full secret.
- **No silent skips:** every unreadable file or line is listed and makes the exit code 2.
  Exit 0 means nothing found, 1 means findings.

## Redact
- JSONL and JSON only. Cursor's database is never written.
- Each secret becomes `[REDACTED:<rule>:<fingerprint>]`. A changed line must still parse as JSON.
- Safety order per file: skip checks (outside history roots, hard links, changed in the last
  10 minutes), compute the new content, back up, confirm the file has not changed, write a temp
  file, fsync, rename.
- Backups go to `~/.keyhush/backups/<time>-<id>/`, created 0700 and 0600, with a manifest of
  hashes before and after.
- A rescan of every changed file proves the result.

## Undo
Restores only files whose current hash equals the "after" hash, from a backup whose hash equals
the "before" hash, and only inside the history roots.

## Out of scope (v0.1)
Redacting Cursor, live-key checks (they send keys to third parties), secrets with no known shape.
