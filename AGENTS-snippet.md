<!-- Paste this block into your project's AGENTS.md (or CLAUDE.md / GEMINI.md). -->

## Secrets and keyhush

- Do not read, print or copy secret files such as `.env`, `.env.*` (except `.env.example`),
  `.dev.vars`, `*.pem` or anything under `~/.ssh`. If the keyhush guard blocks a read, stop and
  tell me; do not work around it.
- To check for leaked keys, run `keyhush scan --json` (read-only) and `keyhush guard status`.
- Never run `keyhush redact`, `undo`, `backups purge`, `guard install` or `guard uninstall` without
  my explicit yes.
