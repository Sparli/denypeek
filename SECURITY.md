# Security policy

keyhush is a security tool, so please report problems with it privately.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository (Security tab, "Report a
vulnerability"). Please do not open a public issue for a vulnerability. Never include a real key in
a report: describe its shape instead.

We aim to reply within 7 days.

## In scope

- A way to make the guard allow a read, edit or shell use of a file on the pattern list.
- The guard hanging, or allowing a call when it hits an error (it should fail closed).
- `redact` or `undo` writing outside the agent history folders, or losing data.
- A full secret reaching output, JSON, logs, error messages or temporary files.
- Backups readable by other users.
- `guard install` or `uninstall` damaging or dropping other settings in an agent's config.

## Known limits (not vulnerabilities)

The README's "Limits" section lists what keyhush does not claim to stop, for example scripts that
open files themselves, MCP tools, and secrets with no known shape.
