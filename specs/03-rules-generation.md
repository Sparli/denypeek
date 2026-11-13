# 03: Rules generation

## Source
gitleaks `config/gitleaks.toml` at tag v8.30.1 (MIT, 222 rules), stored unmodified at
`tools/pinned/gitleaks.toml` and checked against its SHA-256 before use.

## Conversion (`tools/gen_rules.py`)
- Mid-pattern `(?i)` becomes a scoped `(?i:...)` over the rest of its group, one per alternative,
  so alternation is unchanged.
- POSIX classes such as `[[:alnum:]]` become explicit ranges; `\z` becomes `\Z`.
- Patterns compile with `re.ASCII`, matching Go's ASCII `\w`, `\d`, `\s` and `\b`.
- Keywords, entropy thresholds and allowlists are kept. Allowlists that need a source-path match
  are dropped, because history files never match those paths.
- Literal example keys in allowlists are stored as SHA-256 hashes, so no key-shaped literal is
  committed.
- Result: 217 rules used, 26 converted, 5 left out (path-based), listed in the README.

## Checks
`python tools/gen_rules.py --check` and a test both fail if `rules.py` differs from what the
pinned file produces. Every rule must compile on the supported Python versions.

## Why not the gitleaks binary or trufflehog
The binary would be a second install. trufflehog is AGPL and its live-key checks send keys to
third parties.
