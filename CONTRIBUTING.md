# Contributing

Thanks for helping. denypeek handles secrets, so a few rules matter more than usual.

## Rules
- **No real keys anywhere**: not in code, tests, fixtures, issues or screenshots. Tests assemble fake
  keys at run time from random characters.
- **Never point denypeek at your real home while developing.** Use `--home <temp folder>`. The test
  suite fails if anything touches your real home.
- **No run-time dependencies and no network code.** The package must stay standard-library only.
- Diagrams in `diagrams/` must match the code. If you change a flow, change its `.mmd` file and
  the README block in the same commit (a test checks they match).

## Set up and check
```bash
uv sync
uv run pytest
uv run ruff check .
python tools/gen_rules.py --check
```

## Changing the rules
Do not edit `src/denypeek/rules.py`. Change `tools/gen_rules.py` (or the pinned file, with its new
hash) and regenerate with `python tools/gen_rules.py`.

## Commits and pull requests
Small commits with Conventional Commit messages (`feat:`, `fix:`, `docs:`, `test:`). One pull
request per change, with tests. Describe how you tested it.

## Security issues
Please do not open a public issue. See [SECURITY.md](SECURITY.md).
