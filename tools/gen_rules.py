"""Generate src/keyhush/rules.py from the pinned gitleaks rule file.

    python tools/gen_rules.py           # write rules.py
    python tools/gen_rules.py --check   # exit 1 if rules.py is out of date

Source: gitleaks config/gitleaks.toml at tag v8.30.1 (MIT licence, see THIRD_PARTY.md),
fetched from https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml
and stored at tools/pinned/gitleaks.toml. Needs Python 3.11+ (tomllib). No network.

Go (RE2) to Python conversion:
- `(?i)` in the middle of a pattern becomes a scoped `(?i:...)` over the rest of its group,
  one per alternative, so alternation is unchanged.
- POSIX classes such as `[[:alnum:]]` become explicit ranges.
- `\\z` becomes `\\Z`.
- Patterns are compiled with re.ASCII, because Go's `\\w`, `\\d`, `\\s` and `\\b` are ASCII.
Literal allowlist entries that look like keys (gcp-api-key examples) are stored as SHA-256
hashes, so no key-shaped literal is committed in this repo.
"""

from __future__ import annotations

import hashlib
import pprint
import re
import sys
import warnings
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools" / "pinned" / "gitleaks.toml"
TARGET = ROOT / "src" / "keyhush" / "rules.py"
PINNED_TAG = "v8.30.1"
PINNED_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"

POSIX = {
    "[:alnum:]": "a-zA-Z0-9",
    "[:alpha:]": "a-zA-Z",
    "[:digit:]": "0-9",
    "[:lower:]": "a-z",
    "[:upper:]": "A-Z",
    "[:xdigit:]": "0-9A-Fa-f",
    "[:space:]": r" \t\r\n\v\f",
    "[:word:]": "a-zA-Z0-9_",
}
META = set("\\.^$*+?{}[]|()")


def _skip_class(rx: str, i: int) -> int:
    """i points at '['. Return the index just after the matching ']'."""
    j = i + 1
    if j < len(rx) and rx[j] == "^":
        j += 1
    if j < len(rx) and rx[j] == "]":
        j += 1
    while j < len(rx):
        if rx[j] == "\\":
            j += 2
            continue
        if rx.startswith("[:", j):
            end = rx.find(":]", j + 2)
            if end != -1:
                j = end + 2
                continue
        if rx[j] == "]":
            return j + 1
        j += 1
    raise ValueError("unterminated character class")


def _group_end(rx: str, start: int) -> int:
    """Index of the ')' closing the group that contains `start`, or len(rx)."""
    depth, i = 0, start
    while i < len(rx):
        c = rx[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _skip_class(rx, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            if depth == 0:
                return i
            depth -= 1
        i += 1
    return len(rx)


def _split_alternatives(segment: str) -> list[str]:
    parts, depth, i, last = [], 0, 0, 0
    while i < len(segment):
        c = segment[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _skip_class(segment, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            parts.append(segment[last:i])
            last = i + 1
        i += 1
    parts.append(segment[last:])
    return parts


def _find_inline_flag(rx: str, begin: int) -> int:
    """Index of the next `(?i)` at or after `begin` that is not inside a class or escape."""
    i = begin
    while i < len(rx):
        c = rx[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _skip_class(rx, i)
            continue
        if rx.startswith("(?i)", i):
            return i
        i += 1
    return -1


def convert(rx: str) -> str:
    for posix, repl in POSIX.items():
        rx = rx.replace(posix, repl)
    rx = rx.replace(r"\z", r"\Z")
    search_from = 1  # a leading (?i) is already valid Python
    while True:
        p = _find_inline_flag(rx, search_from)
        if p == -1:
            return rx
        end = _group_end(rx, p + 4)
        segment = rx[p + 4 : end]
        scoped = "|".join(f"(?i:{alt})" for alt in _split_alternatives(segment))
        rx = rx[:p] + scoped + rx[end:]
        search_from = p + 1


def compile_ok(rx: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        re.compile(rx, re.ASCII)


def _is_literal_key(rx: str) -> bool:
    return len(rx) >= 20 and not (set(rx) & META)


def _allowlist(raw: dict) -> dict | None:
    """Return a normalised allowlist, or None if it can never apply to history files."""
    if raw.get("condition") == "AND" and raw.get("paths"):
        return None  # needs a source-path match; history files never match these paths
    if raw.get("paths") and not raw.get("regexes") and not raw.get("stopwords"):
        return None
    regexes, hashes = [], []
    for rx in raw.get("regexes", []):
        if _is_literal_key(rx):
            hashes.append(hashlib.sha256(rx.encode()).hexdigest())
        else:
            conv = convert(rx)
            compile_ok(conv)
            regexes.append(conv)
    return {
        "target": raw.get("regexTarget", "secret"),
        "regexes": regexes,
        "hashes": sorted(hashes),
        "stopwords": [s.lower() for s in raw.get("stopwords", [])],
    }


def build() -> str:
    data = SOURCE.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != PINNED_SHA256:
        raise SystemExit(f"{SOURCE} does not match the pinned gitleaks {PINNED_TAG} file.")
    cfg = tomllib.loads(data.decode())

    rules, unconverted, converted_ids = [], [], []
    for r in cfg["rules"]:
        rid = r["id"]
        if "regex" not in r:
            unconverted.append((rid, "path-only rule (matches file names, not content)"))
            continue
        if "path" in r:
            unconverted.append((rid, "only applies to certain file types (path rule)"))
            continue
        conv = convert(r["regex"])
        try:
            compile_ok(conv)
        except (re.error, Warning) as exc:
            unconverted.append((rid, f"does not compile in Python: {exc}"))
            continue
        if conv != r["regex"]:
            converted_ids.append(rid)
        allow = [a for a in (_allowlist(x) for x in r.get("allowlists", [])) if a]
        rules.append(
            {
                "id": rid,
                "regex": conv,
                "keywords": [k.lower() for k in r.get("keywords", [])],
                "entropy": r.get("entropy"),
                "secret_group": r.get("secretGroup", 0),
                "allowlists": allow,
            }
        )

    g = cfg["allowlist"]
    global_allow = {
        "target": "secret",
        "regexes": [],
        "hashes": [],
        "stopwords": [s.lower() for s in g.get("stopwords", [])],
    }
    for rx in g.get("regexes", []):
        conv = convert(rx)
        compile_ok(conv)
        global_allow["regexes"].append(conv)

    header = (
        '"""Secret detection rules. GENERATED by tools/gen_rules.py. Do not edit.\n\n'
        f"Source: gitleaks config/gitleaks.toml, tag {PINNED_TAG}, sha256 {digest}.\n"
        "Copyright (c) 2019 Zachary Rice, MIT licence. See THIRD_PARTY.md.\n"
        '"""\n\n'
        "# fmt: off\n"
        f"PINNED_TAG = {PINNED_TAG!r}\n"
        f"SOURCE_SHA256 = {digest!r}\n"
        f"SOURCE_RULE_COUNT = {len(cfg['rules'])}\n\n"
    )
    pp = pprint.PrettyPrinter(width=100, sort_dicts=True)
    body = (
        f"RULES = {pp.pformat(rules)}\n\n"
        f"GLOBAL_ALLOWLIST = {pp.pformat(global_allow)}\n\n"
        "# Rules rewritten from Go regex syntax to Python syntax.\n"
        f"CONVERTED = {pp.pformat(sorted(converted_ids))}\n\n"
        "# Rules not used, with the reason.\n"
        f"UNCONVERTED = {pp.pformat(unconverted)}\n"
    )
    return header + body


def main() -> int:
    text = build()
    if "--check" in sys.argv:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != text:
            print("rules.py is out of date: run python tools/gen_rules.py", file=sys.stderr)
            return 1
        print("rules.py matches the pinned gitleaks file.")
        return 0
    TARGET.write_text(text, encoding="utf-8")
    print(f"Wrote {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
