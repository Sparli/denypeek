"""Offline secret scan of agent history. Never stores or prints a full secret."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

from . import rules as R
from .fsutil import ensure_private_dir, write_new_private
from .sources import Home, Source, all_sources

LINE_SEPARATORS = (" ", " ")
# Cursor tables we read, with fixed SQL. Table names never come from the scanned file.
CURSOR_QUERIES = {
    "ItemTable": "SELECT rowid, value FROM ItemTable",
    "cursorDiskKV": "SELECT rowid, value FROM cursorDiskKV",
    "blobs": "SELECT rowid, data FROM blobs",
    "meta": "SELECT rowid, value FROM meta",
}


@dataclass(frozen=True)
class Hit:
    rule: str
    start: int  # span of the secret inside the scanned text
    end: int
    secret: str


@dataclass
class Finding:
    agent: str
    path: Path
    line: str  # line number, or "<table> row <n>" for SQLite
    rule: str
    preview: Optional[str]  # fixed public prefix only; None for rules without one
    length: int
    fingerprint: str


@dataclass
class Problem:
    path: Path
    where: str
    reason: str


@dataclass
class ScanResult:
    files: list[Source] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    incomplete: list[Problem] = field(default_factory=list)  # not fully checked
    notes: list[Problem] = field(default_factory=list)  # checked, but worth knowing

    @property
    def exit_code(self) -> int:
        if self.incomplete:
            return 2
        return 1 if self.findings else 0

    def per_agent(self) -> dict[str, int]:
        return dict(Counter(s.agent for s in self.files))


# --- detection -----------------------------------------------------------------------


@lru_cache(maxsize=1)
def compiled_rules() -> list[dict]:
    out = []
    for r in R.RULES:
        out.append(
            {
                **r,
                "re": re.compile(r["regex"], re.ASCII),
                "allow": [_compile_allow(a) for a in r["allowlists"]],
            }
        )
    return out


def _compile_allow(a: dict) -> dict:
    return {
        **a,
        "res": [re.compile(x, re.ASCII) for x in a["regexes"]],
        "hashset": set(a["hashes"]),
    }


@lru_cache(maxsize=1)
def _global_allow() -> dict:
    return _compile_allow(R.GLOBAL_ALLOWLIST)


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _allowed(a: dict, secret: str, match: str, line: str) -> bool:
    target = {"secret": secret, "match": match, "line": line}.get(a["target"], secret)
    if a["hashset"] and hashlib.sha256(secret.encode()).hexdigest() in a["hashset"]:
        return True
    if any(rx.search(target) for rx in a["res"]):
        return True
    low = secret.lower()
    return any(w in low for w in a["stopwords"])


def _line_at(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start : end if end != -1 else len(text)]


def find_secrets(text: str) -> list[Hit]:
    lower = text.lower()
    hits: list[Hit] = []
    for rule in compiled_rules():
        kws = rule["keywords"]
        if kws and not any(k in lower for k in kws):
            continue
        for m in rule["re"].finditer(text):
            group = rule["secret_group"]
            if not group and m.re.groups:
                group = next((i for i in range(1, m.re.groups + 1) if m.group(i)), 0)
            secret = m.group(group)
            if not secret:
                continue
            if rule["entropy"] and shannon(secret) < rule["entropy"]:
                continue
            line = _line_at(text, m.start())
            if _allowed(_global_allow(), secret, m.group(0), line):
                continue
            if any(_allowed(a, secret, m.group(0), line) for a in rule["allow"]):
                continue
            start, end = m.span(group)
            hits.append(Hit(rule["id"], start, end, secret))
    return _dedupe(hits)


def _dedupe(hits: list[Hit]) -> list[Hit]:
    """Keep one hit per span: the longest; drop hits inside an earlier kept one."""
    kept: list[Hit] = []
    for h in sorted(hits, key=lambda h: (h.start, -(h.end - h.start), h.rule)):
        if any(k.start <= h.start and h.end <= k.end for k in kept):
            continue
        kept = [k for k in kept if not (h.start <= k.start and k.end <= h.end)]
        kept.append(h)
    return sorted(kept, key=lambda h: h.start)


# --- fingerprints --------------------------------------------------------------------


def salt(home: Home) -> bytes:
    """Per-machine random salt, so a short key cannot be recovered from its fingerprint."""
    path = home.denypeek_dir / "salt"
    try:
        data = path.read_bytes()
        if len(data) >= 32:
            return data
    except FileNotFoundError:
        pass
    ensure_private_dir(home.denypeek_dir)
    data = os.urandom(32)
    try:
        write_new_private(path, data)
    except FileExistsError:
        return path.read_bytes()
    return data


def fingerprint(secret: str, key: bytes) -> str:
    return hmac.new(key, secret.encode(), hashlib.sha256).hexdigest()[:8]


@lru_cache(maxsize=1)
def _prefixes() -> dict[str, list[str]]:
    return {r["id"]: r["prefixes"] for r in R.RULES}


def preview(rule: str, secret: str) -> Optional[str]:
    """At most 4 characters of the rule's fixed public prefix (AKIA, ghp_, ...), or None.

    Rules with no fixed prefix (generic-api-key and other keyword rules) show nothing, and a
    preview never runs past the prefix into the secret itself (spec section 3).
    """
    matching = [p for p in _prefixes().get(rule, ()) if secret.startswith(p)]
    if not matching:
        return None
    return max(matching, key=len)[:4] + "…"


# --- readers -------------------------------------------------------------------------


def scan_text_lines(data: bytes, path: Path, kind: str, result: ScanResult):
    """Yield (line_label, text, hits) for a JSONL or JSON file, recording problems."""
    if kind == "json":
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            result.incomplete.append(Problem(path, "", "not valid UTF-8; scanned with replacement"))
            text = data.decode("utf-8", errors="replace")
        try:
            json.loads(text)
        except ValueError as exc:
            result.incomplete.append(
                Problem(path, "", f"broken JSON ({exc.msg}, line {exc.lineno})")
            )
        for sep in LINE_SEPARATORS:
            if sep in text:
                result.notes.append(
                    Problem(path, "", f"contains U+{ord(sep):04X}; read as one record")
                )
        for hit in find_secrets(text):
            yield str(text.count("\n", 0, hit.start) + 1), hit
        return

    for n, raw in enumerate(data.split(b"\n"), start=1):
        if not raw.strip():
            continue
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError:
            result.incomplete.append(
                Problem(path, str(n), "not valid UTF-8; scanned with replacement")
            )
            line = raw.decode("utf-8", errors="replace")
        try:
            json.loads(line)
        except ValueError as exc:
            result.incomplete.append(Problem(path, str(n), f"broken JSON line ({exc.msg})"))
        for sep in LINE_SEPARATORS:
            if sep in line:
                result.notes.append(
                    Problem(path, str(n), f"contains U+{ord(sep):04X}; read as one line, not split")
                )
        for hit in find_secrets(line):
            yield str(n), hit


def scan_sqlite(path: Path, result: ScanResult):
    """Read-only, immutable open: no locks, no journal, never touches the -wal file.

    immutable=1 also means SQLite ignores the write-ahead log, so recent changes still in
    `<db>-wal` are not read. That file is only checked with stat(), never opened: if it is not
    empty, the database is reported as not fully scanned (exit code 2), so a scan never reports
    less than it read without saying so.
    """
    wal = Path(str(path) + "-wal")
    try:
        wal_size = os.stat(wal).st_size
    except FileNotFoundError:
        wal_size = 0
    except OSError as exc:
        wal_size = -1
        result.incomplete.append(Problem(wal, "", f"cannot check this file: {exc.strerror or exc}"))
    if wal_size > 0:
        result.incomplete.append(
            Problem(
                wal,
                "",
                f"{wal_size} bytes not read: recent changes may be here and not yet in the main "
                "database. Close Cursor (it then folds them in) and scan again",
            )
        )
    uri = Path(path).absolute().as_uri() + "?mode=ro&immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        result.incomplete.append(Problem(path, "", f"cannot open database: {exc}"))
        return
    try:
        try:
            tables = {
                r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        except sqlite3.Error as exc:
            result.incomplete.append(Problem(path, "", f"cannot read database: {exc}"))
            return
        for table in sorted(tables - set(CURSOR_QUERIES)):
            result.notes.append(Problem(path, "", f"table {table!r} not scanned (unknown layout)"))
        for table, sql in CURSOR_QUERIES.items():
            if table not in tables:
                continue
            try:
                rows = conn.execute(sql)
                for rowid, value in rows:
                    if value is None:
                        continue
                    text = (
                        value.decode("utf-8", errors="replace")
                        if isinstance(value, bytes)
                        else str(value)
                    )
                    for hit in find_secrets(text):
                        yield f"{table} row {rowid}", hit
            except sqlite3.Error as exc:
                result.incomplete.append(Problem(path, table, f"cannot read table: {exc}"))
    finally:
        conn.close()


def inside(path: Path, roots: list[Path]) -> bool:
    real = Path(os.path.realpath(path))
    for root in roots:
        r = Path(os.path.realpath(root))
        if real == r or r in real.parents:
            return True
    return False


def scan(home: Home, kinds: Optional[set[str]] = None) -> ScanResult:
    result = ScanResult()
    errors: list = []
    sources = all_sources(home, errors)
    for p, reason in errors:
        result.incomplete.append(Problem(p, "", reason))
    allowed_roots = home.history_roots() + [home.cursor_dot_dir, *home.cursor_app_dirs]
    key = None
    for src in sources:
        if kinds and src.kind not in kinds:
            continue
        if src.path.is_symlink() and not inside(src.path, allowed_roots):
            result.notes.append(
                Problem(src.path, "", "symlink to outside the history folders; skipped")
            )
            continue
        result.files.append(src)
        if src.kind == "sqlite":
            items = scan_sqlite(src.path, result)
        else:
            try:
                data = src.path.read_bytes()
            except OSError as exc:
                result.incomplete.append(
                    Problem(src.path, "", f"cannot read: {exc.strerror or exc}")
                )
                continue
            items = scan_text_lines(data, src.path, src.kind, result)
        for where, hit in items:
            if key is None:
                key = salt(home)
            result.findings.append(
                Finding(
                    agent=src.agent,
                    path=src.path,
                    line=where,
                    rule=hit.rule,
                    preview=preview(hit.rule, hit.secret),
                    length=len(hit.secret),
                    fingerprint=fingerprint(hit.secret, key),
                )
            )
    return result
