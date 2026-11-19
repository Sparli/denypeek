"""Offline secret scan of agent history. Never stores or prints a full secret."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
from bisect import bisect_left
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
    stopped: Optional[str] = None  # set when the scan was stopped (Ctrl-C) before the end

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
                "starts": _start_finder(r["regex"]),
            }
        )
    return out


# --- exact fast matching on long text --------------------------------------------------
#
# Some gitleaks rules cost time proportional to the text length at every position they try:
# the "generic" shape `[\w.-]{0,50}?(?:keyword)...` (up to 2,500 prefix choices per position
# on base64) and the curl rules (`\bcurl\b.*?...`, which run to the end of the line from every
# `curl`). On a JSONL record of several MB that is minutes. `_finditer` gives exactly what
# `rule.finditer(text)` gives, but tries the rule only at positions where a match can start,
# found by a necessary condition, and each try is the rule's own regex on the full text.

FAST_MIN = 4096  # shorter texts use plain finditer (both give the same matches)
_CLASS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
_PREFIX_SHAPES = (  # (regex prefix, longest [\w.-] run it allows before the keyword group)
    (r"[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:", 100),
    (r"(?i)[\w.-]{0,50}?(?:", 50),
)
_CURL_FILLERS = (r"(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})", r"(?:.*|.*(?:[\r\n]{1,2}.*){1,5})")


def _top_alternatives(x: str) -> list[str]:
    out, depth, i, in_class, start = [], 0, 0, False, 0
    while i < len(x):
        c = x[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            if x[i + 1 : i + 2] == "]":
                i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            out.append(x[start:i])
            start = i + 1
        i += 1
    out.append(x[start:])
    return out


def _group_end(x: str, i: int) -> int:
    """Index just past the group that opens at x[i] == '('."""
    depth, in_class = 0, False
    while i < len(x):
        c = x[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            if x[i + 1 : i + 2] == "]":
                i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unbalanced group")


def _start_finder(regex: str):
    """A function text -> next_start(pos), or None when the rule has no slow shape (plain
    finditer then). next_start(pos) is the smallest position >= pos where the rule may match:
    every real match start >= pos is >= it. None when there is none."""
    alts = _top_alternatives(regex)
    first = alts[0]
    for prefix, width in _PREFIX_SHAPES:
        if not first.startswith(prefix):
            continue
        # The match is 0..width [\w.-] characters, then `rest` (the keyword group onward).
        if prefix.startswith("(?i)"):
            rest = re.compile("(?i)" + first[len(prefix) - 3 :], re.ASCII)
        else:
            rest = re.compile("(?i:" + first[len(prefix) - 3 :], re.ASCII)
        head_src = first[len(prefix) - 3 :]
        head = re.compile(head_src[: _group_end(head_src, 0)], re.ASCII | re.I)
        flags = re.ASCII | (re.I if regex.startswith("(?i)") else 0)
        others = [re.compile(a, flags) for a in alts[1:]]
        return lambda text: _prefix_next(text, head, rest, width, others)
    if len(alts) == 1 and regex.startswith(r"\bcurl\b"):
        for filler in _CURL_FILLERS:
            if regex.startswith(r"\bcurl\b" + filler):
                tail = re.compile(regex[len(r"\bcurl\b" + filler) :], re.ASCII)
                return lambda text: _curl_next(text, tail)
    return None


def _prefix_next(text: str, head, rest, width: int, others):
    r"""A match starting at s has `rest` matching at some h in [s, s + width] with only [\w.-]
    characters between: so the leftmost start >= pos comes from the first h >= pos where
    `rest` matches, at max(pos, h - (the [\w.-] run before h, at most width))."""
    heads = _all_starts(head, text)
    extra = sorted({s for rx in others for s in _all_starts(rx, text)})
    state = {"i": 0}

    def next_start(pos: int) -> Optional[int]:
        i = state["i"]
        while i < len(heads) and heads[i] < pos:
            i += 1
        found = None
        while i < len(heads):
            h = heads[i]
            if rest.match(text, h):
                s = h
                while s > pos and h - s < width and text[s - 1] in _CLASS:
                    s -= 1
                found = s
                break
            i += 1
        state["i"] = i
        j = bisect_left(extra, pos)
        if j < len(extra) and (found is None or extra[j] < found):
            return extra[j]
        return found

    return next_start


def _curl_next(text: str, tail):
    """A match is `curl` as a word, any filler, then the rule's tail (`-H "Authorization: ..."`,
    `-u user:pass`): so it starts at a `curl` before the last place the tail matches."""
    tails = _all_starts(tail, text)
    starts = _all_starts(_CURL_WORD, text, tails[-1]) if tails else []

    def next_start(pos: int) -> Optional[int]:
        j = bisect_left(starts, pos)
        return starts[j] if j < len(starts) else None

    return next_start


_CURL_WORD = re.compile(r"\bcurl\b", re.ASCII)


def _all_starts(rx, text: str, endpos: Optional[int] = None) -> list[int]:
    """Every position where rx matches, overlapping ones too. A plain search per hit is much
    faster than a (?=...) scan, which loses re's fast skip to the first character."""
    out, pos, end = [], 0, len(text) if endpos is None else endpos
    while True:
        m = rx.search(text, pos, end)
        if m is None:
            return out
        out.append(m.start())
        pos = m.start() + 1


def _finditer(rule: dict, text: str):
    """Exactly the matches of rule["re"].finditer(text), faster on long text: the rule's own
    regex is tried, on the full text, only from places where a match can start."""
    rx, finder = rule["re"], rule["starts"]
    if finder is None or len(text) < FAST_MIN:
        yield from rx.finditer(text)
        return
    next_start = finder(text)
    pos = 0
    while True:
        s = next_start(pos)
        if s is None:
            return
        m = rx.match(text, s)
        if m is None:
            pos = s + 1
            continue
        if m.end() == m.start():  # never for these rules; keep finditer's exact semantics
            yield from rx.finditer(text, s)
            return
        yield m
        pos = m.end()


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
        for m in _finditer(rule, text):
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


PARALLEL_MIN_BYTES = 8_000_000  # below this, one process is fast enough


def _ignore_sigint() -> None:  # pragma: no cover - runs in worker processes
    import signal

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _scan_one(job):
    """Scan one file (in a worker process, or in this one). Returns what the caller needs to
    build Findings and Problems, in the file's own order."""
    index, src = job
    part = ScanResult()
    hits: list = []
    if src.kind == "sqlite":
        items = scan_sqlite(src.path, part)
    else:
        try:
            data = src.path.read_bytes()
        except OSError as exc:
            part.incomplete.append(Problem(src.path, "", f"cannot read: {exc.strerror or exc}"))
            return index, hits, part.incomplete, part.notes
        items = scan_text_lines(data, src.path, src.kind, part)
    for where, hit in items:
        hits.append((where, hit.rule, hit.secret))
    return index, hits, part.incomplete, part.notes


def _size(path: Path) -> int:
    try:
        return os.stat(path).st_size
    except OSError:
        return 0


def scan(
    home: Home,
    kinds: Optional[set[str]] = None,
    progress=None,
    workers: Optional[int] = None,
) -> ScanResult:
    """`progress(done_files, total_files, done_bytes, total_bytes, findings, agent)` is called
    once before the first file (done 0, agent None) and after each file. `workers`: worker
    processes; None picks one per CPU for large histories, 1 scans in this process. Ctrl-C
    stops the scan: the result keeps what was found so far and is marked incomplete."""
    result = ScanResult()
    errors: list = []
    sources = all_sources(home, errors)
    for p, reason in errors:
        result.incomplete.append(Problem(p, "", reason))
    allowed_roots = home.history_roots() + [home.cursor_dot_dir, *home.cursor_app_dirs]
    todo: list[Source] = []
    for src in sources:
        if kinds and src.kind not in kinds:
            continue
        if src.path.is_symlink() and not inside(src.path, allowed_roots):
            result.notes.append(
                Problem(src.path, "", "symlink to outside the history folders; skipped")
            )
            continue
        todo.append(src)
    sizes = [_size(src.path) for src in todo]
    total = sum(sizes)
    if workers is None:
        workers = 1 if total < PARALLEL_MIN_BYTES else min(os.cpu_count() or 1, 16)
    workers = max(1, min(workers, len(todo)))
    if progress:
        progress(0, len(todo), 0, total, 0, None)

    done: dict = {}  # index -> (hits, incomplete, notes)
    done_bytes = 0
    n_hits = 0

    def record(out) -> None:
        nonlocal done_bytes, n_hits
        index, hits, incomplete, notes = out
        done[index] = (hits, incomplete, notes)
        done_bytes += sizes[index]
        n_hits += len(hits)
        if progress:
            progress(len(done), len(todo), done_bytes, total, n_hits, todo[index].agent)

    # Largest files first, so one big file does not finish last on its own.
    jobs = sorted(enumerate(todo), key=lambda j: -sizes[j[0]])
    pool = None
    try:
        if workers == 1:
            for job in sorted(jobs):
                record(_scan_one(job))
        else:
            import multiprocessing

            pool = multiprocessing.get_context("spawn").Pool(workers, _ignore_sigint)
            for out in pool.imap_unordered(_scan_one, jobs, chunksize=1):
                record(out)
            pool.close()
    except KeyboardInterrupt:
        result.stopped = (
            f"stopped (Ctrl-C) after {len(done)} of {len(todo)} files, "
            f"{done_bytes / 1e6:.0f} of {total / 1e6:.0f} MB; the rest was not scanned"
        )
    finally:
        if pool is not None:
            if result.stopped:
                pool.terminate()
            pool.join()

    key = None
    for index, src in enumerate(todo):
        if index not in done:
            continue
        hits, incomplete, notes = done[index]
        result.files.append(src)
        result.incomplete += incomplete
        result.notes += notes
        for where, rule, secret in hits:
            if key is None:
                key = salt(home)
            result.findings.append(
                Finding(
                    agent=src.agent,
                    path=src.path,
                    line=where,
                    rule=rule,
                    preview=preview(rule, secret),
                    length=len(secret),
                    fingerprint=fingerprint(secret, key),
                )
            )
    if result.stopped:
        result.incomplete.append(Problem(home.root, "", f"scan {result.stopped}"))
    return result
