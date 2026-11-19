"""Measure the tree rule's walk (SPEC 3b T7): entries per second, names only.

    uv run python tools/measure_walk.py [--entries 50000] [--runs 5]

Builds a project in a temp folder (nested folders of small files, like node_modules), then
times the guard's own walk over it as any recursive search is walked (every entry visited), with the
default pattern list. The first run after building is closer to a cold cache than the rest,
but not cold: the files were just written. A truly cold cache needs the OS cache dropped
(`sudo purge` on macOS, `echo 3 > /proc/sys/vm/drop_caches` on Linux), which this script
does not do. Writes nothing outside the temp folder.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from denypeek.guard import guard as g  # noqa: E402


def build(root: Path, entries: int) -> int:
    """Folders of 20 files each, three levels deep, until `entries` names exist."""
    made = 0
    i = 0
    while made < entries:
        d = root / "node_modules" / f"pkg{i // 100}" / f"lib{i % 100}"
        d.mkdir(parents=True, exist_ok=True)
        made += 1
        for j in range(20):
            (d / f"file{j}.js").write_bytes(b"x")
            made += 1
        i += 1
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "app.py").write_text("x\n")
    return made


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--entries", type=int, default=50_000)
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "home"
        home.mkdir()
        g._home[0] = str(home)
        proj = Path(tmp) / "proj"
        proj.mkdir()
        made = build(proj, args.entries)
        rules = g.parse_patterns(g.DEFAULT_PATTERNS)
        g.WALK_LIMIT = 10**9
        times = []
        for _ in range(args.runs):
            search = g.Search(str(proj))
            t = time.perf_counter()
            reason = g.search_tree(search, rules, time.monotonic() + 600)
            times.append(time.perf_counter() - t)
            assert reason is None, reason
        print(f"{sys.platform}, Python {sys.version.split()[0]}, {os.cpu_count()} CPUs")
        print(f"tree: {made} entries")
        first = made / times[0]
        print(f"first run (just written, not cold): {times[0]:.3f} s, {first:,.0f} entries/s")
        best = min(times[1:] or times)
        print(f"warm, best of {len(times) - 1}: {best:.3f} s, {made / best:,.0f} entries/s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
