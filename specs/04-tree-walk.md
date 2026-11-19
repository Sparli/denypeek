# 04: The tree walk's limits (spec 3b, T7 and A29)

## What is measured
`tools/measure_walk.py` builds a project of small files under `node_modules` in a temp folder and
times the guard's own walk over it: every entry visited, as for any recursive search, with the
default pattern list. The walk looks at names only; a name gets the full path check only when
it can match a pattern, or when it is a symbolic link.

The first run after building is close to, but not, a cold cache: the files were just written.
A truly cold cache needs the OS cache dropped (`sudo purge` on macOS), which needs a password, so
cold numbers are not measured here.

## Results

| System | Python | Tree | First run | Warm (best) |
|---|---|---|---|---|
| macOS (Apple silicon, 11 CPUs, other work running) | 3.9.6 | 50,001 entries | 0.165 s, 304,000/s | 0.148 s, 337,000/s |
| macOS (same) | 3.9.6 | 100,002 entries | 0.346 s, 289,000/s | 0.299 s, 334,000/s |
| Linux CI | | | to be read from the `Walk speed` step of the `oracle` job | |
| macOS CI | | | to be read from the `Walk speed` step of the `oracle` job | |

The walk sorts each folder's entries and keeps relative paths, so a deny message can name the
first secret files and the clear folders in a fixed order; without that it ran at about 500,000
entries a second. A first version with one regex per pattern instead of one combined regex
managed about 125,000.

## Proposed limits (for approval)
- `WALK_LIMIT = 100,000` entries. A29 asks that a tree of 50,000 visited entries be decided on
  both CI systems. On this Mac 100,000 entries take about 0.3 s warm.
- `WALK_SECONDS = 1.0`, inside `HOOK_SECONDS` (2.5). That leaves about three times the Mac's warm
  time for a slower CI runner or a cold cache at the cap.

`WORD_WALK_LIMIT` (G6, 20,000 entries for one shell word's pattern) is a different limit and is
unchanged.
