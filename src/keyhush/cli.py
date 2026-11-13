"""keyhush command line. Standard library only."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import __version__, report
from .scan import scan
from .sources import Home, resolve_home

EPILOG = "Everything runs offline. Nothing leaves this machine."


def _home(args) -> Home:
    return resolve_home(args.home)


def _print_problems(home: Home, title: str, problems) -> None:
    if problems:
        print(f"\n{title} ({len(problems)}):")
        for p in problems:
            where = f":{p.where}" if p.where else ""
            print(f"  {home.display(p.path)}{where}: {p.reason}")


# --- scan -------------------------------------------------------------------------------


def cmd_scan(args) -> int:
    home = _home(args)
    result = scan(home)
    print(report.scan_json(result, home) if args.json else report.scan_text(result, home))
    return result.exit_code


# --- redact / undo / backups ------------------------------------------------------------


def _confirm(args, question: str) -> bool:
    if args.yes:
        return True
    if not sys.stdin.isatty():
        print("Refusing to change files without confirmation. Re-run with --yes.", file=sys.stderr)
        return False
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")


def cmd_redact(args) -> int:
    from .redact import redact

    home = _home(args)
    preview = scan(home, kinds={"jsonl", "json"})
    files = sorted({str(f.path) for f in preview.findings})
    if not files:
        print("No known key shapes found in JSONL or JSON history. Nothing to redact.")
        print(report.NOT_PROOF)
        return 2 if preview.incomplete else 0
    print(
        f"keyhush will redact {len(preview.findings)} possible secret(s) in {len(files)} file(s)."
    )
    print(
        "A backup of each file goes to ~/.keyhush/backups/ first. Cursor's database is not changed."
    )
    if not _confirm(args, "Redact now?"):
        return 2
    res = redact(home, include_active=args.include_active)
    print(f"\nRedacted {res.redacted} secret(s) in {len(res.changed)} file(s).")
    for p in res.changed:
        print(f"  {home.display(p)}")
    _print_problems(home, "Skipped, NOT redacted", res.skipped)
    if res.leftover:
        _print_problems(home, "VERIFICATION FAILED: still present after redaction", res.leftover)
    elif res.changed:
        print("\nVerified: a rescan of the changed files finds no known key shapes.")
    if res.rotate:
        print(
            f"\nRotate these keys now ({len(res.rotate)}). "
            "Redaction does not make a leaked key safe:"
        )
        for r in res.rotate.values():
            print(f"  {r.rule}  {r.preview} ({r.length} chars)  fp {r.fingerprint}")
    if res.backup:
        print(f"\nBackup: {home.display(res.backup.path)}")
        print(
            "WARNING: the backup still holds the secrets. Check your history, then delete it with:"
        )
        print("  keyhush backups purge --yes")
        print("To put everything back instead: keyhush undo")
    return res.exit_code


def cmd_undo(args) -> int:
    from .redact import undo

    home = _home(args)
    res = undo(home, args.set)
    if res.backup is None:
        print("No backup to undo.", file=sys.stderr)
        return 2
    print(f"Restored {len(res.restored)} file(s) from {home.display(res.backup.path)}.")
    for p in res.restored:
        print(f"  {home.display(p)}")
    _print_problems(home, "Not restored", res.skipped)
    return res.exit_code


def cmd_backups_list(args) -> int:
    from .backups import list_sets, size_of

    home = _home(args)
    sets = list_sets(home)
    if not sets:
        print("No backups.")
        return 0
    for bs in sets:
        state = (
            "undone"
            if bs.manifest.get("undone")
            else ("broken" if bs.manifest.get("broken") else "active")
        )
        print(
            f"{bs.name}  {len(bs.manifest.get('files', []))} file(s)  "
            f"{size_of(bs.path)} bytes  {state}"
        )
    print("These backups still hold the secrets. Delete them with: keyhush backups purge --yes")
    return 0


def cmd_backups_purge(args) -> int:
    from .backups import list_sets, purge

    home = _home(args)
    sets = list_sets(home)
    if not sets:
        print("No backups to delete.")
        return 0
    print(
        f"This deletes {len(sets)} backup set(s) under "
        f"{home.display(home.keyhush_dir / 'backups')}."
    )
    print("After this, `keyhush undo` cannot restore those files.")
    if not _confirm(args, "Delete them?"):
        return 2
    n = purge(home)
    print(f"Deleted {n} backup set(s).")
    return 0


# --- guard ------------------------------------------------------------------------------


def _guard_errors(changes) -> int:
    bad = [c for c in changes if c.error]
    for c in bad:
        print(f"  {c.agent}: NOT changed: {c.error}", file=sys.stderr)
    return 2 if bad else 0


def cmd_guard_install(args) -> int:
    from .guard import SPECS, do_install

    home = _home(args)
    changes, warning = do_install(home, args.agent, args.python)
    print("keyhush guard installed:")
    for c in changes:
        if c.error:
            continue
        what = "updated" if c.changed else "already up to date"
        extra = f" (backup: {home.display(c.backup)})" if c.backup else ""
        print(f"  {SPECS[c.agent].label:<12} {home.display(c.path)}  {what}{extra}")
        for note in SPECS[c.agent].notes:
            print(f"      note: {note}")
    print(f"Secret-file patterns: {home.display(home.keyhush_dir / 'secretfiles')}")
    if warning:
        print(f"WARNING: {warning}")
    print("Restart open agent sessions, then check it works: keyhush guard test")
    return _guard_errors(changes)


def cmd_guard_uninstall(args) -> int:
    from .guard import SPECS, do_uninstall

    home = _home(args)
    changes = do_uninstall(home, args.agent)
    print("keyhush guard removed:")
    for c in changes:
        if not c.error:
            what = "removed our entries" if c.changed else "nothing of ours found"
            print(f"  {SPECS[c.agent].label:<12} {home.display(c.path)}  {what}")
    print("Your pattern list was kept: " + home.display(home.keyhush_dir / "secretfiles"))
    return _guard_errors(changes)


def cmd_guard_status(args) -> int:
    from .guard import do_status

    home = _home(args)
    rows, info = do_status(home, args.agent)
    if args.json:
        print(
            json.dumps(
                {
                    **info,
                    "agents": [
                        {
                            "agent": r.agent,
                            "config": str(r.config),
                            "installed": r.installed,
                            "working": r.installed and r.health is None,
                            "problem": r.health,
                            "error": r.error,
                            "notes": r.notes,
                        }
                        for r in rows
                    ],
                },
                indent=2,
            )
        )
    else:
        print("keyhush guard status:")
        for r in rows:
            state = (
                "installed"
                if r.installed
                else ("ERROR: " + r.error if r.error else "not installed")
            )
            if r.installed and r.health:
                state = "BROKEN"
            print(f"  {r.label:<12} {state:<14} {home.display(r.config)}")
            if r.health:
                print(f"      PROBLEM: {r.health}. Until fixed, this agent may not be protected.")
            if r.installed:
                for note in r.notes:
                    print(f"      note: {note}")
        guard_state = "present" if info["guard_present"] else "missing"
        if info["guard_present"] and not info["guard_current"]:
            guard_state = "present but out of date: run keyhush guard install"
        print(f"  Hook script: {guard_state}")
        print(f"  Patterns:    {'present' if info['patterns_present'] else 'defaults (no file)'}")
    all_ok = (
        all(r.installed and r.health is None for r in rows)
        and info["guard_present"]
        and info["guard_current"]
    )
    return 0 if all_ok else 1


def cmd_guard_test(args) -> int:
    from .guard import SPECS, do_test

    home = _home(args)
    rows = do_test(home, args.agent)
    print(f"{'agent':<12} {'case':<36} {'expected':<9} result")
    for r in rows:
        mark = "ok" if r.ok else "FAIL"
        print(f"{SPECS[r.agent].label:<12} {r.case:<36} {r.expected:<9} {r.got}  {mark}")
    failed = [r for r in rows if not r.ok]
    print()
    if failed:
        print(f"{len(failed)} of {len(rows)} case(s) failed.")
        return 1
    print(f"All {len(rows)} cases behaved as expected: secret files blocked, others allowed.")
    return 0


# --- parser -----------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--home", metavar="DIR", help="use DIR as the home folder (for testing; default: your home)"
    )

    p = argparse.ArgumentParser(
        prog="keyhush", description="Keep API keys out of your coding agents.", epilog=EPILOG
    )
    p.add_argument("--version", action="version", version=f"keyhush {__version__}")
    sub = p.add_subparsers(dest="command", metavar="command")

    s = sub.add_parser("scan", parents=[common], help="find keys in agent history (read-only)")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser(
        "redact", parents=[common], help="replace found keys with markers, with backup"
    )
    r.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    r.add_argument(
        "--include-active",
        action="store_true",
        help="also change files modified in the last 10 minutes",
    )
    r.set_defaults(func=cmd_redact)

    u = sub.add_parser("undo", parents=[common], help="restore files from the last redact backup")
    u.add_argument("--set", help="backup set name (default: the latest)")
    u.set_defaults(func=cmd_undo)

    b = sub.add_parser("backups", help="list or delete redact backups")
    bsub = b.add_subparsers(dest="action", metavar="action")
    bl = bsub.add_parser("list", parents=[common], help="list backups")
    bl.set_defaults(func=cmd_backups_list)
    bp = bsub.add_parser(
        "purge", parents=[common], help="delete all backups (they hold the secrets)"
    )
    bp.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    bp.set_defaults(func=cmd_backups_purge)

    g = sub.add_parser("guard", help="block agents from reading secret files")
    gsub = g.add_subparsers(dest="action", metavar="action")
    agent_help = "only this agent: claude, codex, cursor or gemini (repeatable)"
    gi = gsub.add_parser("install", parents=[common], help="wire the guard into each agent")
    gi.add_argument("--agent", action="append", help=agent_help)
    gi.add_argument("--python", help="Python to run the hook with (default: a stable python3)")
    gi.set_defaults(func=cmd_guard_install)
    gs = gsub.add_parser("status", parents=[common], help="show where the guard is installed")
    gs.add_argument("--agent", action="append", help=agent_help)
    gs.add_argument("--json", action="store_true", help="machine-readable output")
    gs.set_defaults(func=cmd_guard_status)
    gt = gsub.add_parser(
        "test", parents=[common], help="prove the installed hook blocks, per agent"
    )
    gt.add_argument("--agent", action="append", help=agent_help)
    gt.set_defaults(func=cmd_guard_test)
    gu = gsub.add_parser("uninstall", parents=[common], help="remove only keyhush's entries")
    gu.add_argument("--agent", action="append", help=agent_help)
    gu.set_defaults(func=cmd_guard_uninstall)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    from .guard.install_base import ConfigError

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"keyhush: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
