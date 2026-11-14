"""Make the README's terminal capture from a real run on a throwaway fixture home.

    uv run python tools/capture_demo.py

It builds a fake home under a temp folder, with fake keys assembled at run time, runs real
denypeek commands against it with HOME pointed there, and writes the captured output to
docs/assets/demo-run.txt and docs/assets/demo-run.svg. It never touches your real home folder,
and it refuses to write if your real home path appears in the output.
"""

from __future__ import annotations

import html
import json
import os
import secrets
import shutil
import sqlite3
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "assets"
ALNUM = string.ascii_letters + string.digits


def rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def build_home(home: Path) -> None:
    old = time.time() - 3600

    def write(rel: str, text: str) -> None:
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        os.utime(p, (old, old))

    github = "gh" + "p_" + rand(ALNUM, 36)
    aws = "AK" + "IA" + rand(string.ascii_uppercase + "234567", 16)
    stripe = "sk" + "_live_" + rand(ALNUM, 24)
    slack = (
        "xo"
        + "xb-"
        + rand(string.digits, 12)
        + "-"
        + rand(string.digits, 12)
        + "-"
        + rand(ALNUM, 24)
    )
    write(
        ".claude/projects/-home-maya-shop-api/7f3c.jsonl",
        "".join(
            json.dumps(r) + "\n"
            for r in [
                {"type": "user", "message": {"content": "deploy fails with 401"}},
                {"type": "user", "message": {"content": f"here is the token: {github}"}},
                {"type": "assistant", "message": {"content": "Thanks, retrying the push."}},
            ]
        ),
    )
    write(
        ".codex/sessions/2026/11/12/rollout-2026-11-12T09-14-03.jsonl",
        "".join(
            json.dumps(r) + "\n"
            for r in [
                {"type": "session_meta"},
                {"type": "function_call", "name": "shell", "arguments": "cat ~/.aws/config"},
                {"type": "function_call_output", "output": f"aws_access_key_id = {aws}"},
            ]
        ),
    )
    write(
        ".gemini/tmp/5b1e/chats/session-2026-11-10.json",
        json.dumps(
            {
                "messages": [
                    {"type": "user", "content": "why is checkout failing?"},
                    {"type": "gemini", "content": f"Your STRIPE_KEY is {stripe}; it looks valid."},
                ]
            },
            indent=2,
        ),
    )
    db = home / "Library/Application Support/Cursor/User/globalStorage/state.vscdb"
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE ItemTable (key TEXT, value BLOB)")
    conn.execute(
        "INSERT INTO ItemTable VALUES (?, ?)",
        ("composerData:1", json.dumps({"text": f"slack bot {slack}"}).encode()),
    )
    conn.commit()
    conn.close()


def run(home: Path, args: list[str]) -> str:
    env = {
        **os.environ,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "CLAUDE_CONFIG_DIR": str(home / ".claude"),
        "CODEX_HOME": str(home / ".codex"),
    }
    proc = subprocess.run(
        [sys.executable, "-m", "denypeek.cli", *args, "--home", str(home)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(ROOT),
    )
    return (proc.stdout + proc.stderr).rstrip("\n") + f"\n[exit code {proc.returncode}]"


def to_svg(lines: list[str]) -> str:
    char_w, line_h, pad = 8.4, 18, 16
    width = int(max(len(x) for x in lines) * char_w + 2 * pad)
    height = len(lines) * line_h + 2 * pad + 28
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="denypeek terminal run">',
        f'<rect width="{width}" height="{height}" rx="8" fill="#0d1117"/>',
        '<circle cx="18" cy="16" r="5" fill="#ff5f56"/><circle cx="36" cy="16" r="5" '
        'fill="#ffbd2e"/><circle cx="54" cy="16" r="5" fill="#27c93f"/>',
        "<style>text { white-space: pre; }</style>",
        '<g font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" '
        'font-size="14" xml:space="preserve">',
    ]
    for i, line in enumerate(lines):
        y = pad + 28 + i * line_h + 12
        if line.startswith("$ "):
            color = "#7ee787"
        elif line.startswith("#"):
            color = "#8b949e"
        elif "FAIL" in line or "WARNING" in line or "NOT " in line:
            color = "#ffa657"
        else:
            color = "#e6edf3"
        out.append(f'<text x="{pad}" y="{y}" fill="{color}">{html.escape(line)}</text>')
    out.append("</g></svg>")
    return "\n".join(out) + "\n"


def main() -> int:
    real_home = os.path.expanduser("~")
    tmp = Path(tempfile.mkdtemp(prefix="denypeek-demo-"))
    home = tmp / "home"
    home.mkdir()
    try:
        build_home(home)
        lines = [
            "# DEMO is a throwaway home folder under /tmp, holding fake keys made for this run.",
            "# denypeek shows paths under --home as ~/...",
            "",
        ]
        for args in (
            ["scan"],
            ["guard", "install"],
            ["guard", "test", "--agent", "claude", "--agent", "cursor"],
            ["redact", "--yes"],
        ):
            shown = " ".join(args)
            lines.append(f'$ denypeek {shown} --home "$DEMO"')
            lines += run(home, args).splitlines()
            lines.append("")
        text = "\n".join(lines).rstrip() + "\n"
        text = text.replace(str(home), "$DEMO")
        for bad in (real_home, str(tmp)):
            if bad in text:
                raise SystemExit(f"refusing to write: output contains {bad!r}")
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / "demo-run.txt").write_text(text, encoding="utf-8")
        (OUT / "demo-run.svg").write_text(to_svg(text.splitlines()), encoding="utf-8")
        print(f"Wrote {OUT / 'demo-run.svg'} ({len(text.splitlines())} lines)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
