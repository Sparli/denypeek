"""Build a large, realistic fixture home for timing `denypeek scan` (no real history).

    uv run python tools/make_scan_fixture.py OUT_DIR [--mb 50] [--seed 1]

Writes agent history shaped like the real thing: long JSONL records of prose, code and tool
output, some lines of several MB, base64 blobs (pasted images), one Gemini JSON chat and one
Cursor SQLite database. Fake keys are drawn at run time from a seeded generator and placed at
line starts, line ends, inside long lines and inside base64-looking text, one or more per store.
Prints the fake keys' rules and where they are, never the keys themselves.
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import sqlite3
import string
from pathlib import Path

WORDS = (
    "the api key token auth secret password curl request response client server config env "
    "file folder test build deploy error warning function class return import from value user "
    "session agent model tool call output input header bearer json yaml docker git commit branch "
    "merge sk s. ey hash salt cache queue worker retry timeout limit page index query table row"
).split()

CODE = [
    'import os\nAPI_URL = "https://api.example.com/v1"\ntoken = os.environ.get("APP_TOKEN")\n',
    "def handler(event, context):\n    key = event['headers'].get('x-api-key')\n    return key\n",
    'curl -s -H "Authorization: Bearer $TOKEN" https://api.example.com/items | jq .\n',
    "const auth = require('./auth');\nmodule.exports = async (req) => auth.check(req.headers);\n",
    "SELECT id, secret_hash, created_at FROM sessions WHERE user_id = ? LIMIT 50;\n",
]


class Keys:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.placed: list[tuple[str, str]] = []  # (store/file, where)

    def _r(self, alphabet: str, n: int) -> str:
        return "".join(self.rng.choice(alphabet) for _ in range(n))

    def github(self) -> str:
        return "gh" + "p_" + self._r(string.ascii_letters + string.digits, 36)

    def aws(self) -> str:
        return "AK" + "IA" + self._r(string.ascii_uppercase + "234567", 16)

    def stripe(self) -> str:
        return "sk" + "_live_" + self._r(string.ascii_letters + string.digits, 24)

    def slack(self) -> str:
        d = string.digits
        return (
            "xo"
            + "xb-"
            + self._r(d, 12)
            + "-"
            + self._r(d, 12)
            + "-"
            + self._r(string.ascii_letters + string.digits, 24)
        )

    def any(self) -> str:
        return self.rng.choice([self.github, self.aws, self.stripe, self.slack])()


def prose(rng: random.Random, n: int) -> str:
    out, size = [], 0
    while size < n:
        if rng.random() < 0.15:
            s = rng.choice(CODE)
        else:
            s = " ".join(rng.choice(WORDS) for _ in range(rng.randint(8, 30))) + ". "
        out.append(s)
        size += len(s)
    return "".join(out)[:n]


def blob(rng: random.Random, n: int) -> str:
    return base64.b64encode(rng.randbytes(n * 3 // 4)).decode()


def record(text: str, kind: str = "text") -> str:
    if kind == "tool":
        rec = {"type": "user", "message": {"content": [{"type": "tool_result", "content": text}]}}
    elif kind == "image":
        rec = {
            "type": "user",
            "message": {"content": [{"type": "image", "source": {"type": "base64", "data": text}}]},
        }
    else:
        rec = {"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}}
    return json.dumps(rec)


def jsonl_file(rng, keys: Keys, path: Path, target: int, label: str, huge: bool = True) -> None:
    lines, size, n = [], 0, 0
    while size < target:
        n += 1
        roll = rng.random()
        if not huge and roll < 0.06:  # moderate: no line over about 200 kB
            text, kind = blob(rng, rng.randint(20_000, 150_000)), "image"
        elif roll < 0.02:
            text, kind = prose(rng, rng.randint(2_000_000, 4_000_000)), "tool"  # a huge line
        elif roll < 0.06:
            text, kind = blob(rng, rng.randint(200_000, 1_000_000)), "image"
        elif roll < 0.40:
            text, kind = prose(rng, rng.randint(20_000, 200_000)), "tool"
        else:
            text, kind = prose(rng, rng.randint(200, 8_000)), "text"
        if rng.random() < 0.05:
            where = rng.choice(["start", "end", "middle", "base64"])
            key = keys.any()
            if where == "start":
                text = key + " " + text
            elif where == "end":
                text = text + " " + key
            elif where == "middle":
                cut = len(text) // 2
                text = text[:cut] + " " + key + " " + text[cut:]
            else:
                cut = len(text) // 2
                text = blob(rng, 4000)[:2000] + key + blob(rng, 4000) + text
            keys.placed.append((label, f"line {n}, {where}, {len(text)} chars"))
        line = record(text, kind)
        lines.append(line)
        size += len(line) + 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--mb", type=float, default=50)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument(
        "--moderate", action="store_true", help="no lines of several MB (most real histories)"
    )
    args = ap.parse_args()
    rng = random.Random(args.seed)
    keys = Keys(rng)
    home = Path(args.out)
    total = int(args.mb * 1_000_000)
    # Claude Code 60%, Codex 30%, the rest Gemini and Cursor (as on a real machine)
    claude = home / ".claude/projects/-work-app"
    for i in range(6):
        jsonl_file(
            rng, keys, claude / f"s{i}.jsonl", total // 10, f"claude s{i}", not args.moderate
        )
    codex = home / ".codex/sessions/2026/11/13"
    for i in range(3):
        jsonl_file(
            rng, keys, codex / f"rollout-{i}.jsonl", total // 10, f"codex {i}", not args.moderate
        )
    # one key per store for sure, at the line start of the first record
    first = claude / "s0.jsonl"
    first.write_text(record(keys.github() + " leading") + "\n" + first.read_text("utf-8"), "utf-8")
    keys.placed.append(("claude s0", "line 1, start"))
    msgs = [{"type": "user", "content": prose(rng, 5000)} for _ in range(200)]
    msgs[100]["content"] += " " + keys.stripe()
    keys.placed.append(("gemini", "message 100, end"))
    gem = home / ".gemini/tmp/abc/chats/session-1.json"
    gem.parent.mkdir(parents=True, exist_ok=True)
    gem.write_text(json.dumps({"sessionId": "x", "messages": msgs}, indent=2), encoding="utf-8")
    db = home / "Library/Application Support/Cursor/User/globalStorage/state.vscdb"
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
    for i in range(300):
        text = prose(rng, rng.randint(1000, 20000))
        if i == 150:
            text = text[:500] + " " + keys.slack() + " " + text[500:]
            keys.placed.append(("cursor", "ItemTable row 151, inside"))
        conn.execute("INSERT INTO ItemTable VALUES (?, ?)", (f"composerData:{i}", text.encode()))
    conn.commit()
    conn.close()
    for label, where in keys.placed:
        print(f"{label}: {where}")
    print(f"{len(keys.placed)} fake keys placed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
