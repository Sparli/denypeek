"""A3, A4, A5 and detection details."""

from __future__ import annotations

import json
import os
import sys

import pytest

from keyhush.scan import find_secrets

from .conftest import fake_adobe, fake_github, jl, run_cli, write


def test_a3_one_finding_per_store_at_the_right_place(four_store_home, keys):
    home = four_store_home
    code, out, _ = run_cli("scan", "--home", str(home))
    assert code == 1, out
    assert "Scanned 4 file(s): claude 1, codex 1, cursor 1, gemini 1." in out
    assert "~/.claude/projects/-work-app/s1.jsonl:2  github-pat" in out
    assert "~/.codex/sessions/2026/11/13/rollout-1.jsonl:3  aws-access-token" in out
    assert "session-1.json:10  stripe-access-token" in out
    assert "state.vscdb:ItemTable row 2  slack-bot-token" in out
    for k in keys.values():
        assert k not in out
        assert k[4:] not in out

    code, out, _ = run_cli("scan", "--home", str(home), "--json")
    data = json.loads(out)
    assert code == 1 and data["exit_code"] == 1 and data["complete"] is True
    got = {
        (f["agent"], os.path.basename(f["file"]), f["line"], f["rule"]) for f in data["findings"]
    }
    assert got == {
        ("claude", "s1.jsonl", "2", "github-pat"),
        ("codex", "rollout-1.jsonl", "3", "aws-access-token"),
        ("gemini", "session-1.json", "10", "stripe-access-token"),
        ("cursor", "state.vscdb", "ItemTable row 2", "slack-bot-token"),
    }
    for f in data["findings"]:
        assert len(f["preview"]) == 5 and f["preview"].endswith("…")
        assert len(f["fingerprint"]) == 8
    for k in keys.values():
        assert k not in out


def test_a4_broken_line_u2028_and_unreadable_file_are_listed(isolated):
    home = isolated
    key = fake_github()
    good = json.dumps({"text": "a b " + key}, ensure_ascii=False)
    write(home / ".claude/projects/p/a.jsonl", '{"ok": 1}\n{"broken": \n' + good + "\n")
    locked = write(home / ".claude/projects/p/locked.jsonl", jl({"x": 1}))
    if sys.platform != "win32":
        os.chmod(locked, 0)
    try:
        code, out, _ = run_cli("scan", "--home", str(home))
    finally:
        os.chmod(locked, 0o600)
    assert code == 2, out
    assert "a.jsonl:2: broken JSON line" in out
    assert "a.jsonl:3: contains U+2028; read as one line, not split" in out
    assert "a.jsonl:3  github-pat" in out  # the key after U+2028 is still found, on line 3
    if sys.platform != "win32" and os.geteuid() != 0:
        assert "locked.jsonl: cannot read" in out
    assert "The scan was incomplete (exit code 2)" in out


def test_a5_clean_scan_says_it_is_not_proof(isolated):
    write(isolated / ".claude/projects/p/a.jsonl", jl({"text": "nothing here"}))
    code, out, _ = run_cli("scan", "--home", str(isolated))
    assert code == 0
    assert "No known key shapes found." in out
    assert "not proof that this machine is clean" in out
    code, out, _ = run_cli("scan", "--home", str(isolated), "--json")
    assert code == 0 and "not proof" in json.loads(out)["disclaimer"]


def test_empty_home_is_clean(isolated):
    code, out, _ = run_cli("scan", "--home", str(isolated))
    assert code == 0 and "no history files found" in out


def test_converted_inline_flag_rule_keeps_case_sensitive_prefix():
    key = fake_adobe()
    assert [h.rule for h in find_secrets(f"secret {key} end")] == ["adobe-client-secret"]
    upper_prefix = "P8E-" + key[4:]
    assert find_secrets(f"secret {upper_prefix} end") == []


def test_low_entropy_and_allowlisted_values_are_ignored():
    assert find_secrets("api_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa'") == []
    assert find_secrets('token = "${API_TOKEN}"') == []


def test_cursor_db_opened_read_only_and_wal_untouched(isolated, keys):
    from .conftest import make_cursor_db

    db = make_cursor_db(isolated / ".cursor/chats/w/c/store.db.tmp", "x")
    os.remove(db)
    db = isolated / "Library/Application Support/Cursor/User/globalStorage/state.vscdb"
    make_cursor_db(db, f"key {keys['cursor']}")
    wal = db.with_name(db.name + "-wal")
    wal.write_bytes(b"not a real wal")
    before = (db.read_bytes(), wal.read_bytes(), db.stat().st_mtime)
    code, out, _ = run_cli("scan", "--home", str(isolated))
    assert code == 1 and "slack-bot-token" in out
    assert (db.read_bytes(), wal.read_bytes(), db.stat().st_mtime) == before
    assert not db.with_name(db.name + "-shm").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need extra rights on Windows")
def test_scan_skips_symlink_leading_outside(isolated, tmp_path):
    outside = write(tmp_path / "outside/secret.jsonl", jl({"t": fake_github()}))
    link = isolated / ".claude/projects/p/link.jsonl"
    link.parent.mkdir(parents=True)
    link.symlink_to(outside)
    code, out, _ = run_cli("scan", "--home", str(isolated))
    assert code == 0
    assert "symlink to outside the history folders; skipped" in out
