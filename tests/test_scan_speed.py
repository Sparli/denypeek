"""Scan speed work: the fast matcher gives exactly the rules' own matches, parallel scans give
exactly the serial result, progress goes to a terminal only, and Ctrl-C stops cleanly."""

from __future__ import annotations

import base64
import json
import random
import string

import pytest

from denypeek import scan as S
from denypeek.sources import resolve_home

from .conftest import fake_aws, fake_github, fake_slack, fake_stripe, jl, run_cli, write

AL = string.ascii_letters + string.digits
CURL = "cu" + "rl"  # assembled at run time, so no curl command with a credential is in this file


def _texts(seed: int) -> list[str]:
    """Long texts full of rule keywords, base64, curl commands and overlapping keywords."""
    rng = random.Random(seed)

    def r(n, alphabet=AL):
        return "".join(rng.choice(alphabet) for _ in range(n))

    pieces = [
        "accessecret = '" + r(32) + "'",  # `access` and `secret` overlap
        "apikey: " + r(40),
        "OKTA_TOKEN=00" + r(40),
        "sumo_id: su" + r(12),
        "jira_api_token = " + r(20, "abcdefghijklmnopqrstuvwxyz0123456789") + "abcd",
        "ATATT3" + r(186),
        CURL + ' -s -H "Authorization: Bearer ' + r(30) + '" https://x',
        CURL + ' https://x -H "Content-Type: application/json"',
        CURL + " -u admin:" + r(12) + " https://x",
        CURL + " --user=me:" + r(10) + " x",
        CURL + "\\n  -H 'X-Api-Key: " + r(24) + "'",
        "password: " + r(16),
        base64.b64encode(rng.randbytes(3000)).decode(),
        " ".join(
            rng.choice(["key", "token", "auth", "api", "the", "secret", CURL]) for _ in range(300)
        ),
        fake_github(),
        fake_aws(),
        fake_stripe(),
        fake_slack(),
    ]
    out = []
    for _ in range(12):
        parts = [rng.choice(pieces) for _ in range(rng.randint(5, 30))]
        out.append(rng.choice(["", " ", "\\n", "\n", '"', "="]).join(parts))
    return out


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_fast_matcher_gives_exactly_the_rules_own_matches(seed, monkeypatch):
    monkeypatch.setattr(S, "FAST_MIN", 0)
    for text in _texts(seed):
        for rule in S.compiled_rules():
            if rule["starts"] is None:
                continue
            want = [(m.start(), m.end(), m.groups()) for m in rule["re"].finditer(text)]
            got = [(m.start(), m.end(), m.groups()) for m in S._finditer(rule, text)]
            assert got == want, rule["id"]


@pytest.mark.parametrize("seed", [4, 5])
def test_find_secrets_is_the_same_with_and_without_the_fast_matcher(seed, monkeypatch):
    for text in _texts(seed):
        monkeypatch.setattr(S, "FAST_MIN", 10**12)
        slow = S.find_secrets(text)
        monkeypatch.setattr(S, "FAST_MIN", 0)
        assert S.find_secrets(text) == slow


def test_every_slow_rule_shape_has_a_fast_matcher():
    """A rules update that brings a new shape of these patterns must not lose the fast path
    silently: every rule starting with a long [\\w.-] run or `\\bcurl\\b` has one."""
    slow = [
        r["id"]
        for r in S.compiled_rules()
        if r["regex"].startswith((r"[\w.-]{0,50}?", r"(?i)[\w.-]{0,50}?", r"\bcurl\b"))
    ]
    assert len(slow) >= 100
    assert all(r["starts"] is not None for r in S.compiled_rules() if r["id"] in slow)


@pytest.fixture
def big_home(four_store_home):
    """Several history files, some long lines, keys at line starts, ends and in base64."""
    home = four_store_home
    rng = random.Random(9)
    for i in range(5):
        blob = base64.b64encode(rng.randbytes(60_000)).decode()
        write(
            home / f".claude/projects/-work-app/big{i}.jsonl",
            jl(
                {"text": fake_github() + " at the start"},
                {"text": "x " * 40_000 + fake_aws()},
                {"text": blob[:30_000] + fake_stripe() + blob[30_000:]},
                {
                    "text": CURL
                    + ' -H "Authorization: Bearer '
                    + "".join(rng.choices(AL, k=40))
                    + '"'
                },
            ),
        )
    return home


def test_parallel_scan_equals_serial_scan(big_home):
    home = resolve_home(str(big_home))
    one = S.scan(home, workers=1)
    two = S.scan(home, workers=2)
    assert one.findings == two.findings and len(one.findings) >= 4 + 5 * 2
    assert one.incomplete == two.incomplete and one.notes == two.notes
    assert one.files == two.files and two.stopped is None


def test_progress_reports_totals_then_each_file(big_home):
    calls = []
    S.scan(resolve_home(str(big_home)), progress=lambda *a: calls.append(a), workers=1)
    total_files, total_bytes = calls[0][1], calls[0][3]
    assert calls[0] == (0, total_files, 0, total_bytes, 0, None)
    assert [c[0] for c in calls[1:]] == list(range(1, total_files + 1))
    assert calls[-1][2] == total_bytes and calls[-1][4] >= 14


def test_ctrl_c_stops_cleanly_with_findings_so_far(big_home, monkeypatch):
    real = S._scan_one
    seen = []

    def stop_on_third(job):
        seen.append(job)
        if len(seen) == 3:
            raise KeyboardInterrupt
        return real(job)

    monkeypatch.setattr(S, "_scan_one", stop_on_third)
    code, out, err = run_cli("scan", "--home", str(big_home))
    assert code == 2, out
    assert "INCOMPLETE: the scan was stopped (Ctrl-C) after 2 of " in out
    assert "Possible secrets (" in out
    assert "stopped before the end (exit code 2)" in out
    assert "Traceback" not in out + err
    seen.clear()
    code, out, _ = run_cli("scan", "--home", str(big_home), "--json")
    data = json.loads(out)
    assert code == 2 and data["complete"] is False and data["stopped"].startswith("stopped")


def test_no_progress_output_when_stderr_is_not_a_terminal(big_home):
    code, out, err = run_cli("scan", "--home", str(big_home))
    assert err == "" and code == 1


class FakeTerminal:
    def __init__(self):
        self.text = ""

    def write(self, s):
        self.text += s

    def flush(self):
        pass


def test_progress_line_shows_store_files_size_and_findings_only():
    from denypeek.cli import ScanProgress

    term = FakeTerminal()
    show = ScanProgress(term)
    show(0, 3, 0, 2_500_000_000, 0, None)
    show(3, 3, 2_500_000_000, 2_500_000_000, 4, "claude")
    show.finish()
    assert "Scanning 3 file(s), 2.50 GB. Press Ctrl-C to stop" in term.text
    assert "Claude Code: file 3 of 3, 2.50 GB of 2.50 GB, 4 found so far" in term.text
    assert term.text.endswith("\r")


def test_ctrl_c_during_redact_changes_nothing(big_home, monkeypatch):
    before = {p: p.read_bytes() for p in big_home.rglob("*.jsonl")}

    def stop(job):
        raise KeyboardInterrupt

    monkeypatch.setattr(S, "_scan_one", stop)
    code, out, err = run_cli("redact", "--home", str(big_home), "--yes")
    assert code == 2 and "Stopped before redacting anything" in out, out
    assert "Traceback" not in out + err
    assert {p: p.read_bytes() for p in big_home.rglob("*.jsonl")} == before
