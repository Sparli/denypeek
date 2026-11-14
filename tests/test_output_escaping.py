"""A22: names from disk cannot inject terminal escapes, fake lines or bidi tricks into output."""

from __future__ import annotations

import json
import sys

import pytest

from .conftest import fake_github, jl, run_cli, write

ESC = "\x1b"
RLO = "‮"
BAD_FOLDER = "proj" + ESC + "[31m-red" + RLO + "gnp."
BAD_FILE = "s\nFAKE LINE: all clean" + ESC + "[2J.jsonl"

WIN_SKIP = pytest.mark.skipif(
    sys.platform == "win32", reason="Windows file names cannot hold these characters"
)


@pytest.fixture
def hostile_home(isolated):
    write(isolated / ".claude" / "projects" / BAD_FOLDER / BAD_FILE, jl({"t": fake_github()}))
    return isolated


def assert_clean(text):
    assert ESC not in text and RLO not in text, repr(text)
    assert "\nFAKE LINE" not in text


@WIN_SKIP
def test_a22_text_output_escapes_names(hostile_home):
    code, out, err = run_cli("scan", "--home", str(hostile_home))
    assert code == 1
    assert_clean(out + err)
    assert "\\x1b[31m" in out and "\\u202e" in out and "\\n" in out


@WIN_SKIP
def test_a22_json_is_ascii_and_decodes_to_the_exact_path(hostile_home):
    code, out, _ = run_cli("scan", "--home", str(hostile_home), "--json")
    assert code == 1
    assert_clean(out)
    assert out.isascii()
    files = [f["file"] for f in json.loads(out)["findings"]]
    assert any(f.endswith(BAD_FOLDER + "/" + BAD_FILE) for f in files), files


@WIN_SKIP
def test_a22_redact_output_escapes_names(hostile_home):
    code, out, err = run_cli("redact", "--home", str(hostile_home), "--yes")
    assert code == 0, out + err
    assert_clean(out + err)


def test_a22_windows_separators_are_not_doubled(monkeypatch):
    from denypeek import sources

    monkeypatch.setattr(sources.os, "sep", "\\")
    assert sources.safe_text("~\\.claude\\x") == "~\\.claude\\x"
    monkeypatch.setattr(sources.os, "sep", "/")
    assert sources.safe_text("a\\b") == "a\\\\b"
