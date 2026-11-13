"""A2, A16 and the team safety rules (spec section 7)."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from . import conftest
from .conftest import REPO

NETWORK_MODULES = (
    "socket",
    "ssl",
    "http",
    "http.client",
    "urllib.request",
    "ftplib",
    "smtplib",
    "asyncio",
    "requests",
    "httpx",
    "urllib3",
)


def test_a2_package_imports_no_network_module():
    code = (
        "import sys, pkgutil, importlib, keyhush\n"
        "for m in pkgutil.walk_packages(keyhush.__path__, 'keyhush.'):\n"
        "    importlib.import_module(m.name)\n"
        f"bad = [m for m in {NETWORK_MODULES!r} if m in sys.modules]\n"
        "print(','.join(bad))\n"
    )
    out = subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        env={**os.environ, "PYTHONPATH": str(REPO / "src")},
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "", f"network modules imported: {out.stdout}"


def test_a2_source_has_no_network_code():
    pattern = re.compile(
        r"^\s*(?:import|from)\s+(socket|ssl|http|urllib|ftplib|smtplib|asyncio)\b", re.M
    )
    for path in (REPO / "src").rglob("*.py"):
        assert not pattern.search(path.read_text(encoding="utf-8")), path


def test_a2_socket_is_disabled_in_tests():
    import socket

    with pytest.raises(OSError):
        socket.create_connection(("example.com", 80))


def test_a16_generator_reproduces_rules_exactly():
    if sys.version_info < (3, 11):
        pytest.skip("tools/gen_rules.py needs tomllib (Python 3.11+)")
    out = subprocess.run(
        [sys.executable, str(REPO / "tools" / "gen_rules.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stdout + out.stderr


def test_a16_every_rule_compiles_and_unconverted_are_listed():
    from keyhush import rules

    for r in rules.RULES:
        re.compile(r["regex"], re.ASCII)
    assert rules.SOURCE_RULE_COUNT == len(rules.RULES) + len(rules.UNCONVERTED)
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    for rule_id, _reason in rules.UNCONVERTED:
        assert rule_id in readme, f"{rule_id} not listed in README"


def test_third_party_notice_present():
    text = (REPO / "THIRD_PARTY.md").read_text(encoding="utf-8")
    assert "Copyright (c) 2019 Zachary Rice" in text and "v8.30.1" in text


def committed_files():
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, cwd=str(REPO))
    return [REPO / p for p in out.stdout.splitlines()]


def test_no_key_shaped_literal_is_committed():
    from keyhush.scan import find_secrets

    skip = {
        REPO / "tools" / "pinned" / "gitleaks.toml",  # upstream file, see THIRD_PARTY.md
        # Generated regexes. One rule's pattern holds a fixed public prefix (base64 of
        # "bedrock.amazonaws.com"); literal example keys are stored as hashes (next test).
        REPO / "src" / "keyhush" / "rules.py",
        REPO / ".gitleaks.toml",  # allowlists that same public prefix by exact match
    }
    for path in committed_files():
        if path in skip or not path.is_file() or path.suffix in (".lock",):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        hits = find_secrets(text)
        assert not hits, f"{path}: {[h.rule for h in hits]}"


def test_rules_file_holds_no_literal_example_keys():
    text = (REPO / "src" / "keyhush" / "rules.py").read_text(encoding="utf-8")
    assert not re.search(r"AIza[0-9A-Za-z_-]{35}", text)


def test_tripwire_blocks_the_real_home():
    probe = Path(conftest.REAL_HOME) / ".keyhush-tripwire-probe"
    with pytest.raises(PermissionError):
        open(probe)
    assert conftest._state["violations"]
    conftest._state["violations"].clear()
