"""A23 to A25: the review's glob oracle (tests/oracle) against the hook.

Real bash, zsh and sh expand generated words in a throwaway fixture home; any word that reaches
a protected path must be denied, and a list of everyday commands must be allowed. The files in
tests/oracle are the review's, copied unchanged from the reference copy; the build does not edit
the word list or the must-allow list (A25).

Here the quick tier runs when every shell the oracle needs is present. Without them the test
skips, unless DENYPEEK_ORACLE_REQUIRE=1 is set: then a missing shell fails (A25). The CI job
`oracle` sets it and runs the full list with the hook on Python 3.9 and the newest Python.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ORACLE = HERE / "oracle" / "glob_oracle.py"
GUARD = HERE.parent / "src" / "denypeek" / "guard" / "guard.py"


def missing_shells() -> list[str]:
    sys.path.insert(0, str(ORACLE.parent))
    try:
        import glob_oracle as oracle
    finally:
        sys.path.pop(0)
    have = set(oracle._find_bashes())
    if shutil.which("zsh") or os.path.exists("/bin/zsh"):
        have.add("zsh")
    if os.path.exists("/bin/sh"):
        have.add("sh")
    return [f for f in oracle.required_families("auto") if f not in have]


def test_oracle_quick_tier_has_no_bypass_and_allows_everyday_commands():
    required = os.environ.get("DENYPEEK_ORACLE_REQUIRE") == "1"
    missing = missing_shells() if sys.platform != "win32" else ["bash", "zsh", "sh"]
    if missing and not required:
        pytest.skip(
            f"oracle shells not installed here: {', '.join(missing)} (CI job `oracle` runs it)"
        )
    proc = subprocess.run(
        [
            sys.executable,
            str(ORACLE),
            "--quick",
            "--require",
            "auto",
            "--hook",
            str(GUARD),
            "--python",
            sys.executable,
        ],
        capture_output=True,
        text=True,
        timeout=1800,
        stdin=subprocess.DEVNULL,
    )
    result = [line for line in proc.stdout.splitlines() if line.startswith("RESULT")]
    assert proc.returncode == 0, "\n".join(proc.stdout.splitlines()[-60:]) + proc.stderr[-2000:]
    assert result and " 0 failed" in result[0], result
