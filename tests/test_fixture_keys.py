"""CI failure at 9982943 (python-3-9, macOS): "Restored 2 file(s)" where 3 were expected.

Cause: about 1 in 2,200 random fake AWS keys has Shannon entropy below 3.0, the threshold in
gitleaks' aws-access-token rule, so it is correctly not a finding. redact then changed 2 files,
and undo correctly restored those 2. The code was right; the fixture assumed every fake key is
a finding. The fake-key helpers now redraw until the key is one, and these tests pin both sides.
"""

from __future__ import annotations

import string

from denypeek.scan import find_secrets

from . import conftest
from .conftest import fake_adobe, fake_aws, fake_github, fake_slack, fake_stripe, jl, run_cli, write

LOW_ENTROPY = "AAAAAAAABBBBBBBB"  # fits [A-Z2-7]{16}; with AKIA, entropy is about 2.2


def test_fake_key_helpers_redraw_a_key_that_is_not_a_finding(monkeypatch):
    real = conftest._rand
    calls = {"n": 0}

    def first_draw_is_weak(alphabet: str, n: int) -> str:
        calls["n"] += 1
        if calls["n"] == 1 and n == 16 and set(alphabet) == set(string.ascii_uppercase + "234567"):
            return LOW_ENTROPY
        return real(alphabet, n)

    monkeypatch.setattr(conftest, "_rand", first_draw_is_weak)
    key = fake_aws()
    assert key != "AKIA" + LOW_ENTROPY
    assert [(h.rule, h.secret) for h in find_secrets(f"aws_access_key_id = {key}")] == [
        ("aws-access-token", key)
    ]


def test_every_fake_key_helper_returns_a_finding():
    for make in (fake_github, fake_aws, fake_stripe, fake_slack, fake_adobe):
        for _ in range(50):
            key = make()
            assert any(h.secret == key for h in find_secrets(f"value {key} end")), make.__name__


def test_low_entropy_aws_shape_is_not_redacted_and_undo_restores_only_what_changed(isolated):
    home = isolated
    weak = "AKIA" + LOW_ENTROPY
    claude = write(home / ".claude/projects/p/s1.jsonl", jl({"text": f"token {fake_github()}"}))
    codex = write(
        home / ".codex/sessions/2026/11/13/rollout-1.jsonl",
        jl({"type": "function_call_output", "output": f"aws_access_key_id = {weak}"}),
    )
    claude_before, codex_before = claude.read_bytes(), codex.read_bytes()

    code, out, _ = run_cli("redact", "--home", str(home), "--yes")
    assert code == 0, out
    assert "Redacted 1 secret(s) in 1 file(s)." in out
    assert codex.read_bytes() == codex_before

    code, out, _ = run_cli("undo", "--home", str(home))
    assert code == 0, out
    assert "Restored 1 file(s)" in out and "Not restored" not in out
    assert claude.read_bytes() == claude_before and codex.read_bytes() == codex_before
