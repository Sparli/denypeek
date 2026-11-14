"""S1: a preview shows only a rule's fixed public prefix (at most 4 characters), else nothing.

Spec section 3: "The first four characters are shown only for rules with a fixed public prefix
(such as AKIA); otherwise none."
"""

from __future__ import annotations

import json
import string

from denypeek import rules as R
from denypeek.scan import find_secrets, preview

from .conftest import _rand, fake_aws, fake_github, jl, run_cli, write

ALNUM = string.ascii_letters + string.digits
BY_ID = {r["id"]: r for r in R.RULES}


def fake_generic() -> str:
    """A secret that only `generic-api-key` finds: no fixed prefix of its own."""
    for _ in range(50):
        secret = _rand(ALNUM, 24)
        hits = find_secrets(f"API_KEY={secret}")
        if [h.rule for h in hits] == ["generic-api-key"] and hits[0].secret == secret:
            return secret
    raise AssertionError("could not build a generic-api-key test secret")


def fake_huggingface() -> str:
    return "hf" + "_" + _rand(string.ascii_letters, 34)


def fake_anthropic() -> str:
    return "sk-ant-" + "api03-" + _rand(ALNUM + "_-", 93) + "AA"


# --- the preview function --------------------------------------------------------------


def test_generic_rule_has_no_preview():
    secret = fake_generic()
    assert preview("generic-api-key", secret) is None


def test_fixed_prefix_rules_show_their_prefix():
    assert preview("aws-access-token", fake_aws()) == "AKIA…"
    assert preview("github-pat", fake_github()) == "ghp_…"


def test_short_prefix_shows_only_the_prefix():
    # hf_ is 3 characters: the 4th character belongs to the secret and stays hidden.
    assert preview("huggingface-access-token", fake_huggingface()) == "hf_…"


def test_long_prefix_is_cut_to_four_characters():
    assert preview("anthropic-api-key", fake_anthropic()) == "sk-a…"


def test_unknown_rule_or_secret_not_starting_with_the_prefix_has_no_preview():
    assert preview("no-such-rule", "AKIA" + "X" * 16) is None
    assert preview("aws-access-token", "ZZZZ" + "X" * 16) is None


def test_no_rule_ever_shows_a_character_past_its_fixed_prefix():
    tail = "Q9q9Q9q9Q9q9"
    for rule in R.RULES:
        prefixes = rule["prefixes"]
        if not prefixes:
            assert preview(rule["id"], "abcd" + tail) is None, rule["id"]
            continue
        for p in prefixes:
            secret = p + tail
            longest = max((q for q in prefixes if secret.startswith(q)), key=len)
            assert preview(rule["id"], secret) == longest[:4] + "…", rule["id"]


def test_prefixes_are_derived_from_the_rules():
    assert BY_ID["generic-api-key"]["prefixes"] == []
    assert set(BY_ID["aws-access-token"]["prefixes"]) >= {"AKIA", "ASIA"}
    assert BY_ID["github-pat"]["prefixes"] == ["ghp_"]
    # A rule with a branch that has no literal start has no fixed prefix at all.
    for r in R.RULES:
        assert all(r["prefixes"]), r["id"]


# --- scan, scan --json and redact's rotate list ------------------------------------------


def test_scan_shows_no_characters_of_an_unprefixed_secret(isolated):
    secret = fake_generic()
    write(isolated / ".claude/projects/p/a.jsonl", jl({"text": f"API_KEY={secret}"}))

    code, out, _ = run_cli("scan", "--home", str(isolated))
    assert code == 1, out
    assert "generic-api-key" in out
    assert secret[:4] + "…" not in out
    assert "(24 chars)" in out

    code, out, _ = run_cli("scan", "--home", str(isolated), "--json")
    data = json.loads(out)
    [f] = data["findings"]
    assert f["rule"] == "generic-api-key"
    assert f["preview"] is None
    assert secret[:4] + "…" not in out


def test_scan_shows_the_fixed_prefix_of_a_prefixed_secret(isolated):
    key = fake_github()
    write(isolated / ".claude/projects/p/a.jsonl", jl({"text": key}))
    code, out, _ = run_cli("scan", "--home", str(isolated), "--json")
    [f] = json.loads(out)["findings"]
    assert f["rule"] == "github-pat" and f["preview"] == "ghp_…"


def test_rotate_list_shows_no_characters_of_an_unprefixed_secret(isolated):
    secret = fake_generic()
    write(isolated / ".claude/projects/p/a.jsonl", jl({"text": f"API_KEY={secret}"}))
    code, out, _ = run_cli("redact", "--home", str(isolated), "--yes")
    assert code == 0, out
    assert "Rotate these keys now (1)" in out
    assert "generic-api-key  (24 chars)  fp " in out
    assert secret[:4] not in out
