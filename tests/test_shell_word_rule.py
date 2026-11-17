"""SPEC section 3a, the shell-word rule: cases the oracle does not generate yet, through the
real hook script. The oracle (tests/oracle) is the main check; these pin the spec's own
examples, words with a pattern in an earlier path part, variables that hold quote or comment
characters, the spec's "Open today" list, fail-closed limits and a short fuzz run.
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
import time
from pathlib import Path

import pytest

from denypeek.guard import blocked
from denypeek.guard import guard as g

GUARD = Path(__file__).resolve().parents[1] / "src" / "denypeek" / "guard" / "guard.py"


@pytest.fixture
def lab(isolated, tmp_path):
    home = isolated
    (home / ".claude").mkdir()
    (home / ".denypeek").mkdir()
    (home / ".denypeek" / "secretfiles").write_text(".env\n")
    (home / ".gemini").mkdir()
    (home / ".gemini" / "settings.json").write_text("{}\n")
    proj = tmp_path / "proj"
    for d in ("src/deep", "tests", "docs", "out", "app/[lang]/[id]"):
        (proj / d).mkdir(parents=True)
    (proj / ".env").write_text("X=1\n")
    (proj / ".env.example").write_text("X=\n")
    (proj / "src" / ".env").write_text("X=1\n")
    (proj / "src" / "deep" / ".env").write_text("X=1\n")
    for f in (
        "README.md",
        "app.py",
        "app.pyc",
        "src/app.py",
        "tests/test_app.py",
        "app/[lang]/[id]/page.tsx",
    ):
        (proj / f).write_text("x\n")
    return home, proj


def run_hook(command: str, home: Path, cwd: Path):
    payload = {
        "session_id": "t",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    proc = subprocess.run(
        [sys.executable, "-I", "-S", str(GUARD), "--agent", "claude", "--home", str(home)],
        input=json.dumps(payload).encode(),
        capture_output=True,
        timeout=60,
        cwd=str(cwd),
        env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
    )
    return blocked("claude", proc.stdout.decode(), proc.returncode), proc.stdout.decode()


# The must-allow list of section 3a, in a project that holds .env (A24).
SPEC_MUST_ALLOW = [
    "ls *.py",
    "cat *.md",
    "rm *.pyc",
    "pytest tests/test_*.py",
    "grep -o '[a-z]*' README.md",
    "git diff HEAD~1",
    "git reset HEAD^",
    "git stash show stash@{0}",
    "pip install -e .[dev]",
    "echo $#",
    "echo ${x[1]}",
    "echo ${v#p}",
    "echo ${v^^}",
    "x=(a b c)",
    "(cd src && ls)",
    "[ -f x ]",
    "curl https://example.com/a?b=1#frag",
    "curl 'https://example.com/a?b=1#frag'",
    "find . -name '*.py'",
    "mkdir -p out/{a,b}",
    "cat .env.example",
    "echo '*'",
    "echo '.e*'",
    "diff <(ls) <(ls -a)",
    "grep -E '(API|KEY)' app.py",
    'grep -E "^(foo|bar)$" app.py',
    "python3 -c 'print([1, 2][0])'",
    # a pattern part, then a name: only paths that exist (the review, confirmation pass at 0ea7c2b)
    "ls */README.md",
    "rm -rf */__pycache__",
    "ls src/*/x.py",
    # G2: a part that begins with *, ? or a bracket never stands for . or .. (the spec)
    "ls */",
    "ls -d */",
    # G3c trips, but nothing under app/ is protected (the spec)
    "cat app/[lang]/[id]/page.tsx",
]


@pytest.mark.parametrize("command", SPEC_MUST_ALLOW)
def test_spec_must_allow(command, lab):
    home, proj = lab
    denied, out = run_hook(command, home, proj)
    assert not denied, (command, out)


MUST_DENY_PROJ = [
    # a pattern in an earlier path part, the secret only in a subfolder
    "cat (src|x)/.e?v",
    "cat s[r]c/.e*",
    "cat s?c/.en[^x]",
    "cat src/(.env|x)",
    "cat {src,x}/.en[!z-a]",
    "cat src/**/.e?v",
    "cat **/deep/.e?v",
    "cat sr(c)/deep/.env",
    "cat s#rc/.env",
    # variables are data: a quote or # in a value starts nothing
    "c='#'; p=.e; cat $c $p*",
    'q="\'"; p=.e; cat $q $p* $q',
    "a='[!x]'; cat .en$a",
    "a=.e; b=$a; cat ${b}*",
    "cat ${x:-.env}",
    "a='.e*'; cat $~a",
    # section 3a "Open today"
    "cat .env[x]#",
    # the review's C1 and C2: a widened part, then a bracket holding `/` later in the word
    "cat .e##[^/][^x]",
    "cat s(r)c/.e[^/]v",
    "cat .*/.en?",
    # names written out in code and in nested shells
    "python3 -c \"open('.env')\"",
    "bash -c 'cat .e?v'",
    "diff <(cat .env) README.md",
    "cat $(echo .e?v)",
    "x=(.e?v); cat ${x[0]}",
    # process substitution in the middle of a word: a command, and widened (the spec, 3a G1)
    "cat x<(cat .env)",
    "cat .en<(true)",
    "cat --x=(cat .env)",
]


@pytest.mark.parametrize("command", MUST_DENY_PROJ)
def test_must_deny_in_project(command, lab):
    home, proj = lab
    denied, out = run_hook(command, home, proj)
    assert denied, (command, out)


def test_dot_dot_from_a_subfolder(lab):
    home, proj = lab
    denied, out = run_hook("cat .?/.en?", home, proj / "docs")
    assert denied, out


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf ~+/.denypeek",
        "cat ~+/.denypeek/secretfiles",
        "rm -rf ~/.claude/.?/.denypeek",
        "rm -rf ~-/.denypeek",
        "rm -rf ~nobody/../$USER/.claude",
        "mv ~/.c(l)aude /tmp/x",
        "rm -rf ~/.[c/]laude",
        "rm -rf ~/x~/../.claude",
        "cat ~/.gemini/se(t)tings.[^/]son",
    ],
)
def test_must_deny_from_home(command, lab):
    home, _ = lab
    denied, out = run_hook(command, home, home)
    assert denied, (command, out)


def _decide(command, cwd):
    event = {
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    return g.decide(event, g.parse_patterns(g.DEFAULT_PATTERNS))


def test_a_pattern_that_visits_too_many_entries_is_denied(lab, monkeypatch):
    _, proj = lab
    for n in range(60):
        (proj / "docs" / f"f{n}.md").write_text("x")
    monkeypatch.setattr(g, "WORD_WALK_LIMIT", 40)
    try:
        reason = _decide("ls docs/**/*.md", proj)
    except g.HookTimeout:
        reason = "timeout"
    assert reason, "G6: a pattern past the walk limit must be denied, not skipped"


ALPHABET = list("abe.nv*?[]!^#~(){},|;&<>$`'\"\\/ -=:@+0123456789\n\t") + [".env", "~/", "$(", "${"]


def test_fuzz_the_word_reader_never_crashes(lab):
    """Random commands over shell metacharacters: decide() must return or raise HookTimeout
    (which the hook turns into a deny), never anything else, and stay fast."""
    _, proj = lab
    rng = random.Random(1234)
    start = time.monotonic()
    for _ in range(3000):
        command = "cat " + "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 30)))
        g._deadline[0] = time.monotonic() + 5
        try:
            _decide(command, proj)
        except g.HookTimeout:
            pass
        finally:
            g._deadline[0] = float("inf")
    assert time.monotonic() - start < 120


@pytest.fixture
def ssh_lab(isolated, tmp_path):
    ssh = isolated / ".ssh"
    ssh.mkdir()
    for name in ("id_ed25519", "id_ed25519.pub", "known_hosts", "config"):
        (ssh / name).write_text("x\n")
    return isolated, tmp_path


@pytest.mark.parametrize("command", ["cat ~/.ssh/id_ed25519.pub", "cat ~/.ssh/*.pub"])
def test_public_keys_are_allowed_inside_ssh(command, ssh_lab):
    home, cwd = ssh_lab
    denied, out = run_hook(command, home, cwd)
    assert not denied, (command, out)


@pytest.mark.parametrize(
    "command",
    ["cat ~/.ssh/id_ed25519", "cat ~/.ssh/id_ed25519*", "cat ~/.ssh/*", "cat ~/.ssh/known_hosts"],
)
def test_the_rest_of_ssh_stays_protected(command, ssh_lab):
    home, cwd = ssh_lab
    denied, out = run_hook(command, home, cwd)
    assert denied, (command, out)
