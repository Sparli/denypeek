"""SPEC 3b, the tree rule: a recursive search is allowed only if nothing under the folders it
reads matches the secret patterns. The walk skips nothing (no hidden names, ignore files or
node_modules); only grep's own literal --include, --exclude and --exclude-dir narrow it.

A26: the project fixture through the real hook, per agent format. A27: the tool tier, where
the real search tool runs first, and the hook must deny whenever it prints a marker. A28:
protected paths, the deny messages, and every rewrite a message suggests. Then every
reproduction from the security reviews, each of which must be denied.

The large fixtures (50,000 and over 100,000 entries) are built once per module. Windows is
skipped for them: A26 names macOS and Linux, and creating that many files there takes minutes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from denypeek.guard import blocked
from denypeek.guard import guard as g

GUARD = Path(__file__).resolve().parents[1] / "src" / "denypeek" / "guard" / "guard.py"
AGENTS = ("claude", "codex", "cursor", "gemini")
MARK = "M" + "ARKER" + "4711"  # the word every secret file holds in the tool tier
LIMIT = 4.0  # seconds, as in the other hook tests (the hook's own limit is 2.5)
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="A26 and A27 run on macOS and Linux")


# --- fixtures -------------------------------------------------------------------------------


def filler(root: Path, entries: int) -> None:
    """Folders of 20 small files under root until about `entries` names exist."""
    made, i = 0, 0
    while made < entries:
        d = root / f"pkg{i // 50}" / f"lib{i % 50}"
        d.mkdir(parents=True, exist_ok=True)
        made += 1 + (1 if i % 50 == 0 else 0)
        for j in range(20):
            (d / f"f{j}.js").write_bytes(b"x\n")
            made += 1
        i += 1


def a26_project(root: Path, entries: int = 50_000, secrets: bool = True) -> Path:
    """The A26 project: a repository with node_modules/ and .env in .gitignore, two virtualenvs
    whose own .gitignore is `*`, secret files in node_modules, and filler."""
    proj = root
    (proj / ".git").mkdir(parents=True)
    (proj / ".gitignore").write_text("node_modules/\n.env\n")
    (proj / "src").mkdir()
    (proj / "src" / "app.py").write_text(f"print('{MARK if not secrets else 'app'}')\n")
    if secrets:
        (proj / ".env").write_text(f"KEY={MARK}\n")
        for venv in (".venv", "venv"):
            (proj / venv / "lib").mkdir(parents=True)
            (proj / venv / ".gitignore").write_text("*\n")
            (proj / venv / "lib" / "cacert.pem").write_text(f"{MARK}\n")
        (proj / "node_modules" / "pkg").mkdir(parents=True)
        (proj / "node_modules" / "pkg" / ".env").write_text(f"{MARK}\n")
        (proj / "node_modules" / "pkg" / "test.pem").write_text(f"{MARK}\n")
    filler(proj / "node_modules", entries)
    return proj


@pytest.fixture(scope="module")
def big(tmp_path_factory):
    if os.name == "nt":
        pytest.skip("A26 and A27 run on macOS and Linux")
    return a26_project(tmp_path_factory.mktemp("a26") / "proj")


@pytest.fixture(scope="module")
def past_cap(tmp_path_factory):
    if os.name == "nt":
        pytest.skip("A26 and A27 run on macOS and Linux")
    return a26_project(
        tmp_path_factory.mktemp("cap") / "proj", entries=g.WALK_LIMIT + 1_000, secrets=False
    )


def installed(home: Path) -> None:
    """The state `guard install` writes, as far as the tree rule is concerned: nothing."""
    (home / ".denypeek").mkdir(exist_ok=True)
    (home / ".denypeek" / "guard-state.json").write_text("{}")


# --- running the hook -----------------------------------------------------------------------


def shell_event(agent: str, command: str, cwd: Path) -> dict:
    if agent == "cursor":
        return {
            "hook_event_name": "beforeShellExecution",
            "command": command,
            "cwd": str(cwd),
            "workspace_roots": [str(cwd)],
        }
    if agent == "gemini":
        return {
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": command, "dir_path": str(cwd)},
            "cwd": str(cwd),
        }
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(cwd),
    }


def search_tool_event(agent: str, path: str, cwd: Path) -> dict:
    if agent == "gemini":
        return {
            "hook_event_name": "BeforeTool",
            "tool_name": "search_file_content",
            "tool_input": {"pattern": "foo", "dir_path": path},
            "cwd": str(cwd),
        }
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Grep",
        "tool_input": {"pattern": "foo", "path": path},
        "cwd": str(cwd),
    }


def hook(agent: str, event: dict, cwd: Path):
    """(denied, reason text, seconds)."""
    start = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-I", "-S", str(GUARD), "--agent", agent, "--home", os.environ["HOME"]],
        input=json.dumps(event).encode(),
        capture_output=True,
        timeout=60,
        cwd=str(cwd),
        env=dict(os.environ),
    )
    out = proc.stdout.decode()
    return blocked(agent, out, proc.returncode), out, time.monotonic() - start


def reason_of(out: str) -> str:
    data = json.loads(out)
    hso = data.get("hookSpecificOutput") or {}
    return hso.get("permissionDecisionReason") or data.get("reason") or data.get("agent_message")


# --- A26 ------------------------------------------------------------------------------------


def project_p(root: Path, marker: bool = True) -> Path:
    """Project P of SPEC A26: a repository whose only secret file is the top `.env`."""
    proj = root
    (proj / ".git").mkdir(parents=True)
    (proj / ".gitignore").write_text("node_modules/\n.env\n!.env.example\n")
    (proj / ".env").write_text(f"KEY={MARK if marker else 'x'}\n")
    (proj / ".env.example").write_text("KEY=\n")
    (proj / "src").mkdir()
    (proj / "src" / "app.py").write_text("print(1)\n")
    (proj / "tests").mkdir()
    (proj / "tests" / "test_app.py").write_text("x\n")
    (proj / "docs").mkdir()
    (proj / "docs" / "index.md").write_text("x\n")
    certifi = proj / ".venv" / "lib" / "python3.12" / "site-packages" / "certifi"
    certifi.mkdir(parents=True)
    (proj / ".venv" / ".gitignore").write_text("*\n")
    (certifi / "cacert.pem").write_text("public certificate list\n")
    (proj / "node_modules" / "pkg").mkdir(parents=True)
    (proj / "node_modules" / "pkg" / "index.js").write_text("x\n")
    return proj


@pytest.fixture
def p_proj(tmp_path):
    return project_p(tmp_path / "proj")


# From the top: each reads `.env`, so each is denied with message (a).
A26_DENIED = [
    "rg foo",
    "rg -n foo .",
    "rg --hidden foo",
    "rg -g '*.py' foo",
    "grep -rn foo .",
    "git grep foo",
    "ag foo",
]
# Narrowed: each reads no secret file.
A26_ALLOWED = [
    "rg foo src",
    "rg foo src tests",
    "rg foo .venv",
    "grep -rn foo src",
    "grep -rn foo . --include='*.py'",
    "git grep foo -- src",
]
GIT_GREP_DISK_ONLY = [
    "git grep foo HEAD",
    "git grep foo HEAD --",
    "git grep --cached foo",
    "git grep foo -- '*.env'",
]
SEARCH_TEXTS = [
    'rg "export function load"',
    'rg "type alias "',
    "rg exclude",
    "rg -n 'GIT_DIR'",
    "rg 'site-packages/certifi'",
]


@POSIX_ONLY
@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("command", A26_DENIED)
def test_a26_from_the_top_denied_with_message_a(agent, command, p_proj, isolated):
    installed(isolated)
    denied, out, secs = hook(agent, shell_event(agent, command, p_proj), p_proj)
    assert denied, (command, out)
    assert "(.env)" in reason_of(out) and g.TREE_SECRET in reason_of(out), out
    assert secs < LIMIT, secs


@POSIX_ONLY
@pytest.mark.parametrize("agent", ["claude", "gemini"])
@pytest.mark.parametrize("glob", [None, "*.py"])
def test_a26_a_built_in_search_with_no_path_is_denied(agent, glob, p_proj, isolated):
    installed(isolated)
    event = search_tool_event(agent, "", p_proj)
    key = "dir_path" if agent == "gemini" else "path"
    del event["tool_input"][key]
    if glob:
        event["tool_input"]["glob"] = glob
    denied, out, _ = hook(agent, event, p_proj)
    assert denied, out


@POSIX_ONLY
@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("command", A26_ALLOWED)
def test_a26_narrowed_allowed(agent, command, p_proj, isolated):
    installed(isolated)
    denied, out, secs = hook(agent, shell_event(agent, command, p_proj), p_proj)
    assert not denied, (command, out)
    assert secs < LIMIT, secs


@pytest.mark.parametrize("agent", ["claude", "gemini"])
def test_a26_a_built_in_search_on_src_is_allowed(agent, p_proj, isolated):
    installed(isolated)
    denied, out, _ = hook(agent, search_tool_event(agent, "src", p_proj), p_proj)
    assert not denied, out


def test_a26_exclude_env_is_denied_by_the_shell_word_rule(p_proj, isolated):
    """SPEC A26 lists `grep -rn foo . --exclude=.env` as allowed. The tree rule allows it, but
    the shell-word rule (3a) reads the word `.env` and denies the call as naming a secret
    file, as S7 says it reads every word. Recorded here; the spec is to be corrected."""
    installed(isolated)
    command = "grep -rn foo . --exclude=.env"
    g._home[0] = str(isolated)
    [search] = g.search_targets(command, str(p_proj), command)
    rules = g.parse_patterns(g.DEFAULT_PATTERNS)
    assert g.search_trees([search], rules, time.monotonic() + 5) is None  # the tree rule
    denied, out, _ = hook("claude", shell_event("claude", command, p_proj), p_proj)
    assert denied and "names a secret file (.env)" in reason_of(out)


@POSIX_ONLY
@pytest.mark.parametrize("command", A26_DENIED)
def test_a26_after_env_is_deleted_the_top_is_allowed(command, p_proj, isolated):
    (p_proj / ".env").unlink()
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", command, p_proj), p_proj)
    assert not denied, (command, out)


@POSIX_ONLY
@pytest.mark.parametrize("command", GIT_GREP_DISK_ONLY)
def test_a26_git_grep_on_the_index_or_a_revision_is_denied_with_message_e(
    command, p_proj, isolated
):
    if command.endswith("--"):
        (p_proj / "HEAD").mkdir()  # SPEC A26: a folder named like the revision
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", command, p_proj), p_proj)
    assert denied and g.GIT_GREP_UNCHECKED in reason_of(out), (command, out)
    assert "secretfiles" not in reason_of(out)


@pytest.mark.parametrize("text", SEARCH_TEXTS)
def test_a26_the_search_text_never_changes_the_tree_rule(text, p_proj, isolated):
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", f"{text} src", p_proj), p_proj)
    assert not denied, (text, out)
    top = hook("claude", shell_event("claude", text, p_proj), p_proj)
    plain = hook("claude", shell_event("claude", "rg foo", p_proj), p_proj)
    assert top[0] and reason_of(top[1]) == reason_of(plain[1]), (text, top[1])


# --- A27: invariance --------------------------------------------------------------------------


def _plant(rel, text):
    def plant(proj, home):
        base = home if rel.startswith("~/") else proj
        path = base / rel[2:] if rel.startswith("~/") else base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(text)

    return plant


def _plant_gitconfig(proj, home):
    (home / "excl").write_text("!.env\n")
    (home / ".gitconfig").write_text(f"[core]\n\texcludesFile = {home / 'excl'}\n")


def _plant_nested(proj, home):
    (proj / "sub" / ".git").mkdir(parents=True)


def _plant_state(value):
    def plant(proj, home):
        state = {} if value is None else {"ripgrep_config": value}
        (home / ".denypeek" / "guard-state.json").write_text(json.dumps(state))

    return plant


PLANTS = [
    ("ignore !.env", _plant(".ignore", "!.env\n")),
    ("rgignore !\\.env", _plant(".rgignore", "!\\.env\n")),
    ("gitignore !*", _plant(".gitignore", "!*\n")),
    ("info/exclude", _plant(".git/info/exclude", "!.env\n")),
    ("nested .git", _plant_nested),
    ("global git ignore", _plant("~/.config/git/ignore", "!.env\n")),
    ("gitconfig excludesFile", _plant_gitconfig),
    ("HOME=", "HOME={home}/elsewhere "),
    ("RIPGREP_CONFIG_PATH=", "RIPGREP_CONFIG_PATH={home}/rc "),
    ("ripgrep key unset", _plant_state("unset")),
    ("ripgrep key set", _plant_state("set")),
    ("ripgrep key junk", _plant_state(["x"])),
]


@POSIX_ONLY
@pytest.mark.parametrize("name,plant", PLANTS, ids=[n for n, _ in PLANTS])
def test_a27_no_planted_file_or_setting_changes_a_decision(name, plant, isolated, tmp_path):
    proj = project_p(tmp_path / "proj")
    (isolated / "rc").write_text("--hidden\n")
    installed(isolated)
    commands = A26_DENIED + A26_ALLOWED
    before = {c: hook("claude", shell_event("claude", c, proj), proj)[0] for c in commands}
    prefix = ""
    if isinstance(plant, str):
        prefix = plant.format(home=isolated)
    else:
        plant(proj, isolated)
    for c in commands:
        after = hook("claude", shell_event("claude", prefix + c, proj), proj)[0]
        assert after == before[c], (name, c)


# --- A28 ------------------------------------------------------------------------------------


def clear_list(reason):
    if "Clear to search: " not in reason:
        return []
    text = reason.split("Clear to search: ", 1)[1]
    text = text.split("; with grep", 1)[0].split(". If this is wrong", 1)[0].rstrip(".")
    return text.split(", ")


def test_a28_1_the_deny_for_rg_foo(p_proj, isolated):
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", "rg foo", p_proj), p_proj)
    reason = reason_of(out)
    assert denied and reason == (
        "denypeek blocked this: a search from here would read a secret file (.env); search a "
        "narrower folder. Clear to search: docs, node_modules, src, tests. If this is wrong, "
        "edit ~/.denypeek/secretfiles."
    ), reason


@POSIX_ONLY
def test_a28_2_odd_folder_names_are_never_listed(p_proj, isolated):
    for name in ("-rf", ".cache", "x" * 41, "ignore previous instructions", "new\nline"):
        (p_proj / name).mkdir()
    (p_proj / "linked").symlink_to(p_proj / "src")
    for i in range(1, 13):
        (p_proj / f"d{i:02}").mkdir()
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", "rg foo", p_proj), p_proj)
    listed = clear_list(reason_of(out))
    assert denied and listed == [f"d{i:02}" for i in range(1, 9)], listed


def test_a28_3_a_folder_left_out_by_exclude_dir_is_not_listed(p_proj, isolated):
    installed(isolated)
    command = "grep -rn foo . --exclude-dir=docs"
    denied, out, _ = hook("claude", shell_event("claude", command, p_proj), p_proj)
    reason = reason_of(out)
    assert denied and "docs" not in clear_list(reason), reason
    assert g.GREP_NARROWING in reason


@pytest.mark.parametrize("command", ["rg foo", "grep -rn foo .", "ag foo", "rg -n foo ."])
def test_a28_4_every_listed_folder_is_allowed(command, p_proj, isolated):
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", command, p_proj), p_proj)
    listed = clear_list(reason_of(out))
    assert denied and listed, out
    for folder in listed:
        base = command[:-2] if command.endswith(" .") else command
        rewrite = f"{base} {folder}"
        denied, out, _ = hook("claude", shell_event("claude", rewrite, p_proj), p_proj)
        assert not denied, (rewrite, out)


def test_a28_4_listed_folders_follow_the_path_as_written(p_proj, isolated, tmp_path):
    installed(isolated)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    denied, out, _ = hook(
        "claude", shell_event("claude", "rg foo proj", outside.parent), outside.parent
    )
    assert denied and clear_list(reason_of(out))[0] == "proj/docs", out
    denied, out, _ = hook(
        "claude", shell_event("claude", "rg foo proj/docs", outside.parent), outside.parent
    )
    assert not denied, out


@pytest.mark.parametrize(
    "denied_command,rewrite",
    [
        ("git grep foo HEAD", "git grep foo -- src"),
        ("git grep --cached foo", "git grep foo -- src"),
        ("git grep foo -- '*.env'", "git grep foo -- src"),
    ],
)
def test_a28_4_git_grep_rewrites_are_allowed(denied_command, rewrite, p_proj, isolated):
    installed(isolated)
    assert hook("claude", shell_event("claude", denied_command, p_proj), p_proj)[0]
    denied, out, _ = hook("claude", shell_event("claude", rewrite, p_proj), p_proj)
    assert not denied, out


@pytest.mark.parametrize("command", ["rg foo ~", "grep -r foo ~", "rg foo ~/.denypeek"])
def test_a28_5_searching_the_home_folder_is_denied_without_a_walk(command, isolated, tmp_path):
    installed(isolated)
    filler(isolated / "big", g.WALK_LIMIT // 20)  # a walk would be slow; S6 needs none
    denied, out, secs = hook("claude", shell_event("claude", command, tmp_path), tmp_path)
    reason = reason_of(out)
    assert denied and "which denypeek protects so an agent cannot switch the guard off" in reason
    assert "Clear to search" not in reason and "secretfiles" not in reason
    assert secs < LIMIT


def test_a28_5_a_built_in_search_on_the_home_folder_is_denied(isolated, tmp_path):
    installed(isolated)
    denied, out, _ = hook("claude", search_tool_event("claude", str(isolated), tmp_path), tmp_path)
    assert denied and "denypeek protects" in reason_of(out), out


CERTIFI_NEAR_MISSES = [
    "certifi/cacert.pem",
    "lib/site-packages/certifi/sub/cacert.pem",
    "lib/site-packages/certifi/other.pem",
    "lib/site-packages/Certifi/cacert.pem",
    "lib/site-packages/certifi/CACERT.PEM",
    "lib/site-packages/notcertifi/cacert.pem",
]


@pytest.mark.parametrize("path", CERTIFI_NEAR_MISSES)
def test_a28_6_certifi_near_misses_count(path, isolated, tmp_path):
    proj = tmp_path / "proj"
    (proj / path).parent.mkdir(parents=True)
    (proj / path).write_text("x\n")
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", "rg foo", proj), proj)
    assert denied, (path, out)


@POSIX_ONLY
def test_a28_6_a_symbolic_link_at_the_certifi_path_counts(isolated, tmp_path):
    proj = tmp_path / "proj"
    certifi = proj / "lib" / "site-packages" / "certifi"
    certifi.mkdir(parents=True)
    (tmp_path / "real.pem").write_text("x\n")
    (certifi / "cacert.pem").symlink_to(tmp_path / "real.pem")
    installed(isolated)
    assert hook("claude", shell_event("claude", "rg foo", proj), proj)[0]


@pytest.mark.parametrize(
    "path",
    [
        "venv/lib/python3.12/site-packages/certifi/cacert.pem",
        "venv/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem",
        "usr/lib/python3/dist-packages/certifi/cacert.pem",
    ],
)
def test_a28_6_the_real_certifi_shape_does_not_count_unless_named(path, isolated, tmp_path):
    proj = tmp_path / "proj"
    (proj / path).parent.mkdir(parents=True)
    (proj / path).write_text("public certificate list\n")
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", "rg foo", proj), proj)
    assert not denied, out
    denied, out, _ = hook("claude", shell_event("claude", f"cat {path}", proj), proj)
    assert denied, out


def test_a28_no_message_holds_more_than_two_paths(isolated, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    for name in (".env", ".env.local", "id_rsa", "server.pem"):
        (proj / name).write_text("x\n")
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", "rg foo", proj), proj)
    reason = reason_of(out)
    assert denied and "(.env, .env.local, and more)" in reason, reason


# --- A29 ------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def project_q(tmp_path_factory):
    if os.name == "nt":
        pytest.skip("A29 runs on macOS and Linux")
    q = tmp_path_factory.mktemp("q") / "proj"
    (q / ".git").mkdir(parents=True)
    (q / "src").mkdir()
    (q / "src" / "app.py").write_text("x\n")
    filler(q / "node_modules", g.WALK_LIMIT + 1_000)
    return q


@POSIX_ONLY
@pytest.mark.parametrize("which", ["rg foo", "grep -rn foo .", "built-in"])
def test_a29_past_the_limit_denied_with_message_b(which, project_q, isolated):
    installed(isolated)
    if which == "built-in":
        event = search_tool_event("claude", "", project_q)
        del event["tool_input"]["path"]
    else:
        event = shell_event("claude", which, project_q)
    denied, out, secs = hook("claude", event, project_q)
    reason = reason_of(out)
    assert denied and reason.startswith(f"denypeek blocked this: {g.TREE_TOO_BIG}"), reason
    assert "src" in clear_list(reason) and "secretfiles" not in reason
    assert secs < LIMIT, secs


@POSIX_ONLY
@pytest.mark.parametrize("command", ["rg foo src", "grep -rn foo . --exclude-dir=node_modules"])
def test_a29_narrowed_allowed(command, project_q, isolated):
    installed(isolated)
    denied, out, secs = hook("claude", shell_event("claude", command, project_q), project_q)
    assert not denied, (command, out)
    assert secs < LIMIT, secs


# --- S2: start folders that cannot be told -------------------------------------------------------


@pytest.mark.parametrize(
    "command,reason",
    [
        ("echo src | xargs grep -rn foo", "undetermined"),
        ("rg foo $DIR", "undetermined"),
        ("grep -rn foo `pwd`", "any"),  # split at the backtick: the working folder, (a)
        ("ack --files-from=list foo", "undetermined"),
        ("ack -x foo < list", "undetermined"),
        ("git --git-dir=/tmp/x grep foo -- src", "git"),
        ("git --work-tree=/tmp grep foo -- src", "git"),
        ("GIT_DIR=/tmp/x git grep foo -- src", "git"),
        ("env GIT_WORK_TREE=/tmp git grep foo -- src", "git"),
        ("export GIT_INDEX_FILE=/tmp/i; git grep foo -- src", "git"),
        ("git grep foo -- ':(glob)src/**'", "git"),
        ("git grep foo -- ':!docs'", "git"),
    ],
)
def test_s2_folders_that_cannot_be_told_are_denied(command, reason, p_proj, isolated):
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", command, p_proj), p_proj)
    text = {"undetermined": g.TREE_UNDETERMINED, "git": g.GIT_GREP_UNCHECKED, "any": ""}[reason]
    assert denied and text in reason_of(out), (command, out)


@pytest.mark.parametrize("command", ["rg --files", "rg --type-list", "ag -g app", "rg --version"])
def test_s1_forms_that_read_no_contents_are_not_searches(command, p_proj, isolated):
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", command, p_proj), p_proj)
    assert not denied, (command, out)


def test_s5_the_cap_counts_all_start_folders_together(isolated, tmp_path, monkeypatch):
    for d in ("a", "b"):
        filler(tmp_path / d, 600)
    g._home[0] = str(isolated)
    monkeypatch.setattr(g, "WALK_LIMIT", 1_000)
    rules = g.parse_patterns(g.DEFAULT_PATTERNS)
    one = [g.Search(str(tmp_path / "a"))]
    both = one + [g.Search(str(tmp_path / "b"))]
    assert g.search_trees(one, rules, time.monotonic() + 9) is None
    assert g.search_trees(both, rules, time.monotonic() + 9).startswith(g.TREE_TOO_BIG)


# --- finding the folders a search reads --------------------------------------------------------


@pytest.mark.parametrize(
    "command,found",
    [
        ("rg foo", True),
        ("rg -l foo", True),
        ("ag foo", True),
        ("ack foo", True),
        ("git grep foo", True),
        ("git -C . grep foo", True),
        ("grep -rn foo .", True),
        ("ugrep -r foo .", True),
        ("grep -n foo file", False),
    ],
)
def test_each_search_tool_is_seen(command, found, tmp_path):
    (tmp_path / "file").write_text("x\n")
    assert bool(g.search_targets(command, str(tmp_path), command)) == found, command


def test_grep_narrowing_reads_literal_values_without_a_slash(tmp_path):
    cmd = "grep -r foo . --include='*.py' --exclude .env --exclude-dir=node_modules --include=a/b"
    [s] = g.search_targets(cmd, str(tmp_path), cmd)
    assert s.includes == ["*.py"] and s.excludes == [".env"] and s.exclude_dirs == ["node_modules"]


@pytest.mark.parametrize(
    "command,folders",
    [
        ("grep -r -e foo src", ["src"]),
        ("grep -re foo src", ["src"]),
        ("grep -rf pats src lib", ["src", "lib"]),
        ("rg -e foo src lib", ["src", "lib"]),
        ("grep -r foo -- src", ["src"]),
    ],
)
def test_with_a_pattern_option_every_word_is_a_path(command, folders, tmp_path):
    for f in ("src", "lib", "foo"):
        (tmp_path / f).mkdir()
    got = sorted(os.path.basename(s.folder) for s in g.search_targets(command, str(tmp_path)))
    assert got == sorted(folders), command


# --- A27: the tool tier ----------------------------------------------------------------------


def _rg():
    return os.environ.get("DENYPEEK_TEST_RG") or shutil.which("rg")


def _require_tools():
    return os.environ.get("DENYPEEK_TREE_REQUIRE") == "1"


@pytest.fixture
def tools(tmp_path):
    """A bin folder with the real tools, for an empty environment."""
    if os.name == "nt":
        pytest.skip("A27 runs on macOS and Linux")
    rg = _rg()
    if not rg:
        if _require_tools():
            pytest.fail("ripgrep is required for the tool tier (DENYPEEK_TREE_REQUIRE=1)")
        pytest.skip("ripgrep not found: the tool tier runs in CI's oracle job")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "rg").symlink_to(rg)
    for name in ("ag",):
        path = shutil.which(name)
        if path:
            (bindir / name).symlink_to(path)
    return bindir


def tool_prints_marker(command: str, cwd: Path, bindir: Path, home: Path) -> bool:
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(home)}
    proc = subprocess.run(
        ["/bin/sh", "-c", command],
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
    )
    return MARK in proc.stdout.decode(errors="replace")


def tier_project(tmp_path: Path, change=None) -> Path:
    """Project P (SPEC A27), with node_modules and virtualenv secrets added so the widening
    flags have something to find."""
    proj = project_p(tmp_path / "proj")
    (proj / "node_modules" / "pkg" / ".env").write_text(f"{MARK}\n")
    (proj / "node_modules" / "pkg" / "test.pem").write_text(f"{MARK}\n")
    (proj / "venv" / "lib").mkdir(parents=True)
    (proj / "venv" / ".gitignore").write_text("*\n")
    (proj / "venv" / "lib" / "cacert.pem").write_text(f"{MARK}\n")
    if change:
        change(proj)
    return proj


def _top(name):
    return lambda p: (p / name).write_text(f"{MARK}\n")


def _ignore_line(file, line):
    def change(p):
        with open(p / file, "a") as f:
            f.write(line + "\n")

    return change


def _no_git(p):
    shutil.rmtree(p / ".git")


def _no_node_modules_line(p):
    (p / ".gitignore").write_text(".env\n")


def _real_git(tracked_env=False):
    def change(p):
        shutil.rmtree(p / ".git")
        env = {"PATH": "/usr/bin:/bin", "HOME": str(p)}
        subprocess.run(["git", "init", "-q", "."], cwd=p, env=env, check=True)
        subprocess.run(["git", "add", "src", ".gitignore"], cwd=p, env=env, check=True)
        if tracked_env:
            subprocess.run(["git", "add", "-f", ".env"], cwd=p, env=env, check=True)

    return change


def _rc_hidden(p):
    (p / "rc").write_text("--hidden\n")


TIER = [
    ("grep -rn M .", None),
    ("grep -rn M node_modules", None),
    ("grep -r M . --include='.env*'", None),
    ("grep -r M . --exclude-dir=src", None),
    ("rg --hidden M", None),
    ("rg -uu M", None),
    ("rg --no-ignore M", None),
    ("rg -g '*' M", None),
    ("rg M", _top("server.pem")),
    ("rg M", _ignore_line(".gitignore", "!.env")),
    ("rg M", _ignore_line(".ignore", "!.env")),
    ("rg M", _ignore_line(".rgignore", "!.env")),
    ("RIPGREP_CONFIG_PATH=rc rg M", _rc_hidden),
    ("rg M", _no_git),
    ("git grep M", _no_git),
    ("rg M", _no_node_modules_line),
    ("rg M", _top(".ENV")),
    ("rg M", _top("Server.PEM")),
    ("git grep M", _real_git(tracked_env=True)),
    ("git grep --no-index M", _real_git()),
    ("git grep --untracked M", _real_git()),
    ("ag M", None),
    ("ag -u M", None),
    ("ag --hidden M", None),
] + [(c.replace("foo", "M"), None) for c in A26_ALLOWED + A26_DENIED]


@POSIX_ONLY
@pytest.mark.parametrize("command,change", TIER, ids=[f"{i}:{c}" for i, (c, _) in enumerate(TIER)])
def test_a27_when_the_real_tool_prints_a_marker_the_hook_denies(
    command, change, tools, isolated, tmp_path
):
    if command.startswith("ag ") and not (tools / "ag").exists():
        pytest.skip("ag is not installed")
    proj = tier_project(tmp_path, change)
    installed(isolated)
    command = command.replace(" M", f" {MARK}")
    prints = tool_prints_marker(command, proj, tools, isolated)
    denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
    if prints:
        assert denied, (command, "the real tool read a secret file, the hook allowed it")
    if change is None and command in [c.replace("foo", MARK) for c in A26_ALLOWED]:
        assert not prints, (command, "a must-allow command printed a marker")
        assert not denied, (command, "a must-allow command was denied", out)


# --- security review of the tree rule: reproductions -----------------------------------------
# Each case: the real tool (where installed) and the hook on the same command. The hook must
# deny every one: real ripgrep 14.1.1 read the secret in each.


def review_project(tmp_path: Path, gitignore="node_modules/\n.env\n") -> Path:
    proj = tmp_path / "proj"
    (proj / ".git" / "info").mkdir(parents=True)
    (proj / ".gitignore").write_text(gitignore)
    (proj / ".env").write_text(f"KEY={MARK}\n")
    (proj / "src").mkdir()
    (proj / "src" / "app.py").write_text("print(1)\n")
    (proj / "venv" / "lib").mkdir(parents=True)
    (proj / "venv" / ".gitignore").write_text("*\n")
    (proj / "venv" / "lib" / "cacert.pem").write_text(f"{MARK}\n")
    (proj / "node_modules" / "pkg").mkdir(parents=True)
    (proj / "node_modules" / "pkg" / "test.pem").write_text(f"{MARK}\n")
    return proj


def _write(rel, text, append=False):
    def change(proj, home):
        base = home if rel.startswith("~/") else proj
        path = base / rel[2:] if rel.startswith("~/") else base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a" if append else "w") as f:
            f.write(text)

    return change


def _excludes_file(proj, home):
    (home / "excl").write_text("!.env\n")
    (home / ".gitconfig").write_text(f"[core]\n\texcludesFile = {home / 'excl'}\n")


IGNORE_CASES = [
    ("node_modules/\n.env\n", _write(".ignore", "!\\.env\n"), "rg M"),
    ("node_modules/\n.env\n", _write(".ignore", "!.e[^x]v\n"), "rg M"),
    ("node_modules/\n", _write(".git/info/exclude", "!.env\n"), "rg M"),
    ("node_modules/\n", _write("~/.config/git/ignore", "!.env\n"), "rg M"),
    ("node_modules/\n", _excludes_file, "rg M"),
    ("node_modules/\n.env\n", _write(".ignore", "!node_modules/\n"), "rg M"),
    ("node_modules/\n.env\n", _write(".gitignore", "!node_module*\n", append=True), "rg M"),
    ("node_modules/\n.env\n", _write("venv/.rgignore", "!*\n"), "rg M"),
    # one call: the command writes the ignore file and searches
    ("node_modules/\n.env\n", None, "printf '!.e?v\\n' > .ignore; rg M"),
    ("node_modules/\n.env\n", None, "sed -i '' '/node_modules/d' .gitignore; rg M"),
]


@POSIX_ONLY
@pytest.mark.parametrize(
    "gitignore,change,command", IGNORE_CASES, ids=[f"ignore-{i}" for i in range(len(IGNORE_CASES))]
)
def test_ignore_file_reproductions_are_denied(gitignore, change, command, isolated, tmp_path):
    proj = review_project(tmp_path, gitignore)
    installed(isolated)
    if change:
        change(proj, isolated)
    command = command.replace(" M", f" {MARK}")
    denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
    rg = _rg()
    if rg and "sed -i" not in command:  # BSD sed syntax; the hook side is what matters
        bindir = tmp_path / "bin"
        bindir.mkdir()
        (bindir / "rg").symlink_to(rg)
        assert tool_prints_marker(command, proj, bindir, isolated), "fixture: rg reads nothing"
    assert denied, (command, out)


OPTION_CASES = [
    "grep -r --context {m} {proj}",
    "grep -r --context=2 {m} {proj}",
    "git grep -O {m} {proj}",
    "git grep --open-files-in-pager {m} {proj}",
    "ag -C {m} {proj}",
    "ag --context {m} {proj}",
]


@POSIX_ONLY
@pytest.mark.parametrize("template", OPTION_CASES)
def test_an_optional_value_never_hides_the_folder(template, isolated, tmp_path):
    proj = review_project(tmp_path)
    clean = tmp_path / "clean"
    clean.mkdir()
    installed(isolated)
    command = template.format(m=MARK, proj=proj)
    if command.startswith("grep "):
        prints = tool_prints_marker(command, clean, tmp_path, isolated)
        assert prints, "fixture: grep reads nothing"
    denied, out, _ = hook("claude", shell_event("claude", command, clean), clean)
    assert denied, (command, out)


def ignored_only_project(tmp_path: Path, home: Path) -> Path:
    """A real git repository whose secret files are only in gitignored folders."""
    proj = review_project(tmp_path)
    (proj / ".env").unlink()
    shutil.rmtree(proj / ".git")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home)}
    subprocess.run(["git", "init", "-q", "."], cwd=proj, env=env, check=True)
    subprocess.run(["git", "add", "src", ".gitignore"], cwd=proj, env=env, check=True)
    return proj


# git, ag and getopt-style greps accept any unambiguous prefix of a long option
ABBREVIATED = [
    "git grep --no-ind {m}",
    "git grep --untr --no-exclude-st {m}",
    "git grep --no-exclude-s {m}",
    "ag --unres {m}",
    "ag --skip-vcs {m}",
    "ag --all-ty {m}",
    "grep --recur {m} .",
    "grep --rec {m} .",
    "grep --deref {m} .",
    "grep --dir=recurse {m} .",
    "grep --direc recurse {m} .",
]


@POSIX_ONLY
@pytest.mark.parametrize("template", ABBREVIATED)
def test_abbreviated_long_options_are_seen(template, isolated, tmp_path):
    proj = ignored_only_project(tmp_path, isolated)
    installed(isolated)
    command = template.format(m=MARK)
    # --deref is GNU only (BSD grep has no --dereference-recursive); --no-exclude-standard
    # widens git grep only together with --untracked. The hook denies both regardless.
    no_check = ("grep --deref {m} .", "git grep --no-exclude-s {m}")
    if template.startswith(("git", "grep")) and template not in no_check:
        assert tool_prints_marker(command, proj, tmp_path, isolated), "fixture: tool reads nothing"
    denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
    assert denied, (command, out)


# A search behind a wrapper command, or after `cd`, reads what it reads without one.
WRAPPED = [
    ("env grep -r {m} .", "proj"),
    ("env FOO=1 grep -r {m} .", "proj"),
    ("command grep -r {m} .", "proj"),
    ("nice grep -r {m} .", "proj"),
    ("nice -n 5 grep -r {m} .", "proj"),
    ("nohup grep -r {m} .", "proj"),
    ("timeout 5 grep -r {m} .", "proj"),
    ("timeout -s KILL 5 grep -r {m} .", "proj"),
    ("time grep -r {m} .", "proj"),
    ("stdbuf -oL grep -r {m} .", "proj"),
    ("exec grep -r {m} .", "proj"),
    ("sudo grep -r {m} .", "proj"),
    ("echo . | xargs grep -r {m}", "proj"),
    ("xargs -n1 grep -r {m} < list", "proj"),
    ("cd {proj} && grep -r {m} .", "clean"),
    ("cd {proj}; rg --hidden {m}", "clean"),
    ("(cd {proj} && grep -r {m} .)", "clean"),
    ("env -C {proj} grep -r {m} .", "clean"),
]
REAL_RUN = {
    "env grep -r {m} .",
    "command grep -r {m} .",
    "nice grep -r {m} .",
    "timeout 5 grep -r {m} .",
    "echo . | xargs grep -r {m}",
    "cd {proj} && grep -r {m} .",
}


@POSIX_ONLY
@pytest.mark.parametrize("template,where", WRAPPED)
def test_wrappers_and_cd_do_not_hide_a_search(template, where, isolated, tmp_path):
    proj = review_project(tmp_path)
    clean = tmp_path / "clean"
    clean.mkdir()
    installed(isolated)
    cwd = proj if where == "proj" else clean
    command = template.format(m=MARK, proj=proj)
    if template in REAL_RUN:
        assert tool_prints_marker(command, cwd, tmp_path, isolated), "fixture: reads nothing"
    denied, out, _ = hook("claude", shell_event("claude", command, cwd), cwd)
    assert denied, (command, out)


@POSIX_ONLY
def test_xargs_message_suggests_an_allowed_rewrite(isolated, tmp_path):
    proj = review_project(tmp_path)
    installed(isolated)
    denied, out, _ = hook(
        "claude", shell_event("claude", "echo src | xargs grep -rn foo", proj), proj
    )
    assert denied and g.TREE_UNDETERMINED in reason_of(out), out
    denied, out, _ = hook("claude", shell_event("claude", "grep -rn foo src", proj), proj)
    assert not denied, out


@POSIX_ONLY
@pytest.mark.parametrize(
    "command", ["git grep {m} HEAD", "git grep {m} -- '*.env'", "git grep -e {m} main"]
)
def test_git_grep_with_a_revision_or_pathspec_is_denied(command, isolated, tmp_path):
    """A revision reads committed files, even ones deleted from disk; a pathspec glob reads
    tracked files the walk would not pick. The hook cannot list either."""
    proj = ignored_only_project(tmp_path, isolated)
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", command.format(m=MARK), proj), proj)
    assert denied, out
    assert "git grep" in reason_of(out)
    denied, out, _ = hook("claude", shell_event("claude", f"git grep {MARK} -- src", proj), proj)
    assert not denied, out  # the rewrite the message suggests


# --- second security review: reproductions, each must be denied ------------------------------


def _nested_repo(proj, home):
    (proj / "sub" / ".git").mkdir(parents=True)
    (proj / "sub" / ".env").write_text(f"{MARK}\n")
    (proj / "sub" / "node_modules" / "pkg").mkdir(parents=True)
    (proj / "sub" / "node_modules" / "pkg" / "t.pem").write_text(f"{MARK}\n")
    (proj / "sub" / ".git" / "info").mkdir()
    (proj / "sub" / ".git" / "info" / "exclude").write_text("!.env\n")


def _fake_home_ignore(proj, home):
    (home / "fake" / ".config" / "git").mkdir(parents=True)
    (home / "fake" / ".config" / "git" / "ignore").write_text("!.env\n")


def _template_ignore(proj, home):
    (proj / "tmpl").mkdir()
    (proj / "tmpl" / ".ignore").write_text("!.env\n")


SECOND_REVIEW = [
    (_nested_repo, "rg M"),
    (_nested_repo, "rg M sub"),
    (_fake_home_ignore, "HOME={home}/fake rg M"),
    (_fake_home_ignore, "env HOME={home}/fake rg M"),
    (None, "printf '!.e?v\\n' > .ign\"\"ore; rg M"),
    (_template_ignore, "cp -r tmpl/. . ; rg M"),
    (None, "git checkout -q b2 && rg M"),
]


@POSIX_ONLY
@pytest.mark.parametrize("change,command", SECOND_REVIEW)
def test_second_review_reproductions_are_denied(change, command, isolated, tmp_path):
    proj = review_project(tmp_path, "node_modules/\n")
    installed(isolated)
    if change:
        change(proj, isolated)
    command = command.replace(" M", f" {MARK}").replace("{home}", str(isolated))
    denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
    assert denied, (command, out)


def _deleted_env_repo(tmp_path, home):
    proj = tmp_path / "proj"
    proj.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    (proj / ".env").write_text(f"{MARK}\n")
    (proj / "src").mkdir()
    (proj / "src" / "a.py").write_text("x\n")
    for args in (["init", "-q", "."], ["add", "-f", ".env", "src"], ["commit", "-qm", "c"]):
        subprocess.run(["git", *args], cwd=proj, env=env, check=True)
    (proj / ".env").unlink()
    return proj, env


@POSIX_ONLY
@pytest.mark.parametrize(
    "command", ["git grep {m} HEAD --", "git grep --cached {m}", "git grep --cach {m}"]
)
def test_git_grep_reading_a_revision_or_the_index_is_denied(command, isolated, tmp_path):
    proj, env = _deleted_env_repo(tmp_path, isolated)
    (proj / "HEAD").mkdir()  # a folder named like the revision
    installed(isolated)
    command = command.format(m=MARK)
    proc = subprocess.run(["/bin/sh", "-c", command], cwd=proj, env=env, capture_output=True)
    assert MARK in proc.stdout.decode(), "fixture: git reads nothing"
    denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
    assert denied, (command, out)


@POSIX_ONLY
@pytest.mark.parametrize("glob", ["*", "**/*", "*.pem"])
def test_an_agents_search_tool_with_a_glob_is_walked_in_full(glob, isolated, tmp_path):
    proj = ignored_only_project(tmp_path, isolated)
    installed(isolated)
    event = search_tool_event("claude", ".", proj)
    event["tool_input"]["glob"] = glob
    denied, out, _ = hook("claude", event, proj)
    assert denied, out


@pytest.mark.parametrize(
    "command",
    [
        'rg "export function load"',
        'rg "type alias "',
        "rg exclude",
        "rg -n 'GIT_DIR'",
        "rg -n '.gitignore'",
        "grep -rn 'HOME=' .",
        'rg "f(){ x; }"',
    ],
)
def test_the_search_text_never_changes_the_decision(command, isolated, tmp_path):
    proj = a26_project(tmp_path / "proj", entries=50, secrets=False)
    (proj / ".gitignore").write_text("node_modules/\n!.env.example\n# keep it!\n")
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
    assert not denied, (command, out)


# --- review of the simple rule: redirections (a redirect target is never a path) -----------------


def _ugrep():
    return os.environ.get("DENYPEEK_TEST_UGREP") or shutil.which("ugrep")


REDIRECTS = [
    "rg -uu {m} 2>/dev/null",
    "rg -uu {m} >/dev/stdout",
    "rg -uu {m} 2>&1",
    "rg -uu {m} 2> /dev/null",
    "rg -uu {m} >> {log}",
    "rg -uu {m} &> {log}",
    "rg -uu {m} &>>{log}",
    "rg -uu {m} > {log} 2>&1",
    "rg -uu {m} 3>&2",
    "rg -uu {m} < /dev/null",
    "rg -uu {m} <<< x",
    "rg -uu {m} 1>{log}",
    "grep -r {m} 2>/dev/null",
    "grep -r {m} . 2>/dev/null",
    # as Claude Code's shell runs `grep`: ugrep with --hidden (plain ugrep skips hidden names)
    "ugrep -r --hidden {m} 2>/dev/null",
]


@POSIX_ONLY
@pytest.mark.parametrize("template", REDIRECTS)
def test_a_redirection_is_never_a_path(template, isolated, tmp_path):
    proj = project_p(tmp_path / "proj")
    installed(isolated)
    command = template.format(m=MARK, log=tmp_path / "log")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    tool = (
        _rg() if template.startswith("rg") else _ugrep() if template.startswith("ugrep") else None
    )
    if tool:
        (bindir / template.split()[0]).symlink_to(tool)
    # The real tool's output is seen only when it stays on stdout; with `<<<` rg reads stdin,
    # and BSD grep -r with no path reads stdin too. The hook denies every form regardless.
    on_stdout = ("2>/dev/null", ">/dev/stdout", "2>&1", "2> /dev/null", "3>&2")
    if (
        (tool or template.startswith("grep -r {m} ."))
        and template.endswith(on_stdout)
        and "{log}" not in template
    ):
        assert tool_prints_marker(command, proj, bindir, isolated), (
            "fixture: reads nothing",
            command,
        )
    denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
    assert denied, (command, out)


@pytest.mark.parametrize(
    "command",
    ["rg foo src 2>/dev/null", "rg foo src > {log} 2>&1", "grep -rn foo src 2>&1 | head -5"],
)
def test_a_redirection_after_a_clear_folder_is_allowed(command, isolated, tmp_path):
    proj = project_p(tmp_path / "proj")
    installed(isolated)
    command = command.format(log=tmp_path / "log")
    denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
    assert not denied, (command, out)


# --- review of the simple rule: a path that does not exist is not left out ------------------------


def _clean_with_sibling(tmp_path):
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "a.py").write_text("x\n")
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / ".env").write_text(f"{MARK}\n")
    return proj


@POSIX_ONLY
@pytest.mark.parametrize(
    "command",
    [
        "mv ../other nn && grep -r {m} nn",
        "ln -s ../other nn && grep -r {m} nn/",
        "grep -r {m} nn",
        "rg {m} src nn",
        "grep -r {m} src/nope*",
    ],
)
def test_a_search_path_that_does_not_exist_is_denied(command, isolated, tmp_path):
    proj = _clean_with_sibling(tmp_path)
    installed(isolated)
    command = command.format(m=MARK)
    denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
    # the mv and ln forms are also denied for writing before the search, which comes first
    expected = g.TREE_WRITES if command.startswith(("mv", "ln")) else g.TREE_UNDETERMINED
    assert denied and expected in reason_of(out), (command, out)
    if command.startswith(("mv", "ln")):
        assert tool_prints_marker(command, proj, tmp_path, isolated), "fixture: reads nothing"


# --- review of the simple rule: the same command writes before it searches ---------------------


@POSIX_ONLY
@pytest.mark.parametrize(
    "command",
    [
        "cp -r ../other/. src/ && grep -r {m} src",
        "cp -r ../other/. src/; rg -uu {m} src",
        "echo KEY=1 > src/.env && grep -r KEY src",
        "tar xf x.tar && rg {m} src",
        "git checkout -q b2 && rg {m} src",
        "rsync -a ../other/ src/ && rg -uu {m} src",
        "cp -r ../other/. src/ && bash -c 'grep -r {m} src'",
    ],
)
def test_a_command_that_writes_before_it_searches_is_denied(command, isolated, tmp_path):
    proj = _clean_with_sibling(tmp_path)
    installed(isolated)
    command = command.format(m=MARK)
    denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
    assert denied, (command, out)
    if command.startswith("cp -r ../other/. src/ && grep"):
        assert tool_prints_marker(command, proj, tmp_path, isolated), "fixture: reads nothing"


@pytest.mark.parametrize(
    "command",
    [
        "cd src && rg foo .",
        "pwd; ls; rg foo src",
        "echo start; grep -rn foo src | head -20",
        "rg foo src | sort | uniq -c",
        "true && rg foo src 2>/dev/null",
        "echo x > /dev/null && rg foo src",
    ],
)
def test_read_only_parts_before_a_search_are_allowed(command, isolated, tmp_path):
    proj = _clean_with_sibling(tmp_path)
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
    assert not denied, (command, out)


# --- review of the simple rule: a folder the walk cannot list ----------------------------------


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs POSIX permissions")
@pytest.mark.parametrize("command", ["grep -r {m} .", "rg {m}", "rg {m} locked"])
def test_a_folder_that_cannot_be_listed_denies_the_search(command, isolated, tmp_path):
    proj = _clean_with_sibling(tmp_path)
    (proj / "locked").mkdir()
    (proj / "locked" / ".env").write_text(f"{MARK}\n")
    os.chmod(proj / "locked", 0)
    try:
        installed(isolated)
        denied, out, _ = hook("claude", shell_event("claude", command.format(m=MARK), proj), proj)
    finally:
        os.chmod(proj / "locked", 0o755)
    assert denied and g.TREE_UNLISTABLE in reason_of(out), (command, out)
    assert "secretfiles" not in reason_of(out)


# --- review of the simple rule: cd ... && runs the search only in the new folder -----------------


@pytest.mark.parametrize(
    "command,allowed",
    [
        ("cd src && rg text", True),
        ("cd src && rg text .", True),
        ("cd src && cd ../tests && grep -rn text .", True),
        ("(cd src && rg text)", True),
        ("cd src; rg text", False),  # if cd fails, the search runs in the first folder
        ("cd src || rg text", False),
        ("cd $DIR && rg text", False),
        ("cd - && rg text", False),
    ],
)
def test_cd_and_then_search_walks_the_new_folder_only(command, allowed, p_proj, isolated):
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", command, p_proj), p_proj)
    assert denied != allowed, (command, out)


@pytest.mark.parametrize(
    "command,allowed",
    [
        ("cd src && rg a; rg b src", True),
        ("cd src && rg a; rg b", False),  # if cd failed, rg b runs at the top
        ("cd src && rg a && rg b", True),
    ],
)
def test_a_failed_cd_is_allowed_for_after_the_chain(command, allowed, p_proj, isolated):
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", command, p_proj), p_proj)
    assert denied != allowed, (command, out)
