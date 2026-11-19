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

# Searches that read no secret file in the A26 project: a clear subfolder, grep with literal
# excludes that leave every secret file out.
A26_ALLOWED = [
    "rg foo src",
    "rg -n foo src",
    "grep -rn foo src",
    "git grep -n foo -- src",
    "grep -rn foo . --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=venv "
    "--exclude='.env*'",
]
# Searches from the project root: each reads a secret file (.env, a virtualenv's cacert.pem
# outside certifi, files in node_modules), so each is denied with message (a).
A26_DENIED = [
    "rg foo",
    "rg -n foo .",
    "grep -rn foo .",
    "grep -rn foo . --exclude-dir=node_modules",
    "grep -rn foo . --exclude-dir=node_modules --exclude-dir=.venv --exclude='.env*'",
]


@POSIX_ONLY
@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("command", A26_ALLOWED)
def test_a26_searches_that_read_no_secret_are_allowed(agent, command, big, isolated):
    installed(isolated)
    denied, out, secs = hook(agent, shell_event(agent, command, big), big)
    assert not denied, (command, out)
    assert secs < LIMIT, secs


@POSIX_ONLY
@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("command", A26_DENIED)
def test_a26_searches_from_the_root_are_denied_with_message_a(agent, command, big, isolated):
    installed(isolated)
    denied, out, secs = hook(agent, shell_event(agent, command, big), big)
    assert denied, (command, out)
    reason = reason_of(out)
    assert g.TREE_SECRET in reason and "Clear to search: src" in reason, reason
    assert "secretfiles" not in reason
    assert secs < LIMIT, secs


@POSIX_ONLY
@pytest.mark.parametrize("agent", ["claude", "gemini"])
def test_a26_an_agents_own_search_tool_on_src_is_allowed_and_on_root_denied(agent, big, isolated):
    installed(isolated)
    denied, out, _ = hook(agent, search_tool_event(agent, "src", big), big)
    assert not denied, out
    denied, out, _ = hook(agent, search_tool_event(agent, ".", big), big)
    assert denied, out


@POSIX_ONLY
def test_a26_too_big_to_check_is_denied_with_message_b(past_cap, isolated):
    installed(isolated)
    denied, out, secs = hook("claude", shell_event("claude", "grep -rn foo .", past_cap), past_cap)
    assert denied, out
    reason = reason_of(out)
    assert reason == f"denypeek blocked this: {g.TREE_TOO_BIG}.", reason
    assert "secretfiles" not in reason and "--include" not in reason
    assert secs < LIMIT, secs


@POSIX_ONLY
@pytest.mark.parametrize(
    "command",
    [
        "rg foo src",
        "grep -rn foo src",
        "grep -rn foo . --exclude-dir=node_modules",
        # the rewrite message (b) suggests
        "grep -rn foo . --exclude-dir=node_modules --exclude-dir=.venv",
    ],
)
def test_a26_past_the_cap_narrower_searches_are_allowed(command, past_cap, isolated):
    installed(isolated)
    denied, out, secs = hook("claude", shell_event("claude", command, past_cap), past_cap)
    assert not denied, (command, out)
    assert secs < LIMIT, secs


def test_a26_a_project_with_no_secret_file_is_searched_from_the_root(isolated, tmp_path):
    proj = a26_project(tmp_path / "proj", entries=500, secrets=False)
    installed(isolated)
    for command in ("rg foo", "rg --hidden foo .", "grep -rn foo .", "git grep foo", "ag foo"):
        denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
        assert not denied, (command, out)


# --- A28 ------------------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["rg foo ~", "grep -r foo ~", "rg foo ~/.denypeek"])
def test_a28_searching_the_home_folder_is_denied_without_a_walk(command, isolated, tmp_path):
    installed(isolated)
    filler(isolated / "big", g.WALK_LIMIT // 20)  # a walk would be slow; T6 needs none
    denied, out, secs = hook("claude", shell_event("claude", command, tmp_path), tmp_path)
    assert denied, out
    assert "which denypeek protects so an agent cannot switch the guard off" in reason_of(out)
    assert "secretfiles" not in reason_of(out)
    assert secs < LIMIT


def test_a28_an_agents_search_tool_on_the_home_folder_is_denied(isolated, tmp_path):
    installed(isolated)
    denied, out, _ = hook("claude", search_tool_event("claude", str(isolated), tmp_path), tmp_path)
    assert denied and "denypeek protects" in reason_of(out), out


def small_project(tmp_path: Path) -> Path:
    return a26_project(tmp_path / "proj", entries=200)


def test_a28_message_a_names_the_files_and_the_clear_folders(isolated, tmp_path):
    proj = tmp_path / "proj"
    for d in ("src", "tests", "docs", "secrets", ".venv"):
        (proj / d).mkdir(parents=True)
    (proj / "secrets" / "id_rsa").write_text("x\n")
    (proj / ".env").write_text("x\n")
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", "grep -rn foo .", proj), proj)
    assert denied
    reason = reason_of(out)
    assert reason == (
        "denypeek blocked this: a search from here would read a secret file "
        "(.env, secrets/id_rsa); search a narrower folder. Clear to search: docs, src, tests, "
        ".venv."
    ), reason


def test_a28_message_a_caps_the_folders_and_escapes_names(isolated, tmp_path):
    proj = tmp_path / "proj"
    (proj / "sub").mkdir(parents=True)
    bad = ".env.\x1b[31mred" + "y" * 100
    (proj / "sub" / bad).write_text("x\n")
    for i in range(12):
        (proj / f"d{i:02}").mkdir()
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", "rg foo", proj), proj)
    assert denied and "\x1b" not in out
    reason = reason_of(out)
    assert "sub/.env.\\x1b[31mred" in reason and "…" in reason, reason
    assert "Clear to search: d00, d01, d02, d03, d04, d05, d06, d07 and 4 more." in reason
    assert "secretfiles" not in reason


def test_a28_message_a_when_no_folder_is_clear(isolated, tmp_path):
    proj = tmp_path / "proj"
    (proj / "a").mkdir(parents=True)
    (proj / "a" / ".env").write_text("x\n")
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", "rg foo", proj), proj)
    assert denied
    assert "no folder directly under this one is clear" in reason_of(out)


@pytest.mark.parametrize("denied_command", ["grep -rn foo .", "rg foo", "git grep foo"])
def test_a28_every_folder_message_a_lists_is_allowed(denied_command, isolated, tmp_path):
    proj = small_project(tmp_path)
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", denied_command, proj), proj)
    assert denied, out
    reason = reason_of(out)
    listed = reason.split("Clear to search: ", 1)[1].rstrip(".").split(", ")
    assert listed == ["src"], reason
    for folder in listed:
        rewrite = denied_command.replace(" .", "") + f" {folder}"
        if rewrite.startswith("git grep"):
            rewrite = f"git grep foo -- {folder}"
        denied, out, _ = hook("claude", shell_event("claude", rewrite, proj), proj)
        assert not denied, (rewrite, out)


# --- certificate bundles -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,counts",
    [
        ("venv/lib/python3.12/site-packages/certifi/cacert.pem", False),
        ("venv/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem", False),
        ("venv/lib/cacert.pem", True),
        ("certifi/sub/cacert.pem", True),
        ("notcertifi/cacert.pem", True),
        ("Certifi/cacert.pem", True),  # the exception matches names exactly
        ("certifi/server.pem", True),
    ],
)
def test_only_certifis_cacert_pem_is_exempt(path, counts, isolated, tmp_path):
    proj = tmp_path / "proj"
    (proj / path).parent.mkdir(parents=True)
    (proj / path).write_text("x\n")
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", "rg foo", proj), proj)
    assert denied == counts, (path, out)


def test_certifis_cacert_pem_still_counts_when_named(isolated, tmp_path):
    proj = tmp_path / "proj"
    (proj / "certifi").mkdir(parents=True)
    (proj / "certifi" / "cacert.pem").write_text("x\n")
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", "cat certifi/cacert.pem", proj), proj)
    assert denied, out


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
    proj = a26_project(tmp_path / "proj", entries=100)
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
    assert denied and "xargs" in reason_of(out), out
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
