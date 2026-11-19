"""SPEC 3b, the tree rule: what a recursive search can read decides, not the folder's size.

A26: the project fixture through the real hook, per agent format. A27: the tool tier, where
the real search tool runs first and the hook must deny whenever it prints a marker. A28:
protected paths, the ripgrep key, and every rewrite a deny message suggests.

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


def installed(home: Path, ripgrep="unset") -> None:
    """The state `guard install` writes; ripgrep None leaves the key out (an older install)."""
    (home / ".denypeek").mkdir(exist_ok=True)
    state = {} if ripgrep is None else {"ripgrep_config": ripgrep}
    (home / ".denypeek" / "guard-state.json").write_text(json.dumps(state))


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

A26_ALLOWED = [
    "rg foo",
    "rg -n foo .",
    "rg foo src",
    "grep -rn foo src",
    "grep -rn foo . --include='*.py'",
]
# In SPEC A26's list, but real grep reads venv/lib/cacert.pem with it (venv is not excluded and
# *.pem is a secret pattern), so by A27's principle the hook must deny it. Reported for the spec.
A26_READS_A_SECRET = (
    "grep -rn foo . --exclude-dir=node_modules --exclude-dir=.venv --exclude='.env*'"
)


@POSIX_ONLY
@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("command", A26_ALLOWED)
def test_a26_searches_that_read_no_secret_are_allowed(agent, command, big, isolated):
    installed(isolated)
    denied, out, secs = hook(agent, shell_event(agent, command, big), big)
    assert not denied, (command, out)
    assert secs < LIMIT, secs


@POSIX_ONLY
@pytest.mark.parametrize("agent", ["claude", "gemini"])
def test_a26_an_agents_own_search_tool_on_src_is_allowed(agent, big, isolated):
    installed(isolated)
    denied, out, secs = hook(agent, search_tool_event(agent, "src", big), big)
    assert not denied, out
    assert secs < LIMIT, secs


@POSIX_ONLY
@pytest.mark.parametrize("agent", AGENTS)
def test_a26_grep_that_still_reaches_venv_cacert_is_denied(agent, big, isolated):
    installed(isolated)
    denied, out, _ = hook(agent, shell_event(agent, A26_READS_A_SECRET, big), big)
    assert denied, out
    assert "the search would read a secret file (cacert.pem)" in reason_of(out)


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
        "rg foo",
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


@pytest.mark.parametrize("ripgrep", [None, "set", "garbage"])
def test_a28_rg_beside_env_is_denied_unless_install_recorded_no_config(ripgrep, isolated, tmp_path):
    proj = small_project(tmp_path)
    installed(isolated, ripgrep)
    denied, out, _ = hook("claude", shell_event("claude", "rg foo", proj), proj)
    assert denied, out
    installed(isolated, "unset")
    denied, out, _ = hook("claude", shell_event("claude", "rg foo", proj), proj)
    assert not denied, out


def test_a28_a_ripgrep_config_in_the_command_widens_rg(isolated, tmp_path):
    proj = small_project(tmp_path)
    installed(isolated)
    command = "RIPGREP_CONFIG_PATH=rc rg foo"
    denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
    assert denied, out


def test_a28_guard_status_never_changes_the_ripgrep_key(isolated, monkeypatch):
    from .conftest import run_cli

    monkeypatch.delenv("RIPGREP_CONFIG_PATH", raising=False)
    code, out, _ = run_cli("guard", "install", "--home", str(isolated), "--agent", "claude")
    assert code == 0, out
    state = json.loads((isolated / ".denypeek" / "guard-state.json").read_text())
    assert state["ripgrep_config"] == "unset"
    _, out, _ = run_cli("guard", "status", "--home", str(isolated), "--agent", "claude")
    assert "CHANGED: RIPGREP_CONFIG_PATH" not in out
    monkeypatch.setenv("RIPGREP_CONFIG_PATH", str(isolated / "rc"))
    _, out, _ = run_cli("guard", "status", "--home", str(isolated), "--agent", "claude")
    assert "CHANGED: RIPGREP_CONFIG_PATH is now set" in out
    state = json.loads((isolated / ".denypeek" / "guard-state.json").read_text())
    assert state["ripgrep_config"] == "unset"
    code, out, _ = run_cli("guard", "install", "--home", str(isolated), "--agent", "claude")
    assert "RIPGREP_CONFIG_PATH was set" in out
    state = json.loads((isolated / ".denypeek" / "guard-state.json").read_text())
    assert state["ripgrep_config"] == "set"


@pytest.mark.parametrize(
    "denied_command,rewrites",
    [
        # (a): "search a narrower folder, or leave it out: `rg` skips hidden files"
        ("grep -rn foo .", ["grep -rn foo src", "rg foo"]),
        (A26_READS_A_SECRET, ["grep -rn foo src", "rg foo"]),
        # (a): "with grep add `--include` or `--exclude-dir`"
        ("grep -rn foo .", ["grep -rn foo . --include='*.py'"]),
    ],
)
def test_a28_every_rewrite_a_message_suggests_is_allowed(
    denied_command, rewrites, isolated, tmp_path
):
    proj = small_project(tmp_path)
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", denied_command, proj), proj)
    assert denied, out
    assert "search a narrower folder" in reason_of(out)
    for rewrite in rewrites:
        denied, out, _ = hook("claude", shell_event("claude", rewrite, proj), proj)
        assert not denied, (rewrite, out)


def test_a28_secret_message_names_the_file_escaped_and_keeps_the_pattern_hint(isolated, tmp_path):
    proj = tmp_path / "proj"
    (proj / "sub").mkdir(parents=True)
    (proj / "sub" / ".env.\x1b[31mred").write_text("x\n")
    installed(isolated)
    denied, out, _ = hook("claude", shell_event("claude", "grep -r foo .", proj), proj)
    assert denied
    assert "\x1b" not in out  # JSON escapes it
    reason = reason_of(out)
    assert reason.startswith("denypeek blocked this: the search would read a secret file (.env.")
    assert reason.endswith("If this is wrong, edit ~/.denypeek/secretfiles.")


# --- parsing: classes (T1, T3) and grep narrowing (T5) ---------------------------------------


@pytest.mark.parametrize(
    "command,cls",
    [
        ("rg foo", "D"),
        ("rg -n foo .", "D"),
        ("rg --hidden foo", "I"),
        ("rg -. foo", "I"),
        ("rg -uu foo", "E"),
        ("rg -nu foo", "E"),
        ("rg --no-ignore-vcs foo", "E"),
        ("rg -g '*' foo", "E"),
        ("rg -g '!x' foo", "D"),
        ("rg --glob=*.py foo", "E"),
        ("rg --pre cat foo", "E"),
        ("rg --ignore-file x foo", "E"),
        ("rg -t $T foo", "E"),
        ("git grep foo", "I"),
        ("git -C . grep foo", "I"),
        ("git grep --untracked foo", "E"),
        ("git grep --no-index foo", "E"),
        ("ag foo", "I"),
        ("ag -u foo", "E"),
        ("ack foo", "E"),
        ("grep -rn foo .", "E"),
        ("ugrep -r foo .", "E"),
    ],
)
def test_search_classes(command, cls, isolated, tmp_path):
    installed(isolated)
    g._home[0] = str(isolated)
    [s] = g.search_targets(command, str(tmp_path), command)
    if os.name == "nt" and cls == "D":
        cls = "I"  # T3: no class D on Windows
    assert s.cls == cls, command


def test_rg_on_windows_is_class_i(isolated, tmp_path, monkeypatch):
    installed(isolated)
    g._home[0] = str(isolated)
    monkeypatch.setattr(g, "WINDOWS", True)
    [s] = g.search_targets("rg foo", str(tmp_path), "rg foo")
    assert s.cls == "I"


def test_ripgrep_config_text_anywhere_widens(isolated, tmp_path):
    installed(isolated)
    g._home[0] = str(isolated)
    [s] = g.search_targets("rg foo", str(tmp_path), "export RIPGREP_CONFIG_PATH=x; rg foo")
    assert s.cls == "E"


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
] + [(c.replace("foo", "M"), None) for c in A26_ALLOWED + [A26_READS_A_SECRET]]


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
        assert not prints, (command, "an A26 command printed a marker")


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
def test_ignore_files_are_trusted_only_when_certain(gitignore, change, command, isolated, tmp_path):
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


@pytest.mark.parametrize("folders", [700, 2_100])
def test_many_folders_do_not_deny_plain_rg_or_error(folders, isolated, tmp_path):
    """Only ignore files that exist are read and counted; no internal error past a limit."""
    proj = review_project(tmp_path)
    for i in range(folders):
        (proj / "src" / f"d{i}").mkdir()
    installed(isolated)
    for command in ("rg foo", "rg --hidden foo"):
        denied, out, _ = hook("claude", shell_event("claude", command, proj), proj)
        assert "guard error" not in out, out
    denied, out, _ = hook("claude", shell_event("claude", "rg foo", proj), proj)
    assert not denied, out


def test_too_many_ignore_files_is_message_b(isolated, tmp_path, monkeypatch):
    proj = review_project(tmp_path)
    for i in range(30):
        (proj / "src" / f"d{i}").mkdir()
        (proj / "src" / f"d{i}" / ".ignore").write_text("x\n")
    installed(isolated)
    g._home[0] = str(isolated)
    monkeypatch.setattr(g, "IGNORE_FILES_MAX", 10)
    reason = g.search_tree(
        g.Search(str(proj), "D"), g.parse_patterns(g.DEFAULT_PATTERNS), time.monotonic() + 9
    )
    assert reason == g.TREE_TOO_BIG


# Options whose value is optional in one grep and required in another: the hook walks the
# paths of both readings (BSD grep takes `--context`'s value only after `=`; GNU takes the
# next word). git takes an optional value only when attached (`-O`).
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
def test_abbreviated_long_options_count(template, isolated, tmp_path):
    proj = ignored_only_project(tmp_path, isolated)
    installed(isolated)
    plain = "git grep {m}" if template.startswith("git") else "ag {m}"
    if not template.startswith("grep"):
        denied, out, _ = hook("claude", shell_event("claude", plain.format(m=MARK), proj), proj)
        assert not denied, ("fixture: the plain search reads no secret", out)
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


@POSIX_ONLY
@pytest.mark.parametrize(
    "command",
    [
        'rg(){ grep -r "$@"; }; rg {m} .',
        'function rg { grep -r "$@"; }; rg {m} .',
        "alias rg='grep -r'; rg {m} .",
    ],
)
def test_a_command_that_defines_a_function_or_alias_counts_as_reading_everything(
    command, isolated, tmp_path
):
    proj = review_project(tmp_path)
    (proj / ".env").unlink()
    (proj / "sub").mkdir()
    (proj / "sub" / ".env").write_text("x\n")
    installed(isolated)
    plain = hook("claude", shell_event("claude", f"rg {MARK} .", proj), proj)
    assert not plain[0], ("fixture: plain rg skips the hidden file", plain[1])
    denied, out, _ = hook("claude", shell_event("claude", command.replace("{m}", MARK), proj), proj)
    assert denied, out
