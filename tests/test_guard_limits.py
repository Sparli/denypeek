"""G2 (inputs that hang the hook) and G3 (strings too long to check are denied, not skipped)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from keyhush.guard import blocked

GUARD = Path(__file__).resolve().parents[1] / "src" / "keyhush" / "guard" / "guard.py"


def run(agent, payload, cwd, raw=None):
    data = raw if raw is not None else json.dumps(payload).encode()
    start = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-I", "-S", str(GUARD), "--agent", agent, "--home", os.environ["HOME"]],
        input=data,
        capture_output=True,
        timeout=60,
        cwd=str(cwd),
        env=dict(os.environ),
    )
    return proc, time.monotonic() - start


def bash(command, cwd):
    return {
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


LIMIT = 4.0  # the agents' timeout is 10 s; the hook must answer well inside it


def test_g2_many_newlines_answer_fast(tmp_path):
    proc, secs = run("codex", bash("cat .env" + "\n" * 40000, tmp_path), tmp_path)
    assert secs < LIMIT, secs
    assert blocked("codex", proc.stdout.decode(), proc.returncode)


def test_g2_wide_globs_answer_fast(tmp_path):
    wide = tmp_path / "wide"
    for a in range(14):
        for b in range(14):
            for c in range(14):
                (wide / str(a) / str(b) / str(c)).mkdir(parents=True)
    proc, secs = run("claude", bash(" ".join(["cat"] + ["wide/*/*/*/*"] * 10), tmp_path), tmp_path)
    assert secs < LIMIT, secs
    assert proc.returncode in (0, 2)
    out = proc.stdout.decode()
    assert out.strip(), "the hook must always answer"


def test_g2_many_brace_groups_answer_fast(tmp_path):
    token = "{a,b}" * 8
    proc, secs = run("claude", bash(" ".join(["cat"] + [token] * 300), tmp_path), tmp_path)
    assert secs < LIMIT, secs
    assert proc.stdout.decode().strip()


def test_g2_timeout_denies_and_says_why(tmp_path, monkeypatch):
    """Deterministic: the deadline is already in the past, whatever the clock resolution."""
    from keyhush.guard import guard as g

    monkeypatch.setattr(g, "HOOK_SECONDS", -1.0)
    out, code, msg = g.run(["--agent", "claude"], json.dumps(bash("cat x", tmp_path)).encode())
    assert code == 2 and "too long" in msg
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_g2_deadline_reached_on_a_coarse_clock_counts_as_passed(monkeypatch):
    """Windows with Python 3.12: the clock may not move between setting and checking."""
    from keyhush.guard import guard as g

    class FrozenClock:
        @staticmethod
        def monotonic():
            return 1000.0

    monkeypatch.setattr(g, "time", FrozenClock)
    monkeypatch.setattr(g, "_deadline", [1000.0])
    with pytest.raises(g.HookTimeout):
        g.tick()


@pytest.mark.parametrize("use_signals", [False, True])
def test_g2_watchdog_denies_a_stuck_check(use_signals, tmp_path):
    """The watchdog itself, both the thread version (used on Windows) and the signal version
    (POSIX), tested on any platform with a decision that never finishes."""
    import signal as signal_module

    if use_signals and not hasattr(signal_module, "setitimer"):
        pytest.skip("no interval timer on this platform; the thread version covers it")
    script = (
        "import json, sys, time\n"
        f"sys.path.insert(0, {str(GUARD.parent)!r})\n"
        "import guard\n"
        "guard.HOOK_SECONDS = 0.2\n"
        "def stuck(event, rules):\n"
        "    while True:\n"
        "        time.sleep(0.01)\n"
        "guard.decide = stuck\n"
        f"guard.start_watchdog('claude', use_signals={use_signals})\n"
        f"out, code, msg = guard.run(['--agent', 'claude', '--home', {str(tmp_path)!r}], "
        'b\'{"tool_name": "Read"}\')\n'
        "sys.stdout.write(out)\n"
        "sys.exit(code)\n"
    )
    start = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script],
        capture_output=True,
        timeout=30,
        cwd=str(tmp_path),
    )
    assert time.monotonic() - start < 5
    assert proc.returncode == 2, (proc.returncode, proc.stderr)
    assert blocked("claude", proc.stdout.decode(), proc.returncode)
    assert b"too long" in proc.stdout


# --- G4: working-folder parameters ------------------------------------------------------


def test_g4_codex_workdir_is_used(tmp_path, isolated):
    payload = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": ["cat", "credentials"], "workdir": "~/.aws"},
    }
    proc, _ = run("codex", payload, tmp_path)
    assert blocked("codex", proc.stdout.decode(), proc.returncode)


def test_g4_gemini_dir_path_is_used(tmp_path, isolated):
    payload = {
        "cwd": str(tmp_path),
        "hook_event_name": "BeforeTool",
        "tool_name": "run_shell_command",
        "tool_input": {"command": "cat credentials", "dir_path": "~/.aws"},
    }
    proc, _ = run("gemini", payload, tmp_path)
    assert blocked("gemini", proc.stdout.decode(), proc.returncode)


def test_g4_relative_file_tool_path_with_working_directory(tmp_path):
    (tmp_path / "app").mkdir()
    payload = {
        "cwd": str(tmp_path),
        "hook_event_name": "preToolUse",
        "tool_name": "Read",
        "tool_input": {"path": ".env", "working_directory": str(tmp_path / "app")},
    }
    proc, _ = run("cursor", payload, tmp_path)
    assert blocked("cursor", proc.stdout.decode(), proc.returncode)


def test_g4_workdir_does_not_block_normal_commands(tmp_path):
    (tmp_path / "src").mkdir()
    payload = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls", "workdir": str(tmp_path / "src")},
    }
    proc, _ = run("codex", payload, tmp_path)
    assert not blocked("codex", proc.stdout.decode(), proc.returncode)


# --- G6: recursive reads ----------------------------------------------------------------


def g6_project(tmp_path):
    proj = tmp_path / "proj"
    (proj / "node_modules" / "pkg").mkdir(parents=True)
    (proj / "node_modules" / "pkg" / ".env").write_text("PLACEHOLDER=1\n")
    (proj / "src").mkdir()
    return proj


@pytest.mark.parametrize(
    "command",
    [
        "grep -d recurse KEY .",
        "grep --directories=recurse KEY .",
        "grep -r KEY .",
        "grep -rn KEY node_modules",
    ],
)
def test_g6_recursive_grep_forms_see_node_modules(command, tmp_path):
    proj = g6_project(tmp_path)
    proc, _ = run("claude", bash(command, proj), proj)
    assert blocked("claude", proc.stdout.decode(), proc.returncode), command


@pytest.mark.parametrize("command", ["rg KEY .", "git grep KEY", "grep -r KEY src"])
def test_g6_tools_that_skip_node_modules_are_allowed(command, tmp_path):
    proj = g6_project(tmp_path)
    proc, _ = run("claude", bash(command, proj), proj)
    assert not blocked("claude", proc.stdout.decode(), proc.returncode), command


# --- G7: line continuation ---------------------------------------------------------------


@pytest.mark.parametrize("command", ["cat .e\\\nnv", "cat .e\\\r\nnv", "c\\\nat ~/.ssh/id\\\n_rsa"])
def test_g7_backslash_newline_is_joined(command, tmp_path):
    proc, _ = run("claude", bash(command, tmp_path), tmp_path)
    assert blocked("claude", proc.stdout.decode(), proc.returncode), repr(command)


# --- G8: Gemini read_many_files -----------------------------------------------------------


def gemini_many(include, cwd):
    return {
        "cwd": str(cwd),
        "hook_event_name": "BeforeTool",
        "tool_name": "read_many_files",
        "tool_input": {"include": include},
    }


@pytest.mark.parametrize("include", [["."], ["**/*"], ["src", "**/*.txt"], [""]])
def test_g8_read_many_files_over_a_folder_with_secrets_is_denied(include, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / ".env").write_text("PLACEHOLDER=1\n")
    proc, _ = run("gemini", gemini_many(include, tmp_path), tmp_path)
    assert blocked("gemini", proc.stdout.decode(), proc.returncode), include


def test_g8_read_many_files_without_secrets_is_allowed(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x\n")
    (tmp_path / ".env").write_text("PLACEHOLDER=1\n")
    proc, _ = run("gemini", gemini_many(["src/**/*.py", "README.md"], tmp_path), tmp_path)
    assert not blocked("gemini", proc.stdout.decode(), proc.returncode)


# --- variable concatenation (G9 known miss, now handled for simple assignments) ----------


@pytest.mark.parametrize(
    "command",
    [
        "a=.e; cat ${a}nv",
        "a=.e && cat $a'nv'",
        "export F=.env; cat $F",
        "d=~/.ssh; cat $d/id_rsa",
        "x=.e y=nv; cat ${x}${y}",
    ],
)
def test_simple_variable_assignments_are_resolved(command, tmp_path, isolated):
    proc, _ = run("claude", bash(command, tmp_path), tmp_path)
    assert blocked("claude", proc.stdout.decode(), proc.returncode), command


def test_variables_do_not_block_normal_commands(tmp_path):
    proc, _ = run("claude", bash("name=world; echo hello $name", tmp_path), tmp_path)
    assert not blocked("claude", proc.stdout.decode(), proc.returncode)


# --- R4: variable expansion cannot blow up -------------------------------------------------


def nested_assignments(levels=400):
    parts = ["a0=xxxxxxxx"]
    for i in range(1, levels):
        parts.append(f"a{i}=$a{i - 1}$a{i - 1}$a{i - 1}")
    return "; ".join(parts) + f"; cat $a{levels - 1}"


def exploding_command():
    """Each value multiplies the last: far past the size limit within the first passes."""
    return "a=" + "x" * 1000 + "; b=" + "$a" * 200 + "; c=$b$b$b$b; echo $c"


def test_r4_nested_assignments_answer_fast(tmp_path):
    command = nested_assignments()
    assert len(command) < 10_000
    proc, secs = run("claude", bash(command, tmp_path), tmp_path)
    assert secs < LIMIT, secs
    assert proc.stdout.strip(), "the hook must always answer"


def test_r4_expansion_past_the_limit_is_denied_fast(tmp_path):
    proc, secs = run("claude", bash(exploding_command(), tmp_path), tmp_path)
    assert secs < LIMIT, secs
    assert blocked("claude", proc.stdout.decode(), proc.returncode)
    assert b"too much text to check" in proc.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="resource module is POSIX only")
def test_r4_exploding_variables_use_little_memory(tmp_path):
    payload = tmp_path / "payload.json"
    payload.write_text(
        json.dumps(bash(exploding_command() + "; " + nested_assignments(), tmp_path))
    )
    argv = [sys.executable, "-I", "-S", str(GUARD), "--agent", "claude", "--home", str(tmp_path)]
    code = (
        "import resource, subprocess, sys\n"
        f"subprocess.run({argv!r}, input=open({str(payload)!r}, 'rb').read(), "
        "capture_output=True)\n"
        "print(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    peak = int(out.stdout.strip())
    peak_mb = peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024
    assert peak_mb < 200, peak_mb


def test_r4_substitution_stops_at_the_size_limit():
    from keyhush.guard import guard as g

    with pytest.raises(g.HookTimeout):
        g.substitute_variables(exploding_command())
