"""A10, A11, A15 and config-edit safety."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .conftest import run_cli

PY = sys.executable


def seed(home: Path) -> dict[Path, dict]:
    """Agent configs that already hold other settings and hooks."""
    configs = {
        home / ".claude/settings.json": {
            "model": "opus",
            "permissions": {"allow": ["Bash(npm test)"], "deny": ["Read(./private/**)"]},
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine"}]}
                ],
                "Stop": [{"hooks": [{"type": "command", "command": "say done"}]}],
            },
        },
        home / ".codex/hooks.json": {
            "description": "my hooks",
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "python3 my_policy.py"}],
                    }
                ]
            },
        },
        home / ".cursor/hooks.json": {
            "version": 1,
            "hooks": {
                "afterFileEdit": [{"command": "./format.sh"}],
                "beforeShellExecution": [{"command": "./audit.sh"}],
            },
        },
        home / ".gemini/settings.json": {"theme": "GitHub", "general": {"vimMode": True}},
    }
    for path, data in configs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=4))
    return configs


def count_ours(obj) -> int:
    text = json.dumps(obj)
    return text.count(".keyhush/guard.py") + text.count(".keyhush\\\\guard.py")


def test_a10_install_twice_keeps_other_settings(isolated):
    home = isolated
    configs = seed(home)
    for _ in range(2):
        code, out, err = run_cli("guard", "install", "--home", str(home), "--python", PY)
        assert code == 0, out + err
    claude = json.loads((home / ".claude/settings.json").read_text())
    assert claude["model"] == "opus"
    assert claude["permissions"]["allow"] == ["Bash(npm test)"]
    assert claude["permissions"]["deny"][0] == "Read(./private/**)"
    assert claude["permissions"]["deny"].count("Read(//**/.env)") == 1
    assert claude["hooks"]["Stop"] == configs[home / ".claude/settings.json"]["hooks"]["Stop"]
    pre = claude["hooks"]["PreToolUse"]
    assert pre[0]["hooks"][0]["command"] == "echo mine" and len(pre) == 2
    assert count_ours(claude) == 1

    codex = json.loads((home / ".codex/hooks.json").read_text())
    assert codex["description"] == "my hooks" and count_ours(codex) == 1
    cursor = json.loads((home / ".cursor/hooks.json").read_text())
    assert cursor["version"] == 1
    assert cursor["hooks"]["afterFileEdit"] == [{"command": "./format.sh"}]
    assert cursor["hooks"]["beforeShellExecution"][0] == {"command": "./audit.sh"}
    assert count_ours(cursor) == 3  # beforeReadFile, beforeShellExecution, preToolUse
    assert all(
        e.get("failClosed") is True
        for k in ("beforeReadFile", "preToolUse")
        for e in cursor["hooks"][k]
    )
    gemini = json.loads((home / ".gemini/settings.json").read_text())
    assert gemini["general"] == {"vimMode": True} and count_ours(gemini) == 1

    backups = list((home / ".keyhush/config-backups").iterdir())
    for path in configs:
        assert any(b.name.endswith(f"{path.parent.name}-{path.name}") for b in backups), path
    assert (home / ".keyhush/guard.py").exists() and (home / ".keyhush/secretfiles").exists()


def test_a11_uninstall_restores_each_config(isolated):
    home = isolated
    configs = seed(home)
    run_cli("guard", "install", "--home", str(home), "--python", PY)
    run_cli("guard", "install", "--home", str(home), "--python", PY)
    code, out, err = run_cli("guard", "uninstall", "--home", str(home))
    assert code == 0, out + err
    for path, original in configs.items():
        assert json.loads(path.read_text()) == original, path
    assert not (home / ".keyhush/guard.py").exists()


def test_a11_files_created_by_install_are_removed(isolated):
    home = isolated
    run_cli("guard", "install", "--home", str(home), "--python", PY)
    for rel in (
        ".claude/settings.json",
        ".codex/hooks.json",
        ".cursor/hooks.json",
        ".gemini/settings.json",
    ):
        assert (home / rel).exists()
    run_cli("guard", "uninstall", "--home", str(home))
    for rel in (
        ".claude/settings.json",
        ".codex/hooks.json",
        ".cursor/hooks.json",
        ".gemini/settings.json",
    ):
        assert not (home / rel).exists(), rel


def test_a15_guard_test_table(isolated):
    home = isolated
    seed(home)
    run_cli("guard", "install", "--home", str(home), "--python", PY)
    run_cli("guard", "install", "--home", str(home), "--python", PY)
    code, out, _ = run_cli("guard", "test", "--home", str(home))
    assert code == 0, out
    rows = [line for line in out.splitlines() if line.endswith("  ok") or line.endswith("FAIL")]
    assert len(rows) == 4 * 9
    blocked_rows = [r for r in rows if " blocked " in r and r.rstrip().endswith("ok")]
    assert len(blocked_rows) == 4 * 5
    for label in ("Claude Code", "Codex CLI", "Cursor", "Gemini CLI"):
        assert sum(r.startswith(label) for r in rows) == 9

    run_cli("guard", "uninstall", "--home", str(home))
    code, out, _ = run_cli("guard", "test", "--home", str(home))
    assert code == 1 and "not installed" in out


def test_status_reports_and_exits(isolated):
    home = isolated
    code, out, _ = run_cli("guard", "status", "--home", str(home))
    assert code == 1 and "not installed" in out
    run_cli("guard", "install", "--home", str(home), "--python", PY)
    code, out, _ = run_cli("guard", "status", "--home", str(home), "--json")
    data = json.loads(out)
    assert code == 0 and all(a["installed"] for a in data["agents"])
    code, out, _ = run_cli("guard", "status", "--home", str(home))
    assert "run /hooks to trust" in out


def test_malformed_config_is_never_touched(isolated):
    home = isolated
    bad = home / ".claude/settings.json"
    bad.parent.mkdir(parents=True)
    bad.write_text('{"model": "opus",, broken')
    code, out, err = run_cli("guard", "install", "--home", str(home), "--python", PY)
    assert code == 2 and "not valid JSON" in err
    assert bad.read_text() == '{"model": "opus",, broken'
    gem = json.loads((home / ".gemini/settings.json").read_text())  # others still installed
    assert count_ours(gem) == 1


def test_unexpected_types_are_never_touched(isolated):
    home = isolated
    cfg = home / ".gemini/settings.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"hooks": "not an object"}))
    code, _out, err = run_cli(
        "guard", "install", "--home", str(home), "--python", PY, "--agent", "gemini"
    )
    assert code == 2 and "unexpected type" in err
    assert json.loads(cfg.read_text()) == {"hooks": "not an object"}


def test_temporary_python_is_never_used():
    from keyhush.guard.install_base import _temporary

    assert _temporary("/Users/a/.cache/uv/archive-v0/abc/bin/python")
    assert not _temporary("/usr/bin/python3")
