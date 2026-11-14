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
    """Hook entries pointing at denypeek: guard.sh (macOS, Linux) or guard.py (Windows)."""
    text = json.dumps(obj)
    return sum(
        text.count(f".denypeek{sep}guard.{ext}") for sep in ("/", "\\\\") for ext in ("py", "sh")
    )


def our_commands(obj) -> list[str]:
    found = []

    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                if k == "command" and isinstance(x, str) and "denypeek" in x:
                    found.append(x)
                else:
                    walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(obj)
    return found


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
    for command in our_commands(claude):  # absolute, quoted path to the hook
        quoted = command.split('"')[1]
        assert Path(quoted).is_absolute() and Path(quoted).exists(), command

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

    backups = list((home / ".denypeek/config-backups").iterdir())
    for path in configs:
        assert any(b.name.endswith(f"{path.parent.name}-{path.name}") for b in backups), path
    assert (home / ".denypeek/guard.py").exists() and (home / ".denypeek/secretfiles").exists()


def test_a11_uninstall_restores_each_config(isolated):
    home = isolated
    configs = seed(home)
    run_cli("guard", "install", "--home", str(home), "--python", PY)
    run_cli("guard", "install", "--home", str(home), "--python", PY)
    code, out, err = run_cli("guard", "uninstall", "--home", str(home))
    assert code == 0, out + err
    for path, original in configs.items():
        assert json.loads(path.read_text()) == original, path
    assert not (home / ".denypeek/guard.py").exists()


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
    assert len(rows) == 4 * 10
    blocked_rows = [r for r in rows if " blocked " in r and r.rstrip().endswith("ok")]
    assert len(blocked_rows) == 4 * 6
    for label in ("Claude Code", "Codex CLI", "Cursor", "Gemini CLI"):
        assert sum(r.startswith(label) for r in rows) == 10

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
    from denypeek.guard.install_base import _temporary

    assert _temporary("/Users/a/.cache/uv/archive-v0/abc/bin/python")
    assert not _temporary("/usr/bin/python3")


def test_a10_read_only_config_is_left_untouched(isolated):
    import os
    import stat

    # On Windows, chmod 0o444 sets the read-only attribute, which os.access honours.
    home = isolated
    cfg = home / ".claude/settings.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text('{"model": "opus"}')
    os.chmod(cfg, 0o444)
    before = cfg.read_bytes()
    code, out, err = run_cli("guard", "install", "--home", str(home), "--python", PY)
    assert code == 2
    assert "read-only; not touched" in err and "opus" not in err + out
    assert cfg.read_bytes() == before
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o444
    state = json.loads((home / ".denypeek/guard-state.json").read_text())
    assert "claude" not in state
    gem = json.loads((home / ".gemini/settings.json").read_text())  # others still installed
    assert count_ours(gem) == 1

    os.chmod(cfg, 0o644)
    run_cli("guard", "install", "--home", str(home), "--python", PY)
    os.chmod(cfg, 0o444)
    installed_bytes = cfg.read_bytes()
    code, _out, err = run_cli("guard", "uninstall", "--home", str(home))
    assert code == 2 and "read-only; not touched" in err
    assert cfg.read_bytes() == installed_bytes
    os.chmod(cfg, 0o644)


def test_a10_mode_600_and_symlink_are_kept(isolated, tmp_path):
    import os
    import stat
    import sys

    home = isolated
    cfg = home / ".gemini/settings.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("{}")
    os.chmod(cfg, 0o600)
    real = tmp_path / "dotfiles" / "claude.json"
    real.parent.mkdir()
    real.write_text('{"model": "opus"}')
    (home / ".claude").mkdir()
    try:
        (home / ".claude/settings.json").symlink_to(real)
        linked = True
    except (OSError, NotImplementedError):
        linked = False
    run_cli("guard", "install", "--home", str(home), "--python", PY)
    if sys.platform != "win32":
        assert stat.S_IMODE(cfg.stat().st_mode) == 0o600
    if linked:
        assert (home / ".claude/settings.json").is_symlink()
        assert count_ours(json.loads(real.read_text())) == 1


def test_header_says_how_many_agents_were_installed(isolated):
    bad = isolated / ".claude/settings.json"
    bad.parent.mkdir(parents=True)
    bad.write_text("{broken")
    code, out, err = run_cli("guard", "install", "--home", str(isolated), "--python", PY)
    assert code == 2
    assert "denypeek guard installed for 3 of 4 agent(s):" in out
    assert "denypeek guard installed:" not in out
    assert "claude: NOT changed" in err


def test_uninstall_removes_state_and_offers_config_purge(isolated):
    seed(isolated)
    run_cli("guard", "install", "--home", str(isolated), "--python", PY)
    code, out, _ = run_cli("guard", "uninstall", "--home", str(isolated))
    assert code == 0
    assert not (isolated / ".denypeek/guard-state.json").exists()
    assert not (isolated / ".denypeek/guard.sh").exists()
    assert "denypeek backups purge --config --yes" in out
    cfg = isolated / ".denypeek/config-backups"
    assert any(cfg.iterdir())
    code, out, _ = run_cli("backups", "list", "--home", str(isolated))
    assert "copy(ies) of earlier agent settings" in out
    code, out, _ = run_cli("backups", "purge", "--home", str(isolated), "--config", "--yes")
    assert code == 0 and "Deleted" in out
    assert list(cfg.iterdir()) == []


def test_partial_uninstall_keeps_state_for_the_rest(isolated):
    run_cli("guard", "install", "--home", str(isolated), "--python", PY)
    run_cli("guard", "uninstall", "--home", str(isolated), "--agent", "claude")
    state = json.loads((isolated / ".denypeek/guard-state.json").read_text())
    assert "claude" not in state and "gemini" in state


def test_g12_user_hook_in_our_group_survives_reinstall_and_uninstall(isolated):
    home = isolated
    run_cli("guard", "install", "--home", str(home), "--python", PY, "--agent", "claude")
    cfg = home / ".claude/settings.json"
    data = json.loads(cfg.read_text())
    group = data["hooks"]["PreToolUse"][-1]
    group["hooks"].append({"type": "command", "command": "echo users-own-hook"})
    cfg.write_text(json.dumps(data))
    run_cli("guard", "install", "--home", str(home), "--python", PY, "--agent", "claude")
    assert "users-own-hook" in cfg.read_text() and count_ours(json.loads(cfg.read_text())) == 1
    run_cli("guard", "uninstall", "--home", str(home), "--agent", "claude")
    after = json.loads(cfg.read_text())
    assert count_ours(after) == 0
    assert "users-own-hook" in json.dumps(after)


def test_g12_loose_names_are_not_ours():
    from denypeek.guard.install_base import is_ours

    assert not is_ours("python3 ~/tools/denypeek-notes/guard.py")
    assert not is_ours("echo denypeek guard.py")
    assert is_ours('/bin/sh "/Users/x/.denypeek/guard.sh" --agent claude')
    windows = r'"C:\Python\python.exe" -I -S "C:\Users\x\.denypeek\guard.py" --agent codex'
    assert is_ours(windows)


def test_unwritable_config_folder_gives_a_message_not_a_traceback(isolated):
    import os

    if os.name != "posix" or os.geteuid() == 0:
        import pytest

        pytest.skip("needs POSIX folder permissions and a non-root user")
    folder = isolated / ".claude"
    folder.mkdir()
    (folder / "settings.json").write_text('{"model": "opus"}')
    os.chmod(folder, 0o555)
    try:
        code, out, err = run_cli("guard", "install", "--home", str(isolated), "--python", PY)
    finally:
        os.chmod(folder, 0o755)
    assert code == 2
    assert "cannot write" in err and "Traceback" not in err + out
    assert json.loads((folder / "settings.json").read_text()) == {"model": "opus"}
    assert count_ours(json.loads((isolated / ".gemini/settings.json").read_text())) == 1
