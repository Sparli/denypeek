"""G5: settings that turn hooks off are found by parsing, at any depth, not by text match."""

from __future__ import annotations

import json

import pytest

from keyhush.guard import guard as g


@pytest.fixture
def rules():
    return g.parse_patterns(g.DEFAULT_PATTERNS)


def write_event(path, content, tool="Write"):
    return {
        "cwd": str(path.parent.parent),
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"file_path": str(path), "content": content},
    }


def edit_event(path, old, new):
    return {
        "cwd": str(path.parent.parent),
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {"file_path": str(path), "old_string": old, "new_string": new},
    }


OFF = [
    (".claude/settings.local.json", '{"disable\\u0041llHooks": true}'),  # JSON escape
    (".claude/settings.json", '{"permissions": {}, "disableAllHooks": 1}'),
    (".codex/config.toml", "features.hooks = false\n"),
    (".codex/config.toml", "features = { hooks = false }\n"),
    (".codex/config.toml", "[features]\ncodex_hooks = false\n"),
    (".gemini/settings.json", '{"hooksConfig": {"enabled": false}}'),
    (".gemini/settings.json", '{"hooksConfig": {"disabled": ["keyhush-guard"]}}'),
]


@pytest.mark.parametrize("rel,content", OFF)
def test_g5_writes_that_turn_hooks_off_are_denied(rel, content, rules, tmp_path):
    path = tmp_path / "proj" / rel
    path.parent.mkdir(parents=True)
    reason = g.decide(write_event(path, content), rules)
    assert reason and "hooks" in reason, (rel, content, reason)


def test_g5_edit_is_checked_against_the_resulting_file(rules, tmp_path):
    path = tmp_path / "proj" / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"permissions": {"allow": []}, "x": false}')
    assert g.decide(edit_event(path, '"x": false', '"disableAllHooks": true'), rules)
    assert g.decide(edit_event(path, '"allow": []', '"allow": ["Bash(npm test)"]'), rules) is None


@pytest.mark.parametrize(
    "rel,content",
    [
        (".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash(npm test)"]}})),
        (".codex/config.toml", 'model = "o4"\n[features]\nweb_search = true\n'),
        (".gemini/settings.json", '{"theme": "GitHub", "hooksConfig": {"notifications": false}}'),
        (".cursor/hooks.json", '{"version": 1, "hooks": {}}'),
    ],
)
def test_g5_normal_settings_edits_are_allowed(rel, content, rules, tmp_path):
    path = tmp_path / "proj" / rel
    path.parent.mkdir(parents=True)
    assert g.decide(write_event(path, content), rules) is None


def test_g5_unparseable_settings_write_is_denied(rules, tmp_path):
    path = tmp_path / "proj" / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    assert g.decide(write_event(path, '{"disableAllHooks": tr'), rules)


@pytest.mark.parametrize(
    "command",
    [
        "echo '{\"disableAllHooks\": true}' > .claude/settings.local.json",
        "echo e30K | base64 -d > .claude/settings.local.json",
        "sed -i '' 's/a/b/' .codex/config.toml",
        "cp /tmp/x .gemini/settings.json",
        "tee .claude/settings.json < /tmp/x",
    ],
)
def test_g5_shell_writes_to_project_settings_are_denied(command, rules, tmp_path):
    (tmp_path / ".claude").mkdir()
    event = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    assert g.decide(event, rules), command


@pytest.mark.parametrize(
    "command",
    [
        "cat .claude/settings.json",
        "jq . .gemini/settings.json",
        "git diff .claude/settings.json",
        "ls .claude",
    ],
)
def test_g5_shell_reads_of_project_settings_are_allowed(command, rules, tmp_path):
    event = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    assert g.decide(event, rules) is None, command


def test_g5_reading_project_settings_with_tools_is_allowed(rules, tmp_path):
    path = tmp_path / "proj" / ".claude" / "settings.json"
    event = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(path)},
    }
    assert g.decide(event, rules) is None


def test_g5_codex_patch_on_project_settings(rules, tmp_path):
    add_off = (
        "*** Begin Patch\n*** Add File: .codex/config.toml\n+[features]\n+hooks = false\n"
        "*** End Patch\n"
    )
    update = "*** Begin Patch\n*** Update File: .claude/settings.json\n@@\n-a\n+b\n*** End Patch\n"
    for patch in (add_off, update):
        event = {
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "apply_patch",
            "tool_input": {"command": patch},
        }
        assert g.decide(event, rules), patch


def test_g5_user_settings_protected_in_both_locations(rules, tmp_path, monkeypatch, isolated):
    custom = tmp_path / "custom-claude"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(custom))
    for path in (isolated / ".claude" / "settings.json", custom / "settings.json"):
        event = {
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": f"cat {path}"},
        }
        assert g.decide(event, rules), path


# --- R2: writes that do not name the settings file ---------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "cp notes/s.json .claude/",
        "cp notes/s.json .claude",
        "git mv notes/s.json .claude/settings.json",
        "git checkout -- .claude/settings.json",
        "dd if=notes/s.json of=.claude/settings.json",
        "mv newconf .claude",
        "tar xf conf.tar -C .claude",
        "unzip conf.zip -d .codex",
        "install -m 644 notes/s.json .claude/settings.local.json",
        "rsync -a notes/ .gemini/",
        "ln -sf ../notes/s.json .claude/settings.json",
        "cp -r tmpl/.claude sub/",
    ],
)
def test_r2_writes_into_project_settings_folders_are_denied(command, rules, tmp_path):
    for d in (".claude", ".codex", ".gemini", "notes", "sub", "tmpl/.claude"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    event = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    assert g.decide(event, rules), command


@pytest.mark.parametrize(
    "command",
    [
        "cp cmd.md .claude/commands/",
        "mkdir -p .claude/commands",
        "git status",
        "git diff .claude/settings.json",
        "git log -p .claude/settings.json",
        "echo hi > .claude/commands/hi.md",
        "ls .claude",
        "cat .codex/config.toml",
    ],
)
def test_r2_normal_work_in_project_settings_folders_is_allowed(command, rules, tmp_path):
    (tmp_path / ".claude" / "commands").mkdir(parents=True)
    event = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    assert g.decide(event, rules) is None, command


def test_r2_escaped_hooks_off_text_is_denied_anywhere(rules, tmp_path):
    event = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": str(tmp_path / "notes" / "s.json"),
            "content": '{"disable\\u0041llHooks": true}',
        },
    }
    assert g.decide(event, rules)
