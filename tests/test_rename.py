"""The project was renamed before its first release. The guard protects the new name only.

The self-protection tests (`test_guard_self_protection.py`, `test_guard_settings.py`,
`test_g12_loose_names_are_not_ours`) prove the ~/.denypeek folder deny, the
`denypeek guard install|uninstall` deny and our hook-entry check under the new name. These tests
prove the pre-release name gets no special treatment any more. The old name is built from two
parts, so a search of the repository for it finds only the changelog line and the README note.
"""

from __future__ import annotations

import pytest

from denypeek.guard import guard as g
from denypeek.guard.install_base import is_ours

from .test_guard_self_protection import event, project, run  # noqa: F401  (project: fixture)

OLD = "key" + "hush"


@pytest.mark.parametrize(
    "command",
    [
        f"{OLD} guard uninstall",
        f"uv run {OLD} guard install --python /usr/bin/python3",
        f"cat ~/.{OLD}/secretfiles",
        f"rm -rf ~/.{OLD}",
    ],
)
def test_old_name_commands_are_not_treated_as_switching_the_guard(command, project, isolated):  # noqa: F811
    (isolated / f".{OLD}").mkdir()
    denied, out = run("claude", event("claude", "shell", command, project), project, isolated)
    assert not denied, (command, out)


def test_new_name_commands_are_still_denied(project, isolated):  # noqa: F811
    for command in ("denypeek guard uninstall", "rm -rf ~/.denypeek"):
        denied, out = run("claude", event("claude", "shell", command, project), project, isolated)
        assert denied, (command, out)


def test_old_name_folder_is_not_protected(project, isolated):  # noqa: F811
    path = isolated / f".{OLD}" / "guard.py"
    path.parent.mkdir()
    for kind in ("read", "edit"):
        denied, out = run("claude", event("claude", kind, str(path), project), project, isolated)
        assert not denied, (kind, out)


def test_old_name_hook_entries_are_not_ours():
    assert not is_ours(f'/bin/sh "/Users/x/.{OLD}/guard.sh" --agent claude')
    assert not is_ours(rf'"C:\Python\python.exe" -I -S "C:\Users\x\.{OLD}\guard.py" --agent codex')
    assert is_ours('/bin/sh "/Users/x/.denypeek/guard.sh" --agent claude')


def test_gemini_disabled_list_matches_the_new_hook_name_only():
    assert g.settings_problem("gemini", '{"hooksConfig": {"disabled": ["denypeek-guard"]}}')
    old_off = '{"hooksConfig": {"disabled": ["' + OLD + '-guard"]}}'
    assert g.settings_problem("gemini", old_off) is None
