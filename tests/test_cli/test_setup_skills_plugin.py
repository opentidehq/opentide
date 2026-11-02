"""``opentide setup skills --plugin``: the opentidehq/skills Agent Plugin for Claude Code (#431)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.enums import SkillTarget
from opentide.cli.services.setup import skills as skills_mod
from opentide.cli.services.setup.plugin import (
    CLAUDE_SETTINGS,
    PLUGIN_ID,
    PluginConfigError,
    register_claude_code_plugin,
)
from opentide.cli.services.setup.skills import SkillsSetupOptions, run_skills_setup


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """The plugin needs no skill download: any catalogue fetch fails the test."""

    def _no_network(*_: object, **__: object) -> None:
        raise AssertionError("the plugin install must not fetch the skills catalogue")

    monkeypatch.setattr(skills_mod, "load_manifest", _no_network)


def _settings(root: Path) -> dict[str, object]:
    return json.loads((root / CLAUDE_SETTINGS).read_text(encoding="utf-8"))


def test_register_writes_the_marketplace_and_enables_the_plugin(tmp_path: Path) -> None:
    assert register_claude_code_plugin(tmp_path) == CLAUDE_SETTINGS

    assert _settings(tmp_path) == {
        "extraKnownMarketplaces": {
            "opentide": {"source": {"source": "github", "repo": "opentidehq/skills"}}
        },
        "enabledPlugins": {"opentide@opentide": True},
    }


def test_register_keeps_every_other_setting(tmp_path: Path) -> None:
    dest = tmp_path / CLAUDE_SETTINGS
    dest.parent.mkdir()
    dest.write_text(
        '{\n  // JSONC\n  "permissions": {"allow": ["Bash(ls)"]},\n'
        '  "enabledPlugins": {"other@team": false}\n}\n',
        encoding="utf-8",
    )

    register_claude_code_plugin(tmp_path)
    register_claude_code_plugin(tmp_path)

    settings = _settings(tmp_path)
    assert settings["permissions"] == {"allow": ["Bash(ls)"]}
    assert settings["enabledPlugins"] == {"other@team": False, PLUGIN_ID: True}


@pytest.mark.parametrize(
    "existing",
    ["{not json", "[]", '{"enabledPlugins": ["opentide@opentide"]}'],
    ids=["invalid", "not-an-object", "plugins-not-an-object"],
)
def test_register_leaves_a_file_it_cannot_merge(tmp_path: Path, existing: str) -> None:
    dest = tmp_path / CLAUDE_SETTINGS
    dest.parent.mkdir()
    dest.write_text(existing, encoding="utf-8")

    with pytest.raises(PluginConfigError):
        register_claude_code_plugin(tmp_path)

    assert dest.read_text(encoding="utf-8") == existing


def test_plugin_alone_writes_only_the_settings(tmp_path: Path) -> None:
    result = run_skills_setup(SkillsSetupOptions(path=tmp_path, plugin=True, yes=True))

    assert result["files"] == [CLAUDE_SETTINGS]
    assert result["skills"] == []
    assert result["plugin"] == PLUGIN_ID
    assert "/add-plugin opentidehq/skills" in str(result["advice"])
    assert not (tmp_path / ".agents").exists()


def test_plugin_with_claude_code_writes_claude_md_without_copying_skills(tmp_path: Path) -> None:
    """The plugin carries the skills: a copy in .claude/skills/ would load each twice."""
    result = run_skills_setup(
        SkillsSetupOptions(path=tmp_path, targets=[SkillTarget.claude_code], plugin=True, yes=True)
    )

    assert (tmp_path / "CLAUDE.md").is_file()
    assert not (tmp_path / ".claude" / "skills").exists()
    assert result["files"] == [CLAUDE_SETTINGS, "CLAUDE.md"]


def test_unmergeable_settings_is_a_warning(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / CLAUDE_SETTINGS).write_text("[]", encoding="utf-8")

    result = run_skills_setup(SkillsSetupOptions(path=tmp_path, plugin=True, yes=True))

    assert result["files"] == []
    assert any("left unchanged" in str(w) for w in result["warnings"])  # type: ignore[union-attr]


def test_cli_plugin_flag(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app, ["--json", "setup", "skills", "--plugin", "--yes", "--path", str(tmp_path)]
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["plugin"] == PLUGIN_ID
    assert payload["files"] == [CLAUDE_SETTINGS]
    assert _settings(tmp_path)["enabledPlugins"] == {PLUGIN_ID: True}
