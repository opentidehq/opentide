"""The workspace an Agent Plugin launch serves (#431).

An Agent Plugins 1.0 client starts ``opentide mcp start`` in the plugin root,
which for the opentide skills plugin is the skills package, not a catalogue.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from opentide.mcp_server import workspace
from opentide.mcp_server.workspace import (
    AGENT_PLUGINS_SCHEMA,
    is_agent_plugin_root,
    resolve_plugin_launch,
)


def _plugin(root: Path, schema: str = f"{AGENT_PLUGINS_SCHEMA}1.0.0/plugin.schema.json") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / ".git").mkdir()
    (root / "skills").mkdir()
    (root / "plugin.json").write_text(
        json.dumps({"$schema": schema, "name": "opentide"}), encoding="utf-8"
    )
    return root


def _workspace(root: Path) -> Path:
    (root / ".opentide").mkdir(parents=True)
    (root / ".git").mkdir()
    return root


@pytest.fixture(autouse=True)
def _reset() -> None:
    workspace.apply_plugin_launch(None)


def test_a_plugin_root_is_recognised_by_its_manifest_schema(tmp_path: Path) -> None:
    assert is_agent_plugin_root(_plugin(tmp_path / "a"))
    assert not is_agent_plugin_root(_plugin(tmp_path / "b", schema="https://example.com/p"))
    assert not is_agent_plugin_root(tmp_path / "missing")
    broken = tmp_path / "c"
    broken.mkdir()
    (broken / "plugin.json").write_text("{", encoding="utf-8")
    assert not is_agent_plugin_root(broken)


def test_outside_a_plugin_nothing_changes(tmp_path: Path) -> None:
    assert resolve_plugin_launch(tmp_path, env={}) is None


def test_a_plugin_that_is_a_workspace_is_served_as_one(tmp_path: Path) -> None:
    root = _plugin(tmp_path / "p")
    (root / ".opentide").mkdir()
    assert resolve_plugin_launch(root, env={}) is None


def test_an_explicit_workspace_wins(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path / "p")
    repo = _workspace(tmp_path / "repo")
    assert resolve_plugin_launch(plugin, env={"OPENTIDE_REPO_ROOT": str(repo)}) is None


def test_the_cli_export_of_the_plugin_root_is_not_explicit(tmp_path: Path) -> None:
    """The root callback exports the directory it resolved, here the plugin root."""
    plugin = _plugin(tmp_path / "p")
    env = {"OPENTIDE_REPO_ROOT": str(plugin), "OPENTIDE_TIDE_WORKSPACE": str(plugin)}
    launch = resolve_plugin_launch(plugin, env=env)
    assert launch is not None and launch.workspace is None


def test_the_host_project_directory_is_served(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path / "p")
    repo = _workspace(tmp_path / "repo")
    (repo / "objects").mkdir()
    launch = resolve_plugin_launch(plugin, env={"CLAUDE_PROJECT_DIR": str(repo / "objects")})
    assert launch is not None
    assert (launch.workspace, launch.variable) == (repo.resolve(), "CLAUDE_PROJECT_DIR")


def test_a_host_directory_that_is_no_workspace_is_ignored(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path / "p")
    other = tmp_path / "other"
    other.mkdir()
    launch = resolve_plugin_launch(plugin, env={"PWD": str(other)})
    assert launch is not None and launch.workspace is None


def test_without_a_workspace_catalogue_tools_refuse(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path / "p")
    workspace.apply_plugin_launch(resolve_plugin_launch(plugin, env={}))
    with pytest.raises(ToolError, match="workspace_not_found") as error:
        workspace.require_workspace()
    assert "OPENTIDE_REPO_ROOT" in str(error.value)
    workspace.apply_plugin_launch(None)
    workspace.require_workspace()


def test_a_found_workspace_is_exported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.core.root import get_repo_root

    plugin = _plugin(tmp_path / "p")
    repo = _workspace(tmp_path / "repo")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(plugin))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(plugin))
    get_repo_root.cache_clear()
    assert get_repo_root() == plugin
    workspace.apply_plugin_launch(resolve_plugin_launch(plugin, env={"PWD": str(repo)}))
    assert get_repo_root() == repo.resolve()
    workspace.require_workspace()
    get_repo_root.cache_clear()
