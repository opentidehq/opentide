"""MCP ``validate_query`` knows the datasets the workspace's ``visibility.toml`` declares (#720).

The offline check ran the engine without the workspace's declarations, so an agent
checking a query through MCP got other findings than ``opentide validate query``:
a declared table was unknown, and an undeclared one was not reported.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opentide.cli import app
from opentide.mcp_server import tools, workspace

#: The workspace's ``visibility.toml``: one Defender log source, whose ``name`` is the
#: custom table it declares (``visibility::1.0``). Kept as one string so a change to the
#: file's shape is a change here only.
VISIBILITY = """\
[[logsources]]
name = "MyApp_CL"
description = "The application's own events"
system = "defender_for_endpoint"
"""

PLATFORM = "defender_for_endpoint"
#: Reads the table ``VISIBILITY`` declares; unknown to the engine without it (an error).
DECLARED = "MyApp_CL | take 1"
#: Reads a table the engine ships but ``VISIBILITY`` does not declare (a warning with it).
UNDECLARED = "DeviceProcessEvents | take 1"

runner = CliRunner()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    from opentide.analysis import install_workspace_visibility
    from opentide.core.root import get_repo_root

    root = tmp_path / "detections"
    (root / "objects").mkdir(parents=True)
    configurations = root / ".opentide" / "configurations"
    configurations.mkdir(parents=True)
    (configurations / "visibility.toml").write_text(VISIBILITY, encoding="utf-8")
    for name in ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"):
        monkeypatch.setenv(name, str(root))
    monkeypatch.chdir(root)
    get_repo_root.cache_clear()
    workspace.apply_plugin_launch(None)
    yield root
    get_repo_root.cache_clear()
    # The declarations are the engine's process-wide state: leave none behind.
    install_workspace_visibility(None)


def _cli(repo: Path, query: str) -> dict:
    path = repo / "query.kql"
    path.write_text(f"{query}\n", encoding="utf-8")
    argv = ["--json", "--repo", str(repo), "validate", "query"]
    result = runner.invoke(app, [*argv, "--platform", PLATFORM, "--file", str(path)])
    assert result.exit_code in (0, 1), result.output
    return json.loads(result.stdout)


def _errors(diagnostics: list[dict]) -> list[str]:
    return [item["code"] for item in diagnostics if item["severity"] == "error"]


@pytest.mark.parametrize("query", [DECLARED, UNDECLARED])
def test_validate_query_agrees_with_the_cli_on_declared_tables(repo: Path, query: str) -> None:
    # MCP first: the CLI run installs the declarations in this process's engine too.
    mcp = tools.tool_validate_query(query, PLATFORM)
    cli = _cli(repo, query)
    assert (mcp["status"], _errors(mcp["diagnostics"])) == (
        cli["status"],
        _errors(cli["diagnostics"]),
    )
    assert mcp["status"] == "passed", mcp
    warnings = [item["code"] for item in mcp["warnings"]]
    expected = ["kql_table_not_declared"] if query == UNDECLARED else []
    assert warnings == expected


def test_validate_query_reads_visibility_toml_on_every_call(repo: Path) -> None:
    assert tools.tool_validate_query(DECLARED, PLATFORM)["valid"] is True
    (repo / ".opentide" / "configurations" / "visibility.toml").write_text("", encoding="utf-8")
    unknown = tools.tool_validate_query(DECLARED, PLATFORM)
    assert unknown["valid"] is False
    assert _errors(unknown["diagnostics"]) == ["kql_unknown_table"]
    assert _errors(_cli(repo, DECLARED)["diagnostics"]) == ["kql_unknown_table"]


def test_validate_query_declares_nothing_without_a_workspace(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An Agent Plugin launch that found no workspace still answers offline (#431)."""
    assert tools.tool_validate_query(DECLARED, PLATFORM)["valid"] is True
    monkeypatch.setattr(workspace, "_problem", "workspace_not_found: none")
    result = tools.tool_validate_query(DECLARED, PLATFORM)
    assert _errors(result["diagnostics"]) == ["kql_unknown_table"]
