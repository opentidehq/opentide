"""Broad CLI coverage for opentide setup_app and remaining setup gaps."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

from typer.testing import CliRunner

import opentide.cli.services.setup as setup_package
from opentide.cli import app
from opentide.cli.enums import CiPlatform, DetectionPlatform

setup_app_module = importlib.import_module("opentide.cli.setup_app")
_has_repo_flags = setup_app_module._has_repo_flags
_should_run_repo = setup_app_module._should_run_repo
_resolve_setup_path = setup_app_module._resolve_setup_path

runner = CliRunner()


def test_setup_package_exports() -> None:
    assert setup_package.SetupOptions is not None
    assert setup_package.run_setup is not None
    assert "run_repo_setup" in setup_package.__all__


def test_has_repo_flags_and_should_run_repo() -> None:
    assert _has_repo_flags("n", None, None, []) is True
    assert _has_repo_flags(None, None, None, [DetectionPlatform.sentinel]) is True
    assert _has_repo_flags(None, None, None, []) is False
    assert (
        _should_run_repo(
            yes=True,
            interactive=False,
            has_repo_flags=False,
            ci=None,
            vscode_setup=False,
        )
        is True
    )
    assert (
        _should_run_repo(
            yes=True,
            interactive=False,
            has_repo_flags=False,
            ci=CiPlatform.github,
            vscode_setup=False,
        )
        is False
    )


def test_resolve_setup_path_uses_cli_repo_when_path_is_dot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from opentide.cli.context import CliContext

    repo = tmp_path / "detection"
    repo.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(other)
    cli = CliContext(repo=repo)
    assert _resolve_setup_path(cli, ".") == repo
    assert _resolve_setup_path(cli, str(other)) == other


def test_setup_yes_only_scaffolds_repo(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "--path", str(tmp_path), "--yes"],
    )
    assert result.exit_code == 0
    assert (tmp_path / "README.md").is_file()
    assert '"steps"' in result.stdout


def test_setup_scripted_full_flags(tmp_path: Path, mock_skill_download) -> None:
    result = runner.invoke(
        app,
        [
            "--json",
            "setup",
            "--path",
            str(tmp_path),
            "--yes",
            "--name",
            "Full",
            "--ci",
            "github",
            "--vscode-setup",
            "--no-staging",
            "--no-promotion",
            "--promotion-target",
            "STAGING",
            "--python-version",
            "3.11",
        ],
    )
    assert result.exit_code == 0
    assert (tmp_path / ".github" / "workflows" / "opentide.yml").is_file()
    assert (tmp_path / ".vscode" / "settings.json").is_file()

    mcp_result = runner.invoke(
        app,
        ["--json", "setup", "mcp", str(tmp_path), "--yes", "--vscode"],
    )
    assert mcp_result.exit_code == 0
    assert (tmp_path / ".vscode" / "mcp.json").is_file()

    skills_result = runner.invoke(
        app,
        ["--json", "setup", "skills", "--yes", "--generic", "--path", str(tmp_path)],
    )
    assert skills_result.exit_code == 0
    assert (tmp_path / "AGENTS.md").is_file()


def test_setup_repo_interactive(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        setup_app_module,
        "run_interactive_repo_setup",
        lambda cli, base: {"message": "repo-wizard", "path": str(base)},
    )
    result = runner.invoke(app, ["--json", "setup", "repo", str(tmp_path)])
    assert result.exit_code == 0
    assert "repo-wizard" in result.stdout


def test_setup_ci_platforms(tmp_path: Path) -> None:
    for ci in ("github", "gitlab", "azure"):
        target = tmp_path / ci
        target.mkdir()
        result = runner.invoke(
            app,
            ["--json", "setup", "ci", ci, "--path", str(target), "--yes"],
        )
        assert result.exit_code == 0


def test_setup_ci_none_rejected() -> None:
    result = runner.invoke(app, ["setup", "ci", "none"])
    assert result.exit_code != 0


def test_setup_mcp_all_hosts(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--json",
            "setup",
            "mcp",
            str(tmp_path),
            "--yes",
            "--vscode",
            "--cursor",
            "--claude-code",
            "--generic",
        ],
    )
    assert result.exit_code == 0
    for rel in (
        ".vscode/mcp.json",
        ".cursor/mcp.json",
        ".mcp.json",
        "opentide.mcp.json",
    ):
        assert (tmp_path / rel).is_file()


def test_setup_mcp_interactive(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        setup_app_module,
        "run_interactive_mcp_setup",
        lambda base: {"message": "mcp-wizard", "files": []},
    )
    result = runner.invoke(app, ["--json", "setup", "mcp", str(tmp_path)])
    assert result.exit_code == 0
    assert "mcp-wizard" in result.stdout


def test_setup_skills_all_targets(tmp_path: Path, mock_skill_download) -> None:
    result = runner.invoke(
        app,
        [
            "--json",
            "setup",
            "skills",
            "--yes",
            "--cursor",
            "--claude-code",
            "--generic",
            "--github-copilot",
            "--name",
            "SOC",
            "--org",
            "SecOps",
            "--description",
            "Detections",
            "--path",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert (tmp_path / ".cursor" / "skills" / "opentide-detection-rule" / "SKILL.md").is_file()
    assert (tmp_path / "CLAUDE.md").is_file()
    assert (tmp_path / "AGENTS.md").is_file()
    assert (tmp_path / ".github" / "copilot-instructions.md").is_file()


def test_setup_skills_interactive(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        setup_app_module,
        "run_interactive_skills_setup",
        lambda base: {"message": "skills-wizard", "files": []},
    )
    result = runner.invoke(app, ["--json", "setup", "skills", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "skills-wizard" in result.stdout


def test_setup_vscode_flags(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "vscode", str(tmp_path), "--settings", "--no-merge"],
    )
    assert result.exit_code == 0
    assert (tmp_path / ".vscode" / "settings.json").is_file()


def test_setup_vscode_snippets_success_message(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        setup_app_module,
        "run_vscode_snippets",
        lambda target: ".vscode/model-templates.code-snippets",
    )
    result = runner.invoke(
        app,
        ["--json", "setup", "vscode", str(tmp_path), "--snippets"],
    )
    assert result.exit_code == 0
    assert "complete" in result.stdout.lower()


def test_setup_subcommand_skips_default_callback(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "repo", str(tmp_path), "--yes", "--name", "Only Repo"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload.get("message") == "Repository scaffold created"
