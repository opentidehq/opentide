"""Tests for interactive setup wizards (mocked prompts)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from opentide.cli.context import CliContext
from opentide.cli.services.setup.mcp import run_interactive_mcp_setup
from opentide.cli.services.setup.orchestrator import run_interactive_setup
from opentide.cli.services.setup.repo import run_interactive_repo_setup
from opentide.cli.services.setup.skills import run_interactive_skills_setup
from opentide.core.root import get_repo_root


@pytest.fixture(autouse=True)
def _reset_repo_root_env() -> None:
    yield
    os.environ.pop("OPENTIDE_REPO_ROOT", None)
    get_repo_root.cache_clear()


@pytest.fixture
def cli_context(tmp_path: Path) -> CliContext:
    return CliContext(repo=tmp_path, json_output=True, show_banner=False)


def test_run_interactive_repo_setup(monkeypatch, cli_context: CliContext, tmp_path: Path) -> None:
    prompts = iter(["Repo", "Org", "Desc", "sentinel"])
    monkeypatch.setattr("rich.prompt.Prompt.ask", lambda *args, **kwargs: next(prompts))
    result = run_interactive_repo_setup(cli_context, tmp_path / "repo")
    assert result["message"] == "Repository scaffold created"
    assert (tmp_path / "repo" / "README.md").is_file()


def test_run_interactive_mcp_setup(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("rich.prompt.Prompt.ask", lambda *args, **kwargs: "vscode,cursor")
    result = run_interactive_mcp_setup(tmp_path)
    assert set(result["files"]) == {".vscode/mcp.json", ".cursor/mcp.json"}


def test_run_interactive_mcp_setup_defaults_when_empty(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("rich.prompt.Prompt.ask", lambda *args, **kwargs: "")
    result = run_interactive_mcp_setup(tmp_path)
    assert result["files"] == [".vscode/mcp.json"]


def _fake_download_skill(slug: str, dest: Path, *, source: str, ref: str) -> list[str]:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "SKILL.md").write_text(f"# {slug} ({source}@{ref})\n", encoding="utf-8")
    return ["SKILL.md"]


def test_run_interactive_skills_setup(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("rich.prompt.Prompt.ask", lambda *args, **kwargs: "generic")
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _fake_download_skill,
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda path, **_: None,
    )
    result = run_interactive_skills_setup(tmp_path)
    assert (tmp_path / "AGENTS.md").is_file()
    assert "opentide-detection-rule" in result["skills"]


def test_run_interactive_skills_setup_defaults_when_empty(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("rich.prompt.Prompt.ask", lambda *args, **kwargs: "")
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _fake_download_skill,
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda path, **_: None,
    )
    result = run_interactive_skills_setup(tmp_path)
    assert (tmp_path / "AGENTS.md").is_file()
    assert "opentide-detection-rule" in result["skills"]


def test_run_interactive_setup_full_wizard(
    monkeypatch, cli_context: CliContext, tmp_path: Path
) -> None:
    prompts = iter(
        [
            "Wizard Repo",
            "Wizard Org",
            "Wizard Desc",
            "sentinel",
            "github",
            "vscode",
            "generic",
        ]
    )
    confirms = iter([True, True, True, True, True, False])

    monkeypatch.setattr("rich.prompt.Prompt.ask", lambda *args, **kwargs: next(prompts))
    monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *args, **kwargs: next(confirms))
    monkeypatch.setattr("rich.console.Console.print", MagicMock())
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _fake_download_skill,
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda path, **_: None,
    )

    import warnings

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_interactive_setup(cli_context, tmp_path / "wizard")
    steps = result["steps"]
    assert isinstance(steps, list)
    step_names = {step["step"] for step in steps}
    assert {"repo", "platforms", "ci", "mcp", "skills"}.issubset(step_names)
