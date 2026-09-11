"""Tests for interactive setup wizards (mocked prompts)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from opentide.cli.context import CliContext
from opentide.cli.enums import CiPlatform, DetectionPlatform
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
    prompts = iter(["Repo", "Org", "Desc"])
    monkeypatch.setattr("opentide.cli.services.setup.repo.require_interactive", lambda: None)
    monkeypatch.setattr(
        "opentide.cli.services.setup.repo.ask_text",
        lambda *args, **kwargs: next(prompts),
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.repo.ask_platforms",
        lambda: [DetectionPlatform.sentinel],
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.repo.ask_confirm", lambda *args, **kwargs: True
    )
    result = run_interactive_repo_setup(cli_context, tmp_path / "repo")
    assert result["message"] == "Repository scaffold created"
    assert (tmp_path / "repo" / "README.md").is_file()


def test_run_interactive_mcp_setup(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("opentide.cli.services.setup.mcp.require_interactive", lambda: None)
    monkeypatch.setattr(
        "opentide.cli.services.setup.mcp.ask_checkbox",
        lambda *args, **kwargs: ["vscode", "cursor"],
    )
    monkeypatch.setattr("opentide.cli.services.setup.mcp.ask_confirm", lambda *args, **kwargs: True)
    result = run_interactive_mcp_setup(tmp_path)
    assert set(result["files"]) == {".vscode/mcp.json", ".cursor/mcp.json"}


def test_run_interactive_mcp_setup_can_cancel(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("opentide.cli.services.setup.mcp.require_interactive", lambda: None)
    monkeypatch.setattr(
        "opentide.cli.services.setup.mcp.ask_checkbox",
        lambda *args, **kwargs: ["vscode"],
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.mcp.ask_confirm", lambda *args, **kwargs: False
    )
    result = run_interactive_mcp_setup(tmp_path)
    assert result["status"] == "skipped"
    assert not (tmp_path / ".vscode/mcp.json").exists()


def _fake_download_skill(slug: str, dest: Path, *, source: str, ref: str) -> list[str]:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "SKILL.md").write_text(f"# {slug} ({source}@{ref})\n", encoding="utf-8")
    return ["SKILL.md"]


def test_run_interactive_skills_setup(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("opentide.cli.services.setup.skills.require_interactive", lambda: None)
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.ask_checkbox",
        lambda *args, **kwargs: ["generic"],
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.ask_confirm", lambda *args, **kwargs: True
    )
    monkeypatch.setattr("opentide.cli.services.setup.skills.unavailable_skills", lambda options: [])
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


def test_run_interactive_skills_setup_can_cancel(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("opentide.cli.services.setup.skills.require_interactive", lambda: None)
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.ask_checkbox",
        lambda *args, **kwargs: ["generic"],
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.ask_confirm", lambda *args, **kwargs: False
    )
    monkeypatch.setattr("opentide.cli.services.setup.skills.unavailable_skills", lambda options: [])
    result = run_interactive_skills_setup(tmp_path)
    assert result["status"] == "skipped"
    assert result["message"] == "Agent skills setup cancelled"
    assert not (tmp_path / "AGENTS.md").exists()


def test_run_interactive_skills_setup_reports_unavailable(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("opentide.cli.services.setup.skills.require_interactive", lambda: None)
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.ask_checkbox",
        lambda *args, **kwargs: ["generic"],
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.unavailable_skills",
        lambda options: ["opentide-detection-rule"],
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _fake_download_skill,
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda path, **_: None,
    )
    with pytest.raises(RuntimeError, match="Agent skills unavailable"):
        run_interactive_skills_setup(tmp_path)
    assert not (tmp_path / "AGENTS.md").exists()


def test_run_interactive_setup_full_wizard(
    monkeypatch, cli_context: CliContext, tmp_path: Path
) -> None:
    prompts = iter(["Wizard Repo", "Wizard Org", "Wizard Desc"])
    checkboxes = iter(
        [
            ["staging", "inflight", "promotion"],
            ["vscode"],
            ["generic"],
        ]
    )
    confirms = iter([True, True, True])
    monkeypatch.setattr(
        "opentide.cli.services.setup.orchestrator.require_interactive", lambda: None
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.orchestrator.ask_text",
        lambda *args, **kwargs: next(prompts),
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.orchestrator.ask_platforms",
        lambda: [DetectionPlatform.sentinel],
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.orchestrator.ask_select",
        lambda *args, **kwargs: CiPlatform.github,
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.orchestrator.ask_checkbox",
        lambda *args, **kwargs: next(checkboxes),
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.orchestrator.ask_confirm",
        lambda *args, **kwargs: next(confirms),
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.orchestrator.unavailable_skills",
        lambda options: [],
    )
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
