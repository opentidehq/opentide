"""Tests for setup orchestrator and default callback behaviour."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.cli.enums import CiPlatform, DetectionPlatform, McpHost, SkillTarget
from opentide.cli.services.setup.orchestrator import SetupOptions, run_setup


def test_run_setup_repo_only(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    result = run_setup(
        SetupOptions(
            path=target,
            name="Test",
            platforms=[DetectionPlatform.sentinel],
            yes=True,
            run_repo=True,
            run_ci=False,
        )
    )
    steps = result["steps"]
    assert isinstance(steps, list)
    assert len(steps) == 1
    assert steps[0]["step"] == "repo"
    assert (target / "README.md").is_file()


def test_run_setup_with_ci_and_mcp(tmp_path: Path) -> None:
    target = tmp_path / "full"
    result = run_setup(
        SetupOptions(
            path=target,
            name="Test",
            platforms=[DetectionPlatform.sentinel],
            ci=CiPlatform.github,
            mcp_hosts=[McpHost.vscode],
            yes=True,
            run_repo=True,
            run_ci=True,
            run_mcp=True,
        )
    )
    steps = result["steps"]
    assert isinstance(steps, list)
    assert {step["step"] for step in steps} == {"repo", "platforms", "ci", "mcp"}
    assert (target / ".opentide" / "configurations" / "platforms" / "sentinel.toml").is_file()
    workflow = (target / ".github" / "workflows" / "opentide.yml").read_text(encoding="utf-8")
    assert "validate query" in workflow
    assert "sentinel" in workflow
    assert (target / ".vscode" / "mcp.json").is_file()


def test_run_setup_skills_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        lambda slug, dest, *, ref: (
            dest.mkdir(parents=True, exist_ok=True),
            (dest / "SKILL.md").write_text(f"# {slug}\n", encoding="utf-8"),
            ["SKILL.md"],
        )[2],
    )
    monkeypatch.setattr("opentide.cli.services.setup.skills._fetch_bytes", lambda url: None)
    target = tmp_path / "skills-only"
    target.mkdir()
    result = run_setup(
        SetupOptions(
            path=target,
            skill_targets=[SkillTarget.generic],
            yes=True,
            run_repo=False,
            run_skills=True,
        )
    )
    steps = result["steps"]
    assert isinstance(steps, list)
    assert len(steps) == 1
    assert (target / "AGENTS.md").is_file()


def test_run_setup_vscode_deprecated(tmp_path: Path) -> None:
    target = tmp_path / "vscode"
    target.mkdir()
    (target / "Schemas" / "Templates").mkdir(parents=True)
    result = run_setup(
        SetupOptions(
            path=target,
            yes=True,
            run_repo=False,
            vscode_setup=True,
        )
    )
    steps = result["steps"]
    assert isinstance(steps, list)
    assert steps[0]["step"] == "vscode"
    assert (target / ".vscode" / "settings.json").is_file()
    vscode_files = steps[0]["files"]
    assert isinstance(vscode_files, list)
    assert ".vscode/settings.json" in vscode_files
    assert ".vscode/model-templates.code-snippets" not in vscode_files


def test_run_setup_ci_none_skips_ci_step(tmp_path: Path) -> None:
    target = tmp_path / "no-ci"
    result = run_setup(
        SetupOptions(
            path=target,
            name="No CI",
            ci=CiPlatform.none,
            yes=True,
            run_repo=True,
            run_ci=False,
        )
    )
    steps = result["steps"]
    assert isinstance(steps, list)
    assert {step["step"] for step in steps} == {"repo"}


def test_run_setup_auto_platforms_before_ci_without_run_platforms_flag(tmp_path: Path) -> None:
    target = tmp_path / "ci-only"
    result = run_setup(
        SetupOptions(
            path=target,
            platforms=[DetectionPlatform.sentinel],
            ci=CiPlatform.github,
            yes=True,
            run_repo=False,
            run_ci=True,
            run_platforms=False,
        )
    )
    steps = result["steps"]
    assert isinstance(steps, list)
    assert [step["step"] for step in steps] == ["platforms", "ci"]
    workflow = (target / ".github" / "workflows" / "opentide.yml").read_text(encoding="utf-8")
    assert "validate query" in workflow
    assert "sentinel" in workflow
