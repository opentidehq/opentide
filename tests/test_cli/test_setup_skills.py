"""Tests for setup skills command module."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from opentide.cli.enums import SkillTarget
from opentide.cli.services.setup.skills import SkillsSetupOptions, run_skills_setup


@pytest.fixture(autouse=True)
def _mock_skill_download(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(slug: str, dest: Path, *, ref: str) -> list[str]:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "SKILL.md").write_text(f"# {slug}\n", encoding="utf-8")
        return ["SKILL.md"]

    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _fake,
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._fetch_bytes",
        lambda url: None,
    )


def test_run_skills_setup_generic(tmp_path: Path) -> None:
    result = run_skills_setup(
        SkillsSetupOptions(
            path=tmp_path,
            targets=[SkillTarget.generic],
            name="SOC",
            org="SecOps",
            yes=True,
        )
    )
    assert (tmp_path / "AGENTS.md").is_file()
    assert (tmp_path / ".agents" / "skills" / "opentide-detection-rule" / "SKILL.md").is_file()
    assert "AGENTS.md" in result["files"]


def test_run_skills_setup_cursor(tmp_path: Path) -> None:
    run_skills_setup(SkillsSetupOptions(path=tmp_path, targets=[SkillTarget.cursor], yes=True))
    assert (tmp_path / ".cursor" / "skills" / "opentide-detection-rule" / "SKILL.md").is_file()


def test_run_skills_setup_claude_code(tmp_path: Path) -> None:
    run_skills_setup(
        SkillsSetupOptions(path=tmp_path, targets=[SkillTarget.claude_code], name="SOC", yes=True)
    )
    assert (tmp_path / "CLAUDE.md").is_file()
    assert (tmp_path / ".claude" / "skills" / "opentide-detection-rule" / "SKILL.md").is_file()


def test_run_skills_setup_copilot(tmp_path: Path) -> None:
    run_skills_setup(
        SkillsSetupOptions(
            path=tmp_path,
            targets=[SkillTarget.github_copilot],
            name="SOC",
            yes=True,
        )
    )
    assert (tmp_path / ".github" / "copilot-instructions.md").is_file()
    assert (tmp_path / "AGENTS.md").is_file()
    assert (tmp_path / ".agents" / "skills" / "opentide-detection-rule" / "SKILL.md").is_file()


def test_run_skills_setup_requires_target() -> None:
    with pytest.raises(typer.BadParameter):
        _ = run_skills_setup(SkillsSetupOptions(targets=[]))
