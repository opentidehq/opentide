"""Tests for setup skills command module."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from opentide.cli.enums import SkillTarget
from opentide.cli.services.setup import skills as skills_mod
from opentide.cli.services.setup import skills_registry as registry
from opentide.cli.services.setup.skills import SkillsSetupOptions, run_skills_setup

_real_download_skill = skills_mod._download_skill


@pytest.fixture(autouse=True)
def _mock_skill_download(monkeypatch: pytest.MonkeyPatch) -> None:
    registry.clear_manifest_cache()

    def _fake(slug: str, dest: Path, *, source: str, ref: str) -> list[str]:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "SKILL.md").write_text(f"# {slug} ({source}@{ref})\n", encoding="utf-8")
        return ["SKILL.md"]

    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _fake,
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda path, **_: None,
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
    result = run_skills_setup(
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
    assert result["also_applied"] == ["generic"]


def test_run_skills_setup_requires_target() -> None:
    with pytest.raises(typer.BadParameter):
        _ = run_skills_setup(SkillsSetupOptions(targets=[]))


def test_run_skills_setup_rejects_unknown_slug(tmp_path: Path) -> None:
    with pytest.raises(typer.BadParameter, match="Unknown skill slug"):
        run_skills_setup(
            SkillsSetupOptions(
                path=tmp_path,
                targets=[SkillTarget.generic],
                skill_slugs=["no-such-skill-xyz"],
                yes=True,
            )
        )


def test_run_skills_setup_accepts_bundled_only_slug(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    remote_entries = [registry.SkillEntry(name="Remote", slug="remote-only", description="live")]
    monkeypatch.setattr(
        registry,
        "_fetch_remote_manifest",
        lambda **_: ("OpenTideHQ/skills", "main", remote_entries),
    )
    registry.clear_manifest_cache()
    result = run_skills_setup(
        SkillsSetupOptions(
            path=tmp_path,
            targets=[SkillTarget.generic],
            skill_slugs=["detection-engineering"],
            yes=True,
        )
    )
    assert "detection-engineering" in result["skills"]


def test_download_skill_uses_manifest_ref(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: list[tuple[str, str, str]] = []

    def _capture(path: str, *, source: str, ref: str) -> bytes | None:
        captured.append((path, source, ref))
        if path.endswith("SKILL.md"):
            return b"# skill\n"
        return None

    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _real_download_skill,
    )
    monkeypatch.setattr("opentide.cli.services.setup.skills.fetch_github_bytes", _capture)
    run_skills_setup(
        SkillsSetupOptions(
            path=tmp_path,
            targets=[SkillTarget.generic],
            skill_slugs=["detection-engineering"],
            yes=True,
        )
    )
    skill_calls = [item for item in captured if item[0].endswith("SKILL.md")]
    assert skill_calls
    _, source, ref = skill_calls[0]
    assert source == "OpenTideHQ/skills"
    assert ref


def test_download_skill_actionable_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _real_download_skill,
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda *_, **__: None,
    )
    with pytest.raises(typer.BadParameter, match="network access"):
        run_skills_setup(
            SkillsSetupOptions(
                path=tmp_path,
                targets=[SkillTarget.generic],
                skill_slugs=["detection-engineering"],
                yes=True,
            )
        )
