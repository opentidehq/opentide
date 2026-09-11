"""Tests for setup skills command module."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from opentide.cli.enums import SkillTarget
from opentide.cli.services.setup import skills as skills_mod
from opentide.cli.services.setup import skills_registry as registry
from opentide.cli.services.setup.skills import (
    SkillsDownloadError,
    SkillsSetupOptions,
    run_skills_setup,
)

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


def test_copy_skill_tree_includes_references(tmp_path: Path) -> None:
    src = tmp_path / "src-skill"
    src.mkdir()
    (src / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    refs = src / "references"
    refs.mkdir()
    (refs / "Best-Practices.md").write_text("# bp\n", encoding="utf-8")
    (refs / "nested").mkdir()
    dest = tmp_path / "dest"
    written = skills_mod._copy_skill_tree(src, dest)
    assert written == ["SKILL.md", "references/Best-Practices.md"]
    assert (dest / "references" / "Best-Practices.md").read_text(encoding="utf-8") == "# bp\n"
    assert not (dest / "references" / "nested").exists()


def test_download_skill_falls_back_to_bundled_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _real_download_skill,
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda *_, **__: None,
    )
    result = run_skills_setup(
        SkillsSetupOptions(
            path=tmp_path,
            targets=[SkillTarget.generic],
            skill_slugs=["detection-engineering"],
            yes=True,
        )
    )
    skill_md = tmp_path / ".agents" / "skills" / "detection-engineering" / "SKILL.md"
    assert skill_md.is_file()
    assert "detection-engineering" in skill_md.read_text(encoding="utf-8")
    assert "detection-engineering" in result["skills"]


def test_download_skill_fallback_logs_info_not_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _real_download_skill,
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda *_, **__: None,
    )
    infos: list[object] = []
    warnings: list[object] = []
    monkeypatch.setattr(
        skills_mod.logger,
        "info",
        lambda event, **kwargs: infos.append(event),
    )
    monkeypatch.setattr(
        skills_mod.logger,
        "warning",
        lambda event, **kwargs: warnings.append(event),
    )
    run_skills_setup(
        SkillsSetupOptions(
            path=tmp_path,
            targets=[SkillTarget.generic],
            skill_slugs=["detection-engineering"],
            yes=True,
        )
    )
    assert "skills_download_fallback_bundled" in infos
    assert warnings == []


def test_unavailable_skills_empty_for_bundled_starters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda *_, **__: None,
    )
    missing = skills_mod.unavailable_skills(
        SkillsSetupOptions(targets=[SkillTarget.generic], yes=True)
    )
    assert missing == []


def test_unavailable_skills_reports_remote_only_catalogue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda *_, **__: None,
    )
    missing = skills_mod.unavailable_skills(
        SkillsSetupOptions(targets=[SkillTarget.generic], install_all=True, yes=True)
    )
    assert "opentide-detection-rule" not in missing
    assert "detection-engineering" not in missing
    assert "kusto-query-language" in missing


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
    with pytest.raises(SkillsDownloadError, match="network access"):
        run_skills_setup(
            SkillsSetupOptions(
                path=tmp_path,
                targets=[SkillTarget.generic],
                skill_slugs=["kusto-query-language"],
                yes=True,
            )
        )


def test_skill_reachable_when_github_returns_skill_md(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        skills_mod,
        "fetch_github_bytes",
        lambda path, **_: b"# skill\n" if str(path).endswith("SKILL.md") else None,
    )
    assert skills_mod._skill_reachable(
        "kusto-query-language", source="OpenTideHQ/skills", ref="main"
    )
    missing = skills_mod.unavailable_skills(
        SkillsSetupOptions(targets=[SkillTarget.generic], install_all=True, yes=True)
    )
    assert missing == []


def test_download_skill_writes_github_reference_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _fetch(path: str, **_: object) -> bytes | None:
        if path.endswith("SKILL.md"):
            return b"# remote skill\n"
        if path.endswith("Best-Practices.md"):
            return b"# best\n"
        if path.endswith("Anti-Patterns.md"):
            return b"# anti\n"
        return None

    monkeypatch.setattr(skills_mod, "_download_skill", _real_download_skill)
    monkeypatch.setattr(skills_mod, "fetch_github_bytes", _fetch)
    dest = tmp_path / "downloaded"
    written = skills_mod._download_skill("demo-skill", dest, source="OpenTideHQ/skills", ref="main")
    assert written == [
        "SKILL.md",
        "references/Best-Practices.md",
        "references/Anti-Patterns.md",
    ]
    assert (dest / "SKILL.md").read_text(encoding="utf-8") == "# remote skill\n"
    assert (dest / "references" / "Best-Practices.md").read_text(encoding="utf-8") == "# best\n"
    assert (dest / "references" / "Anti-Patterns.md").read_text(encoding="utf-8") == "# anti\n"


def test_install_cursor_replaces_existing_destination(tmp_path: Path) -> None:
    options = SkillsSetupOptions(path=tmp_path, targets=[SkillTarget.cursor], yes=True)
    run_skills_setup(options)
    dest = tmp_path / ".cursor" / "skills" / "opentide-detection-rule"
    stale = dest / "stale.txt"
    stale.write_text("old", encoding="utf-8")
    run_skills_setup(options)
    assert dest.is_dir()
    assert not stale.exists()


def test_install_claude_replaces_existing_destination(tmp_path: Path) -> None:
    options = SkillsSetupOptions(
        path=tmp_path, targets=[SkillTarget.claude_code], name="SOC", yes=True
    )
    run_skills_setup(options)
    dest = tmp_path / ".claude" / "skills" / "opentide-detection-rule"
    stale = dest / "stale.txt"
    stale.write_text("old", encoding="utf-8")
    run_skills_setup(options)
    assert dest.is_dir()
    assert not stale.exists()


def test_install_generic_uses_github_agents_md(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        skills_mod,
        "fetch_github_bytes",
        lambda path, **_: b"# remote agents\n" if path == "AGENTS.md" else None,
    )
    run_skills_setup(SkillsSetupOptions(path=tmp_path, targets=[SkillTarget.generic], yes=True))
    assert (tmp_path / "AGENTS.md").read_text(encoding="utf-8") == "# remote agents\n"
