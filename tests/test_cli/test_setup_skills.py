"""Tests for setup skills command module."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
from tests.test_cli.conftest import stub_remote_skills_manifest

from opentide.cli.enums import SkillTarget
from opentide.cli.services.setup import skills as skills_mod
from opentide.cli.services.setup import skills_registry as registry
from opentide.cli.services.setup.skills import (
    SkillsDownloadError,
    SkillsSetupOptions,
    run_skills_setup,
)
from opentide.cli.services.setup.skills_registry import SkillsManifestError

_real_download_skill = skills_mod._download_skill


@pytest.fixture(autouse=True)
def _mock_skill_download(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_remote_skills_manifest(monkeypatch)

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
    files = result["files"]
    assert isinstance(files, list)
    assert files.count(".agents/skills/opentide-detection-rule/SKILL.md") == 1


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


def test_run_skills_setup_rejects_slug_absent_from_live_catalogue(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An unknown slug is still refused.

    This used to pass ``detection-engineering`` -- a skill bundled in the wheel
    -- and assert it was rejected, which encoded the defect rather than the
    contract. A slug that is neither in the catalogue nor bundled is the real
    case to refuse.
    """
    stub_remote_skills_manifest(
        monkeypatch,
        [registry.SkillEntry(name="Remote", slug="remote-only", description="live")],
    )
    with pytest.raises(typer.BadParameter, match="Unknown skill slug"):
        run_skills_setup(
            SkillsSetupOptions(
                path=tmp_path,
                targets=[SkillTarget.generic],
                skill_slugs=["no-such-skill-anywhere"],
                yes=True,
            )
        )


def test_run_skills_setup_accepts_a_bundled_slug_the_catalogue_omits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A wheel-bundled authoring skill installs even when upstream omits it."""
    stub_remote_skills_manifest(
        monkeypatch,
        [registry.SkillEntry(name="Remote", slug="remote-only", description="live")],
    )
    run_skills_setup(
        SkillsSetupOptions(
            path=tmp_path,
            targets=[SkillTarget.generic],
            skill_slugs=["opentide-detection-rule"],
            yes=True,
        )
    )
    installed = tmp_path / ".agents" / "skills" / "opentide-detection-rule" / "SKILL.md"
    assert installed.is_file(), "a bundled authoring skill did not install from the package"


def test_download_skill_uses_manifest_ref(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: list[tuple[str, str, str]] = []

    def _capture(path: str, *, source: str, ref: str) -> bytes | None:
        captured.append((path, source, ref))
        if path.endswith("SKILL.md"):
            return b"# skill\n"
        return None

    stub_remote_skills_manifest(monkeypatch, ref="pin-ref")
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _real_download_skill,
    )
    monkeypatch.setattr("opentide.cli.services.setup.skills.fetch_github_bytes", _capture)
    monkeypatch.setattr(
        skills_mod,
        "list_github_paths",
        lambda prefix, **_: [f"{prefix}/SKILL.md"],
    )
    run_skills_setup(
        SkillsSetupOptions(
            path=tmp_path,
            targets=[SkillTarget.generic],
            skill_slugs=["kusto-query-language"],
            yes=True,
        )
    )
    skill_calls = [item for item in captured if item[0].endswith("SKILL.md")]
    assert skill_calls
    _, source, ref = skill_calls[0]
    assert source == "opentidehq/skills"
    assert ref == "pin-ref"


def test_authoring_skills_install_from_the_package_when_github_is_down(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The skills repository still describes CoreTide. These four must not.

    #405: installing the remote text taught agents ``mdr::2.1`` and
    ``Schemas/Templates``.
    """
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _real_download_skill,
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda *_, **__: None,
    )
    monkeypatch.setattr(skills_mod, "list_github_paths", lambda *_, **__: None)
    run_skills_setup(
        SkillsSetupOptions(
            path=tmp_path,
            targets=[SkillTarget.generic],
            skill_slugs=["detection-engineering", "opentide-detection-rule"],
            yes=True,
        )
    )
    engineering = (
        tmp_path / ".agents" / "skills" / "detection-engineering" / "SKILL.md"
    ).read_text(encoding="utf-8")
    rule = (tmp_path / ".agents" / "skills" / "opentide-detection-rule" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    assert "rule::1.0" in engineering
    assert "objects/rules/" in rule
    # The retired schema may appear only as a prohibition, not as the layout to author.
    assert "schema: mdr::" not in engineering
    assert "Do not create" in engineering
    assert "`mdr::2.1`" in engineering
    assert "Schemas/Templates" not in rule


def test_unavailable_skills_keeps_bundled_starters_when_github_is_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda *_, **__: None,
    )
    missing = skills_mod.unavailable_skills(
        SkillsSetupOptions(targets=[SkillTarget.generic], yes=True)
    )
    assert missing == []


def test_unavailable_skills_reports_unreachable_catalogue_slugs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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


def test_run_skills_setup_raises_when_manifest_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    registry.clear_manifest_cache()
    with pytest.raises(SkillsManifestError, match="opentidehq/skills"):
        run_skills_setup(SkillsSetupOptions(path=tmp_path, targets=[SkillTarget.generic], yes=True))


def test_download_skill_actionable_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        _real_download_skill,
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda *_, **__: None,
    )
    monkeypatch.setattr(skills_mod, "list_github_paths", lambda *_, **__: None)
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
        "kusto-query-language", source="opentidehq/skills", ref="main"
    )
    missing = skills_mod.unavailable_skills(
        SkillsSetupOptions(targets=[SkillTarget.generic], install_all=True, yes=True)
    )
    assert missing == []


def test_download_skill_writes_every_file_in_the_github_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Only Best-Practices.md and Anti-Patterns.md used to be fetched (#399)."""

    def _fetch(path: str, **_: object) -> bytes | None:
        name = path.rsplit("/", 1)[-1]
        return f"# {name}\n".encode()

    monkeypatch.setattr(skills_mod, "_download_skill", _real_download_skill)
    monkeypatch.setattr(skills_mod, "fetch_github_bytes", _fetch)
    monkeypatch.setattr(
        skills_mod,
        "list_github_paths",
        lambda prefix, **_: [
            f"{prefix}/SKILL.md",
            f"{prefix}/references/Best-Practices.md",
            f"{prefix}/references/Anti-Patterns.md",
            f"{prefix}/references/Examples.md",
        ],
    )
    dest = tmp_path / "downloaded"
    written = skills_mod._download_skill("demo-skill", dest, source="opentidehq/skills", ref="main")
    assert written == [
        "SKILL.md",
        "references/Best-Practices.md",
        "references/Anti-Patterns.md",
        "references/Examples.md",
    ]
    assert (dest / "references" / "Examples.md").read_text(encoding="utf-8") == "# Examples.md\n"


def test_download_skill_refuses_paths_that_leave_the_skill_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _fetch(path: str, **_: object) -> bytes | None:
        return b"# skill\n"

    monkeypatch.setattr(skills_mod, "_download_skill", _real_download_skill)
    monkeypatch.setattr(skills_mod, "fetch_github_bytes", _fetch)
    monkeypatch.setattr(
        skills_mod,
        "list_github_paths",
        lambda prefix, **_: [f"{prefix}/SKILL.md", f"{prefix}/../../.git/hooks/pre-commit"],
    )
    dest = tmp_path / ".agents" / "skills" / "demo-skill"
    with pytest.raises(SkillsDownloadError, match="Refusing skill path"):
        skills_mod._download_skill("demo-skill", dest, source="opentidehq/skills", ref="main")
    assert not (tmp_path / ".git").exists()
    assert not dest.exists()


def test_download_skill_refuses_a_slug_that_leaves_the_skills_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(skills_mod, "_download_skill", _real_download_skill)
    dest = tmp_path / ".agents" / "skills" / ".." / ".." / ".git" / "hooks"
    with pytest.raises(SkillsDownloadError, match="Refusing skill slug"):
        skills_mod._download_skill("../.git", dest, source="opentidehq/skills", ref="main")
    assert not (tmp_path / ".git").exists()


def test_download_skill_keeps_the_previous_tree_when_a_later_file_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dest = tmp_path / "downloaded"
    (dest / "references").mkdir(parents=True)
    (dest / "SKILL.md").write_text("previous\n", encoding="utf-8")
    (dest / "references" / "Old.md").write_text("old\n", encoding="utf-8")

    def _fetch(path: str, **_: object) -> bytes | None:
        if path.endswith("SKILL.md"):
            return b"new\n"
        return None

    monkeypatch.setattr(skills_mod, "_download_skill", _real_download_skill)
    monkeypatch.setattr(skills_mod, "fetch_github_bytes", _fetch)
    monkeypatch.setattr(
        skills_mod,
        "list_github_paths",
        lambda prefix, **_: [f"{prefix}/SKILL.md", f"{prefix}/references/Examples.md"],
    )
    with pytest.raises(SkillsDownloadError, match="network access"):
        skills_mod._download_skill("demo-skill", dest, source="opentidehq/skills", ref="main")
    assert (dest / "SKILL.md").read_text(encoding="utf-8") == "previous\n"
    assert (dest / "references" / "Old.md").read_text(encoding="utf-8") == "old\n"
    assert not (dest / "references" / "Examples.md").exists()
    assert not (tmp_path / ".downloaded.incoming").exists()


def test_bundled_reinstall_drops_stale_reference_files(tmp_path: Path) -> None:
    dest = tmp_path / "opentide-detection-rule"
    (dest / "references").mkdir(parents=True)
    (dest / "SKILL.md").write_text("stale remote skill\n", encoding="utf-8")
    (dest / "references" / "Best-Practices.md").write_text("coretide\n", encoding="utf-8")
    written = skills_mod._install_bundled_skill("opentide-detection-rule", dest)
    text = (dest / "SKILL.md").read_text(encoding="utf-8")
    assert "rule::1.0" in text
    assert "SKILL.md" in written
    assert not (dest / "references").exists()
    assert not (tmp_path / ".opentide-detection-rule.incoming").exists()
    assert not (tmp_path / ".opentide-detection-rule.previous").exists()


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


def test_install_generic_renders_the_package_agents_template(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The skills-repo AGENTS.md is not this repository's entrypoint (#399)."""
    monkeypatch.setattr(
        skills_mod,
        "fetch_github_bytes",
        lambda path, **_: b"# remote agents\n" if path == "AGENTS.md" else None,
    )
    run_skills_setup(
        SkillsSetupOptions(
            path=tmp_path,
            targets=[SkillTarget.generic],
            name="SOC Detections",
            yes=True,
        )
    )
    text = (tmp_path / "AGENTS.md").read_text(encoding="utf-8")
    assert "# remote agents" not in text
    assert "SOC Detections" in text


def test_rendered_entrypoints_name_mcp_start_not_the_removed_script(tmp_path: Path) -> None:
    """0.12.0 removed ``opentide-mcp``; the entrypoints still told agents to use it (#460)."""
    result = run_skills_setup(
        SkillsSetupOptions(
            path=tmp_path,
            targets=[SkillTarget.claude_code, SkillTarget.github_copilot],
            name="SOC",
            yes=True,
        )
    )
    files = result["files"]
    assert isinstance(files, list)
    for rel in files:
        assert "opentide-mcp" not in (tmp_path / rel).read_text(encoding="utf-8"), rel
    for entrypoint in ("AGENTS.md", "CLAUDE.md"):
        text = (tmp_path / entrypoint).read_text(encoding="utf-8")
        assert "`opentide mcp start`" in text, entrypoint


@pytest.mark.parametrize(
    ("targets", "entrypoint"),
    [
        ([SkillTarget.claude_code], "CLAUDE.md"),
        ([SkillTarget.generic], "AGENTS.md"),
        ([SkillTarget.github_copilot], "AGENTS.md"),
        ([SkillTarget.github_copilot], ".github/copilot-instructions.md"),
    ],
)
def test_setup_skills_keeps_an_existing_entrypoint(
    tmp_path: Path, targets: list[SkillTarget], entrypoint: str
) -> None:
    """The repository's own agent instructions were replaced with the template."""
    dest = tmp_path / entrypoint
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("# Our team's agent rules\n", encoding="utf-8")

    result = run_skills_setup(SkillsSetupOptions(path=tmp_path, targets=targets, yes=True))

    assert dest.read_text(encoding="utf-8") == "# Our team's agent rules\n"
    files = result["files"]
    assert isinstance(files, list)
    assert entrypoint not in files
    assert result["skipped"] == [entrypoint]
    assert result["warnings"] == [
        f"Left {entrypoint} unchanged because the file already exists; point it at "
        ".agents/skills/ by hand, or delete it and re-run to write opentide's template."
    ]


def test_setup_skills_rerun_skips_its_own_entrypoints_quietly(tmp_path: Path) -> None:
    options = SkillsSetupOptions(path=tmp_path, targets=[SkillTarget.claude_code], yes=True)
    run_skills_setup(options)

    again = run_skills_setup(options)

    assert again["skipped"] == ["CLAUDE.md"]
    assert "warnings" not in again
