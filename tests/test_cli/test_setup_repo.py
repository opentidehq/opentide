"""Tests for setup repository scaffolding."""

from __future__ import annotations

from pathlib import Path

from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup


def test_setup_repo_creates_scaffold(tmp_path: Path) -> None:
    target = tmp_path / "my-detections"
    options = RepoSetupOptions(
        path=target,
        name="SOC Detections",
        org="Security Operations",
        platforms=[DetectionPlatform.sentinel, DetectionPlatform.defender],
        yes=True,
    )
    result = run_repo_setup(options)
    assert target.is_dir()
    assert (target / "README.md").is_file()
    assert (target / "objects" / "rules").is_dir()
    assert (target / "docs" / "rules").is_dir()
    assert (target / "docs" / "objectives").is_dir()
    assert (target / "docs" / "threats").is_dir()
    assert (target / ".opentide" / "schemas").is_dir()
    assert (target / ".opentide" / "templates").is_dir()
    assert (target / ".opentide" / "inflight").is_dir()
    assert not (target / "External").exists()
    assert not (target / ".vscode").exists()
    assert result["path"] == str(target.resolve())
    assert "sentinel" in result["platforms"]
    sentinel = target / ".opentide" / "configurations" / "platforms" / "sentinel.toml"
    defender = target / ".opentide" / "configurations" / "platforms" / "defender_for_endpoint.toml"
    assert sentinel.is_file()
    assert defender.is_file()
    assert "enabled = true" in sentinel.read_text(encoding="utf-8")
    assert "enabled = true" in defender.read_text(encoding="utf-8")
    files = result["platform_files"]
    assert isinstance(files, list)
    assert any(str(path).endswith("sentinel.toml") for path in files)


def test_setup_repo_without_platform_leaves_toml_empty(tmp_path: Path) -> None:
    target = tmp_path / "bare"
    result = run_repo_setup(RepoSetupOptions(path=target, name="Bare", yes=True))
    platforms_dir = target / ".opentide" / "configurations" / "platforms"
    assert platforms_dir.is_dir()
    assert list(platforms_dir.glob("*.toml")) == []
    assert "platform_files" not in result


def test_setup_repo_readme_uses_setup_command(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    run_repo_setup(RepoSetupOptions(path=target, name="Test", yes=True))
    readme = (target / "README.md").read_text(encoding="utf-8")
    assert "opentide setup" in readme
    assert "**Organisation:**" not in readme


def test_setup_repo_platform_generate_emits_configuration_stubs(
    tmp_path: Path, monkeypatch
) -> None:
    """First-user path: setup repo --platform then generate templates (#211)."""
    from tests.corpus_support import clear_runtime_caches

    from opentide.core.registry import OpenTide
    from opentide.generation.pydantic_templates import generate_core_template

    target = tmp_path / "sentinel-repo"
    run_repo_setup(
        RepoSetupOptions(
            path=target,
            name="Sentinel Repo",
            platforms=[DetectionPlatform.sentinel],
            yes=True,
        )
    )
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(target))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(target))
    monkeypatch.delenv("OPENTIDE_DATA_ROOT", raising=False)
    clear_runtime_caches()
    OpenTide.initialise()
    path = target / ".opentide" / "templates" / "rule.1.0.template.yaml"
    generate_core_template("rule", path)
    text = path.read_text(encoding="utf-8")
    assert "configurations: {}" not in text
    assert "#sentinel:" in text
    clear_runtime_caches()
