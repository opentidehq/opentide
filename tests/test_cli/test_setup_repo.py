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
    assert (target / "Objects" / "Detection Rules").is_dir()
    assert (target / "Analytics").is_dir()
    assert (target / "Schemas" / "Templates").is_dir()
    assert not (target / "External").exists()
    assert not (target / ".vscode").exists()
    assert result["path"] == str(target.resolve())
    assert "sentinel" in result["platforms"]


def test_setup_repo_readme_uses_setup_command(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    run_repo_setup(RepoSetupOptions(path=target, name="Test", yes=True))
    readme = (target / "README.md").read_text(encoding="utf-8")
    assert "opentide setup" in readme
    assert "**Organisation:** Security Operations" in readme
