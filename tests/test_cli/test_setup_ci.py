"""Tests for setup CI command module."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from opentide.cli.enums import CiPlatform
from opentide.cli.services.setup.ci import CiSetupOptions, run_ci_setup

_PLATFORM_TOML = "[platform]\nenabled = true\n"


@pytest.mark.parametrize(
    ("ci", "expected"),
    [
        (CiPlatform.github, ".github/workflows/opentide.yml"),
        (CiPlatform.gitlab, ".gitlab-ci.yml"),
        (CiPlatform.azure, "azure-pipelines.yml"),
    ],
)
def test_run_ci_setup(tmp_path: Path, ci: CiPlatform, expected: str) -> None:
    (tmp_path / ".opentide" / "configurations" / "platforms").mkdir(parents=True)
    (tmp_path / ".opentide" / "configurations" / "platforms" / "sentinel.toml").write_text(
        _PLATFORM_TOML, encoding="utf-8"
    )
    result = run_ci_setup(
        CiSetupOptions(
            path=tmp_path,
            ci=ci,
            yes=True,
        )
    )
    assert (tmp_path / expected).is_file()
    assert expected in result["files"]
    assert result["platforms"] == ["sentinel"]
    rendered = (tmp_path / expected).read_text(encoding="utf-8")
    assert "OPENTIDE_REPO_ROOT" in rendered
    parsed = yaml.safe_load(rendered)
    assert parsed is not None


def test_run_ci_setup_skips_none(tmp_path: Path) -> None:
    result = run_ci_setup(CiSetupOptions(path=tmp_path, ci=CiPlatform.none, yes=True))
    assert result["files"] == []
    assert result["message"] == "CI setup skipped"


def test_run_ci_setup_warns_when_no_platforms(tmp_path: Path) -> None:
    result = run_ci_setup(CiSetupOptions(path=tmp_path, ci=CiPlatform.github, yes=True))
    assert result["warnings"]
    assert result["platforms"] == []
    assert "setup platforms" in result["warnings"][0]
