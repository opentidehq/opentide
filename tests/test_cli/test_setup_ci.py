"""Tests for setup CI command module."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.cli.enums import CiPlatform, DetectionPlatform
from opentide.cli.services.setup.ci import CiSetupOptions, run_ci_setup


@pytest.mark.parametrize(
    ("ci", "expected"),
    [
        (CiPlatform.github, ".github/workflows/opentide.yml"),
        (CiPlatform.gitlab, ".gitlab-ci.yml"),
        (CiPlatform.azure, "azure-pipelines.yml"),
    ],
)
def test_run_ci_setup(tmp_path: Path, ci: CiPlatform, expected: str) -> None:
    result = run_ci_setup(
        CiSetupOptions(
            path=tmp_path,
            ci=ci,
            platforms=[DetectionPlatform.sentinel],
            yes=True,
        )
    )
    assert (tmp_path / expected).is_file()
    assert expected in result["files"]


def test_run_ci_setup_skips_none(tmp_path: Path) -> None:
    result = run_ci_setup(CiSetupOptions(path=tmp_path, ci=CiPlatform.none, yes=True))
    assert result["files"] == []
    assert result["message"] == "CI setup skipped"
