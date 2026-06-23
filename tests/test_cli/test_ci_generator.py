"""Tests for generated client CI pipeline files."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.ci.models import CiRenderOptions
from opentide.ci.render import render_ci
from opentide.cli.enums import CiPlatform, DetectionPlatform
from opentide.cli.services.ci_generator import write_ci
from opentide.cli.services.init import InitOptions, run_init

FORBIDDEN = (
    "CoreTide",
    "coretide",
    "Orchestration",
    "Engines/requirements",
    "TIDE_CORE_REPO",
    "raw.githubusercontent.com/OpenTideHQ/CoreTide",
)

REQUIRED = (
    "opentide validate",
    "opentide generate",
    "opentide deploy",
    "opentide document",
)


@pytest.mark.parametrize(
    "ci",
    [CiPlatform.github, CiPlatform.gitlab, CiPlatform.azure],
)
def test_render_ci_smoke(ci: CiPlatform) -> None:
    options = CiRenderOptions(
        ci=ci.value,
        platforms=[DetectionPlatform.sentinel.value, DetectionPlatform.defender.value],
        staging=True,
        promotion=True,
    )
    files = render_ci(options)
    assert len(files) == 1
    path, content = next(iter(files.items()))
    assert path == CiRenderOptions(ci=ci.value).output_path()
    for token in FORBIDDEN:
        assert token not in content
    for token in REQUIRED:
        assert token in content


@pytest.mark.parametrize(
    "ci",
    [CiPlatform.github, CiPlatform.gitlab, CiPlatform.azure],
)
def test_render_ci_respects_flags(ci: CiPlatform) -> None:
    options = CiRenderOptions(
        ci=ci.value,
        platforms=[DetectionPlatform.sentinel.value],
        staging=False,
        promotion=False,
    )
    content = next(iter(render_ci(options).values()))
    assert "deploy --plan STAGING" not in content
    assert "mutate promote" not in content


@pytest.mark.parametrize(
    "ci",
    [CiPlatform.github, CiPlatform.gitlab, CiPlatform.azure],
)
def test_write_ci_creates_expected_file(tmp_path: Path, ci: CiPlatform) -> None:
    options = CiRenderOptions(ci=ci.value, platforms=[DetectionPlatform.sentinel.value])
    written = write_ci(tmp_path, options)
    assert written == [options.output_path()]
    assert (tmp_path / options.output_path()).is_file()


@pytest.mark.parametrize(
    ("ci", "expected"),
    [
        (CiPlatform.github, ".github/workflows/opentide.yml"),
        (CiPlatform.gitlab, ".gitlab-ci.yml"),
        (CiPlatform.azure, "azure-pipelines.yml"),
    ],
)
def test_init_generates_ci_file(tmp_path: Path, ci: CiPlatform, expected: str) -> None:
    target = tmp_path / f"repo-{ci.value}"
    options = InitOptions(
        path=target,
        name="Test Detections",
        platforms=[DetectionPlatform.sentinel],
        ci=ci,
        yes=True,
    )
    run_init(options)
    content = (target / expected).read_text(encoding="utf-8")
    for token in FORBIDDEN:
        assert token not in content
    for token in REQUIRED:
        assert token in content
