"""Tests for CI stage helpers."""

from __future__ import annotations

from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import (
    core_cli_steps,
    document_steps,
    pip_install,
    production_deploy_steps,
    promotion_steps,
    query_platforms,
    staging_deploy_steps,
)


def test_pip_install_includes_version() -> None:
    options = CiRenderOptions(ci="github", opentide_version="1.2.3")
    assert pip_install(options) == 'pip install "opentide[cli]>=1.2.3"'


def test_query_platforms_filters_supported() -> None:
    options = CiRenderOptions(
        ci="github",
        platforms=["sentinel", "crowdstrike", "defender_for_endpoint"],
    )
    assert query_platforms(options) == ["sentinel", "defender_for_endpoint"]


def test_core_cli_steps_include_validate_and_generate() -> None:
    options = CiRenderOptions(ci="github", platforms=["sentinel"])
    steps = core_cli_steps(options)
    assert steps[0] == "opentide validate"
    assert "opentide validate query --platform sentinel" in steps
    assert steps[-1] == "opentide generate"


def test_staging_and_promotion_steps() -> None:
    enabled = CiRenderOptions(ci="github", staging=True, promotion=True)
    disabled = CiRenderOptions(ci="github", staging=False, promotion=False)
    assert staging_deploy_steps(enabled) == ["opentide deploy --plan STAGING"]
    assert staging_deploy_steps(disabled) == []
    assert promotion_steps(enabled) == ["opentide mutate promote --target PRODUCTION"]
    assert promotion_steps(disabled) == []
    assert production_deploy_steps(enabled) == ["opentide deploy --plan PRODUCTION"]
    assert document_steps(enabled) == ["opentide document --output docs"]
    assert document_steps(CiRenderOptions(ci="github", docs_enabled=False)) == []
