"""Tests for CI stage helpers."""

from __future__ import annotations

from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import (
    core_cli_steps,
    document_steps,
    inflight_generate_steps,
    pip_install,
    production_deploy_steps,
    query_platforms,
    staging_deploy_steps,
)


def test_pip_install_includes_version() -> None:
    options = CiRenderOptions(ci="github", opentide_version="1.2.3")
    assert pip_install(options) == 'pip install "opentide>=1.2.3"'


def test_query_platforms_filters_supported() -> None:
    options = CiRenderOptions(
        ci="github",
        platforms=["sentinel", "crowdstrike", "defender_for_endpoint"],
    )
    assert query_platforms(options) == ["sentinel", "defender_for_endpoint"]


def test_core_cli_steps_include_validate_and_generate() -> None:
    options = CiRenderOptions(ci="github", platforms=["sentinel"])
    steps = core_cli_steps(options)
    assert steps[0] == "opentide validate --strict"
    assert steps[1] == "opentide lint --strict"
    assert "opentide validate query --platform sentinel" in steps
    assert steps[-1] == "opentide generate"


def test_platform_credentials_are_the_variables_bundled_platform_files_reference() -> None:
    from opentide.ci.stages import header_comment, platform_credential_names

    names = platform_credential_names()
    assert "AZURE_CLIENT_SECRET" in names
    assert "OPENTIDE_SECRETS" not in names
    header = header_comment(CiRenderOptions(ci="github"))
    assert "OPENTIDE_SECRETS" not in header
    for name in names:
        assert f"#   {name}" in header


def test_staging_and_production_steps() -> None:
    enabled = CiRenderOptions(ci="github", staging=True)
    disabled = CiRenderOptions(ci="github", staging=False)
    assert staging_deploy_steps(enabled) == [
        "opentide deploy --dry-run --plan STAGING",
        "opentide deploy --plan STAGING --skip-unconfigured",
    ]
    assert staging_deploy_steps(disabled) == []
    assert production_deploy_steps(enabled) == [
        "opentide deploy --dry-run --plan PRODUCTION",
        "opentide deploy --plan PRODUCTION --skip-unconfigured",
    ]
    assert document_steps(enabled) == ["opentide generate docs --output docs"]
    assert document_steps(CiRenderOptions(ci="github", docs_enabled=False)) == []


def test_inflight_generate_steps() -> None:
    assert inflight_generate_steps(CiRenderOptions(ci="github")) == ["opentide generate inflight"]


def test_inflight_prune_steps() -> None:
    from opentide.ci.stages import inflight_prune_steps

    assert inflight_prune_steps(CiRenderOptions(ci="github")) == [
        "opentide generate inflight prune"
    ]
