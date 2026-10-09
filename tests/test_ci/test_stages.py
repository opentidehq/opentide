"""Tests for CI stage helpers."""

from __future__ import annotations

from pathlib import Path

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
    assert pip_install(options) == 'pip install "opentide==1.2.3"'


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
    query = next(step for step in steps if "validate query" in step)
    assert query == "opentide validate query --platform sentinel --live"
    assert steps[-1] == "opentide generate"


def test_query_validation_command_guards_workspace_references(tmp_path: Path) -> None:
    from opentide.ci.azure import render_azure
    from opentide.ci.gitlab import render_gitlab
    from opentide.ci.stages import platform_credential_names_for, query_validation_command

    names = platform_credential_names_for("sentinel")
    assert names == [
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_SUBSCRIPTION_ID",
        "AZURE_TENANT_ID",
        "AZURE_WORKSPACE_ID",
    ]
    assert "SPLUNK_TOKEN" not in names
    assert query_validation_command("sentinel") == (
        "opentide validate query --platform sentinel --live"
    )

    platform_dir = tmp_path / ".opentide" / "configurations" / "platforms"
    platform_dir.mkdir(parents=True)
    (platform_dir / "splunk.toml").write_text(
        "\n".join(
            [
                "[platform]",
                "enabled = true",
                "[tenants.setup]",
                'url = "$SPLUNK_URL"',
                'port = "$SPLUNK_PORT"',
                'token = "$SPLUNK_TOKEN"',
                'app = "DA-DIGIT-S2-CSOC"  # literal — $SPLUNK_APP is never referenced',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (platform_dir / "literal.toml").write_text(
        '[platform]\nenabled = true\napp = "search"\n',
        encoding="utf-8",
    )
    command = query_validation_command("splunk", repo=tmp_path)
    assert "SPLUNK_APP" not in command
    assert ":" not in command
    assert "$SPLUNK_URL$SPLUNK_PORT" not in command
    assert '[ -z "$SPLUNK_PORT" ] || [ -z "$SPLUNK_TOKEN" ] || [ -z "$SPLUNK_URL" ]' in command
    assert (
        "echo skip splunk live query validation SPLUNK_PORT SPLUNK_TOKEN SPLUNK_URL; exit 2"
        in command
    )
    assert command.endswith("else opentide validate query --platform splunk --live; fi")
    assert query_validation_command("literal", repo=tmp_path) == (
        "opentide validate query --platform literal --live"
    )

    options = CiRenderOptions(ci="gitlab", platforms=["splunk", "harfanglab"], repo=tmp_path)
    gitlab = render_gitlab(options)
    azure = render_azure(CiRenderOptions(ci="azure", platforms=["splunk"], repo=tmp_path))
    assert command in gitlab
    assert command in azure
    assert "validate_query_harfanglab" not in gitlab
    assert "validate_query_harfanglab" not in azure


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
