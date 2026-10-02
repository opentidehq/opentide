"""Azure CI template generation tests."""

from __future__ import annotations

import yaml

from opentide.ci.azure import render_azure
from opentide.ci.models import CiRenderOptions


def test_render_azure_sets_repo_root_without_inflight() -> None:
    options = CiRenderOptions(ci="azure", inflight=False)
    content = render_azure(options)
    assert "OPENTIDE_REPO_ROOT: $(Build.SourcesDirectory)" in content
    preamble = content.split("\nstages:", 1)[0]
    assert "OPENTIDE_REPO_ROOT: $(Build.SourcesDirectory)" in preamble
    assert "job: validate" in content
    assert "job: generate" in content


def test_render_azure_runs_on_ubuntu_and_documents_repos_pull_requests() -> None:
    """Azure Repos rejects a pipeline with no pool, and ignores the pr: trigger.

    Topic-branch pushes still validate. Staging stays PullRequest-gated, which
    on Azure Repos requires a build validation policy (#398).
    """
    content = render_azure(CiRenderOptions(ci="azure", default_branch="development"))
    parsed = yaml.safe_load(content)
    assert parsed["pool"] == {"vmImage": "ubuntu-latest"}
    assert parsed["trigger"]["branches"]["include"] == ["*"]
    assert parsed["pr"]["branches"]["include"] == ["development"]
    assert "build validation policy" in content
    assert "eq(variables['Build.Reason'], 'PullRequest')" in content
    assert "refs/heads/development" in content


def test_render_azure_includes_validate_stage() -> None:
    options = CiRenderOptions(ci="azure", platforms=["sentinel"])
    content = render_azure(options)
    assert "trigger:" in content
    assert "Validate" in content
    assert "opentide validate --strict" in content
    assert "opentide lint --strict" in content
    assert "opentide deploy --plan PRODUCTION --skip-unconfigured" in content
    assert "OPENTIDE_SECRETS" not in content
    assert "#   AZURE_CLIENT_SECRET" in content


def test_render_azure_has_no_promote_stage() -> None:
    options = CiRenderOptions(ci="azure", promotion=True)
    content = render_azure(options)
    assert "stage: Promote" not in content


def test_render_azure_inflight_job_when_enabled() -> None:
    options = CiRenderOptions(ci="azure", inflight=True, default_branch="development")
    content = render_azure(options)
    assert "inflight_shards" in content
    assert "inflight_prune" in content
    assert "opentide generate inflight" in content
    assert "opentide generate inflight prune" in content


def test_render_azure_no_inflight_skips_inflight_job() -> None:
    options = CiRenderOptions(ci="azure", inflight=False)
    content = render_azure(options)
    assert "inflight_shards" not in content
