"""Azure CI template generation tests."""

from __future__ import annotations

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


def test_render_azure_includes_validate_stage() -> None:
    options = CiRenderOptions(ci="azure", platforms=["sentinel"])
    content = render_azure(options)
    assert "trigger:" in content
    assert "Validate" in content


def test_render_azure_omits_promote_when_no_steps() -> None:
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
