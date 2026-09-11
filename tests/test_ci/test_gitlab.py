"""GitLab CI template generation tests."""

from __future__ import annotations

from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions


def test_render_gitlab_sets_repo_root_without_inflight() -> None:
    options = CiRenderOptions(ci="gitlab", inflight=False)
    content = render_gitlab(options)
    assert "variables:" in content
    assert "OPENTIDE_REPO_ROOT: $CI_PROJECT_DIR" in content
    preamble = content.split("\nstages:", 1)[0]
    assert "OPENTIDE_REPO_ROOT: $CI_PROJECT_DIR" in preamble
    assert "validate:" in content
    assert "generate:" in content


def test_render_gitlab_includes_stages() -> None:
    options = CiRenderOptions(ci="gitlab", platforms=["sentinel"])
    content = render_gitlab(options)
    assert "stages:" in content
    assert "validate" in content


def test_render_gitlab_omits_promote_when_no_steps() -> None:
    options = CiRenderOptions(ci="gitlab", promotion=True)
    content = render_gitlab(options)
    assert "promote:" not in content
    assert "  - promote" not in content


def test_render_gitlab_inflight_job_when_enabled() -> None:
    options = CiRenderOptions(ci="gitlab", inflight=True)
    content = render_gitlab(options)
    assert "inflight_shards:" in content
    assert "inflight_prune:" in content
    assert "opentide generate inflight" in content
    assert "opentide generate inflight prune" in content


def test_render_gitlab_no_inflight_skips_inflight_job() -> None:
    options = CiRenderOptions(ci="gitlab", inflight=False)
    content = render_gitlab(options)
    assert "inflight_shards:" not in content
