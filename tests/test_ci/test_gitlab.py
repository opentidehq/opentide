"""GitLab CI template generation tests."""

from __future__ import annotations

import yaml

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


def test_render_gitlab_has_no_promote_stage() -> None:
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


def test_generate_needs_every_query_validation_job() -> None:
    options = CiRenderOptions(
        ci="gitlab",
        platforms=[
            "crowdstrike",
            "sentinel",
            "harfanglab",
            "defender_for_endpoint",
            "splunk",
        ],
    )
    parsed = yaml.safe_load(render_gitlab(options))
    assert parsed["generate"]["needs"] == [
        "validate",
        "validate_query_sentinel",
        "validate_query_defender-for-endpoint",
        "validate_query_splunk",
    ]
    assert "validate_query_crowdstrike" not in parsed
    assert "validate_query_harfanglab" not in parsed
    assert parsed["deploy_production"]["needs"] == ["generate"]


def test_disabled_docs_omits_the_document_job() -> None:
    content = render_gitlab(CiRenderOptions(ci="gitlab", docs_enabled=False, sharing=True))
    parsed = yaml.safe_load(content)
    assert parsed["stages"] == ["validate", "generate", "share", "deploy"]
    assert "document" not in parsed
    assert "script:\n  needs:" not in content


def test_inflight_shell_quotes_the_default_branch_and_exits_on_cd_failure() -> None:
    content = render_gitlab(CiRenderOptions(ci="gitlab", inflight=True))
    assert 'git fetch origin "$CI_DEFAULT_BRANCH"' in content
    assert "git fetch origin $CI_DEFAULT_BRANCH\n" not in content
    assert 'cd "$shards_base" || exit' in content
