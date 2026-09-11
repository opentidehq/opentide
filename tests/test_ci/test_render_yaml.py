"""Generated CI pipelines must parse as YAML (issue #163)."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
import yaml

from opentide.ci.azure import render_azure
from opentide.ci.github import render_github
from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions

_OPTION_CASES = (
    pytest.param(CiRenderOptions(ci="github", platforms=["sentinel"]), id="minimal"),
    pytest.param(
        CiRenderOptions(
            ci="github",
            platforms=["sentinel", "splunk"],
            staging=True,
            inflight=True,
            explorer_pages=True,
            default_branch="development",
        ),
        id="all-optional-jobs",
    ),
    pytest.param(
        CiRenderOptions(
            ci="github",
            platforms=["crowdstrike"],
            staging=False,
            inflight=False,
            explorer_pages=False,
            promotion=False,
        ),
        id="no-optional-jobs",
    ),
)


def _load(text: str) -> Any:
    parsed = yaml.safe_load(text)
    assert parsed is not None
    return parsed


@pytest.mark.parametrize("options", _OPTION_CASES)
def test_render_github_is_parseable_yaml(options: CiRenderOptions) -> None:
    options = replace(options, ci="github")
    parsed = _load(render_github(options))
    # PyYAML 1.1 maps unquoted ``on:`` to True; GitHub Actions still accepts the file.
    jobs = parsed["jobs"]
    assert "validate" in jobs
    assert "generate" in jobs
    assert "deploy_production" in jobs
    assert "document" in jobs
    steps = jobs["validate"]["steps"]
    assert isinstance(steps, list)
    assert steps[0]["uses"] == "actions/checkout@v4"
    if options.staging:
        assert "deploy_staging" in jobs
    else:
        assert "deploy_staging" not in jobs
    if options.inflight:
        assert "inflight_shards" in jobs
        assert "inflight_prune" in jobs
    if options.explorer_pages:
        assert "explorer" in jobs
        assert "deploy-explorer" in jobs


@pytest.mark.parametrize("options", _OPTION_CASES)
def test_render_gitlab_is_parseable_yaml(options: CiRenderOptions) -> None:
    options = replace(options, ci="gitlab")
    parsed = _load(render_gitlab(options))
    assert isinstance(parsed["stages"], list)
    assert "validate" in parsed["stages"]
    assert "generate" in parsed["stages"]
    assert "validate" in parsed
    assert parsed["validate"]["script"] == ["opentide validate"]
    if options.inflight:
        assert "inflight_shards" in parsed
    if "sentinel" in options.platforms:
        assert "validate_query_sentinel" in parsed


@pytest.mark.parametrize("options", _OPTION_CASES)
def test_render_azure_is_parseable_yaml(options: CiRenderOptions) -> None:
    options = replace(options, ci="azure")
    parsed = _load(render_azure(options))
    assert "trigger" in parsed
    stages = parsed["stages"]
    assert isinstance(stages, list)
    names = [stage["stage"] for stage in stages]
    assert names[:3] == ["Validate", "Generate", "Deploy"]
    validate_jobs = stages[0]["jobs"]
    assert validate_jobs[0]["job"] == "validate"
    assert isinstance(validate_jobs[0]["steps"], list)
    if options.inflight:
        deploy_jobs = {job["job"] for job in stages[2]["jobs"]}
        assert "inflight_shards" in deploy_jobs
