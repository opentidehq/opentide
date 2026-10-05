"""Optional default-branch share stage (sharing CI)."""

from __future__ import annotations

import yaml

from opentide.ci.azure import render_azure
from opentide.ci.github import render_github
from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions

_COMMAND = "opentide share push --changed"


def _options(*, sharing: bool) -> CiRenderOptions:
    return CiRenderOptions(
        ci="github",
        platforms=["sentinel"],
        default_branch="main",
        sharing=sharing,
        staging=True,
        inflight=True,
    )


def test_sharing_is_absent_unless_selected() -> None:
    options = _options(sharing=False)
    for render in (render_github, render_gitlab, render_azure):
        text = render(options)
        assert "opentide share" not in text
        yaml.safe_load(text)


def test_github_share_job_follows_generate_and_not_deploy() -> None:
    text = render_github(_options(sharing=True))
    parsed = yaml.safe_load(text)
    jobs = parsed["jobs"]
    share = jobs["share"]
    assert share["needs"] == "generate"
    assert jobs["deploy_production"]["needs"] == "generate"
    assert "share" not in str(jobs["deploy_production"]["needs"])
    assert share["if"] == "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    assert "format(" not in text
    checkout = next(
        step for step in share["steps"] if str(step.get("uses", "")).startswith("actions/checkout")
    )
    assert checkout["with"]["fetch-depth"] == 0
    runs = [step.get("run") for step in share["steps"]]
    assert _COMMAND in runs
    assert text.count(_COMMAND) == 1
    assert "MISP_" not in text


def test_gitlab_share_stage_needs_generate() -> None:
    text = render_gitlab(_options(sharing=True))
    parsed = yaml.safe_load(text)
    assert parsed["stages"] == ["validate", "generate", "share", "deploy", "document"]
    share = parsed["share"]
    assert share["script"] == [_COMMAND]
    assert share["needs"] == ["generate"]
    assert parsed["deploy_production"]["needs"] == ["generate"]
    assert share["variables"]["GIT_DEPTH"] == "0"
    rule = share["rules"][0]["if"]
    assert "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH" in rule
    assert "merge_request_event" in rule
    assert text.count(_COMMAND) == 1


def test_azure_share_stage_parses_and_does_not_gate_deploy() -> None:
    text = render_azure(_options(sharing=True))
    parsed = yaml.safe_load(text)
    stages = parsed["stages"]
    names = [stage["stage"] for stage in stages]
    assert names == ["Validate", "Generate", "Share", "Deploy", "Document"]
    by_name = {stage["stage"]: stage for stage in stages}
    assert by_name["Share"]["dependsOn"] == "Generate"
    assert by_name["Deploy"]["dependsOn"] == "Generate"
    assert "PullRequest" in by_name["Share"]["condition"]
    assert "refs/heads/main" in by_name["Share"]["condition"]
    assert "condition" not in by_name["Deploy"]
    job = by_name["Share"]["jobs"][0]
    assert job["job"] == "share"
    checkout = next(step for step in job["steps"] if step.get("checkout") == "self")
    assert checkout["fetchDepth"] == 0
    script = job["steps"][-1]["script"]
    assert _COMMAND in script
    assert text.count(_COMMAND) == 1
