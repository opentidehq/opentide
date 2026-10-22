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


def test_github_share_job_runs_after_production_on_the_branch_tip() -> None:
    """#590: the share job reads the production write-back, so it follows deploy."""
    text = render_github(_options(sharing=True))
    parsed = yaml.safe_load(text)
    jobs = parsed["jobs"]
    share = jobs["share"]
    assert share["needs"] == ["generate", "deploy_production"]
    assert jobs["deploy_production"]["needs"] == "generate"
    assert "share" not in str(jobs["deploy_production"]["needs"])
    # A failed or no-op deploy still shares; a failed generate or a cancel does not.
    assert share["if"] == (
        "${{ !cancelled() && needs.generate.result == 'success' && "
        "github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
    )
    assert "format(" not in text
    checkout = next(
        step for step in share["steps"] if str(step.get("uses", "")).startswith("actions/checkout")
    )
    # The default branch, not the triggering commit: the tip holds the write-back.
    assert checkout["with"]["ref"] == "main"
    assert checkout["with"]["fetch-depth"] == 0
    runs = [step.get("run") for step in share["steps"]]
    assert _COMMAND in runs
    assert text.count(_COMMAND) == 1
    assert "MISP_" not in text
    assert list(jobs).index("share") > list(jobs).index("deploy_production")


def test_github_share_checkout_follows_the_default_branch() -> None:
    options = CiRenderOptions(ci="github", default_branch="trunk", sharing=True)
    share = yaml.safe_load(render_github(options))["jobs"]["share"]
    checkout = share["steps"][0]
    assert checkout["with"]["ref"] == "trunk"
    assert "refs/heads/trunk" in share["if"]


def test_gitlab_share_job_runs_after_production_on_the_branch_tip() -> None:
    text = render_gitlab(_options(sharing=True))
    parsed = yaml.safe_load(text)
    assert parsed["stages"] == ["validate", "generate", "deploy", "share", "document"]
    share = parsed["share"]
    assert share["needs"] == ["generate", "deploy_production"]
    assert parsed["deploy_production"]["needs"] == ["generate"]
    # The tip checkout comes first, and the share command reads it.
    assert share["script"] == [
        'git fetch origin "$CI_DEFAULT_BRANCH"',
        "git checkout -q FETCH_HEAD",
        "opentide validate --strict",
        _COMMAND,
    ]
    assert any("apt-get install" in line for line in share["before_script"])
    assert share["variables"]["GIT_DEPTH"] == "0"
    rule = share["rules"][0]
    assert "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH" in rule["if"]
    assert "merge_request_event" in rule["if"]
    # A failed deploy still shares, as on GitHub and Azure.
    assert rule["when"] == "always"
    assert text.count(_COMMAND) == 1
    assert "when: always" not in yaml.safe_dump(parsed["deploy_production"])


def test_azure_share_stage_runs_after_deploy_on_the_branch_tip() -> None:
    text = render_azure(_options(sharing=True))
    parsed = yaml.safe_load(text)
    stages = parsed["stages"]
    names = [stage["stage"] for stage in stages]
    assert names == ["Validate", "Generate", "Deploy", "Share", "Document"]
    by_name = {stage["stage"]: stage for stage in stages}
    assert by_name["Share"]["dependsOn"] == ["Generate", "Deploy"]
    assert by_name["Deploy"]["dependsOn"] == "Generate"
    condition = by_name["Share"]["condition"]
    assert "not(canceled())" in condition
    assert "eq(dependencies.Generate.result, 'Succeeded')" in condition
    # A failed Deploy must not skip the share, so its result is not tested.
    assert "dependencies.Deploy" not in condition
    assert "PullRequest" in condition
    assert "refs/heads/main" in condition
    assert "condition" not in by_name["Deploy"]
    job = by_name["Share"]["jobs"][0]
    assert job["job"] == "share"
    checkout = next(step for step in job["steps"] if step.get("checkout") == "self")
    assert checkout["fetchDepth"] == 0
    assert checkout["persistCredentials"] is True
    script = job["steps"][-1]["script"]
    lines = script.splitlines()
    assert lines.index("git fetch origin main") < lines.index("git checkout -q FETCH_HEAD")
    assert lines.index("git checkout -q FETCH_HEAD") < lines.index(_COMMAND)
    assert text.count(_COMMAND) == 1
