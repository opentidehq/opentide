"""``setup ci --lint-changed``: the lint gate checks the files each run changed."""

from __future__ import annotations

import pytest
import yaml

from opentide.ci.azure import render_azure
from opentide.ci.github import render_github
from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import object_validate_commands


def test_the_default_gate_lints_every_file() -> None:
    assert object_validate_commands() == ["opentide validate --strict", "opentide lint --strict"]


def test_lint_changed_narrows_lint_only() -> None:
    assert object_validate_commands("sarif", lint_changed=True) == [
        "opentide validate --strict --format sarif --output opentide-reports/validate.sarif",
        "opentide lint --strict --changed --format sarif --output opentide-reports/lint.sarif",
    ]


@pytest.mark.parametrize("lint_changed", [False, True])
def test_gitlab_validate_job_has_git_and_history_for_a_changed_lint(lint_changed: bool) -> None:
    pipeline = yaml.safe_load(
        render_gitlab(CiRenderOptions(ci="gitlab", inflight=False, lint_changed=lint_changed))
    )
    job = pipeline["validate"]
    lint = [line for line in job["script"] if line.startswith("opentide lint")]
    assert len(lint) == 1
    assert ("--changed" in lint[0]) is lint_changed
    assert (job.get("variables", {}).get("GIT_DEPTH") == "0") is lint_changed
    assert any("install" in line and " git" in line for line in job["before_script"]) is (
        lint_changed
    )


@pytest.mark.parametrize("lint_changed", [False, True])
def test_github_and_azure_fetch_history_for_a_changed_lint(lint_changed: bool) -> None:
    github = render_github(CiRenderOptions(ci="github", inflight=False, lint_changed=lint_changed))
    azure = render_azure(CiRenderOptions(ci="azure", inflight=False, lint_changed=lint_changed))
    for text in (github, azure):
        assert ("opentide lint --strict --changed" in text) is lint_changed
    if lint_changed:
        assert "fetch-depth: 0" in github
        assert "fetchDepth: 0" in azure
