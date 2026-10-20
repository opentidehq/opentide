"""The inflight commit fragment must be runnable before any shard exists."""

from __future__ import annotations

import pytest

from opentide.ci.inflight import (
    _commit_and_push,
    azure_inflight_job,
    github_inflight_job,
    gitlab_inflight_job,
)


def test_commit_and_push_creates_inflight_before_git_add() -> None:
    script = _commit_and_push(
        message="ci: prune inflight preview shards [skip ci]",
        empty_note="No inflight prune changes",
        push="git push origin HEAD:main",
        fetch="git fetch origin main",
    )
    mkdir = script.index("mkdir -p .opentide/inflight")
    add = script.index("git add .opentide/inflight/")
    assert mkdir < add


@pytest.mark.parametrize(
    "job",
    [
        github_inflight_job(python_version="3.12", opentide_version="0.1.0", default_branch="main"),
        gitlab_inflight_job(python_version="3.12", opentide_version="0.1.0"),
        azure_inflight_job(python_version="3.12", opentide_version="0.1.0", default_branch="main"),
    ],
    ids=["github", "gitlab", "azure"],
)
def test_inflight_jobs_no_longer_export_a_deployment_plan(job: str) -> None:
    """``DEPLOYMENT_PLAN`` was removed in 0.17.0; setting it now fails ``deploy``."""
    assert "opentide generate inflight" in job
    assert "DEPLOYMENT_PLAN" not in job
    assert "--plan" not in job
