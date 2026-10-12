"""Branch gates for generated CI jobs.

A generated job that writes outside its own pipeline -- deploying to a tenant,
or pushing a commit to the default branch -- must never run just because a
review is happening. "A pull request is open" says nothing about *where* the
change is headed, so a pull request between two feature branches would
otherwise deploy to a live tenant and land a commit on the default branch.

Every such job is therefore gated on the pair (this is a pull/merge request)
AND (its target is the default branch). The helpers below are the single
definition of that pair per provider; jobs import them rather than spelling
out a condition, so a new job cannot accidentally ship with an event-only
gate.

Jobs that run *after* merge stay gated on the branch they are running on
(``$CI_COMMIT_BRANCH``, ``github.ref``, ``Build.SourceBranch``). Those are
already branch-aware and need nothing from this module.
"""

from __future__ import annotations

GITLAB_MERGE_REQUEST = '$CI_PIPELINE_SOURCE == "merge_request_event"'
"""GitLab: the pipeline is for a merge request, whatever its target."""


def gitlab_premerge_rule() -> str:
    """GitLab ``rules:`` expression for a pre-merge job that writes externally."""
    return f"{GITLAB_MERGE_REQUEST} && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == $CI_DEFAULT_BRANCH"


def github_premerge_if(default_branch: str) -> str:
    """GitHub Actions ``if:`` expression for a pre-merge job that writes externally.

    ``github.base_ref`` is the pull request's target branch and is set only on
    ``pull_request`` events, so it is the branch-aware half of the gate.
    """
    return f"github.event_name == 'pull_request' && github.base_ref == '{default_branch}'"


def azure_premerge_condition(default_branch: str) -> str:
    """Azure Pipelines ``condition:`` for a pre-merge job that writes externally.

    ``System.PullRequest.TargetBranch`` carries the full ref, so it is compared
    against ``refs/heads/<default branch>``.
    """
    return (
        "and("
        "eq(variables['Build.Reason'], 'PullRequest'), "
        f"eq(variables['System.PullRequest.TargetBranch'], 'refs/heads/{default_branch}')"
        ")"
    )
