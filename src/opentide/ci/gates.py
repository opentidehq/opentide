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


def gitlab_workflow_rules() -> tuple[str, ...]:
    """GitLab ``workflow:rules``: merge request pipelines and default-branch pipelines.

    Without ``workflow:rules`` a job with no ``rules`` defaults to
    ``except: merge_requests``. A merge request pipeline then held only
    ``deploy_staging`` and ``inflight_shards``, whose ``needs: generate``
    named a job that was not added, so GitLab refused to start it, and every
    push to a branch with an open merge request also ran a branch pipeline.
    With these rules every job runs in merge request pipelines, and a branch
    is validated once it has a merge request, as GitHub validates pull
    requests and pushes to the default branch.
    """
    return (GITLAB_MERGE_REQUEST, "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH")


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


# --- Skipping deploys for a change that touches the whole catalogue -----------------------

SKIP_DEPLOY_MARKER = "[skip deploy]"
"""In a commit message (or a pull/merge request title): run no deploy, share or live check."""

SKIP_DEPLOY_LABEL = "skip-deploy"
"""A pull/merge request label with the same effect as :data:`SKIP_DEPLOY_MARKER`."""

SKIP_DEPLOY_NOTE = (
    f"{SKIP_DEPLOY_MARKER} or the {SKIP_DEPLOY_LABEL} label: no live query check, "
    "deploy or share in this pipeline."
)

#: :data:`SKIP_DEPLOY_MARKER` as a GitLab (RE2) regex literal.
_GITLAB_MARKER = r"/\[skip deploy\]/"


def gitlab_skip_deploy_rules() -> list[dict[str, str]]:
    """``rules:`` entries, listed first, that leave a job out of a skipped pipeline.

    A migration, bulk rename or reformat changes every rule file: its merge
    request would staging-deploy and live-check the whole catalogue, and its
    merge promote and redeploy it. ``[skip deploy]`` in the commit message
    (the merged commit on the default branch: GitLab's default merge and
    squash commit messages include the merge request title), in the merge
    request title, or the ``skip-deploy`` label skips those jobs. Every
    ``needs`` on a job that has these rules is optional, so the pipeline
    still starts.
    """
    label = rf"/(^|,){SKIP_DEPLOY_LABEL}(,|$)/"
    return [
        {"if": f"$CI_COMMIT_MESSAGE =~ {_GITLAB_MARKER}", "when": "never"},
        {"if": f"$CI_MERGE_REQUEST_TITLE =~ {_GITLAB_MARKER}", "when": "never"},
        {"if": f"$CI_MERGE_REQUEST_LABELS =~ {label}", "when": "never"},
    ]


def github_not_skipped() -> str:
    """GitHub ``if:`` terms that are false when a deploy is skipped.

    On a push, the pushed tip's message (a merge commit's holds the pull
    request title); on a pull request, its title or labels. A property of
    the other event is null there, and ``contains`` of null is false.
    """
    return (
        f"!contains(github.event.head_commit.message, '{SKIP_DEPLOY_MARKER}') && "
        f"!contains(github.event.pull_request.title, '{SKIP_DEPLOY_MARKER}') && "
        f"!contains(github.event.pull_request.labels.*.name, '{SKIP_DEPLOY_LABEL}')"
    )


def azure_not_skipped() -> str:
    """Azure ``condition:`` term, false when the triggering commit's first line has the marker.

    ``Build.SourceVersionMessage`` is that first line: an Azure Repos merge
    is ``Merged PR <n>: <title>``, a squash merge the title. Pull request
    builds read the source commit's message in the job instead, see
    :func:`azure_pull_request_skip_guard`; Azure exposes no labels.
    """
    return f"not(contains(variables['Build.SourceVersionMessage'], '{SKIP_DEPLOY_MARKER}'))"


def azure_pull_request_skip_guard() -> str:
    """Shell that exits 0 when the pull request's source commit asks to skip deploys.

    Runs first in the pull request jobs, whose full-history checkout holds
    that commit. Outside a pull request the variable is unset and it does
    nothing.
    """
    return (
        'if [ -n "${SYSTEM_PULLREQUEST_SOURCECOMMITID:-}" ] && '
        'git log -1 --format=%B "$SYSTEM_PULLREQUEST_SOURCECOMMITID" 2>/dev/null '
        f"| grep -qF '{SKIP_DEPLOY_MARKER}'; then "
        f'echo "{SKIP_DEPLOY_NOTE}"; exit 0; fi'
    )
