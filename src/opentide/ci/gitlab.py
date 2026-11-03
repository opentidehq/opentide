"""GitLab CI pipeline renderer.

The pipeline is built as data and written by :func:`~opentide.ci.text.dump_pipeline`:
a rule expression with ``/``, ``[`` or ``: ``, or a commit message in a
command, is quoted by the dumper instead of breaking hand-built YAML.
"""

from __future__ import annotations

from typing import Any

from opentide.ci.gates import gitlab_premerge_rule, gitlab_workflow_rules
from opentide.ci.inflight import (
    GITLAB_FETCH,
    GITLAB_IDENTITY,
    GITLAB_INSTALL_GIT,
    GITLAB_PUSH,
    gitlab_inflight_job,
    gitlab_inflight_prune_job,
)
from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import (
    CODEQUALITY_REPORT,
    DOCS_ARTIFACT,
    OPENTIDE_VERSION_VARIABLE,
    REPORTS_DIR,
    SHARE_COMMAND,
    codequality_merge_command,
    document_steps,
    header_comment,
    object_validate_commands,
    pip_install,
    production_deploy_steps,
    reviewed_query_validation_command,
    staging_deploy_steps,
    trusted_platform_config_commands,
)
from opentide.ci.text import dump_pipeline
from opentide.ci.writeback import (
    deploy_then_writeback,
    overlay_default_branch_state,
    rules_folder,
    writeback_after_cancel,
)
from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS
from opentide.cli.ui.ci import GITLAB_SUMMARY

#: One GitLab job, or one entry of ``rules:``.
Job = dict[str, Any]
Rule = dict[str, str]

#: The project's default branch as GitLab reports it, as in ``GITLAB_FETCH``.
_DEFAULT_BRANCH = '"$CI_DEFAULT_BRANCH"'

#: ``--changed`` diffs from the merge request's base or the previous tip,
#: which a shallow clone may not contain.
FULL_HISTORY = {"GIT_DEPTH": "0"}

DEFAULT_BRANCH_RULE: Rule = {"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"}

#: The deploy jobs record deployments, so GitLab keeps their history, lists
#: the environments, can protect them (approvals, protected variables) and
#: counts production deployments in its DORA metrics. Staging is one
#: environment per merge request: with a single ``staging``, GitLab's
#: "Prevent outdated deployment jobs" would fail the staging job of an older
#: merge request's pipeline once a newer one had deployed. Nothing undeploys a
#: staging environment's rules, so it is only marked stopped after a week.
STAGING_ENVIRONMENT = {
    "name": "staging/mr-$CI_MERGE_REQUEST_IID",
    "deployment_tier": "staging",
    "auto_stop_in": "1 week",
}
PRODUCTION_ENVIRONMENT = {"name": "production", "deployment_tier": "production"}

_WORKFLOW_NOTE = (
    "# Merge request and default-branch pipelines only. Every job then runs in\n"
    "# merge request pipelines, and a push to a branch with an open merge request\n"
    "# starts one pipeline, not two.\n"
)


def optional_need(job: str) -> dict[str, str | bool]:
    """A ``needs`` entry that is ignored when *job* is not in the pipeline.

    A job left out by its ``rules`` (or by rules a project adds) otherwise
    makes GitLab refuse the whole pipeline: "needs job ..., but it was not
    added to the pipeline". Every need of a job that has ``rules`` is one.
    """
    return {"job": job, "optional": True}


def gitlab_job(
    *,
    options: CiRenderOptions,
    stage: str,
    script: list[str],
    needs: list[str | dict[str, str | bool]] | None = None,
    rules: list[Rule] | None = None,
    variables: dict[str, str] | None = None,
    extra: Job | None = None,
    before: list[str] | None = None,
    after: list[str] | None = None,
) -> Job:
    """One job: the image, then *before* and the opentide install, then *script*."""
    job: Job = {"stage": stage, "image": f"python:{options.python_version}-slim"}
    if rules:
        job["rules"] = rules
    if variables:
        job["variables"] = variables
    if extra:
        job.update(extra)
    job["before_script"] = [*(before or []), pip_install()]
    job["script"] = script
    if after:
        job["after_script"] = after
    if needs:
        job["needs"] = needs
    return job


def _block(script: str) -> str:
    """A multi-line command, written as a ``|`` block (a trailing newline, as ``|`` keeps)."""
    return script.rstrip("\n") + "\n"


def _report_artifacts(*, expose_as: str | None = None, codequality: bool = False) -> Job:
    """Keep what opentide wrote under ``opentide-reports/``, failed jobs included.

    Every opentide command appends its summary to ``GITLAB_SUMMARY`` in a
    GitLab job. The validate job also keeps its findings as a Code Quality
    report, which GitLab shows in the merge request and its diff. It declares
    one file, :data:`CODEQUALITY_REPORT`: the runner uploads a ``raw`` report
    as a single file and failed the job when it listed one per command.
    """
    artifacts: Job = {"when": "always"}
    if expose_as:
        artifacts["expose_as"] = expose_as
    artifacts["paths"] = [f"{REPORTS_DIR}/" if codequality else GITLAB_SUMMARY]
    if codequality:
        artifacts["reports"] = {"codequality": CODEQUALITY_REPORT}
    return {"artifacts": artifacts}


def _production_script(options: CiRenderOptions) -> list[str]:
    """Dry-run, then deploy and commit the write-backs (#548).

    GitLab stops at the first failing script line, so the deploy and the
    write-back share one block: the write-back runs even when the deploy
    failed part way, and the block still exits with the deploy's status. The
    default branch's deployment state is laid over the checkout before the
    dry-run.
    """
    dry_run, deploy = production_deploy_steps(options)
    script = deploy_then_writeback(
        deploy=deploy,
        rules=rules_folder(options.repo),
        push=GITLAB_PUSH,
        fetch=GITLAB_FETCH,
    )
    return [
        *GITLAB_IDENTITY,
        _block(overlay_default_branch_state(fetch=GITLAB_FETCH)),
        dry_run,
        _block(script),
    ]


def _production_after_script(options: CiRenderOptions) -> list[str]:
    """Write back after a cancelled deploy; see :func:`writeback_after_cancel`."""
    script = writeback_after_cancel(
        rules=rules_folder(options.repo), push=GITLAB_PUSH, fetch=GITLAB_FETCH
    )
    return [_block(script)]


def _share_job(options: CiRenderOptions) -> Job:
    """Share what the push changed, read from the default branch after the write-back (#590).

    The job needs ``deploy_production`` and checks out the default branch's
    tip, which holds the ``[skip ci]`` commit recording promoted statuses.
    ``--changed`` diffs from ``CI_COMMIT_BEFORE_SHA`` (or the pushed commit's
    parent) to that tip, so a rule this pipeline promoted is shared in it.

    ``when: always`` runs it after a failed deploy too: a share skipped now
    would never come back, because the next push diffs only its own commits.
    GitLab cannot ask for "generate passed, deploy finished", so the job
    validates the checkout first and shares nothing from a broken catalogue.
    """
    return gitlab_job(
        options=options,
        stage="share",
        script=[
            GITLAB_FETCH,
            "git checkout -q FETCH_HEAD",
            "opentide validate --strict",
            SHARE_COMMAND,
        ],
        # deploy_production has rules; when they leave it out the share
        # still runs, as it does after a failed deploy.
        needs=["generate", optional_need("deploy_production")],
        rules=[
            {
                "if": (
                    "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && "
                    '$CI_PIPELINE_SOURCE != "merge_request_event"'
                ),
                "when": "always",
            }
        ],
        variables=dict(FULL_HISTORY),
        # ``python:<ver>-slim`` ships without git; the tip checkout needs it.
        before=[GITLAB_INSTALL_GIT],
    )


def _query_job(options: CiRenderOptions, platform: str) -> Job:
    return gitlab_job(
        options=options,
        stage="validate",
        script=[
            *trusted_platform_config_commands(_DEFAULT_BRANCH),
            reviewed_query_validation_command(platform, repo=options.repo),
        ],
        variables=dict(FULL_HISTORY),
        extra=_report_artifacts(expose_as=f"opentide query {platform}"),
        # python slim has no git; without it the endpoint checkout cannot run.
        before=[GITLAB_INSTALL_GIT],
    )


def pipeline_document(options: CiRenderOptions) -> Job:
    """The pipeline as data: global keys first, then the jobs in stage order."""
    # An empty ``script:`` is null YAML. GitLab rejects the pipeline (GL003, #430).
    doc_commands = document_steps(options)
    stages = ["validate", "generate", "deploy"]
    if doc_commands:
        stages.append("document")
    if options.sharing:
        # After deploy: the share job reads the production write-back (#590).
        stages.insert(stages.index("deploy") + 1, "share")

    # Query jobs share the validate stage. ``needs: validate`` alone lets
    # generate, then deploy, start while a query job is still running or after
    # it has failed (#429).
    query_jobs: dict[str, Job] = {}
    for platform in options.platforms:
        if platform in QUERY_VALIDATION_PLATFORMS:
            query_jobs[f"validate_query_{platform.replace('_', '-')}"] = _query_job(
                options, platform
            )

    jobs: dict[str, Job] = {
        "validate": gitlab_job(
            options=options,
            stage="validate",
            script=object_validate_commands("codequality"),
            extra=_report_artifacts(expose_as="opentide reports", codequality=True),
            # ``after_script`` runs after a failed command too, so the merge
            # request shows the findings of the command that failed.
            after=[codequality_merge_command()],
        ),
        "generate": gitlab_job(
            options=options,
            stage="generate",
            script=["opentide generate"],
            # Optional: a query job that rules leave out, such as rules a
            # project adds, must not stop GitLab creating the pipeline.
            needs=["validate", *(optional_need(name) for name in query_jobs)],
        ),
        **query_jobs,
    }
    if options.staging:
        jobs["deploy_staging"] = gitlab_job(
            options=options,
            stage="deploy",
            script=[
                *trusted_platform_config_commands(_DEFAULT_BRANCH),
                *staging_deploy_steps(options),
            ],
            needs=["generate"],
            rules=[{"if": gitlab_premerge_rule()}],
            variables=dict(FULL_HISTORY),
            extra={
                "environment": dict(STAGING_ENVIRONMENT),
                **_report_artifacts(expose_as="opentide staging plan"),
            },
            before=[GITLAB_INSTALL_GIT],
        )
    jobs["deploy_production"] = gitlab_job(
        options=options,
        stage="deploy",
        script=_production_script(options),
        needs=["generate"],
        rules=[dict(DEFAULT_BRANCH_RULE)],
        variables=dict(FULL_HISTORY),
        extra={
            # One production deploy at a time: two at once would both create
            # the same new rule. A resource group is ``unordered`` until its
            # process mode is set to ``oldest_first`` (API only; see the docs).
            "resource_group": "opentide-production",
            "environment": dict(PRODUCTION_ENVIRONMENT),
            **_report_artifacts(),
        },
        # ``python:<ver>-slim`` ships without git; the write-back needs it.
        before=[GITLAB_INSTALL_GIT],
        after=_production_after_script(options),
    )
    if options.inflight:
        jobs["inflight_shards"] = gitlab_inflight_job(
            python_version=options.python_version,
        )
        jobs["inflight_prune"] = gitlab_inflight_prune_job(
            python_version=options.python_version,
        )
    if options.sharing:
        jobs["share"] = _share_job(options)
    if doc_commands:
        jobs["document"] = gitlab_job(
            options=options,
            stage="document",
            script=doc_commands,
            needs=["generate"],
            rules=[dict(DEFAULT_BRANCH_RULE)],
            # The pages were rendered and thrown away with the runner.
            extra={"artifacts": {"name": DOCS_ARTIFACT, "paths": [f"{options.docs_output}/"]}},
        )

    return {
        "workflow": {"rules": [{"if": rule} for rule in gitlab_workflow_rules()]},
        "variables": {
            "OPENTIDE_REPO_ROOT": "$CI_PROJECT_DIR",
            # Every job installs this release; a project or group CI/CD
            # variable of the same name overrides it.
            OPENTIDE_VERSION_VARIABLE: options.opentide_version,
        },
        "stages": stages,
        "default": {"image": f"python:{options.python_version}-slim"},
        **jobs,
    }


def render_gitlab(options: CiRenderOptions) -> str:
    return (
        header_comment(options) + "\n" + _WORKFLOW_NOTE + dump_pipeline(pipeline_document(options))
    )
