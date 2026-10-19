"""Azure DevOps pipeline renderer."""

from __future__ import annotations

import shlex

from opentide.ci.gates import azure_premerge_condition
from opentide.ci.inflight import azure_inflight_job, azure_inflight_prune_job
from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import (
    document_steps,
    header_comment,
    object_validate_commands,
    pip_install,
    production_deploy_steps,
    query_validation_command,
    staging_deploy_steps,
    trusted_platform_config_commands,
)
from opentide.ci.text import indent
from opentide.ci.writeback import (
    overlay_default_branch_state,
    production_writeback,
    rules_folder,
)
from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS


def _python_setup(options: CiRenderOptions) -> str:
    """UsePythonVersion + pip install, unindented relative to ``steps:``."""
    return (
        "- task: UsePythonVersion@0\n"
        "  inputs:\n"
        f"    versionSpec: '{options.python_version}'\n"
        f"- script: {pip_install(options)}\n"
        "  displayName: Install OpenTide"
    )


def _bash_script(commands: list[str]) -> str:
    """One multi-line bash step.

    Joining with ``&&`` made control flow impossible: an ``exit 0`` guard
    swallowed every later command, and a deliberate non-zero test aborted the
    rest of the chain. ``set -e`` keeps the fail-fast behaviour that the
    ``&&`` join was there for.
    """
    body = "\n".join(["set -e", *commands])
    return "- script: |\n" + indent(body, 4)


def _checkout_step(*, persist_credentials: bool, full_history: bool = False) -> str:
    """Azure clones with throwaway credentials unless asked otherwise.

    Persisted credentials alone keep the pipeline's fetch depth: a job that
    only fetches one path does not need the full history.
    """
    if not persist_credentials and not full_history:
        return ""
    lines = ["- checkout: self"]
    if persist_credentials:
        lines.append("  persistCredentials: true")
    if full_history:
        lines.append("  fetchDepth: 0")
    return "\n".join(lines) + "\n"


def _job_steps(
    options: CiRenderOptions,
    commands: list[str],
    *,
    persist_credentials: bool = False,
    full_history: bool = False,
) -> str:
    return (
        _checkout_step(persist_credentials=persist_credentials, full_history=full_history)
        + _python_setup(options)
        + "\n"
        + _bash_script(commands)
    )


#: Set by the deploy step just before the real deploy starts.
DEPLOY_STARTED = "OPENTIDE_DEPLOY_STARTED"

#: Run after a failed, cancelled or timed-out deploy too, so the ids of the
#: rules it did create are committed, but not when the deploy never started.
#: ``succeededOrFailed()`` is false after a cancellation; ``always()`` is not.
WRITEBACK_CONDITION = f"and(always(), eq(variables['{DEPLOY_STARTED}'], 'true'))"

_GIT_IDENTITY = (
    'git config user.email "azure-pipelines@opentide.local"',
    'git config user.name "azure-pipelines"',
)


def _production_commands(options: CiRenderOptions) -> list[str]:
    dry_run, deploy = production_deploy_steps(options)
    return [
        *_GIT_IDENTITY,
        overlay_default_branch_state(fetch=f"git fetch origin {options.default_branch}"),
        dry_run,
        f'echo "##vso[task.setvariable variable={DEPLOY_STARTED}]true"',
        deploy,
    ]


def _writeback_step(options: CiRenderOptions) -> str:
    """Commit promoted rules and deployment state to the default branch (#548).

    A step of its own. It runs when the deploy step failed after starting
    the real deploy, and the failed deploy step still fails the job.
    """
    branch = options.default_branch
    script = _bash_script(
        [
            *_GIT_IDENTITY,
            production_writeback(
                rules=rules_folder(options.repo),
                push=f"git push origin HEAD:{branch}",
                fetch=f"git fetch origin {branch}",
            ),
        ]
    )
    return (
        script
        + "\n  displayName: Commit deployment write-backs"
        + f"\n  condition: {WRITEBACK_CONDITION}"
    )


def _azure_job(
    job_id: str,
    *,
    display_name: str,
    steps: str,
    condition: str | None = None,
) -> str:
    """Render one job.

    Deliberately no ``dependsOn``: Azure resolves job dependencies inside a
    single stage, and every caller here wanted a job from an earlier stage.
    The stage-level ``dependsOn`` already expresses that ordering.
    """
    lines = [f"- job: {job_id}", f"  displayName: {display_name}"]
    if condition:
        lines.append(f"  condition: {condition}")
    lines.append("  steps:")
    lines.append(indent(steps, 4))
    return "\n".join(lines)


def render_azure(options: CiRenderOptions) -> str:
    branch = options.default_branch
    restore = trusted_platform_config_commands(shlex.quote(branch))

    query_jobs: list[str] = []
    for platform in options.platforms:
        if platform not in QUERY_VALIDATION_PLATFORMS:
            continue
        safe = platform.replace("_", "-")
        query_jobs.append(
            _azure_job(
                f"validate_query_{safe}",
                display_name=f"Validate query ({platform})",
                steps=_job_steps(
                    options,
                    [*restore, query_validation_command(platform, repo=options.repo)],
                    # The checkout token is removed before later steps unless it
                    # is persisted, and the endpoint restore has to fetch.
                    persist_credentials=True,
                ),
            )
        )

    validate_jobs = [
        _azure_job(
            "validate",
            display_name="Validate objects",
            steps=_job_steps(options, object_validate_commands()),
        ),
        *query_jobs,
    ]

    generate_job = _azure_job(
        "generate",
        display_name="Generate framework artifacts",
        steps=_job_steps(options, ["opentide generate"]),
    )

    deploy_jobs: list[str] = []
    if options.staging:
        deploy_jobs.append(
            _azure_job(
                "deploy_staging",
                display_name="Deploy Staging",
                condition=azure_premerge_condition(branch),
                steps=_job_steps(
                    options,
                    [*restore, *staging_deploy_steps(options)],
                    persist_credentials=True,
                    full_history=True,
                ),
            )
        )
    if options.inflight:
        deploy_jobs.append(
            azure_inflight_job(
                python_version=options.python_version,
                opentide_version=options.opentide_version,
                default_branch=branch,
            )
        )
        deploy_jobs.append(
            azure_inflight_prune_job(
                python_version=options.python_version,
                opentide_version=options.opentide_version,
                default_branch=branch,
            )
        )
    deploy_jobs.append(
        _azure_job(
            "deploy_production",
            display_name="Deploy Production",
            condition=f"eq(variables['Build.SourceBranch'], 'refs/heads/{branch}')",
            # Persisted credentials let the write-back step push.
            steps=_job_steps(
                options,
                _production_commands(options),
                persist_credentials=True,
                full_history=True,
            )
            + "\n"
            + _writeback_step(options),
        )
    )

    share_stage = ""
    if options.sharing:
        share_stage = (
            "- stage: Share\n"
            "  displayName: Share\n"
            "  dependsOn: Generate\n"
            "  condition: and("
            f"eq(variables['Build.SourceBranch'], 'refs/heads/{branch}'), "
            "ne(variables['Build.Reason'], 'PullRequest'))\n"
            "  jobs:\n"
            + indent(
                _azure_job(
                    "share",
                    display_name="Share changed objects",
                    steps=_job_steps(
                        options,
                        ["opentide share push --changed"],
                        full_history=True,
                    ),
                ),
                4,
            )
        )

    document_stage = (
        "- stage: Document\n"
        "  displayName: Document\n"
        "  dependsOn: Generate\n"
        f"  condition: eq(variables['Build.SourceBranch'], 'refs/heads/{branch}')\n"
        "  jobs:\n"
        + indent(
            _azure_job(
                "document",
                display_name="Generate documentation",
                steps=_job_steps(options, document_steps(options)),
            ),
            4,
        )
    )

    validate_jobs_yaml = indent("\n".join(validate_jobs), 6)
    generate_job_yaml = indent(generate_job, 6)
    deploy_jobs_yaml = indent("\n".join(deploy_jobs), 6)
    share_stage_yaml = indent(share_stage, 2) if share_stage else ""
    # indent() drops the trailing newline, so a share stage must be followed by
    # a blank line or its last job line glues onto Deploy.
    share_block = f"{share_stage_yaml}\n\n" if share_stage_yaml else ""
    document_stage_yaml = indent(document_stage, 2)

    body = (
        "trigger:\n"
        "  branches:\n"
        "    include:\n"
        "      - '*'\n"
        "\n"
        "# Azure Repos Git ignores pr:. Add a build validation policy on the\n"
        "# default branch so pull requests set Build.Reason to PullRequest.\n"
        "# Staging deploy stays gated on that reason. Hosted Azure Pipelines\n"
        "# (GitHub or Bitbucket) honor pr: as written.\n"
        "pr:\n"
        "  branches:\n"
        "    include:\n"
        f"      - {branch}\n"
        "\n"
        "pool:\n"
        "  vmImage: ubuntu-latest\n"
        "\n"
        "variables:\n"
        "  OPENTIDE_REPO_ROOT: $(Build.SourcesDirectory)\n"
        "\n"
        "# Azure cannot serialise a job from YAML alone. Add an Exclusive lock\n"
        "# check to a resource the Deploy stage uses (for example an environment\n"
        "# or the agent pool); this line then queues runs in order instead of\n"
        "# cancelling all but the latest.\n"
        "lockBehavior: sequential\n"
        "\n"
        "stages:\n"
        "  - stage: Validate\n"
        "    displayName: Validate\n"
        "    jobs:\n"
        f"{validate_jobs_yaml}\n"
        "\n"
        "  - stage: Generate\n"
        "    displayName: Generate\n"
        "    dependsOn: Validate\n"
        "    jobs:\n"
        f"{generate_job_yaml}\n"
        "\n"
        f"{share_block}"
        "  - stage: Deploy\n"
        "    displayName: Deploy\n"
        "    dependsOn: Generate\n"
        "    jobs:\n"
        f"{deploy_jobs_yaml}\n"
        "\n"
        f"{document_stage_yaml}\n"
    )
    return header_comment(options) + body
