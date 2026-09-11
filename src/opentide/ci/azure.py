"""Azure DevOps pipeline renderer."""

from __future__ import annotations

from opentide.ci.inflight import azure_inflight_job, azure_inflight_prune_job
from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import (
    document_steps,
    header_comment,
    pip_install,
    production_deploy_steps,
    promotion_steps,
    staging_deploy_steps,
)
from opentide.ci.text import indent
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
    joined = " && ".join(commands)
    return f"- script: |\n    {joined}"


def _job_steps(options: CiRenderOptions, commands: list[str]) -> str:
    return _python_setup(options) + "\n" + _bash_script(commands)


def _azure_job(
    job_id: str,
    *,
    display_name: str,
    steps: str,
    depends_on: str | None = None,
    condition: str | None = None,
) -> str:
    lines = [f"- job: {job_id}", f"  displayName: {display_name}"]
    if depends_on:
        lines.append(f"  dependsOn: {depends_on}")
    if condition:
        lines.append(f"  condition: {condition}")
    lines.append("  steps:")
    lines.append(indent(steps, 4))
    return "\n".join(lines)


def render_azure(options: CiRenderOptions) -> str:
    branch = options.default_branch

    query_jobs: list[str] = []
    for platform in options.platforms:
        if platform not in QUERY_VALIDATION_PLATFORMS:
            continue
        safe = platform.replace("_", "-")
        query_jobs.append(
            _azure_job(
                f"validate_query_{safe}",
                display_name=f"Validate query ({platform})",
                steps=_job_steps(options, [f"opentide validate query --platform {platform}"]),
            )
        )

    validate_jobs = [
        _azure_job(
            "validate",
            display_name="Validate objects",
            steps=_job_steps(options, ["opentide validate"]),
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
                depends_on="generate",
                condition="eq(variables['Build.Reason'], 'PullRequest')",
                steps=_job_steps(options, staging_deploy_steps(options)),
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
            depends_on="generate",
            condition=f"eq(variables['Build.SourceBranch'], 'refs/heads/{branch}')",
            steps=_job_steps(options, production_deploy_steps(options)),
        )
    )

    promote_stage = ""
    promote_cmds = promotion_steps(options)
    if promote_cmds:
        promote_stage = (
            "- stage: Promote\n"
            "  displayName: Promote\n"
            "  dependsOn: Deploy\n"
            "  condition: >\n"
            f"    and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/{branch}'))\n"
            "  jobs:\n"
            + indent(
                _azure_job(
                    "promote",
                    display_name="Promote rules",
                    steps=_job_steps(options, promote_cmds),
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
    document_stage_yaml = indent(document_stage, 2)

    body = (
        "trigger:\n"
        "  branches:\n"
        "    include:\n"
        f"      - {branch}\n"
        "\n"
        "pr:\n"
        "  branches:\n"
        "    include:\n"
        f"      - {branch}\n"
        "\n"
        "variables:\n"
        "  OPENTIDE_REPO_ROOT: $(Build.SourcesDirectory)\n"
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
        "  - stage: Deploy\n"
        "    displayName: Deploy\n"
        "    dependsOn: Generate\n"
        "    jobs:\n"
        f"{deploy_jobs_yaml}\n"
        "\n"
        f"{document_stage_yaml}\n"
    )
    if promote_stage:
        body += "\n" + indent(promote_stage, 2) + "\n"
    return header_comment(options) + body
