"""Azure DevOps pipeline renderer."""

from __future__ import annotations

import textwrap

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
from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS


def _bash_script(commands: list[str], indent: int = 12) -> str:
    joined = " && ".join(commands)
    pad = " " * indent
    return f"{pad}- script: |\n{pad}    {joined}"


def _python_setup(options: CiRenderOptions, indent: int = 10) -> str:
    pad = " " * indent
    return textwrap.dedent(
        f"""\
        {pad}- task: UsePythonVersion@0
        {pad}  inputs:
        {pad}    versionSpec: '{options.python_version}'
        {pad}- script: {pip_install(options)}
        {pad}  displayName: Install OpenTide
        """
    )


def render_azure(options: CiRenderOptions) -> str:
    branch = options.default_branch
    validate_steps = _python_setup(options) + "\n" + _bash_script(["opentide validate"])

    query_jobs: list[str] = []
    for platform in options.platforms:
        if platform not in QUERY_VALIDATION_PLATFORMS:
            continue
        safe = platform.replace("_", "-")
        query_jobs.append(
            textwrap.dedent(
                f"""\
                  - job: validate_query_{safe}
                    displayName: Validate query ({platform})
                    steps:
                {_python_setup(options)}
                {_bash_script([f"opentide validate query --platform {platform}"])}
                """
            )
        )

    staging_job = ""
    inflight_job = ""
    inflight_prune_job = ""
    if options.staging:
        staging_job = textwrap.dedent(
            f"""\
              - job: deploy_staging
                displayName: Deploy Staging
                dependsOn: generate
                condition: eq(variables['Build.Reason'], 'PullRequest')
                steps:
            {_python_setup(options)}
            {_bash_script(staging_deploy_steps(options))}
            """
        )
    if options.inflight:
        inflight_job = azure_inflight_job(
            python_version=options.python_version,
            opentide_version=options.opentide_version,
            default_branch=branch,
        )
        inflight_prune_job = azure_inflight_prune_job(
            python_version=options.python_version,
            opentide_version=options.opentide_version,
            default_branch=branch,
        )

    promote_stage = ""
    promote_cmds = promotion_steps(options)
    if promote_cmds:
        promote_stage = textwrap.dedent(
            f"""\
            - stage: Promote
              displayName: Promote
              dependsOn: Deploy
              condition: >
                and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/{branch}'))
              jobs:
                - job: promote
                  displayName: Promote rules
                  steps:
            {_python_setup(options)}
            {_bash_script(promotion_steps(options))}
            """
        )

    query_jobs_block = "\n".join(query_jobs)
    validate_jobs = textwrap.dedent(
        f"""\
          - job: validate
            displayName: Validate objects
            steps:
        {validate_steps}
        """
    )
    if query_jobs_block:
        validate_jobs = validate_jobs + query_jobs_block

    body = textwrap.dedent(
        f"""\
        trigger:
          branches:
            include:
              - {branch}

        pr:
          branches:
            include:
              - {branch}

        stages:
          - stage: Validate
            displayName: Validate
            jobs:
        {validate_jobs}

          - stage: Generate
            displayName: Generate
            dependsOn: Validate
            jobs:
              - job: generate
                displayName: Generate framework artifacts
                steps:
            {_python_setup(options)}
            {_bash_script(["opentide generate"])}

          - stage: Deploy
            displayName: Deploy
            dependsOn: Generate
            jobs:
        {staging_job}
        {inflight_job}
        {inflight_prune_job}
              - job: deploy_production
                displayName: Deploy Production
                dependsOn: generate
                condition: eq(variables['Build.SourceBranch'], 'refs/heads/{branch}')
                steps:
            {_python_setup(options)}
            {_bash_script(production_deploy_steps(options))}

          - stage: Document
            displayName: Document
            dependsOn: Generate
            condition: eq(variables['Build.SourceBranch'], 'refs/heads/{branch}')
            jobs:
              - job: document
                displayName: Generate documentation
                steps:
            {_python_setup(options)}
            {_bash_script(document_steps(options))}
        {promote_stage}
        """
    )
    return header_comment(options) + body
