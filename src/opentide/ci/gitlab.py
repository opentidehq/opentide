"""GitLab CI pipeline renderer."""

from __future__ import annotations

import textwrap

from opentide.ci.inflight import gitlab_inflight_job
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


def _script_block(commands: list[str], indent: int = 4) -> str:
    pad = " " * indent
    lines = [f"{pad}- {cmd}" for cmd in commands]
    return "\n".join(lines)


def _base_before_script(options: CiRenderOptions) -> str:
    return _script_block([pip_install(options)])


def render_gitlab(options: CiRenderOptions) -> str:
    stages = ["validate", "generate", "deploy", "document"]
    promote_cmds = promotion_steps(options)
    if promote_cmds:
        stages.insert(3, "promote")

    validate_script = _script_block(["opentide validate"])
    query_jobs: list[str] = []
    for platform in options.platforms:
        if platform not in QUERY_VALIDATION_PLATFORMS:
            continue
        job_name = platform.replace("_", "-")
        query_jobs.append(
            textwrap.dedent(
                f"""\
                validate_query_{job_name}:
                  stage: validate
                  image: python:{options.python_version}-slim
                  before_script:
                {_base_before_script(options)}
                  script:
                    - opentide validate query --platform {platform}
                """
            )
        )

    deploy_jobs: list[str] = []
    if options.staging:
        deploy_jobs.append(
            textwrap.dedent(
                f"""\
                deploy_staging:
                  stage: deploy
                  image: python:{options.python_version}-slim
                  rules:
                    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
                  before_script:
                {_base_before_script(options)}
                  script:
                {_script_block(staging_deploy_steps(options))}
                  needs:
                    - generate
                """
            )
        )

    deploy_jobs.append(
        textwrap.dedent(
            f"""\
            deploy_production:
              stage: deploy
              image: python:{options.python_version}-slim
              rules:
                - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
              before_script:
            {_base_before_script(options)}
              script:
            {_script_block(production_deploy_steps(options))}
              needs:
                - generate
            """
        )
    )

    if options.inflight:
        deploy_jobs.append(
            gitlab_inflight_job(
                python_version=options.python_version,
                opentide_version=options.opentide_version,
            )
        )

    promote_job = ""
    if promote_cmds:
        promote_job = textwrap.dedent(
            f"""\
            promote:
              stage: promote
              image: python:{options.python_version}-slim
              rules:
                - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
              before_script:
            {_base_before_script(options)}
              script:
            {_script_block(promotion_steps(options))}
              needs:
                - deploy_production
            """
        )

    document_job = textwrap.dedent(
        f"""\
        document:
          stage: document
          image: python:{options.python_version}-slim
          rules:
            - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
          before_script:
        {_base_before_script(options)}
          script:
        {_script_block(document_steps(options))}
          needs:
            - generate
        """
    )

    stage_lines = "\n".join(f"  - {stage}" for stage in stages)

    core = textwrap.dedent(
        f"""\
        stages:
        {stage_lines}

        default:
          image: python:{options.python_version}-slim

        validate:
          stage: validate
          before_script:
        {_base_before_script(options)}
          script:
        {validate_script}

        generate:
          stage: generate
          before_script:
        {_base_before_script(options)}
          script:
            - opentide generate
          needs:
            - validate
        """
    )

    parts = [header_comment(options), core]
    parts.extend(query_jobs)
    parts.extend(deploy_jobs)
    if promote_job:
        parts.append(promote_job)
    parts.append(document_job)
    return "\n".join(parts)
