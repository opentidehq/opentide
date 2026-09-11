"""GitLab CI pipeline renderer."""

from __future__ import annotations

from opentide.ci.inflight import gitlab_inflight_job, gitlab_inflight_prune_job
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


def _gitlab_job(
    name: str,
    *,
    options: CiRenderOptions,
    stage: str,
    script: list[str],
    needs: str | None = None,
    rules: str | None = None,
    extra_lines: list[str] | None = None,
) -> str:
    lines = [
        f"{name}:",
        f"  stage: {stage}",
        f"  image: python:{options.python_version}-slim",
    ]
    if rules:
        lines.append("  rules:")
        lines.append(f"    - if: {rules}")
    if extra_lines:
        lines.extend(extra_lines)
    lines.append("  before_script:")
    lines.append(f"    - {pip_install(options)}")
    lines.append("  script:")
    lines.extend(f"    - {cmd}" for cmd in script)
    if needs:
        lines.append("  needs:")
        lines.append(f"    - {needs}")
    return "\n".join(lines)


def render_gitlab(options: CiRenderOptions) -> str:
    stages = ["validate", "generate", "deploy", "document"]
    promote_cmds = promotion_steps(options)
    if promote_cmds:
        stages.insert(3, "promote")

    query_jobs: list[str] = []
    for platform in options.platforms:
        if platform not in QUERY_VALIDATION_PLATFORMS:
            continue
        job_name = platform.replace("_", "-")
        query_jobs.append(
            _gitlab_job(
                f"validate_query_{job_name}",
                options=options,
                stage="validate",
                script=[f"opentide validate query --platform {platform}"],
            )
        )

    deploy_jobs: list[str] = []
    if options.staging:
        deploy_jobs.append(
            _gitlab_job(
                "deploy_staging",
                options=options,
                stage="deploy",
                script=staging_deploy_steps(options),
                needs="generate",
                rules='$CI_PIPELINE_SOURCE == "merge_request_event"',
            )
        )

    deploy_jobs.append(
        _gitlab_job(
            "deploy_production",
            options=options,
            stage="deploy",
            script=production_deploy_steps(options),
            needs="generate",
            rules="$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH",
        )
    )

    if options.inflight:
        deploy_jobs.append(
            gitlab_inflight_job(
                python_version=options.python_version,
                opentide_version=options.opentide_version,
            )
        )
        deploy_jobs.append(
            gitlab_inflight_prune_job(
                python_version=options.python_version,
                opentide_version=options.opentide_version,
            )
        )

    promote_job = ""
    if promote_cmds:
        promote_job = _gitlab_job(
            "promote",
            options=options,
            stage="promote",
            script=promote_cmds,
            needs="deploy_production",
            rules="$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH",
        )

    document_job = _gitlab_job(
        "document",
        options=options,
        stage="document",
        script=document_steps(options),
        needs="generate",
        rules="$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH",
    )

    stage_lines = "\n".join(f"  - {stage}" for stage in stages)
    core = (
        "variables:\n"
        "  OPENTIDE_REPO_ROOT: $CI_PROJECT_DIR\n"
        "\n"
        "stages:\n"
        f"{stage_lines}\n"
        "\n"
        f"default:\n"
        f"  image: python:{options.python_version}-slim\n"
        "\n"
        + _gitlab_job(
            "validate",
            options=options,
            stage="validate",
            script=["opentide validate"],
        )
        + "\n\n"
        + _gitlab_job(
            "generate",
            options=options,
            stage="generate",
            script=["opentide generate"],
            needs="validate",
        )
    )

    parts = [header_comment(options), core]
    parts.extend(query_jobs)
    parts.extend(deploy_jobs)
    if promote_job:
        parts.append(promote_job)
    parts.append(document_job)
    return "\n".join(parts) + "\n"
