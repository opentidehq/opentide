"""GitLab CI pipeline renderer."""

from __future__ import annotations

from opentide.ci.inflight import gitlab_inflight_job, gitlab_inflight_prune_job
from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import (
    document_steps,
    header_comment,
    object_validate_commands,
    pip_install,
    production_deploy_steps,
    staging_deploy_steps,
)
from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS


def _need_lines(needs: str | list[str] | None) -> list[str]:
    if needs is None:
        return []
    names = [needs] if isinstance(needs, str) else list(needs)
    if not names:
        return []
    return ["  needs:", *(f"    - {name}" for name in names)]


def _gitlab_job(
    name: str,
    *,
    options: CiRenderOptions,
    stage: str,
    script: list[str],
    needs: str | list[str] | None = None,
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
    lines.extend(_need_lines(needs))
    return "\n".join(lines)


def render_gitlab(options: CiRenderOptions) -> str:
    # An empty ``script:`` is null YAML. GitLab rejects the pipeline (GL003, #430).
    doc_commands = document_steps(options)
    stages = ["validate", "generate", "deploy"]
    if doc_commands:
        stages.append("document")
    if options.sharing:
        stages.insert(2, "share")

    # Query jobs share the validate stage. ``needs: validate`` alone lets
    # generate, then deploy, start while a query job is still running or after
    # it has failed (#429).
    query_job_names: list[str] = []
    query_jobs: list[str] = []
    for platform in options.platforms:
        if platform not in QUERY_VALIDATION_PLATFORMS:
            continue
        job_name = f"validate_query_{platform.replace('_', '-')}"
        query_job_names.append(job_name)
        query_jobs.append(
            _gitlab_job(
                job_name,
                options=options,
                stage="validate",
                script=[f"opentide validate query --platform {platform}"],
            )
        )

    full_history = ["  variables:", '    GIT_DEPTH: "0"']
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
                extra_lines=full_history,
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
            extra_lines=full_history,
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

    document_job = ""
    if doc_commands:
        document_job = _gitlab_job(
            "document",
            options=options,
            stage="document",
            script=doc_commands,
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
            script=object_validate_commands(),
        )
        + "\n\n"
        + _gitlab_job(
            "generate",
            options=options,
            stage="generate",
            script=["opentide generate"],
            needs=["validate", *query_job_names],
        )
    )

    parts = [header_comment(options), core]
    parts.extend(query_jobs)
    if options.sharing:
        parts.append(
            _gitlab_job(
                "share",
                options=options,
                stage="share",
                script=["opentide share push --changed"],
                needs="generate",
                rules=(
                    "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && "
                    '$CI_PIPELINE_SOURCE != "merge_request_event"'
                ),
                extra_lines=["  variables:", '    GIT_DEPTH: "0"'],
            )
        )
    parts.extend(deploy_jobs)
    if document_job:
        parts.append(document_job)
    return "\n".join(parts) + "\n"
