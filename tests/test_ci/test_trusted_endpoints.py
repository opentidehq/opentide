"""Pull-request jobs must not send CI credentials to a tenant URL from the PR."""

from __future__ import annotations

import yaml

from opentide.ci.azure import render_azure
from opentide.ci.github import render_github
from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import trusted_platform_config_commands


def test_commands_replace_the_whole_configuration_tree() -> None:
    commands = trusted_platform_config_commands("main")
    assert commands == [
        "rm -rf -- .opentide/configurations",
        "git fetch origin main --depth=1",
        "git checkout origin/main -- .opentide/configurations",
    ]


def test_branch_name_cannot_break_out_of_the_shell() -> None:
    commands = trusted_platform_config_commands("main; curl https://evil.example")
    assert commands[1] == "git fetch origin 'main; curl https://evil.example' --depth=1"
    assert commands[2] == (
        "git checkout 'origin/main; curl https://evil.example' -- .opentide/configurations"
    )


def test_github_secret_jobs_pin_endpoints_and_production_does_not() -> None:
    workflow = render_github(
        CiRenderOptions(
            ci="github",
            platforms=["elastic", "splunk"],
            staging=True,
            default_branch="development",
        )
    )
    parsed = yaml.safe_load(workflow)
    validate = _run_text(parsed["jobs"]["validate"]["steps"])
    staging = _run_text(parsed["jobs"]["deploy_staging"]["steps"])
    production = _run_text(parsed["jobs"]["deploy_production"]["steps"])
    pin = "git checkout origin/development -- .opentide/configurations"
    assert "rm -rf -- .opentide/configurations" in validate
    assert pin in validate
    assert "opentide validate query --platform elastic --live" in validate
    assert pin in staging
    assert "opentide deploy --plan STAGING" in staging
    assert "rm -rf -- .opentide/configurations" not in production
    assert "AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}" in workflow


def test_gitlab_query_and_staging_jobs_pin_endpoints() -> None:
    parsed = yaml.safe_load(
        render_gitlab(
            CiRenderOptions(
                ci="gitlab",
                platforms=["sentinel", "elastic"],
                staging=True,
                default_branch="main",
            )
        )
    )
    query = parsed["validate_query_elastic"]
    assert "apt-get install -y -qq --no-install-recommends git" in "\n".join(query["before_script"])
    script = "\n".join(query["script"])
    assert "rm -rf -- .opentide/configurations" in script
    assert "git checkout origin/main -- .opentide/configurations" in script
    assert script.index("git checkout") < script.index("opentide validate query")
    staging = "\n".join(parsed["deploy_staging"]["script"])
    assert "git checkout origin/main -- .opentide/configurations" in staging
    assert "rm -rf -- .opentide/configurations" not in "\n".join(parsed["validate"]["script"])
    assert "rm -rf -- .opentide/configurations" not in "\n".join(
        parsed["deploy_production"]["script"]
    )


def test_azure_query_and_staging_jobs_pin_endpoints() -> None:
    text = render_azure(
        CiRenderOptions(
            ci="azure",
            platforms=["elastic"],
            staging=True,
            default_branch="main",
        )
    )
    parsed = yaml.safe_load(text)
    jobs = parsed["stages"][0]["jobs"]
    query = next(job for job in jobs if job["job"] == "validate_query_elastic")
    script = _azure_script(query)
    assert "rm -rf -- .opentide/configurations" in script
    assert "git checkout origin/main -- .opentide/configurations" in script
    query_yaml = text.split("validate_query_elastic", 1)[1].split("- job:", 1)[0]
    assert "persistCredentials: true" in query_yaml
    deploy = next(
        job
        for stage in parsed["stages"]
        if stage.get("displayName") == "Deploy"
        for job in stage["jobs"]
        if job["job"] == "deploy_staging"
    )
    assert "git checkout origin/main -- .opentide/configurations" in _azure_script(deploy)
    objects = next(job for job in jobs if job["job"] == "validate")
    assert "rm -rf -- .opentide/configurations" not in _azure_script(objects)


def _run_text(steps: list[object]) -> str:
    chunks: list[str] = []
    for step in steps:
        if isinstance(step, dict) and isinstance(step.get("run"), str):
            chunks.append(step["run"])
    return "\n".join(chunks)


def _azure_script(job: dict[str, object]) -> str:
    steps = job["steps"]
    assert isinstance(steps, list)
    scripts = [
        step["script"]
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("script"), str)
    ]
    assert scripts
    return "\n".join(scripts)
