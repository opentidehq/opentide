"""GitHub Actions workflow renderer."""

from __future__ import annotations

import textwrap

from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import (
    document_steps,
    header_comment,
    pip_install,
    production_deploy_steps,
    promotion_steps,
    query_platforms,
    staging_deploy_steps,
)


def _indent_yaml(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else line for line in text.splitlines())


def _run_steps(commands: list[str], indent: int = 10) -> str:
    lines = []
    for cmd in commands:
        lines.append(f"- run: {cmd}")
    return _indent_yaml("\n".join(lines), indent)


def render_github(options: CiRenderOptions) -> str:
    branch = options.default_branch
    setup_steps = textwrap.dedent(
        f"""\
        - uses: actions/checkout@v4
        - uses: actions/setup-python@v5
          with:
            python-version: "{options.python_version}"
        - run: {pip_install(options)}
        """
    )

    validate_body = setup_steps + _run_steps(
        ["opentide validate"]
        + [f"opentide validate query --platform {p}" for p in query_platforms(options)]
    )

    generate_body = setup_steps + _run_steps(["opentide generate"])

    jobs: list[str] = []

    jobs.append(
        textwrap.dedent(
            f"""\
            validate:
              name: Validate
              runs-on: ubuntu-latest
              steps:
            {validate_body}
            """
        )
    )

    jobs.append(
        textwrap.dedent(
            f"""\
            generate:
              name: Generate
              needs: validate
              runs-on: ubuntu-latest
              steps:
            {generate_body}
            """
        )
    )

    if options.staging:
        staging_cmds = staging_deploy_steps(options)
        jobs.append(
            textwrap.dedent(
                f"""\
                deploy_staging:
                  name: Deploy Staging
                  needs: generate
                  if: github.event_name == 'pull_request'
                  runs-on: ubuntu-latest
                  steps:
                {setup_steps}{_run_steps(staging_cmds)}
                """
            )
        )

    prod_needs = "deploy_staging" if options.staging else "generate"
    prod_if = f"github.event_name == 'push' && github.ref == format('refs/heads/{branch}')"
    jobs.append(
        textwrap.dedent(
            f"""\
            deploy_production:
              name: Deploy Production
              needs: {prod_needs}
              if: {prod_if}
              runs-on: ubuntu-latest
              steps:
            {setup_steps}{_run_steps(production_deploy_steps(options))}
            """
        )
    )

    if options.promotion:
        jobs.append(
            textwrap.dedent(
                f"""\
                promote:
                  name: Promote Rules
                  needs: deploy_production
                  if: {prod_if}
                  runs-on: ubuntu-latest
                  steps:
                {setup_steps}{_run_steps(promotion_steps(options))}
                """
            )
        )

    jobs.append(
        textwrap.dedent(
            f"""\
            document:
              name: Document
              needs: generate
              if: {prod_if}
              runs-on: ubuntu-latest
              steps:
            {setup_steps}{_run_steps(document_steps(options))}
            """
        )
    )

    body = textwrap.dedent(
        f"""\
        name: OpenTide

        on:
          pull_request:
          push:
            branches:
              - {branch}

        jobs:
        """
    )
    job_yaml = "\n".join(_indent_yaml(job, 2) for job in jobs)
    return header_comment(options) + body + job_yaml
