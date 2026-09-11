"""GitHub Actions workflow renderer."""

from __future__ import annotations

import textwrap

from opentide.ci.inflight import github_inflight_job, github_inflight_prune_job
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
from opentide.ci.text import indent, join_blocks


def _setup_steps(options: CiRenderOptions) -> str:
    """Checkout, Python, and pip install — unindented relative to ``steps:``."""
    return (
        "- uses: actions/checkout@v4\n"
        "- uses: actions/setup-python@v5\n"
        "  with:\n"
        f'    python-version: "{options.python_version}"\n'
        f"- run: {pip_install(options)}"
    )


def _run_steps(commands: list[str]) -> str:
    return "\n".join(f"- run: {cmd}" for cmd in commands)


def _github_job(
    job_id: str,
    *,
    name: str,
    steps: str,
    needs: str | None = None,
    if_cond: str | None = None,
) -> str:
    lines = [f"{job_id}:", f"  name: {name}", "  runs-on: ubuntu-latest"]
    if needs:
        lines.append(f"  needs: {needs}")
    if if_cond:
        lines.append(f"  if: {if_cond}")
    lines.append("  steps:")
    lines.append(indent(steps, 4))
    return "\n".join(lines)


def _explorer_jobs(branch: str, python_version: str) -> list[str]:
    explorer_job = textwrap.dedent(
        f"""\
        explorer:
          name: Build explorer
          runs-on: ubuntu-latest
          needs: document
          env:
            HAS_GITHUB_APP: ${{{{ secrets.GH_APP_ID && secrets.GH_APP_KEY && 'true' || 'false' }}}}
          steps:
            - name: Checkout repository
              uses: actions/checkout@v4

            - name: Generate GitHub App token
              id: generate_token
              if: ${{{{ env.HAS_GITHUB_APP == 'true' }}}}
              uses: actions/create-github-app-token@v1
              with:
                app-id: ${{{{ secrets.GH_APP_ID }}}}
                private-key: ${{{{ secrets.GH_APP_KEY }}}}
                owner: OpenTideHQ
                repositories: opentide

            - name: Checkout opentide
              uses: actions/checkout@v4
              with:
                repository: OpenTideHQ/opentide
                ref: development
                path: opentide
                token: ${{{{ steps.generate_token.outputs.token || secrets.OPENTIDE_REPO_TOKEN }}}}

            - name: Checkout explorer
              uses: actions/checkout@v4
              with:
                repository: OpenTideHQ/explorer
                ref: main
                path: explorer

            - uses: actions/setup-python@v5
              with:
                python-version: "{python_version}"

            - uses: actions/setup-node@v4
              with:
                node-version: "22"

            - name: Install opentide
              run: pip install -e ./opentide

            - name: Build explorer static site
              run: |
                opentide explorer build \
                  --output ./out/explorer \
                  --base-path /${{{{ github.event.repository.name }}}}
              env:
                OPENTIDE_REPO_ROOT: ${{{{ github.workspace }}}}
                OPENTIDE_EXPLORER_PATH: ${{{{ github.workspace }}}}/explorer

            - name: Upload Pages artifact
              uses: actions/upload-pages-artifact@v3
              with:
                path: ./out/explorer
        """
    )
    deploy_job = textwrap.dedent(
        f"""\
        deploy-explorer:
          name: Deploy explorer to GitHub Pages
          runs-on: ubuntu-latest
          needs: explorer
          if: github.event_name == 'push' && github.ref == format('refs/heads/{branch}')
          permissions:
            pages: write
            id-token: write
          environment:
            name: github-pages
            url: ${{{{ steps.deployment.outputs.page_url }}}}
          steps:
            - name: Deploy to GitHub Pages
              id: deployment
              uses: actions/deploy-pages@v4
        """
    )
    return [explorer_job, deploy_job]


def render_github(options: CiRenderOptions) -> str:
    branch = options.default_branch
    setup = _setup_steps(options)
    validate_steps = join_blocks(
        setup,
        _run_steps(
            ["opentide validate"]
            + [f"opentide validate query --platform {p}" for p in query_platforms(options)]
        ),
    )
    generate_steps = join_blocks(setup, _run_steps(["opentide generate"]))

    jobs: list[str] = [
        _github_job("validate", name="Validate", steps=validate_steps),
        _github_job("generate", name="Generate", needs="validate", steps=generate_steps),
    ]

    if options.staging:
        jobs.append(
            _github_job(
                "deploy_staging",
                name="Deploy Staging",
                needs="generate",
                if_cond="github.event_name == 'pull_request'",
                steps=join_blocks(setup, _run_steps(staging_deploy_steps(options))),
            )
        )

    if options.inflight:
        jobs.append(
            github_inflight_job(
                python_version=options.python_version,
                opentide_version=options.opentide_version,
                default_branch=branch,
            )
        )
        jobs.append(
            github_inflight_prune_job(
                python_version=options.python_version,
                opentide_version=options.opentide_version,
                default_branch=branch,
            )
        )

    prod_needs = "deploy_staging" if options.staging else "generate"
    prod_if = f"github.event_name == 'push' && github.ref == format('refs/heads/{branch}')"
    jobs.append(
        _github_job(
            "deploy_production",
            name="Deploy Production",
            needs=prod_needs,
            if_cond=prod_if,
            steps=join_blocks(setup, _run_steps(production_deploy_steps(options))),
        )
    )

    if options.promotion and promotion_steps(options):
        jobs.append(
            _github_job(
                "promote",
                name="Promote Rules",
                needs="deploy_production",
                if_cond=prod_if,
                steps=join_blocks(setup, _run_steps(promotion_steps(options))),
            )
        )

    jobs.append(
        _github_job(
            "document",
            name="Document",
            needs="generate",
            if_cond=prod_if,
            steps=join_blocks(setup, _run_steps(document_steps(options))),
        )
    )

    if options.explorer_pages:
        jobs.extend(_explorer_jobs(branch, options.python_version))

    permissions = ""
    concurrency = ""
    if options.explorer_pages:
        permissions = textwrap.dedent(
            """\
            permissions:
              contents: read
              pages: write
              id-token: write

            """
        )
        concurrency = textwrap.dedent(
            """\
            concurrency:
              group: pages
              cancel-in-progress: false

            """
        )

    preamble = (
        "name: OpenTide\n"
        "\n"
        "on:\n"
        "  pull_request:\n"
        "  push:\n"
        "    branches:\n"
        f"      - {branch}\n"
        "\n"
        "env:\n"
        "  OPENTIDE_REPO_ROOT: ${{ github.workspace }}\n"
        "\n"
        f"{permissions}{concurrency}jobs:\n"
    )
    job_yaml = "\n".join(indent(job, 2) for job in jobs)
    return header_comment(options) + preamble + job_yaml
