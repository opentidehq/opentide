"""GitHub Actions workflow renderer."""

from __future__ import annotations

import shlex
import textwrap

from opentide.ci.gates import github_premerge_if
from opentide.ci.inflight import github_inflight_job, github_inflight_prune_job
from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import (
    GATE_COMMANDS,
    REPORTS_DIR,
    SHARE_COMMAND,
    document_steps,
    github_deploy_env,
    header_comment,
    object_validate_commands,
    pip_install,
    production_deploy_steps,
    query_platforms,
    report_path,
    reviewed_query_validation_command,
    staging_deploy_steps,
    trusted_platform_config_commands,
)
from opentide.ci.text import indent, join_blocks
from opentide.ci.writeback import (
    overlay_default_branch_state,
    production_writeback,
    rules_folder,
)

_SHARE_STEPS_NOTE = (
    "# API key environment variables named in sharing.toml come from the CI secret store."
)


def _setup_steps(options: CiRenderOptions, *, full_history: bool = False) -> str:
    """Checkout, Python, and pip install — unindented relative to ``steps:``."""
    if full_history:
        checkout = "- uses: actions/checkout@v4\n  with:\n    fetch-depth: 0"
    else:
        checkout = "- uses: actions/checkout@v4"
    return (
        f"{checkout}\n"
        "- uses: actions/setup-python@v5\n"
        "  with:\n"
        f'    python-version: "{options.python_version}"\n'
        f"- run: {pip_install(options)}"
    )


def _run_steps(commands: list[str]) -> str:
    return "\n".join(f"- run: {cmd}" for cmd in commands)


#: The validate job writes SARIF and keeps it as the ``opentide-reports``
#: artifact. A separate job sends it to code scanning, so the one token that can
#: write security alerts never shares a job with the platform secrets. Code
#: scanning is free on public repositories and needs GitHub Advanced Security on
#: private ones, so private repositories skip it: remove
#: ``!github.event.repository.private`` once it is enabled. A failed upload
#: never fails the run (a fork's pull request cannot write alerts). Each SARIF
#: run carries ``automationDetails.id`` ``opentide/<command>/``, which
#: upload-sarif uses as the category, so no ``category`` input is passed.
CODE_SCANNING_PERMISSIONS = "security-events: write"
CODE_SCANNING_IF = "${{ !cancelled() && !github.event.repository.private }}"


def _report_artifact_step() -> str:
    """Keep the reports as an artifact, for people and for the code scanning job."""
    return (
        "- name: Upload opentide reports\n"
        "  if: ${{ !cancelled() }}\n"
        "  uses: actions/upload-artifact@v4\n"
        "  with:\n"
        "    name: opentide-reports\n"
        f"    path: {REPORTS_DIR}/\n"
        "    if-no-files-found: ignore"
    )


def _code_scanning_steps() -> str:
    """Download the validate job's reports and send each SARIF file to code scanning."""
    steps = [
        "- name: Download opentide reports\n"
        "  uses: actions/download-artifact@v4\n"
        "  continue-on-error: true\n"
        "  with:\n"
        "    name: opentide-reports\n"
        f"    path: {REPORTS_DIR}/"
    ]
    for command in GATE_COMMANDS:
        sarif = report_path(command, "sarif")
        steps.append(
            f"- name: Upload {command} findings to code scanning\n"
            f"  if: ${{{{ hashFiles('{sarif}') != '' }}}}\n"
            "  uses: github/codeql-action/upload-sarif@v4\n"
            "  continue-on-error: true\n"
            "  with:\n"
            f"    sarif_file: {sarif}"
        )
    return "\n".join(steps)


def _reviewed_tenants_step(name: str, default_branch: str, commands: list[str]) -> str:
    """Run ``commands`` against the default branch's configuration.

    One step, not one per command: the restore exits early when the default
    branch has no configuration yet, and that has to skip ``commands`` too.
    Empty when there is nothing to run.
    """
    if not commands:
        return ""
    restore = trusted_platform_config_commands(shlex.quote(default_branch))
    script = "\n".join([*restore, *commands])
    return f"- name: {name}\n  run: |\n" + indent(script, 4)


def _github_job(
    job_id: str,
    *,
    name: str,
    steps: str,
    needs: str | None = None,
    if_cond: str | None = None,
    env: str | None = None,
    permissions: str | None = None,
    concurrency: str | None = None,
) -> str:
    lines = [f"{job_id}:", f"  name: {name}", "  runs-on: ubuntu-latest"]
    if needs:
        lines.append(f"  needs: {needs}")
    if if_cond:
        lines.append(f"  if: {if_cond}")
    if concurrency:
        lines.append("  concurrency:")
        lines.append(indent(concurrency, 4))
    if permissions:
        lines.append("  permissions:")
        lines.append(indent(permissions, 4))
    if env:
        lines.append(indent(env, 2))
    lines.append("  steps:")
    lines.append(indent(steps, 4))
    return "\n".join(lines)


#: The write-back runs whenever the deploy step started: also when it failed
#: part way, was cancelled, or hit the job timeout, so the ids of the rules it
#: did create are committed. ``always()`` is what lets a step run after a
#: cancellation; ``!cancelled()`` did not. A dry-run failure skips the deploy
#: step, and then there is nothing to record.
WRITEBACK_IF = "${{ always() && steps.deploy.outcome != 'skipped' }}"

#: The GitHub production job deliberately has no ``concurrency`` group. GitHub
#: keeps one run pending per group and cancels an older *pending* run, and the
#: production plan deploys only its own commit's diff, so a burst of merges
#: would silently never deploy the middle one. Overlapping runs are tolerated
#: instead: the tip-state overlay and the per-tenant replay turn a double
#: create into a reported ``deployment_state_conflict`` (RFC 0010).

_GIT_IDENTITY = (
    'git config user.name "github-actions[bot]"',
    'git config user.email "github-actions[bot]@users.noreply.github.com"',
)


def _production_steps(options: CiRenderOptions) -> str:
    """State overlay, dry-run, then the deploy as a step with an id the write-back can test."""
    dry_run, deploy = production_deploy_steps(options)
    overlay = "\n".join(
        [
            *_GIT_IDENTITY,
            overlay_default_branch_state(fetch=f"git fetch origin {options.default_branch}"),
        ]
    )
    return (
        "- name: Use the default branch's deployment state\n  run: |\n"
        + indent(overlay, 4)
        + f"\n- run: {dry_run}\n- name: Deploy\n  id: deploy\n  run: {deploy}"
    )


def _writeback_step(options: CiRenderOptions) -> str:
    """Commit promoted rules and deployment state to the default branch (#548)."""
    branch = options.default_branch
    script = production_writeback(
        rules=rules_folder(options.repo),
        push=f'git push origin "HEAD:{branch}"',
        fetch=f"git fetch origin {branch}",
    )
    body = "\n".join([*_GIT_IDENTITY, script])
    return f"- name: Commit deployment write-backs\n  if: {WRITEBACK_IF}\n  run: |\n" + indent(
        body, 4
    )


#: Share once the production job has finished, whether it deployed, failed or
#: had nothing to do: a share it skipped would never come back, because the
#: next push diffs only its own commits. Generate must have passed.
SHARE_IF_PREFIX = "!cancelled() && needs.generate.result == 'success' && "


def _share_job(options: CiRenderOptions, prod_if: str) -> str:
    """Share what the push changed, read from the default branch after the write-back (#590).

    The production job promotes rules and pushes the new statuses to the
    default branch in a ``[skip ci]`` commit. The share job checks out the
    branch tip after that, and ``--changed`` diffs from the triggering push's
    baseline to the tip, so a rule this run promoted is shared in this run.
    """
    checkout = (
        "- uses: actions/checkout@v4\n"
        "  with:\n"
        f"    ref: {options.default_branch}\n"
        "    fetch-depth: 0"
    )
    setup = (
        f"{checkout}\n"
        "- uses: actions/setup-python@v5\n"
        "  with:\n"
        f'    python-version: "{options.python_version}"\n'
        f"- run: {pip_install(options)}"
    )
    return _github_job(
        "share",
        name="Share",
        needs="[generate, deploy_production]",
        if_cond="${{ " + SHARE_IF_PREFIX + prod_if + " }}",
        steps=join_blocks(
            setup,
            "\n".join([_SHARE_STEPS_NOTE, _run_steps([SHARE_COMMAND])]),
        ),
    )


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
                owner: opentidehq
                repositories: opentide

            - name: Checkout opentide
              uses: actions/checkout@v4
              with:
                repository: opentidehq/opentide
                ref: development
                path: opentide
                token: ${{{{ steps.generate_token.outputs.token || secrets.OPENTIDE_REPO_TOKEN }}}}

            - name: Checkout explorer
              uses: actions/checkout@v4
              with:
                repository: opentidehq/explorer
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

            - name: Export explorer bundle
              run: opentide --json generate explorer
              env:
                OPENTIDE_REPO_ROOT: ${{{{ github.workspace }}}}

            - name: Build explorer static site
              working-directory: explorer
              run: |
                npm ci
                npm run build
              env:
                OPENTIDE_BUNDLE: ${{{{ github.workspace }}}}/.opentide/exports/explorer.bundle.json
                NEXT_PUBLIC_BASE_PATH: /${{{{ github.event.repository.name }}}}

            - name: Collect static site
              run: |
                mkdir -p ./out
                mv explorer/out ./out/explorer

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
          if: github.event_name == 'push' && github.ref == 'refs/heads/{branch}'
          concurrency:
            group: pages
            cancel-in-progress: false
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
    # Object validation reads the pull request's own configuration. Only the
    # steps that send credentials use the default branch's copy.
    queries = [
        reviewed_query_validation_command(p, repo=options.repo) for p in query_platforms(options)
    ]
    validate_steps = join_blocks(
        # ``--changed`` diffs from the pull request's merge base, or from the
        # pushed commit's parent: neither is in a one-commit checkout.
        _setup_steps(options, full_history=bool(queries)),
        _run_steps(object_validate_commands("sarif")),
        _reviewed_tenants_step("Validate queries on reviewed tenants", branch, queries),
        _report_artifact_step(),
    )
    deploy_env = github_deploy_env()
    generate_steps = join_blocks(setup, _run_steps(["opentide generate"]))

    jobs: list[str] = [
        _github_job("validate", name="Validate", env=deploy_env, steps=validate_steps),
        _github_job(
            "code_scanning",
            name="Code scanning",
            needs="validate",
            if_cond=CODE_SCANNING_IF,
            permissions=CODE_SCANNING_PERMISSIONS,
            steps=_code_scanning_steps(),
        ),
        _github_job("generate", name="Generate", needs="validate", steps=generate_steps),
    ]

    prod_if = f"github.event_name == 'push' && github.ref == 'refs/heads/{branch}'"

    if options.staging:
        jobs.append(
            _github_job(
                "deploy_staging",
                name="Deploy Staging",
                needs="generate",
                if_cond=github_premerge_if(branch),
                env=deploy_env,
                steps=join_blocks(
                    _setup_steps(options, full_history=True),
                    _reviewed_tenants_step(
                        "Deploy staging to reviewed tenants", branch, staging_deploy_steps(options)
                    ),
                ),
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

    # Staging runs only on pull requests. Production runs on push to the default
    # branch, so it cannot ``needs`` the staging job: a skipped need skips it too.
    jobs.append(
        _github_job(
            "deploy_production",
            name="Deploy Production",
            needs="generate",
            if_cond=prod_if,
            env=deploy_env,
            # The write-back step pushes to the default branch.
            permissions="contents: write",
            steps=join_blocks(
                _setup_steps(options, full_history=True),
                _production_steps(options),
                _writeback_step(options),
            ),
        )
    )

    if options.sharing:
        jobs.append(_share_job(options, prod_if))

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

    # The Pages permissions and the ``pages`` concurrency group belong to the
    # deploy-explorer job alone. At workflow level the group held every run of
    # the workflow: GitHub keeps one run pending per group and cancels the older
    # pending one, so a burst of merges never deployed the middle merge's rules.
    permissions = ""
    if options.explorer_pages:
        permissions = textwrap.dedent(
            """\
            permissions:
              contents: read

            """
        )

    preamble = (
        "name: opentide\n"
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
        f"{permissions}jobs:\n"
    )
    job_yaml = "\n".join(indent(job, 2) for job in jobs)
    return header_comment(options) + preamble + job_yaml.rstrip("\n") + "\n"
