"""CI job fragments for inflight preview shard updates on pull requests."""

from __future__ import annotations

import textwrap

from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import inflight_generate_steps, inflight_prune_steps, pip_install

#: GitLab expands ``$VAR``; ``${{ }}`` is GitHub Actions expression syntax and
#: would push to a host literally named ``${{CI_SERVER_HOST}}``.
GITLAB_PUSH = (
    'git push "https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/'
    '${CI_PROJECT_PATH}.git" "HEAD:$CI_DEFAULT_BRANCH"'
)

#: ``python:<ver>-slim`` ships without git, so every git step failed with
#: "command not found" before it could fetch, commit, or push.
GITLAB_INSTALL_GIT = (
    "apt-get update -qq && apt-get install -y -qq --no-install-recommends git > /dev/null"
)


def _commit_and_push(*, message: str, empty_note: str, push: str) -> str:
    """Stage, then commit only when something changed.

    ``git diff --staged --quiet`` exits 1 when there *are* staged changes, so
    chaining it with ``&&`` skips the commit in exactly the case that needs one.

    Every caller emits this as a YAML block scalar. A commit message contains
    ``": "``, which a plain ``- git commit -m "ci: ..."`` sequence item parses
    as a mapping instead of a string, and GitLab then rejects the pipeline.
    """
    return "\n".join(
        [
            "git add .opentide/inflight/",
            "if git diff --staged --quiet; then",
            f'  echo "{empty_note}"',
            "  exit 0",
            "fi",
            f'git commit -m "{message}"',
            push,
        ]
    )


def _default_branch_shards(default_ref: str) -> list[str]:
    """Start from exactly the default branch's shards, not the PR head's copy.

    Overlaying with ``git checkout`` alone keeps files the default branch has
    since pruned, and the PR job would publish them again.
    """
    return [
        "rm -rf .opentide/inflight",
        f'git checkout "{default_ref}" -- .opentide/inflight 2>/dev/null '
        "|| mkdir -p .opentide/inflight",
    ]


def _publish_on_default_branch(*, default_ref: str, push: str) -> str:
    """Commit the regenerated shards on top of the default branch, never on the PR.

    The job checks out the PR (or, on Azure, its merge commit) to see the
    changed objects. Committing there and pushing ``HEAD`` to the default
    branch published the unreviewed PR whenever the push fast-forwarded, so
    only ``.opentide/inflight/`` is carried into a worktree of the default
    branch and committed there.
    """
    return "\n".join(
        [
            'shards_base="$(mktemp -d)"',
            f'git worktree add --detach "$shards_base" "{default_ref}"',
            'rm -rf "$shards_base/.opentide/inflight"',
            'mkdir -p "$shards_base/.opentide"',
            'cp -R .opentide/inflight "$shards_base/.opentide/inflight"',
            'cd "$shards_base"',
            _commit_and_push(
                message="ci: update inflight preview shards [skip ci]",
                empty_note="No inflight shard changes",
                push=push,
            ),
        ]
    )


def github_inflight_job(
    *,
    python_version: str,
    opentide_version: str,
    default_branch: str,
) -> str:
    """Render the GitHub Actions job that updates ``.opentide/inflight/`` on PRs."""
    opts = CiRenderOptions(
        ci="github",
        python_version=python_version,
        opentide_version=opentide_version,
    )
    install = pip_install(opts)
    generate_cmd = inflight_generate_steps(opts)[0]
    default_ref = f"origin/{default_branch}"
    checkout_inflight = textwrap.indent(
        "\n".join(_default_branch_shards(default_ref)), " " * 16
    ).lstrip()
    commit_push = textwrap.indent(
        _publish_on_default_branch(
            default_ref=default_ref,
            push=f'git push origin "HEAD:{default_branch}"',
        ),
        " " * 16,
    ).lstrip()
    return textwrap.dedent(
        f"""\
        inflight_shards:
          name: Update inflight preview shards
          needs: generate
          if: github.event_name == 'pull_request'
          runs-on: ubuntu-latest
          permissions:
            contents: write
          steps:
            - name: Checkout pull request head
              uses: actions/checkout@v4
              with:
                ref: ${{{{ github.head_ref }}}}
                fetch-depth: 0
            - uses: actions/setup-python@v5
              with:
                python-version: "{python_version}"
            - run: {install}
            - name: Merge inflight shards from default branch
              run: |
                git fetch origin {default_branch}
                {checkout_inflight}
            - name: Write inflight shards for changed objects
              run: {generate_cmd}
              env:
                OPENTIDE_REPO_ROOT: ${{{{ github.workspace }}}}
                DEPLOYMENT_PLAN: STAGING
            - name: Push inflight shards to default branch
              run: |
                git config user.name "github-actions[bot]"
                git config user.email "github-actions[bot]@users.noreply.github.com"
                {commit_push}
        """
    )


def github_inflight_prune_job(
    *,
    python_version: str,
    opentide_version: str,
    default_branch: str,
) -> str:
    opts = CiRenderOptions(
        ci="github",
        python_version=python_version,
        opentide_version=opentide_version,
    )
    install = pip_install(opts)
    prune_cmd = inflight_prune_steps(opts)[0]
    prod_if = f"github.event_name == 'push' && github.ref == format('refs/heads/{default_branch}')"
    commit_push = textwrap.indent(
        _commit_and_push(
            message="ci: prune inflight preview shards [skip ci]",
            empty_note="No inflight prune changes",
            push=f"git push origin HEAD:{default_branch}",
        ),
        " " * 16,
    ).lstrip()
    return textwrap.dedent(
        f"""\
        inflight_prune:
          name: Prune inflight preview shards
          needs: generate
          if: {prod_if}
          runs-on: ubuntu-latest
          permissions:
            contents: write
          steps:
            - uses: actions/checkout@v4
              with:
                fetch-depth: 0
            - uses: actions/setup-python@v5
              with:
                python-version: "{python_version}"
            - run: {install}
            - name: Prune superseded inflight shards
              run: {prune_cmd}
              env:
                OPENTIDE_REPO_ROOT: ${{{{ github.workspace }}}}
            - name: Push pruned inflight shards
              run: |
                git config user.name "github-actions[bot]"
                git config user.email "github-actions[bot]@users.noreply.github.com"
                {commit_push}
        """
    )


def gitlab_inflight_job(*, python_version: str, opentide_version: str) -> str:
    opts = CiRenderOptions(
        ci="gitlab",
        python_version=python_version,
        opentide_version=opentide_version,
    )
    generate_cmd = inflight_generate_steps(opts)[0]
    default_ref = "origin/$CI_DEFAULT_BRANCH"
    checkout_inflight = "".join(f"    - {cmd}\n" for cmd in _default_branch_shards(default_ref))
    commit_push = textwrap.indent(
        _publish_on_default_branch(default_ref=default_ref, push=GITLAB_PUSH),
        " " * 6,
    ).lstrip()
    return (
        "inflight_shards:\n"
        "  stage: deploy\n"
        f"  image: python:{python_version}-slim\n"
        "  rules:\n"
        '    - if: $CI_PIPELINE_SOURCE == "merge_request_event"\n'
        "  variables:\n"
        '    GIT_DEPTH: "0"\n'
        "  before_script:\n"
        f"    - {GITLAB_INSTALL_GIT}\n"
        f"    - {pip_install(opts)}\n"
        "  script:\n"
        "    - git fetch origin $CI_DEFAULT_BRANCH\n"
        f"{checkout_inflight}"
        '    - export OPENTIDE_REPO_ROOT="$CI_PROJECT_DIR"\n'
        "    - export DEPLOYMENT_PLAN=STAGING\n"
        f"    - {generate_cmd}\n"
        '    - git config user.email "gitlab-ci@opentide.local"\n'
        '    - git config user.name "gitlab-ci"\n'
        "    - |\n"
        f"      {commit_push}\n"
        "  needs:\n"
        "    - generate"
    )


def gitlab_inflight_prune_job(*, python_version: str, opentide_version: str) -> str:
    opts = CiRenderOptions(
        ci="gitlab",
        python_version=python_version,
        opentide_version=opentide_version,
    )
    prune_cmd = inflight_prune_steps(opts)[0]
    commit_push = textwrap.indent(
        _commit_and_push(
            message="ci: prune inflight preview shards [skip ci]",
            empty_note="No inflight prune changes",
            push=GITLAB_PUSH,
        ),
        " " * 6,
    ).lstrip()
    return (
        "inflight_prune:\n"
        "  stage: deploy\n"
        f"  image: python:{python_version}-slim\n"
        "  rules:\n"
        "    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n"
        "  variables:\n"
        '    GIT_DEPTH: "0"\n'
        "  before_script:\n"
        f"    - {GITLAB_INSTALL_GIT}\n"
        f"    - {pip_install(opts)}\n"
        "  script:\n"
        '    - export OPENTIDE_REPO_ROOT="$CI_PROJECT_DIR"\n'
        f"    - {prune_cmd}\n"
        '    - git config user.email "gitlab-ci@opentide.local"\n'
        '    - git config user.name "gitlab-ci"\n'
        "    - |\n"
        f"      {commit_push}\n"
        "  needs:\n"
        "    - generate"
    )


def azure_inflight_job(*, python_version: str, opentide_version: str, default_branch: str) -> str:
    from opentide.ci.azure import _azure_job, _job_steps

    opts = CiRenderOptions(
        ci="azure",
        python_version=python_version,
        opentide_version=opentide_version,
    )
    generate_cmd = inflight_generate_steps(opts)[0]
    default_ref = f"origin/{default_branch}"
    merge_push = "\n".join(
        [
            f"git fetch origin {default_branch}",
            *_default_branch_shards(default_ref),
            'export OPENTIDE_REPO_ROOT="$BUILD_SOURCESDIRECTORY"',
            "export DEPLOYMENT_PLAN=STAGING",
            generate_cmd,
            'git config user.email "azure-pipelines@opentide.local"',
            'git config user.name "azure-pipelines"',
            _publish_on_default_branch(
                default_ref=default_ref,
                push=f"git push origin HEAD:{default_branch}",
            ),
        ]
    )
    return _azure_job(
        "inflight_shards",
        display_name="Inflight preview shards",
        condition="eq(variables['Build.Reason'], 'PullRequest')",
        steps=_job_steps(opts, [merge_push], persist_credentials=True),
    )


def azure_inflight_prune_job(
    *, python_version: str, opentide_version: str, default_branch: str
) -> str:
    from opentide.ci.azure import _azure_job, _job_steps

    opts = CiRenderOptions(
        ci="azure",
        python_version=python_version,
        opentide_version=opentide_version,
    )
    prune_cmd = inflight_prune_steps(opts)[0]
    prune_script = "\n".join(
        [
            'export OPENTIDE_REPO_ROOT="$BUILD_SOURCESDIRECTORY"',
            prune_cmd,
            'git config user.email "azure-pipelines@opentide.local"',
            'git config user.name "azure-pipelines"',
            _commit_and_push(
                message="ci: prune inflight preview shards [skip ci]",
                empty_note="No inflight prune changes",
                push=f"git push origin HEAD:{default_branch}",
            ),
        ]
    )
    return _azure_job(
        "inflight_prune",
        display_name="Prune inflight preview shards",
        condition=f"eq(variables['Build.SourceBranch'], 'refs/heads/{default_branch}')",
        steps=_job_steps(opts, [prune_script], persist_credentials=True),
    )
