"""CI job fragments for inflight preview shard updates on pull requests."""

from __future__ import annotations

import textwrap

from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import inflight_generate_steps, inflight_prune_steps, pip_install


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
    checkout_inflight = (
        f'git checkout "origin/{default_branch}" -- .opentide/inflight 2>/dev/null '
        "|| mkdir -p .opentide/inflight"
    )
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
                git add .opentide/inflight/
                git diff --staged --quiet && echo "No inflight shard changes" && exit 0
                git commit -m "ci: update inflight preview shards [skip ci]"
                git push origin "HEAD:{default_branch}"
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
                git add .opentide/inflight/
                git diff --staged --quiet && echo "No inflight prune changes" && exit 0
                git commit -m "ci: prune inflight preview shards [skip ci]"
                git push origin HEAD:{default_branch}
        """
    )


def gitlab_inflight_job(*, python_version: str, opentide_version: str) -> str:
    opts = CiRenderOptions(
        ci="gitlab",
        python_version=python_version,
        opentide_version=opentide_version,
    )
    install_block = f"    - {pip_install(opts)}"
    generate_cmd = inflight_generate_steps(opts)[0]
    checkout_inflight = (
        'git checkout "origin/$CI_DEFAULT_BRANCH" -- .opentide/inflight 2>/dev/null '
        "|| mkdir -p .opentide/inflight"
    )
    gitlab_push = (
        'git push "https://gitlab-ci-token:${{CI_JOB_TOKEN}}@${{CI_SERVER_HOST}}/'
        '${{CI_PROJECT_PATH}}.git" "HEAD:$CI_DEFAULT_BRANCH"'
    )
    return textwrap.dedent(
        f"""\
        inflight_shards:
          stage: deploy
          image: python:{python_version}-slim
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
          variables:
            GIT_DEPTH: "0"
          before_script:
        {install_block}
          script:
            - git fetch origin $CI_DEFAULT_BRANCH
            - {checkout_inflight}
            - export OPENTIDE_REPO_ROOT="$CI_PROJECT_DIR"
            - export DEPLOYMENT_PLAN=STAGING
            - {generate_cmd}
            - git config user.email "gitlab-ci@opentide.local"
            - git config user.name "gitlab-ci"
            - git add .opentide/inflight/
            - |
              if git diff --staged --quiet; then
                echo "No inflight shard changes"
                exit 0
              fi
            - git commit -m "ci: update inflight preview shards [skip ci]"
            - {gitlab_push}
          needs:
            - generate
        """
    )


def gitlab_inflight_prune_job(*, python_version: str, opentide_version: str) -> str:
    opts = CiRenderOptions(
        ci="gitlab",
        python_version=python_version,
        opentide_version=opentide_version,
    )
    install_block = f"    - {pip_install(opts)}"
    prune_cmd = inflight_prune_steps(opts)[0]
    gitlab_push = (
        'git push "https://gitlab-ci-token:${{CI_JOB_TOKEN}}@${{CI_SERVER_HOST}}/'
        '${{CI_PROJECT_PATH}}.git" "HEAD:$CI_DEFAULT_BRANCH"'
    )
    return textwrap.dedent(
        f"""\
        inflight_prune:
          stage: deploy
          image: python:{python_version}-slim
          rules:
            - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
          variables:
            GIT_DEPTH: "0"
          before_script:
        {install_block}
          script:
            - export OPENTIDE_REPO_ROOT="$CI_PROJECT_DIR"
            - {prune_cmd}
            - git config user.email "gitlab-ci@opentide.local"
            - git config user.name "gitlab-ci"
            - git add .opentide/inflight/
            - |
              if git diff --staged --quiet; then
                echo "No inflight prune changes"
                exit 0
              fi
            - git commit -m "ci: prune inflight preview shards [skip ci]"
            - {gitlab_push}
          needs:
            - generate
        """
    )


def azure_inflight_job(*, python_version: str, opentide_version: str, default_branch: str) -> str:
    from opentide.ci.azure import _bash_script, _python_setup

    opts = CiRenderOptions(
        ci="azure",
        python_version=python_version,
        opentide_version=opentide_version,
    )
    setup = _python_setup(opts)
    generate_cmd = inflight_generate_steps(opts)[0]
    checkout_inflight = (
        f'git checkout "origin/{default_branch}" -- .opentide/inflight 2>/dev/null '
        "|| mkdir -p .opentide/inflight"
    )
    merge_push = " && ".join(
        [
            f"git fetch origin {default_branch}",
            checkout_inflight,
            'export OPENTIDE_REPO_ROOT="$BUILD_SOURCESDIRECTORY"',
            "export DEPLOYMENT_PLAN=STAGING",
            generate_cmd,
            'git config user.email "azure-pipelines@opentide.local"',
            'git config user.name "azure-pipelines"',
            "git add .opentide/inflight/",
            'git diff --staged --quiet && echo "No inflight shard changes" && exit 0',
            'git commit -m "ci: update inflight preview shards [skip ci]"',
            f"git push origin HEAD:{default_branch}",
        ]
    )
    return textwrap.dedent(
        f"""\
              - job: inflight_shards
                displayName: Inflight preview shards
                dependsOn: generate
                condition: eq(variables['Build.Reason'], 'PullRequest')
                steps:
            {setup}
            {_bash_script([merge_push])}
        """
    )


def azure_inflight_prune_job(
    *, python_version: str, opentide_version: str, default_branch: str
) -> str:
    from opentide.ci.azure import _bash_script, _python_setup

    opts = CiRenderOptions(
        ci="azure",
        python_version=python_version,
        opentide_version=opentide_version,
    )
    setup = _python_setup(opts)
    prune_cmd = inflight_prune_steps(opts)[0]
    prune_script = " && ".join(
        [
            'export OPENTIDE_REPO_ROOT="$BUILD_SOURCESDIRECTORY"',
            prune_cmd,
            'git config user.email "azure-pipelines@opentide.local"',
            'git config user.name "azure-pipelines"',
            "git add .opentide/inflight/",
            'git diff --staged --quiet && echo "No inflight prune changes" && exit 0',
            'git commit -m "ci: prune inflight preview shards [skip ci]"',
            f"git push origin HEAD:{default_branch}",
        ]
    )
    return textwrap.dedent(
        f"""\
              - job: inflight_prune
                displayName: Prune inflight preview shards
                dependsOn: generate
                condition: eq(variables['Build.SourceBranch'], 'refs/heads/{default_branch}')
                steps:
            {setup}
            {_bash_script([prune_script])}
        """
    )
