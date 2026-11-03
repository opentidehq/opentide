"""CI job fragments for inflight preview shard updates on pull requests."""

from __future__ import annotations

import textwrap
from typing import Any

from opentide.ci.gates import (
    azure_premerge_condition,
    github_premerge_if,
    gitlab_premerge_rule,
)
from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import inflight_generate_steps, inflight_prune_steps, pip_install

#: CI/CD variable naming where the GitLab write-backs push, any URL git takes
#: (``git@gitlab.example.com:group/project.git`` for SSH). Unset, they push
#: over HTTPS with ``CI_JOB_TOKEN``, which needs job-token push access.
GITLAB_PUSH_URL_VARIABLE = "OPENTIDE_PUSH_URL"

#: File variables: an SSH private key the write-backs push with and sign
#: their commits with, and the ``known_hosts`` lines of the server.
GITLAB_SSH_KEY_VARIABLE = "OPENTIDE_PUSH_SSH_KEY"
GITLAB_SSH_KNOWN_HOSTS_VARIABLE = "OPENTIDE_PUSH_SSH_KNOWN_HOSTS"

#: The push URL, as one shell word. GitLab expands ``$VAR``; ``${{ }}`` is
#: GitHub Actions expression syntax and would push to a host literally named
#: ``${{CI_SERVER_HOST}}``. An explicit URL also sidesteps the runner's own
#: ``insteadOf`` rewrite of ``origin``, which a project cannot override.
GITLAB_PUSH_URL = (
    f'"${{{GITLAB_PUSH_URL_VARIABLE}:-https://gitlab-ci-token:${{CI_JOB_TOKEN}}@'
    '${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git}"'
)
GITLAB_PUSH = f'git push {GITLAB_PUSH_URL} "HEAD:$CI_DEFAULT_BRANCH"'
GITLAB_FETCH = 'git fetch origin "$CI_DEFAULT_BRANCH"'

#: ``python:<ver>-slim`` ships without git, so every git step failed with
#: "command not found" before it could fetch, commit, or push.
GITLAB_INSTALL_GIT = (
    "apt-get update -qq && apt-get install -y -qq --no-install-recommends git > /dev/null"
)

GITLAB_SSH_NOT_A_FILE = (
    f"{GITLAB_SSH_KEY_VARIABLE} must be a CI/CD variable of type File holding the private key."
)
GITLAB_SSH_NO_KNOWN_HOSTS = (
    f"{GITLAB_SSH_KEY_VARIABLE} is set, but {GITLAB_SSH_KNOWN_HOSTS_VARIABLE} is not a "
    "File variable holding the server's known_hosts lines; refusing to push to an "
    "unchecked host."
)


def gitlab_push_setup() -> str:
    """Shell that pushes and signs with the SSH key in :data:`GITLAB_SSH_KEY_VARIABLE`.

    Nothing happens when the variable is unset. Otherwise the job installs
    ``openssh-client`` (``python:<ver>-slim`` has none), and the repository's
    own config, which ``after_script`` and ``git worktree`` share, gets
    ``core.sshCommand`` with that key and the server's known hosts, and SSH
    commit signing with the same key. Strict host-key checking is not
    optional: without known hosts the step fails. The key itself is never
    printed; only the variable names are.
    """
    key = f'"${GITLAB_SSH_KEY_VARIABLE}"'
    ssh = (
        f'ssh -i \\"${GITLAB_SSH_KEY_VARIABLE}\\" -o IdentitiesOnly=yes '
        "-o StrictHostKeyChecking=yes "
        f'-o UserKnownHostsFile=\\"${GITLAB_SSH_KNOWN_HOSTS_VARIABLE}\\"'
    )
    return "\n".join(
        [
            f'if [ -n "${{{GITLAB_SSH_KEY_VARIABLE}:-}}" ]; then',
            f"  if [ ! -f {key} ]; then",
            f'    echo "{GITLAB_SSH_NOT_A_FILE}" >&2',
            "    exit 1",
            "  fi",
            f'  if [ ! -s "${{{GITLAB_SSH_KNOWN_HOSTS_VARIABLE}:-}}" ]; then',
            f'    echo "{GITLAB_SSH_NO_KNOWN_HOSTS}" >&2',
            "    exit 1",
            "  fi",
            "  command -v ssh-keygen > /dev/null || "
            "apt-get install -y -qq --no-install-recommends openssh-client > /dev/null",
            f"  chmod 600 {key}",
            f'  git config core.sshCommand "{ssh}"',
            "  git config gpg.format ssh",
            f"  git config user.signingkey {key}",
            "  git config commit.gpgsign true",
            f"  echo 'Pushing and signing with the {GITLAB_SSH_KEY_VARIABLE} key.'",
            "fi",
        ]
    )


#: Pull request jobs and the prune job race each other to the default branch.
PUSH_ATTEMPTS = 5


#: Stage the inflight shards. ``git add`` exits 128 when the path was never
#: committed (#403); an empty directory stages nothing, so the guard exits 0.
_STAGE_INFLIGHT = ("mkdir -p .opentide/inflight", "git add .opentide/inflight/")


def _commit_and_push(
    *,
    message: str,
    empty_note: str,
    push: str,
    fetch: str,
    stage: tuple[str, ...] | list[str] = _STAGE_INFLIGHT,
    empty_exit: str = "0",
    after: tuple[str, ...] | list[str] = (),
) -> str:
    """Stage, commit only when something changed, and push onto the latest default branch.

    ``git diff --staged --quiet`` exits 1 when there *are* staged changes, so
    chaining it with ``&&`` skips the commit in exactly the case that needs one.

    A push rejected because another job moved the branch first is retried on
    top of the new tip (*fetch*, then rebase). The commit touches only shard
    files, so the rebase normally applies; after :data:`PUSH_ATTEMPTS` the
    job fails.

    Every caller emits this as a YAML block scalar. A commit message contains
    ``": "``, which a plain ``- git commit -m "ci: ..."`` sequence item parses
    as a mapping instead of a string, and GitLab then rejects the pipeline.

    *stage* lists the commands that stage the job's files. The default
    creates the inflight directory first: ``git add`` of a path that was never
    committed exits 128, which fails the prune job on a repository that has
    not published shards yet (#403). *empty_exit* is the exit status when
    nothing was staged, and *after* runs once the push succeeded.
    """
    return "\n".join(
        [
            *stage,
            "if git diff --staged --quiet; then",
            f'  echo "{empty_note}"',
            f"  exit {empty_exit}",
            "fi",
            f'git commit -m "{message}"',
            "push_attempt=1",
            f"until {push}; do",
            f'  if [ "$push_attempt" -ge {PUSH_ATTEMPTS} ]; then',
            '    echo "Push rejected $push_attempt times; giving up." >&2',
            "    exit 1",
            "  fi",
            "  push_attempt=$((push_attempt + 1))",
            f"  {fetch}",
            "  git rebase FETCH_HEAD",
            "done",
            *after,
        ]
    )


#: The default branch commit the shards were copied from; kept in ``.git`` so
#: it survives between CI steps and is never committed.
_SHARDS_BASE = '"$(git rev-parse --git-path opentide-inflight-base)"'


def _default_branch_shards(default_ref: str) -> list[str]:
    """Start from exactly the default branch's shards, not the PR head's copy.

    Overlaying with ``git checkout`` alone keeps files the default branch has
    since pruned, and the PR job would publish them again.
    """
    return [
        "rm -rf .opentide/inflight",
        f'git rev-parse "{default_ref}" > {_SHARDS_BASE}',
        f'git checkout "$(cat {_SHARDS_BASE})" -- .opentide/inflight 2>/dev/null '
        "|| mkdir -p .opentide/inflight",
    ]


def _publish_on_default_branch(*, push: str, fetch: str) -> str:
    """Commit the regenerated shards on top of the default branch, never on the PR.

    The job checks out the PR (or, on Azure, its merge commit) to see the
    changed objects. Committing there and pushing ``HEAD`` to the default
    branch published the unreviewed PR whenever the push fast-forwarded, so
    only ``.opentide/inflight/`` is carried into a worktree of the default
    branch and committed there.

    The worktree starts from the commit the shards were copied from, not the
    default branch's current tip: ``generate inflight`` fetches ``origin`` to
    diff the pull request, and a newer base would make the commit delete every shard
    published in between. The push then rebases onto the latest tip.

    The ``EXIT`` trap removes that worktree on every path out of the script:
    nothing to publish, a failed rebase under ``set -e``, or the final push.
    """
    return "\n".join(
        [
            'shards_repo="$PWD"',
            'shards_base="$(mktemp -d)"',
            f'git worktree add --detach "$shards_base" "$(cat {_SHARDS_BASE})"',
            'trap \'cd "$shards_repo" && git worktree remove --force "$shards_base"\' EXIT',
            'rm -rf "$shards_base/.opentide/inflight"',
            'mkdir -p "$shards_base/.opentide"',
            'cp -R .opentide/inflight "$shards_base/.opentide/inflight"',
            # ``set -e`` is not visible to ShellCheck. A failed ``cd`` must
            # exit the script (#430).
            'cd "$shards_base" || exit',
            _commit_and_push(
                message="ci: update inflight preview shards [skip ci]",
                empty_note="No inflight shard changes",
                push=push,
                fetch=fetch,
            ),
        ]
    )


def github_inflight_job(
    *,
    python_version: str,
    default_branch: str,
) -> str:
    """Render the GitHub Actions job that updates ``.opentide/inflight/`` on PRs."""
    opts = CiRenderOptions(
        ci="github",
        python_version=python_version,
    )
    install = pip_install()
    generate_cmd = inflight_generate_steps(opts)[0]
    default_ref = f"origin/{default_branch}"
    checkout_inflight = textwrap.indent(
        "\n".join(_default_branch_shards(default_ref)), " " * 16
    ).lstrip()
    commit_push = textwrap.indent(
        _publish_on_default_branch(
            push=f'git push origin "HEAD:{default_branch}"',
            fetch=f"git fetch origin {default_branch}",
        ),
        " " * 16,
    ).lstrip()
    return textwrap.dedent(
        f"""\
        inflight_shards:
          name: Update inflight preview shards
          needs: generate
          if: {github_premerge_if(default_branch)}
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
    default_branch: str,
) -> str:
    opts = CiRenderOptions(
        ci="github",
        python_version=python_version,
    )
    install = pip_install()
    prune_cmd = inflight_prune_steps(opts)[0]
    prod_if = f"github.event_name == 'push' && github.ref == 'refs/heads/{default_branch}'"
    commit_push = textwrap.indent(
        _commit_and_push(
            message="ci: prune inflight preview shards [skip ci]",
            empty_note="No inflight prune changes",
            push=f"git push origin HEAD:{default_branch}",
            fetch=f"git fetch origin {default_branch}",
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


#: The commit identity of the GitLab jobs that push.
GITLAB_IDENTITY = (
    'git config user.email "gitlab-ci@opentide.local"',
    'git config user.name "gitlab-ci"',
)


def gitlab_push_preamble() -> list[str]:
    """Script items a GitLab job that commits and pushes runs first.

    The SSH setup is a ``|`` block (it spans lines); the identity follows.
    """
    return [gitlab_push_setup() + "\n", *GITLAB_IDENTITY]


def gitlab_inflight_job(*, python_version: str) -> dict[str, Any]:
    """The GitLab job that publishes ``.opentide/inflight/`` from a merge request."""
    opts = CiRenderOptions(
        ci="gitlab",
        python_version=python_version,
    )
    return {
        "stage": "deploy",
        "image": f"python:{python_version}-slim",
        "rules": [{"if": gitlab_premerge_rule()}],
        "variables": {"GIT_DEPTH": "0"},
        "before_script": [GITLAB_INSTALL_GIT, pip_install()],
        "script": [
            'git fetch origin "$CI_DEFAULT_BRANCH"',
            *_default_branch_shards("origin/$CI_DEFAULT_BRANCH"),
            'export OPENTIDE_REPO_ROOT="$CI_PROJECT_DIR"',
            inflight_generate_steps(opts)[0],
            *gitlab_push_preamble(),
            # A ``|`` block: the commit message holds ``": "`` (see _commit_and_push).
            _publish_on_default_branch(push=GITLAB_PUSH, fetch=GITLAB_FETCH) + "\n",
        ],
        "needs": ["generate"],
    }


def gitlab_inflight_prune_job(*, python_version: str) -> dict[str, Any]:
    """The GitLab job that drops superseded shards after a merge."""
    opts = CiRenderOptions(
        ci="gitlab",
        python_version=python_version,
    )
    commit_push = _commit_and_push(
        message="ci: prune inflight preview shards [skip ci]",
        empty_note="No inflight prune changes",
        push=GITLAB_PUSH,
        fetch=GITLAB_FETCH,
    )
    return {
        "stage": "deploy",
        "image": f"python:{python_version}-slim",
        "rules": [{"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"}],
        "variables": {"GIT_DEPTH": "0"},
        "before_script": [GITLAB_INSTALL_GIT, pip_install()],
        "script": [
            'export OPENTIDE_REPO_ROOT="$CI_PROJECT_DIR"',
            inflight_prune_steps(opts)[0],
            *gitlab_push_preamble(),
            commit_push + "\n",
        ],
        "needs": ["generate"],
    }


def azure_inflight_job(*, python_version: str, default_branch: str) -> str:
    from opentide.ci.azure import _azure_job, _job_steps

    opts = CiRenderOptions(
        ci="azure",
        python_version=python_version,
    )
    generate_cmd = inflight_generate_steps(opts)[0]
    default_ref = f"origin/{default_branch}"
    merge_push = "\n".join(
        [
            f"git fetch origin {default_branch}",
            *_default_branch_shards(default_ref),
            'export OPENTIDE_REPO_ROOT="$BUILD_SOURCESDIRECTORY"',
            generate_cmd,
            'git config user.email "azure-pipelines@opentide.local"',
            'git config user.name "azure-pipelines"',
            _publish_on_default_branch(
                push=f"git push origin HEAD:{default_branch}",
                fetch=f"git fetch origin {default_branch}",
            ),
        ]
    )
    return _azure_job(
        "inflight_shards",
        display_name="Inflight preview shards",
        condition=azure_premerge_condition(default_branch),
        steps=_job_steps(opts, [merge_push], persist_credentials=True, full_history=True),
    )


def azure_inflight_prune_job(*, python_version: str, default_branch: str) -> str:
    from opentide.ci.azure import _azure_job, _job_steps

    opts = CiRenderOptions(
        ci="azure",
        python_version=python_version,
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
                fetch=f"git fetch origin {default_branch}",
            ),
        ]
    )
    return _azure_job(
        "inflight_prune",
        display_name="Prune inflight preview shards",
        condition=f"eq(variables['Build.SourceBranch'], 'refs/heads/{default_branch}')",
        steps=_job_steps(opts, [prune_script], persist_credentials=True, full_history=True),
    )
