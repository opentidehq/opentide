"""Commit what a production deploy writes back to the catalogue (#548).

A production ``opentide deploy`` changes the checkout: promotion rewrites the
``status`` of the rules it deploys, and platforms that return a vendor id
(Defender, SentinelOne, CrowdStrike) record it, under RFC 0010 in
``.opentide/states/deployment/<uuid>.json``. Without this step those changes
died with the runner: promoted rules kept claiming their old status, and the
next deploy of a rule whose id was lost created a duplicate remote rule.

The step runs only in the production job, which is already gated on the
default branch and is queued on GitLab and Azure (never on GitHub, which
would cancel a pending run). Before the deploy,
:func:`overlay_default_branch_state` gives it the default branch's newest
deployment state. The write-back runs whenever the deploy step started,
including when the deploy failed part way, was cancelled or timed out: ids
recorded for the rules it did create must still land, or the next run
creates those rules again. The job still fails when the deploy failed.

Like the inflight job, nothing staged is a no-op, a push rejected because the
branch moved is retried on top of the new tip, and the commit message carries
``[skip ci]``. Unlike it, a conflict never costs the deployment state: see
:func:`production_writeback`.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from opentide.ci.inflight import PUSH_ATTEMPTS

DEPLOYMENT_STATES = ".opentide/states/deployment"
"""Per-rule deployment state shards (RFC 0010)."""

WRITEBACK_MESSAGE = "ci: record production deployment [skip ci]"
WRITEBACK_EMPTY_NOTE = "No deployment write-backs to commit"
DEFAULT_RULES_FOLDER = "objects/rules"


def rules_folder(repo: Path | None) -> str:
    """The workspace rules folder, relative to the repository root.

    Read from the workspace configuration at render time, so a catalogue on
    the legacy ``Objects/Detection Rules/`` layout commits that folder. A
    render without a checkout, or a rules folder outside the repository,
    falls back to the bundled ``objects/rules``.
    """
    if repo is None:
        return DEFAULT_RULES_FOLDER
    try:
        from opentide.core.files import resolve_configurations
        from opentide.registry.paths import resolve_workspace_paths

        root = repo.resolve()
        resolved = resolve_workspace_paths(resolve_configurations(root), workspace=root)
        relative = Path(resolved["rule"]).resolve().relative_to(root)
    except Exception:
        return DEFAULT_RULES_FOLDER
    text = relative.as_posix().strip("/")
    return text if text and text != "." else DEFAULT_RULES_FOLDER


WRITEBACK_RULES_SKIPPED = (
    "opentide validate --strict failed on the deployed rule files: "
    "committing the deployment state only, not the rule files."
)


#: Under ``.git`` (``git rev-parse --git-path``): never committed, and kept
#: between the steps of one job.
STATE_BASE_FILE = "opentide-state-base"
DEPLOY_STARTED_FILE = "opentide-deploy-started"
WRITEBACK_DONE_FILE = "opentide-writeback-done"

STATE_BASE_MESSAGE = "opentide: deployment state of the default branch"


def _git_path(name: str) -> str:
    return f'"$(git rev-parse --git-path {name})"'


def overlay_default_branch_state(*, fetch: str) -> str:
    """Shell that makes the deploy read the default branch's deployment state.

    The job checks out the commit that triggered it. A write-back from an
    earlier run may have landed on the default branch since, recording a
    vendor id this commit's tree does not have, and the deploy would create
    that rule a second time. The tip descends from the triggering commit, so
    its ``.opentide/states/deployment/`` already holds that commit's state:
    it replaces the checkout's copy, folder first, so a shard the tip deleted
    stays deleted.

    The overlay is also recorded as a local commit on top of ``HEAD`` (only
    when it changed anything), and its id saved under ``.git``. The
    write-back commits on top of it, so the commit it pushes holds this run's
    changes and nothing the tip already had. ``HEAD`` itself does not move
    before the deploy, which plans from ``HEAD``'s first parent.
    """
    states = shlex.quote(DEPLOYMENT_STATES)
    return "\n".join(
        [
            fetch,
            f"rm -rf -- {states}",
            f"git rm -r -q --cached --ignore-unmatch -- {states}",
            f'if git cat-file -e "FETCH_HEAD:{DEPLOYMENT_STATES}" 2>/dev/null; then',
            f"  git checkout FETCH_HEAD -- {states}",
            "fi",
            f"if git diff --cached --quiet -- {states}; then",
            "  state_base=$(git rev-parse HEAD)",
            "else",
            '  state_base=$(git commit-tree "$(git write-tree)" -p HEAD '
            f'-m "{STATE_BASE_MESSAGE}")',
            "fi",
            f'echo "$state_base" > {_git_path(STATE_BASE_FILE)}',
        ]
    )


def _stage_states(indent: str = "") -> list[str]:
    """Stage the state folder, deletions included, or nothing when no copy has it.

    ``git add`` of a path that neither the index nor the tree has exits 128.
    """
    states = shlex.quote(DEPLOYMENT_STATES)
    return [
        f'{indent}if [ -d {states} ] || [ -n "$(git ls-files -- {states})" ]; then',
        f"{indent}  git add -A -- {states}",
        f"{indent}fi",
    ]


def writeback_stage(rules: str) -> list[str]:
    """Stage every deployment state shard, then the rule files if they validate.

    The shards are staged first and unconditionally: a broken rule must not
    cost the vendor ids, which is how a later run would create duplicates.
    The rule files the deploy modified (only files git already tracks) are
    checked with ``opentide validate --strict --file ...`` scoped to exactly
    those files, and staged only when that passes. Otherwise the log says so
    and ``writeback_status`` is 1, so the step fails after the state is pushed.

    The file list is NUL-delimited (``git diff -z``, ``read -d ''``, which
    needs bash), so a name with a quote, backslash, tab or newline reaches
    ``--file`` as itself rather than as git's C-quoted spelling; and
    ``opentide validate`` fails on any ``--file`` that matches no object. It
    goes through a file under ``.git`` because a shell variable cannot hold
    a NUL.
    """
    folder = shlex.quote(rules)
    rule_files = _git_path("opentide-rule-files")
    return [
        "writeback_status=0",
        *_stage_states(),
        f"git diff -z --name-only -- {folder} > {rule_files}",
        "set --",
        "while IFS= read -r -d '' rule_file; do",
        '  set -- "$@" --file "$rule_file"',
        f"done < {rule_files}",
        'if [ "$#" -gt 0 ]; then',
        '  if opentide validate --strict "$@"; then',
        f"    git add -u -- {folder}",
        "  else",
        f'    echo "{WRITEBACK_RULES_SKIPPED}" >&2',
        "    writeback_status=1",
        "  fi",
        "fi",
    ]


WRITEBACK_REPLAY_FAILED = "Could not replay the deployment state onto the default branch."

WRITEBACK_UNPUBLISHED = (
    "The deployment state did not reach the default branch. The vendor ids "
    "this run recorded are printed below and pushed to "
    "refs/opentide/deployment-state/<commit>; record them before the next deploy."
)

SIDE_REF_PREFIX = "refs/opentide/deployment-state/"


def _side_ref_push(push: str) -> str:
    """*push* with its refspec (the last word) replaced by a per-commit side ref.

    Every provider's push ends in a ``HEAD:<branch>`` refspec and keeps its own
    remote and credentials before it, so only that word changes. One ref per
    commit, so a later failure never overwrites an earlier one.
    """
    remote = push.rsplit(" ", 1)[0]
    return f'{remote} "$state_commit:{SIDE_REF_PREFIX}$state_commit"'


WRITEBACK_STATE_ONLY = (
    "The rule write-back conflicts with the default branch: "
    "pushing the deployment state alone so no vendor id is lost."
)


def production_writeback(*, rules: str, push: str, fetch: str) -> str:
    """Shell that commits the production write-backs and pushes them.

    Exits 0 when everything was committed (or nothing changed), and 1 when
    the rule files were left out or the state could not be published.

    The deployment state must reach the default branch whatever happens to
    the rule files, because a lost vendor id is a duplicate remote rule on the
    next deploy (RFC 0010). So, unlike the inflight loop:

    - The commit sits on the overlay commit that
      :func:`overlay_default_branch_state` recorded, so it holds only this
      run's state changes; a retry rebases just that commit onto the tip.
    - Rule edits that were not staged (validation failed) are discarded once
      the commit exists. Otherwise ``git rebase`` refuses to run on a branch
      that moved, and nothing would be pushed.
    - A rebase that conflicts (a concurrent merge edited a promoted rule, or
      the same rule's shard) is aborted. The commit is rebuilt on the new tip
      from this run's deployment-state changes only, replayed per platform and
      tenant by :mod:`opentide.ci.state_replay`, pushed, and the step fails so
      the dropped rule write-back is visible. Bindings other runs changed, and
      shards they or this run deleted, are kept as the tip and this run left
      them.
    - Once the state commit exists, an ``EXIT`` trap covers every way out that
      leaves it unpublished (push rejected every time, a failed fetch, a
      failed replay): it prints the state diff and pushes the commit to
      ``refs/opentide/deployment-state/<commit>`` before the step fails.
    """
    states = shlex.quote(DEPLOYMENT_STATES)
    base = _git_path(STATE_BASE_FILE)
    return "\n".join(
        [
            # Commit on the overlay, so the commit is this run's delta only.
            f"if [ -f {base} ]; then",
            f'  git reset -q --soft "$(cat {base})"',
            "fi",
            *writeback_stage(rules),
            "if git diff --staged --quiet; then",
            f'  echo "{WRITEBACK_EMPTY_NOTE}"',
            '  exit "$writeback_status"',
            "fi",
            f'git commit -q -m "{WRITEBACK_MESSAGE}"',
            # Drop what was deliberately left unstaged so a rebase can run.
            "git reset -q --hard HEAD",
            "state_commit=$(git rev-parse HEAD)",
            "state_published=0",
            "# shellcheck disable=SC2317,SC2329 # run by the EXIT trap below",
            "opentide_state_exit() {",
            "  exit_status=$?",
            '  if [ "$state_published" -ne 1 ]; then',
            f'    echo "{WRITEBACK_UNPUBLISHED}" >&2',
            f'    git --no-pager diff "$state_commit^" "$state_commit" -- {states} >&2 || true',
            f"    {_side_ref_push(push)} >&2 || true",
            "  fi",
            '  exit "$exit_status"',
            "}",
            "trap opentide_state_exit EXIT",
            "push_attempt=1",
            f"until {push}; do",
            f'  if [ "$push_attempt" -ge {PUSH_ATTEMPTS} ]; then',
            '    echo "Push rejected $push_attempt times; giving up." >&2',
            "    exit 1",
            "  fi",
            "  push_attempt=$((push_attempt + 1))",
            f"  {fetch}",
            # Only this run's commit: the overlay commit below it is already
            # on the tip, or older than it.
            "  if ! git rebase -q --onto FETCH_HEAD HEAD~1; then",
            "    git rebase --abort",
            f'    echo "{WRITEBACK_STATE_ONLY}" >&2',
            "    writeback_status=1",
            "    git reset -q --hard FETCH_HEAD",
            # Replay this run's per-tenant changes onto the tip's shards; a
            # folder copy would revert other runs' shards and undo deletions.
            '    if ! opentide deploy replay-state "$state_commit"; then',
            f'      echo "{WRITEBACK_REPLAY_FAILED}" >&2',
            "      exit 1",
            "    fi",
            *_stage_states("    "),
            "    if git diff --staged --quiet; then",
            '      echo "The default branch already holds this deployment state." >&2',
            "      state_published=1",
            "      exit 1",
            "    fi",
            f'    git commit -q -m "{WRITEBACK_MESSAGE}"',
            "    state_commit=$(git rev-parse HEAD)",
            "  fi",
            "done",
            "state_published=1",
            'exit "$writeback_status"',
        ]
    )


DEPLOY_FAILED_NOTE = (
    "Deploy failed (exit $deploy_status); committing what it recorded before it stopped."
)


def deploy_then_writeback(*, deploy: str, rules: str, push: str, fetch: str) -> str:
    """One script that deploys, always writes back, and keeps the deploy's exit status.

    For CI providers whose script stops at the first failing line (GitLab):
    the deploy's failure is captured, the write-back runs in a subshell so its
    own ``exit`` ends only the subshell, and the script then exits with the
    deploy's status, or the write-back's when the deploy succeeded. A failed
    deploy therefore still fails the job.

    The subshell is a plain command between ``set +e`` and ``set -e``, not the
    left side of ``||``: bash ignores ``set -e`` inside anything whose status
    is tested, so a failed ``git rebase`` would carry on and push nothing.
    """
    return "\n".join(
        [
            "deploy_status=0",
            f"touch {_git_path(DEPLOY_STARTED_FILE)}",
            f"{deploy} || deploy_status=$?",
            'if [ "$deploy_status" -ne 0 ]; then',
            f'  echo "{DEPLOY_FAILED_NOTE}" >&2',
            "fi",
            "set +e",
            "(",
            "set -e",
            production_writeback(rules=rules, push=push, fetch=fetch),
            ")",
            "writeback_exit=$?",
            f"touch {_git_path(WRITEBACK_DONE_FILE)}",
            "set -e",
            'if [ "$deploy_status" -ne 0 ]; then',
            '  exit "$deploy_status"',
            "fi",
            'exit "$writeback_exit"',
        ]
    )


WRITEBACK_AFTER_CANCEL = (
    "The job stopped after the deploy started and before its write-back: "
    "committing what the deploy recorded."
)


def writeback_after_cancel(*, rules: str, push: str, fetch: str) -> str:
    """GitLab ``after_script``: the write-back for a job cancelled mid-deploy.

    GitLab runs ``after_script`` when a job is cancelled while ``script`` is
    running, but not, by default, when it times out. It runs in a new shell
    whose exit status does not change the job's. The markers under ``.git``
    say whether the deploy started and whether :func:`deploy_then_writeback`
    already finished its write-back, so a normal run never writes back twice.
    """
    return "\n".join(
        [
            f"if [ -f {_git_path(DEPLOY_STARTED_FILE)} ] && "
            f"[ ! -f {_git_path(WRITEBACK_DONE_FILE)} ]; then",
            f'  echo "{WRITEBACK_AFTER_CANCEL}" >&2',
            "  git rebase --abort 2>/dev/null || true",
            "(",
            "set -e",
            production_writeback(rules=rules, push=push, fetch=fetch),
            ")",
            "fi",
        ]
    )
