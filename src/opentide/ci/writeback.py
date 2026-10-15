"""Commit what a production deploy writes back to the catalogue (#548).

A production ``opentide deploy`` changes the checkout: promotion rewrites the
``status`` of the rules it deploys, and platforms that return a vendor id
(Defender, SentinelOne, CrowdStrike) record it, under RFC 0010 in
``.opentide/states/deployment/<uuid>.json``. Without this step those changes
died with the runner: promoted rules kept claiming their old status, and the
next deploy of a rule whose id was lost created a duplicate remote rule.

The step runs only in the production job, which is already gated on the
default branch. It runs whenever the deploy step started, including when the
deploy failed part way: ids recorded for the rules it did create must still
land, or the next run creates those rules again. The job still fails when
the deploy failed.

It reuses the inflight job's commit-and-push loop: nothing staged is a no-op,
a push rejected because the branch moved is retried on top of the new tip,
and the commit message carries ``[skip ci]``.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from opentide.ci.inflight import _commit_and_push

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


def writeback_stage(rules: str) -> list[str]:
    """Stage every deployment state shard, then the rule files if they validate.

    The shards are staged first and unconditionally: a broken rule must not
    cost the vendor ids, which is how a later run would create duplicates.
    The rule files the deploy modified (only files git already tracks) are
    checked with ``opentide validate --strict --file ...`` scoped to exactly
    those files, and staged only when that passes. Otherwise the log says so
    and ``writeback_status`` is 1, so the step fails after the state is pushed.

    A missing folder is skipped: ``git add`` of a path that does not exist
    exits 128. The heredoc keeps the file list in this shell, where ``set --``
    can collect it; a pipe would run the loop in a subshell.
    """
    folder = shlex.quote(rules)
    states = shlex.quote(DEPLOYMENT_STATES)
    return [
        "writeback_status=0",
        f"if [ -d {states} ]; then git add -- {states}; fi",
        "set --",
        "while IFS= read -r rule_file; do",
        '  if [ -n "$rule_file" ]; then set -- "$@" --file "$rule_file"; fi',
        "done <<RULE_FILES",
        f"$(git -c core.quotePath=false diff --name-only -- {folder})",
        "RULE_FILES",
        'if [ "$#" -gt 0 ]; then',
        '  if opentide validate --strict "$@"; then',
        f"    git add -u -- {folder}",
        "  else",
        f'    echo "{WRITEBACK_RULES_SKIPPED}" >&2',
        "    writeback_status=1",
        "  fi",
        "fi",
    ]


def production_writeback(*, rules: str, push: str, fetch: str) -> str:
    """Shell that commits the production write-backs and pushes them.

    Exits 0 when everything was committed (or nothing changed), and 1 when
    the rule files were left out or the push gave up.
    """
    return _commit_and_push(
        message=WRITEBACK_MESSAGE,
        empty_note=WRITEBACK_EMPTY_NOTE,
        push=push,
        fetch=fetch,
        stage=writeback_stage(rules),
        empty_exit='"$writeback_status"',
        after=['exit "$writeback_status"'],
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
            f"{deploy} || deploy_status=$?",
            'if [ "$deploy_status" -ne 0 ]; then',
            f'  echo "{DEPLOY_FAILED_NOTE}" >&2',
            "fi",
            "set +e",
            # Not indented: the write-back holds a heredoc whose terminator
            # must start its line.
            "(",
            "set -e",
            production_writeback(rules=rules, push=push, fetch=fetch),
            ")",
            "writeback_exit=$?",
            "set -e",
            'if [ "$deploy_status" -ne 0 ]; then',
            '  exit "$deploy_status"',
            "fi",
            'exit "$writeback_exit"',
        ]
    )
