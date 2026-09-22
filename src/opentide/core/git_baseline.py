"""Shared git baseline resolution for changed-object discovery.

``generate docs --changed`` and ``generate inflight`` both need "what changed
against the default branch". They previously disagreed: docs tried
``origin/development|main|master`` then fell back to ``merge-base HEAD HEAD``
(always empty, and a hard error without a HEAD), while inflight only tried
``origin/main`` and ``main``. Repos whose default branch is ``master`` or
``development`` saw no changes at all (#251), and repos without a commit
crashed (#241).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import structlog

logger = structlog.get_logger("opentide.core.git_baseline")

#: Default-branch names probed as ``origin/<name>`` then ``<name>``.
DEFAULT_BRANCH_NAMES: tuple[str, ...] = ("development", "main", "master")

NO_GIT_MESSAGE = "changed-object discovery requires a git repository with at least one commit"


class GitBaselineError(RuntimeError):
    """Raised when a git baseline cannot be resolved for changed-object discovery."""


@dataclass(frozen=True)
class GitBaseline:
    """A resolved comparison point for changed-object discovery."""

    ref: str
    commit: str


def _git(repo_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )


def _git_stdout(repo_root: Path, *args: str) -> str | None:
    result = _git(repo_root, *args)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def has_git_head(repo_root: Path) -> bool:
    """Return whether ``repo_root`` is a git worktree with at least one commit."""
    inside = _git_stdout(repo_root, "rev-parse", "--is-inside-work-tree")
    if inside != "true":
        return False
    return _git_stdout(repo_root, "rev-parse", "--verify", "HEAD") is not None


def candidate_refs(repo_root: Path) -> list[str]:
    """Baseline refs to try, most specific first."""
    candidates: list[str] = []
    upstream = _git_stdout(
        repo_root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"
    )
    if upstream:
        candidates.append(upstream)
    candidates.extend(f"origin/{name}" for name in DEFAULT_BRANCH_NAMES)
    candidates.extend(DEFAULT_BRANCH_NAMES)

    head_branch = _git_stdout(repo_root, "rev-parse", "--abbrev-ref", "HEAD")
    ordered: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen or candidate == head_branch:
            # Comparing a branch with itself yields an empty diff; keep looking
            # so a feature branch off ``master`` still resolves to ``master``.
            continue
        seen.add(candidate)
        ordered.append(candidate)
    return ordered


def resolve_baseline(repo_root: Path) -> GitBaseline:
    """Resolve the merge-base to diff against.

    Raises:
        GitBaselineError: when ``repo_root`` has no git worktree, no ``HEAD``,
            or no candidate default branch. Never falls back to
            ``merge-base HEAD HEAD``, which silently reports "no changes".
    """
    if not has_git_head(repo_root):
        raise GitBaselineError(NO_GIT_MESSAGE)
    for candidate in candidate_refs(repo_root):
        commit = _git_stdout(repo_root, "merge-base", "HEAD", candidate)
        if commit:
            logger.debug("git_baseline_resolved", ref=candidate, commit=commit)
            return GitBaseline(ref=candidate, commit=commit)
    # Single-branch repository with no upstream and no other default branch:
    # "changed against the default branch" is undefined, so compare the working
    # tree against HEAD. Untracked object files are added by the callers.
    head = _git_stdout(repo_root, "rev-parse", "HEAD")
    if head:
        logger.debug("git_baseline_head_only", commit=head)
        return GitBaseline(ref="HEAD", commit=head)
    raise GitBaselineError(NO_GIT_MESSAGE)
