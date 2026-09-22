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


@dataclass(frozen=True)
class ChangedPath:
    """One path git reported as changed.

    ``relative`` is relative to the git top level, which is what
    ``git show <rev>:<path>`` expects; ``absolute`` is the on-disk location.
    Keeping both means no caller has to re-derive one from the other against
    the wrong root.
    """

    relative: Path
    absolute: Path


def _git(repo_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run git, reporting "git is unusable here" the same way git reports failure.

    ``subprocess.run`` raises ``FileNotFoundError`` when git is not on ``PATH``
    and ``NotADirectoryError`` when ``cwd`` has been removed under us — both
    ``OSError``. Callers already handle a non-zero return code, so collapse the
    two failure modes into one rather than letting an ``OSError`` escape a
    function documented to raise ``GitBaselineError``.
    """
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repo_root,
            capture_output=True,
            # Paths are bytes to git; decode them the way ``os.fsdecode`` would
            # rather than by locale, which is ASCII in many CI images.
            encoding="utf-8",
            errors="surrogateescape",
            check=False,
        )
    except OSError as exc:
        logger.debug("git_unavailable", args=args, error=str(exc))
        return subprocess.CompletedProcess(
            ["git", *args], returncode=127, stdout="", stderr=str(exc)
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


def _upstream(repo_root: Path, head_branch: str | None) -> str | None:
    """``@{upstream}``, unless it is the branch's own copy on its remote.

    ``git push -u origin feature`` and ``actions/checkout`` (``checkout -B
    feature refs/remotes/origin/feature``) both make a branch track itself.
    ``merge-base HEAD origin/feature`` is then ``HEAD``, and every committed
    change disappears from the diff. A branch that tracks another branch
    (``origin/main``, or ``feature-1`` in a stack) is still a real base.
    """
    upstream = _git_stdout(
        repo_root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"
    )
    if not upstream or not head_branch:
        return None
    merge = _git_stdout(repo_root, "config", "--get", f"branch.{head_branch}.merge")
    if merge == f"refs/heads/{head_branch}":
        return None
    return upstream


def candidate_refs(repo_root: Path) -> list[str]:
    """Baseline refs to try, most specific first."""
    head_branch = _git_stdout(repo_root, "rev-parse", "--abbrev-ref", "HEAD")
    candidates: list[str] = []
    upstream = _upstream(repo_root, head_branch)
    if upstream:
        candidates.append(upstream)
    # A clone records the remote's default branch, whatever it is called.
    remote_default = _git_stdout(
        repo_root, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"
    )
    if remote_default:
        candidates.append(remote_default)
    candidates.extend(f"origin/{name}" for name in DEFAULT_BRANCH_NAMES)
    candidates.extend(DEFAULT_BRANCH_NAMES)

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


def git_toplevel(repo_root: Path) -> Path:
    """The git worktree root that ``git`` prints paths relative to.

    Not always ``repo_root``: ``get_repo_root()`` and ``discover_workspace()``
    can both land on a tide workspace nested inside the checkout, and joining a
    ``git diff --name-only`` line onto that produces a path that does not exist.
    """
    top = _git_stdout(repo_root, "rev-parse", "--show-toplevel")
    return Path(top) if top else repo_root


def changed_paths(
    repo_root: Path, baseline: GitBaseline, *, pathspec: str | None = None
) -> list[ChangedPath]:
    """Paths changed against ``baseline``, plus untracked files.

    Untracked files are included because a brand new object has no diff against
    the baseline but is exactly the thing a preview or a ``--changed`` docs run
    needs to pick up. Deleted paths are kept — callers distinguish them by
    testing ``absolute.exists()``.

    ``pathspec`` is interpreted relative to the git top level, matching the
    paths this returns.
    """
    # Both commands run from the top level: `git diff --name-only` prints
    # top-level-relative paths but `git ls-files --others` prints cwd-relative
    # ones, so running them from a nested workspace mixes two conventions in
    # one result list.
    top = git_toplevel(repo_root)
    scope = ["--", pathspec] if pathspec else []
    # `-z` prints paths verbatim. Without it git C-quotes any non-ASCII name
    # (`"objects/rules/d\303\251tection.yaml"`), which then reads as deleted.
    lines: list[str] = []
    diff = _git(top, "diff", "--name-only", "-z", "--diff-filter=ACMRD", baseline.commit, *scope)
    if diff.returncode == 0:
        lines.extend(diff.stdout.split("\0"))
    untracked = _git(top, "ls-files", "-z", "--others", "--exclude-standard", "--full-name", *scope)
    if untracked.returncode == 0:
        lines.extend(untracked.stdout.split("\0"))

    seen: set[Path] = set()
    results: list[ChangedPath] = []
    for line in lines:
        if not line:
            continue
        relative = Path(line)
        if relative in seen:
            continue
        seen.add(relative)
        results.append(ChangedPath(relative=relative, absolute=top / relative))
    return results
