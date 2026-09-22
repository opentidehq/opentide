"""Unit tests for shared git baseline resolution (#241, #251)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from opentide.core.git_baseline import (
    GitBaselineError,
    candidate_refs,
    has_git_head,
    resolve_baseline,
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "user.email=t@opentide.test", "-c", "user.name=t", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    return path


def test_no_git_directory_has_no_head(repo: Path) -> None:
    assert has_git_head(repo) is False
    with pytest.raises(GitBaselineError):
        resolve_baseline(repo)


def test_initialised_repo_without_commit_has_no_head(repo: Path) -> None:
    _git(repo, "init", "-q", "-b", "main", ".")
    assert has_git_head(repo) is False
    with pytest.raises(GitBaselineError):
        resolve_baseline(repo)


def test_baseline_resolves_to_master_from_feature_branch(repo: Path) -> None:
    _git(repo, "init", "-q", "-b", "master", ".")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "first")
    base_commit = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-qb", "feature")
    (repo / "b.txt").write_text("b\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "second")

    baseline = resolve_baseline(repo)
    assert baseline.ref == "master"
    assert baseline.commit == base_commit


def test_baseline_prefers_development_over_master(repo: Path) -> None:
    _git(repo, "init", "-q", "-b", "master", ".")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "first")
    _git(repo, "branch", "development")
    _git(repo, "checkout", "-qb", "feature")

    assert resolve_baseline(repo).ref == "development"


def test_candidate_refs_skip_the_current_branch(repo: Path) -> None:
    _git(repo, "init", "-q", "-b", "main", ".")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "first")

    assert "main" not in candidate_refs(repo)


def test_single_branch_repo_falls_back_to_head(repo: Path) -> None:
    """Never ``merge-base HEAD HEAD``: the baseline is HEAD, so worktree edits count."""
    _git(repo, "init", "-q", "-b", "main", ".")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "first")

    baseline = resolve_baseline(repo)
    assert baseline.ref == "HEAD"
    assert baseline.commit == _git(repo, "rev-parse", "HEAD")
