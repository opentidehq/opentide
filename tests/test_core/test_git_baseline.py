"""Unit tests for shared git baseline resolution (#241, #251)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from opentide.core.git_baseline import (
    GitBaselineError,
    candidate_refs,
    changed_paths,
    git_toplevel,
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


def test_a_missing_git_binary_raises_the_documented_error(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``GitBaselineError``, not the ``FileNotFoundError`` subprocess raises."""
    _git(repo, "init", "-q", "-b", "main", ".")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "first")

    def explode(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError(2, "No such file or directory: 'git'")

    monkeypatch.setattr("opentide.core.git_baseline.subprocess.run", explode)

    assert has_git_head(repo) is False
    with pytest.raises(GitBaselineError):
        resolve_baseline(repo)


def _nested_workspace_repo(repo: Path) -> Path:
    """A tide workspace in a subdirectory of the checkout, as client repos have."""
    _git(repo, "init", "-q", "-b", "main", ".")
    workspace = repo / "detections"
    (workspace / "objects" / "rules").mkdir(parents=True)
    (workspace / "objects" / "rules" / "tracked.yaml").write_text("uuid: a\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "first")
    return workspace


def test_git_toplevel_climbs_out_of_a_nested_workspace(repo: Path) -> None:
    workspace = _nested_workspace_repo(repo)

    assert git_toplevel(workspace).resolve() == repo.resolve()


def test_changed_paths_are_absolute_against_the_git_top_level(repo: Path) -> None:
    """Joining a ``git diff`` line onto a nested workspace produces a missing path."""
    workspace = _nested_workspace_repo(repo)
    (workspace / "objects" / "rules" / "tracked.yaml").write_text("uuid: b\n", encoding="utf-8")
    (workspace / "objects" / "rules" / "new.yaml").write_text("uuid: c\n", encoding="utf-8")

    baseline = resolve_baseline(workspace)
    changes = changed_paths(workspace, baseline)
    by_name = {change.relative.name: change for change in changes}

    assert set(by_name) == {"tracked.yaml", "new.yaml"}, "untracked objects must be included"
    for change in changes:
        assert change.relative.as_posix().startswith("detections/"), (
            "relative paths are git-top-level relative, which is what `git show` needs"
        )
        assert change.absolute.is_file(), f"{change.absolute} does not exist"


def test_changed_paths_narrow_to_a_pathspec(repo: Path) -> None:
    workspace = _nested_workspace_repo(repo)
    (workspace / "objects" / "rules" / "new.yaml").write_text("uuid: c\n", encoding="utf-8")
    (repo / "README.md").write_text("hi\n", encoding="utf-8")

    baseline = resolve_baseline(workspace)
    scoped = changed_paths(workspace, baseline, pathspec="detections/objects/")

    assert [change.relative.name for change in scoped] == ["new.yaml"]
