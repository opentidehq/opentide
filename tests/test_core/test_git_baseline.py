"""Unit tests for shared git baseline resolution (#241, #251)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from structlog.testing import capture_logs

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


@pytest.mark.parametrize("same_named_tag", [False, True], ids=["plain", "tag-named-main"])
def test_candidate_refs_skip_the_current_branch(repo: Path, same_named_tag: bool) -> None:
    _git(repo, "init", "-q", "-b", "main", ".")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "first")
    if same_named_tag:
        _git(repo, "tag", "main")

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


def _commit_file(repo: Path, name: str, message: str) -> str:
    (repo / name).write_text(f"{name}\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def published(tmp_path: Path, repo: Path) -> tuple[Path, str]:
    """``main`` and a ``feature`` branch, both pushed with ``-u`` to a bare remote."""
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
    _git(repo, "init", "-q", "-b", "main", ".")
    base = _commit_file(repo, "a.txt", "first")
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "-u", "origin", "main")
    _git(repo, "checkout", "-qb", "feature")
    _commit_file(repo, "b.txt", "second")
    _git(repo, "push", "-q", "-u", "origin", "feature")
    return repo, base


def test_a_branch_that_tracks_itself_is_not_its_own_baseline(
    published: tuple[Path, str],
) -> None:
    """After ``push -u`` the upstream is ``origin/feature``, which contains ``HEAD``."""
    repo, base = published
    assert candidate_refs(repo)[-1] == "origin/feature", "only after every default branch"
    baseline = resolve_baseline(repo)
    assert (baseline.ref, baseline.commit) == ("origin/main", base)
    assert [c.relative.as_posix() for c in changed_paths(repo, baseline)] == ["b.txt"]


def test_a_tag_named_like_the_branch_does_not_hide_its_changes(
    published: tuple[Path, str],
) -> None:
    """``rev-parse --abbrev-ref HEAD`` prints ``heads/feature`` once tag ``feature`` exists."""
    repo, base = published
    _git(repo, "tag", "feature")

    baseline = resolve_baseline(repo)
    assert (baseline.ref, baseline.commit) == ("origin/main", base)
    assert [c.relative.as_posix() for c in changed_paths(repo, baseline)] == ["b.txt"]


def test_a_branch_stacked_on_another_keeps_it_as_the_baseline(
    published: tuple[Path, str],
) -> None:
    repo, _ = published
    fork = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-qb", "feature-2", "--track", "feature")
    _commit_file(repo, "c.txt", "third")

    baseline = resolve_baseline(repo)
    assert (baseline.ref, baseline.commit) == ("feature", fork)


def _pushed_trunk(tmp_path: Path, repo: Path, trunk: str) -> str:
    """``trunk`` pushed with ``-u``, as ``git init`` + ``remote add`` + ``push`` leaves it.

    That never records ``origin/HEAD``. Returns the pushed commit.
    """
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", trunk, str(origin))
    _git(repo, "init", "-q", "-b", trunk, ".")
    _commit_file(repo, "a.txt", "first")
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "-u", "origin", trunk)
    _git(repo, "remote", "set-head", "origin", "--delete")
    return _git(repo, "rev-parse", "HEAD")


def test_the_default_branch_diffs_its_unpushed_work_against_its_own_upstream(
    tmp_path: Path, repo: Path
) -> None:
    """``main`` tracks ``origin/main``; the remote also has ``development``.

    Skipping that upstream compared ``main`` against ``origin/development`` and
    reported every hotfix already pushed to ``main`` as changed.
    """
    _pushed_trunk(tmp_path, repo, "main")
    _git(repo, "push", "-q", "origin", "main:development")
    hotfix = _commit_file(repo, "hotfix.txt", "hotfix")
    _git(repo, "push", "-q")
    _commit_file(repo, "unpushed.txt", "local work")

    baseline = resolve_baseline(repo)
    assert (baseline.ref, baseline.commit) == ("origin/main", hotfix)
    assert [c.relative.as_posix() for c in changed_paths(repo, baseline)] == ["unpushed.txt"]


def test_a_trunk_with_an_unprobed_name_diffs_against_its_own_upstream(
    tmp_path: Path, repo: Path
) -> None:
    """No ``origin/HEAD`` and no default-branch name: the upstream beats ``HEAD``."""
    pushed = _pushed_trunk(tmp_path, repo, "trunk")
    _commit_file(repo, "unpushed.txt", "local work")

    baseline = resolve_baseline(repo)
    assert (baseline.ref, baseline.commit) == ("origin/trunk", pushed)
    assert [c.relative.as_posix() for c in changed_paths(repo, baseline)] == ["unpushed.txt"]


def test_origin_head_decides_which_branch_is_the_default(tmp_path: Path, repo: Path) -> None:
    """``main`` is a probed name, but here the remote says ``development`` is the default."""
    fork = _pushed_trunk(tmp_path, repo, "main")
    _git(repo, "push", "-q", "origin", "main:development")
    _git(repo, "remote", "set-head", "origin", "development")
    _commit_file(repo, "hotfix.txt", "hotfix")
    _git(repo, "push", "-q")

    baseline = resolve_baseline(repo)
    assert (baseline.ref, baseline.commit) == ("origin/development", fork)
    assert [c.relative.as_posix() for c in changed_paths(repo, baseline)] == ["hotfix.txt"]


def test_the_remote_default_branch_is_found_by_any_name(tmp_path: Path, repo: Path) -> None:
    """A clone records ``origin/HEAD``; ``trunk`` is not in the probed names."""
    _git(repo, "init", "-q", "-b", "trunk", ".")
    base = _commit_file(repo, "a.txt", "first")
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", str(repo), str(clone))
    _git(clone, "checkout", "-qb", "feature")
    _commit_file(clone, "b.txt", "second")

    baseline = resolve_baseline(clone)
    assert (baseline.ref, baseline.commit) == ("origin/trunk", base)


def test_non_ascii_paths_come_back_verbatim(repo: Path) -> None:
    """Without ``-z`` git prints ``"d\\303\\251tection.yaml"``, a path that does not exist."""
    _git(repo, "init", "-q", "-b", "main", ".")
    _commit_file(repo, "règle.yaml", "first")
    _git(repo, "checkout", "-qb", "feature")
    (repo / "règle.yaml").write_text("changed\n", encoding="utf-8")
    (repo / "détection nouvelle.yaml").write_text("new\n", encoding="utf-8")

    changes = changed_paths(repo, resolve_baseline(repo))
    assert sorted(c.relative.as_posix() for c in changes) == [
        "détection nouvelle.yaml",
        "règle.yaml",
    ]
    assert all(c.absolute.is_file() for c in changes)


def test_a_carriage_return_in_a_file_name_survives(repo: Path) -> None:
    """Text-mode decoding translates ``\\r`` to ``\\n``: a missing path that reads as deleted."""
    _git(repo, "init", "-q", "-b", "main", ".")
    _commit_file(repo, "a.txt", "first")
    _git(repo, "checkout", "-qb", "feature")
    name = "odd\rname.yaml"
    try:
        _commit_file(repo, name, "carriage return")
    except OSError:
        pytest.skip("filesystem rejects a carriage return in a file name")
    (repo / "new\r.yaml").write_text("new\n", encoding="utf-8")

    changes = changed_paths(repo, resolve_baseline(repo))
    assert sorted(c.relative.as_posix() for c in changes) == ["new\r.yaml", name]
    assert all(c.absolute.is_file() for c in changes)


def test_a_non_utf8_file_name_is_skipped_with_a_warning(repo: Path) -> None:
    """It would decode to lone surrogates, which JSON output cannot encode."""
    _git(repo, "init", "-q", "-b", "main", ".")
    _commit_file(repo, "a.txt", "first")
    _git(repo, "checkout", "-qb", "feature")
    try:
        (repo / os.fsdecode(b"r\xe8gle.yaml")).write_bytes(b"latin-1\n")
    except OSError:
        pytest.skip("filesystem refuses a file name that is not valid UTF-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "latin-1 name")
    (repo / "ok.yaml").write_text("ok\n", encoding="utf-8")

    with capture_logs() as logs:
        changes = changed_paths(repo, resolve_baseline(repo))
    assert [c.relative.as_posix() for c in changes] == ["ok.yaml"]
    assert [(e["event"], e["path"]) for e in logs if e["log_level"] == "warning"] == [
        ("git_path_not_utf8", repr(b"r\xe8gle.yaml"))
    ]
