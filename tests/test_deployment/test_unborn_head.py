"""A checkout with no commit yet (right after ``git init``) has an unborn ``HEAD``.

Dulwich raises ``KeyError(b"HEAD")`` for it, and every caller that reported
``str(exc)`` printed ``b'HEAD'``: ``deploy`` with no ``--all``, ``validate query
--changed`` and ``lint --changed`` all failed with that as their message.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from opentide.deployment.git_backend import GitLookupError, NoCommitsError, open_repo
from opentide.deployment.git_repo import (
    DiffSource,
    changed_through_head,
    diff_calculation,
    diff_error_message,
    no_commits_warning,
)


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return done.stdout.strip()


@pytest.fixture
def unborn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A workspace that is a fresh ``git init`` with one uncommitted rule file."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", "dev")
        monkeypatch.setenv(f"GIT_{role}_EMAIL", "dev@example.test")
    repo = tmp_path / "repo"
    rules = repo / "objects" / "rules"
    rules.mkdir(parents=True)
    (rules / "rule.yaml").write_text("name: r\n", encoding="utf-8")
    _git(repo, "init", "-q", "-b", "main")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    return repo


def _commit(repo: Path) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "catalogue")


def test_unborn_head_is_a_sentence_not_a_bytes_key(unborn: Path) -> None:
    repo = open_repo(unborn)

    assert repo.has_commits is False
    with pytest.raises(NoCommitsError) as raised:
        _ = repo.head
    assert str(raised.value) == f"The git repository at {unborn} has no commits yet"
    # Still a KeyError, so callers catching "not found" keep working.
    assert isinstance(raised.value, KeyError)
    with pytest.raises(NoCommitsError):
        repo._resolve_sha("HEAD")
    with pytest.raises(NoCommitsError):
        next(repo.iter_commits())


def test_has_commits_once_head_names_a_commit(unborn: Path) -> None:
    _commit(unborn)

    repo = open_repo(unborn)

    assert repo.has_commits is True
    assert repo.head.hexsha == _git(unborn, "rev-parse", "HEAD")


def test_missing_ref_names_the_ref_without_quotes(unborn: Path) -> None:
    _commit(unborn)

    with pytest.raises(GitLookupError) as raised:
        open_repo(unborn)._resolve_sha("origin/main")

    assert str(raised.value) == "Could not find git ref origin/main"


def test_merge_base_of_a_missing_ref_names_it_without_quotes(unborn: Path) -> None:
    """Dulwich raised ``KeyError(b'origin/feature')``: ``str()`` was its repr."""
    _commit(unborn)

    with pytest.raises(GitLookupError) as raised:
        open_repo(unborn).merge_base("main", "origin/feature")

    assert str(raised.value) == "Could not find git commit origin/feature"


def test_last_commit_diff_without_commits_is_empty(unborn: Path) -> None:
    """There is no last commit, so it changed nothing, as for a first commit's push."""
    assert diff_calculation(DiffSource.LAST_COMMIT) == []


def test_no_commits_warning_names_the_cause_and_the_advice(unborn: Path) -> None:
    assert no_commits_warning("pass --all") == (
        "HEAD names no commit yet (a new repository or an orphan branch), "
        "so no file has changed: pass --all"
    )


def test_an_orphan_branch_in_a_repository_with_history_has_no_last_commit(unborn: Path) -> None:
    """``git checkout --orphan`` leaves HEAD on a branch with no commit, history or not."""
    _commit(unborn)
    _git(unborn, "checkout", "-q", "--orphan", "fresh")

    assert open_repo(unborn).has_commits is False
    assert diff_calculation(DiffSource.LAST_COMMIT) == []
    warning = no_commits_warning("pass --all")
    assert warning is not None
    assert warning.startswith("HEAD names no commit yet (a new repository or an orphan branch)")


def test_no_commits_warning_is_none_once_a_commit_exists(unborn: Path) -> None:
    _commit(unborn)

    assert no_commits_warning("pass --all") is None


def test_no_commits_warning_is_none_in_ci(unborn: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """In CI the run's commit must exist: an unborn HEAD fails the diff instead."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    assert no_commits_warning("pass --all") is None


def test_ci_diff_on_an_unborn_head_fails_with_a_sentence(
    unborn: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(unborn))
    monkeypatch.setenv("GITHUB_SHA", "0" * 40)

    with pytest.raises(NoCommitsError, match="has no commits yet"):
        diff_calculation(DiffSource.PUSH)


def test_changed_through_head_on_an_unborn_head_fails_with_a_sentence(unborn: Path) -> None:
    """``share --changed --since`` outside CI: there is no HEAD to diff to."""
    with pytest.raises(NoCommitsError, match="has no commits yet"):
        changed_through_head("main")


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        pytest.param(
            KeyError(b"HEAD"),
            "Could not find git ref or object HEAD while computing the changed rules",
            id="dulwich-bytes-key",
        ),
        pytest.param(
            GitLookupError("Could not find git ref origin/main"),
            "Could not find git ref origin/main",
            id="lookup-error",
        ),
        pytest.param(
            RuntimeError(""),
            "RuntimeError while computing the changed rules",
            id="no-text",
        ),
    ],
)
def test_diff_error_message_never_shows_a_key_repr(exc: Exception, expected: str) -> None:
    assert diff_error_message(exc, "computing the changed rules") == expected
