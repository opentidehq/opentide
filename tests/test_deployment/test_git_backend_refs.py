"""Ref resolution must not call a Dulwich method that does not exist (#333)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from dulwich.objects import Commit, Tree

from opentide.deployment.git_backend import CommitInfo, open_repo


def _git(cwd: Path, *args: str) -> None:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "dev",
            "GIT_AUTHOR_EMAIL": "dev@example.test",
            "GIT_COMMITTER_NAME": "dev",
            "GIT_COMMITTER_EMAIL": "dev@example.test",
        }
    )
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=env)


def test_resolve_sha_missing_ref_is_key_error(tmp_path: Path) -> None:
    """``iter_commits('origin/main')`` used ``Repo.lookup_ref``."""
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "README.md").write_text("rules\n", encoding="utf-8")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-q", "-m", "init")
    repo = open_repo(tmp_path)

    with pytest.raises(KeyError, match="origin/main"):
        repo._resolve_sha("origin/main")


def _chain(length: int) -> tuple[dict[bytes, Commit], Commit]:
    empty_tree = Tree().id
    store: dict[bytes, Commit] = {}
    previous: Commit | None = None
    tip: Commit | None = None
    for index in range(length):
        commit = Commit()
        commit.tree = empty_tree
        commit.parents = [] if previous is None else [previous.id]
        commit.author = b"Dev <dev@example.test>"
        commit.author_time = 1_700_000_000
        commit.author_timezone = 0
        commit.committer = b"Dev <dev@example.test>"
        commit.commit_time = 1_700_000_000
        commit.commit_timezone = 0
        commit.message = f"commit {index}\n".encode()
        store[commit.id] = commit
        previous = commit
        tip = commit
    assert tip is not None
    return store, tip


def test_from_commit_stops_at_the_immediate_parent() -> None:
    """A long history must not recurse until RecursionError aborts deploy."""
    store, tip = _chain(200)
    parent = store[tip.parents[0]]
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(80)
    try:
        info = CommitInfo.from_commit(tip, store)  # type: ignore[arg-type]
    finally:
        sys.setrecursionlimit(limit)

    assert info.hexsha == tip.id.decode("ascii")
    assert info.message == "commit 199"
    assert len(info.parents) == 1
    assert info.parents[0].hexsha == parent.id.decode("ascii")
    assert info.parents[0].message == "commit 198"
    assert info.parents[0].parents == []


def test_missing_parent_keeps_its_id() -> None:
    """A shallow clone still names the parent that is not in the object store."""
    store, tip = _chain(1)
    missing = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    tip.parents = [missing]
    store[tip.id] = tip

    info = CommitInfo.from_commit(tip, store)  # type: ignore[arg-type]

    assert info.parents[0].hexsha == missing.decode("ascii")
    assert info.parents[0].message == ""
    assert info.parents[0].parents == []


def test_resolve_sha_reads_a_local_branch(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "README.md").write_text("rules\n", encoding="utf-8")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-q", "-m", "init")
    repo = open_repo(tmp_path)

    resolved = repo._resolve_sha("main")
    assert resolved == repo._repo.head()
