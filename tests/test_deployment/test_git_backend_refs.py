"""Ref resolution must not call a Dulwich method that does not exist (#333)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from opentide.deployment.git_backend import open_repo


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


def test_resolve_sha_reads_a_local_branch(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "README.md").write_text("rules\n", encoding="utf-8")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-q", "-m", "init")
    repo = open_repo(tmp_path)

    resolved = repo._resolve_sha("main")
    assert resolved == repo._repo.head()
