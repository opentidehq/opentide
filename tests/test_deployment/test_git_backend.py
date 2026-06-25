"""Smoke tests for Dulwich git backend."""

from __future__ import annotations

from pathlib import Path

from dulwich import porcelain

from opentide.deployment.git_backend import open_repo, rust_extensions_available


def test_rust_extensions_available_is_bool() -> None:
    """Dulwich Rust acceleration probe returns a boolean (CI diagnostic)."""
    assert isinstance(rust_extensions_available(), bool)


def test_commit_accepts_commit_info(tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    porcelain.init(str(repo_path))
    porcelain.commit(
        str(repo_path),
        message=b"init",
        author=b"test <test@example.com>",
        committer=b"test <test@example.com>",
    )
    repo = open_repo(repo_path)
    head = repo.head
    resolved = repo.commit(head)
    assert resolved.hexsha == head.hexsha
