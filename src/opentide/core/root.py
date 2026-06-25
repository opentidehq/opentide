"""Repository and bundled data root discovery."""

from __future__ import annotations

import os
from functools import lru_cache
from importlib.resources import files
from pathlib import Path


def find_repo_root(start: Path | None = None) -> Path:
    """Walk parents from *start* (or cwd) to locate a git work tree root."""
    path = (start or Path.cwd()).resolve()
    for candidate in (path, *path.parents):
        git_path = candidate / ".git"
        if git_path.is_dir() or git_path.is_file():
            return candidate
    return path


@lru_cache(maxsize=1)
def get_data_root() -> Path:
    """Return bundled data directory, honouring ``OPENTIDE_DATA_ROOT``."""
    override = os.environ.get("OPENTIDE_DATA_ROOT")
    if override:
        return Path(override)
    return Path(str(files("opentide.data")))


@lru_cache(maxsize=1)
def get_repo_root() -> Path:
    """Return detection content root, honouring ``OPENTIDE_REPO_ROOT``."""
    override = os.environ.get("OPENTIDE_REPO_ROOT")
    if override:
        return Path(override)
    return find_repo_root()


def repository_root() -> Path:
    """Alias for :func:`get_repo_root` (Phase 4 name retained for callers)."""
    return get_repo_root()
