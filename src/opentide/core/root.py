"""Repository and bundled data root discovery."""

from __future__ import annotations

import os
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

import git


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
    try:
        return Path(str(git.Repo(".", search_parent_directories=True).working_dir))
    except Exception:
        return Path.cwd()


def repository_root() -> Path:
    """Alias for :func:`get_repo_root` (Phase 4 name retained for callers)."""
    return get_repo_root()
