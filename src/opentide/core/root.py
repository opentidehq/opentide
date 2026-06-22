"""Repository root discovery."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import git


@lru_cache(maxsize=1)
def repository_root() -> Path:
    """Return the git working directory for the current OpenTide instance."""
    return Path(str(git.Repo(".", search_parent_directories=True).working_dir))
