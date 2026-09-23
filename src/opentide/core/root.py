"""Git work tree, detection workspace, and bundled data root discovery."""

from __future__ import annotations

import os
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

OPENTIDE_DIR = ".opentide"


def _git_root(path: Path) -> Path | None:
    for candidate in (path, *path.parents):
        git_path = candidate / ".git"
        if git_path.is_dir() or git_path.is_file():
            return candidate
    return None


def find_repo_root(start: Path | None = None) -> Path:
    """Walk parents from *start* (or cwd) to locate a git work tree root.

    Falls back to *start* outside git. This is the checkout, not necessarily
    the detection workspace: see :func:`find_workspace_root`.
    """
    path = (start or Path.cwd()).resolve()
    return _git_root(path) or path


def is_workspace_root(path: Path) -> bool:
    """Whether *path* holds ``.opentide/`` or an ``objects/`` catalogue.

    ``.git/objects`` is git's object store and an ``objects/`` holding
    ``__init__.py`` is Python source; neither is a catalogue.
    """
    if ".git" in path.parts:
        return False
    if (path / OPENTIDE_DIR).is_dir():
        return True
    objects = path / "objects"
    return objects.is_dir() and not (objects / "__init__.py").is_file()


def find_workspace_root(start: Path | None = None) -> Path:
    """Nearest ancestor of *start* (or cwd) that is a detection workspace root.

    The walk stops at the enclosing git work tree root, so a workspace nested in
    a larger checkout beats the checkout, and nothing above the checkout is
    considered. Without a marker this is the git root, or *start* outside git.
    """
    path = (start or Path.cwd()).resolve()
    git_root = _git_root(path)
    for candidate in (path, *path.parents):
        if is_workspace_root(candidate):
            return candidate
        if candidate == git_root:
            break
    return git_root or path


@lru_cache(maxsize=1)
def get_data_root() -> Path:
    """Return bundled data directory, honouring ``OPENTIDE_DATA_ROOT``."""
    override = os.environ.get("OPENTIDE_DATA_ROOT")
    if override:
        return Path(override)
    return Path(str(files("opentide.data")))


@lru_cache(maxsize=1)
def get_repo_root() -> Path:
    """Return the detection workspace root, honouring ``OPENTIDE_REPO_ROOT``.

    Not necessarily the git top level. Git runs fine from here, but the paths it
    prints are top-level-relative: join them onto ``git_baseline.git_toplevel``.
    """
    override = os.environ.get("OPENTIDE_REPO_ROOT")
    if override:
        return Path(override)
    return find_workspace_root()


def repository_root() -> Path:
    """Alias for :func:`get_repo_root` (Phase 4 name retained for callers)."""
    return get_repo_root()
