"""Paths as a person reads them: short, relative, and unambiguous about directories."""

from __future__ import annotations

import os
from pathlib import Path


def display_path(path: str | os.PathLike[str], *, workspace: Path | None = None) -> str:
    """*path* relative to the current directory when inside it, else to *workspace*.

    A directory ends with ``/``. A path outside both stays absolute.
    """
    target = Path(path)
    absolute = target if target.is_absolute() else Path.cwd() / target
    shown = absolute.as_posix()
    for base in (Path.cwd(), workspace):
        if base is None:
            continue
        try:
            relative = absolute.resolve().relative_to(base.resolve())
        except (OSError, ValueError):
            continue
        shown = "." if relative == Path(".") else relative.as_posix()
        break
    if absolute.is_dir() and not shown.endswith("/"):
        shown += "/"
    return shown
