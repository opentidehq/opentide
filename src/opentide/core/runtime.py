"""Runtime context flags replacing the legacy Environment monolith."""

from __future__ import annotations
import os
from pathlib import Path
from opentide.core.root import repository_root


def is_debug() -> bool:
    """Return True when running in a debug context."""
    return os.environ.get("DEBUG") == "True" or os.environ.get("TERM_PROGRAM") == "vscode"


def is_ci() -> bool:
    """Return True when running inside a CI environment."""
    return bool(os.environ.get("CI"))


def repo_root() -> Path:
    """Absolute path to the OpenTide repository root."""
    return repository_root()
