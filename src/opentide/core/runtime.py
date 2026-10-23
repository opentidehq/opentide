"""Runtime context flags replacing the legacy Environment monolith."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from opentide.core.root import repository_root

_TRUE_LITERALS = frozenset({"1", "true", "yes", "on"})
_FALSE_LITERALS = frozenset({"", "0", "false", "no", "off"})


def boolean_env(name: str, env: Mapping[str, str] | None = None) -> bool | None:
    """*name* read as a boolean literal; ``None`` when unset or not a boolean.

    ``DEBUG='*'``, which Node tooling exports, is not a boolean and reads as
    ``None`` rather than failing the command that inherited it.
    """
    value = (os.environ if env is None else env).get(name)
    if value is None:
        return None
    normalised = value.strip().lower()
    if normalised in _TRUE_LITERALS:
        return True
    if normalised in _FALSE_LITERALS:
        return False
    return None


def debug_requested(env: Mapping[str, str] | None = None) -> bool:
    """Whether the environment asks for ``--debug``.

    ``OPENTIDE_DEBUG`` decides when it is a boolean; otherwise ``DEBUG`` does,
    but only when it is a boolean literal too.
    """
    own = boolean_env("OPENTIDE_DEBUG", env)
    if own is not None:
        return own
    return bool(boolean_env("DEBUG", env))


def is_debug() -> bool:
    """Return True when running in a debug context.

    ``--debug`` exports ``OPENTIDE_DEBUG=1``. ``DEBUG=True`` is still read for
    workspaces that set it by hand.
    """
    return (
        bool(boolean_env("OPENTIDE_DEBUG"))
        or os.environ.get("DEBUG") == "True"
        or os.environ.get("TERM_PROGRAM") == "vscode"
    )


def is_ci() -> bool:
    """Return True when running inside a CI environment."""
    return bool(os.environ.get("CI"))


def repo_root() -> Path:
    """Absolute path to the opentide repository root."""
    return repository_root()
