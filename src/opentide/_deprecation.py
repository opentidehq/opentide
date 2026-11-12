"""The SDK's compatibility shims (UC-5.2, #837): one deprecation cycle each.

The entry points the SDK documented before :class:`opentide.Workspace`
(``Opentide.initialise()`` and its accessors, ``run_validation`` and
``ValidationScope``, the documentation writers) keep working, and warn code
outside this package that calls them. opentide's own modules (the CLI, MCP)
still run on them, and never warn: a shim asks who called it.
"""

from __future__ import annotations

import sys
import warnings

#: The release the shims are removed in, as their warnings and the docs say.
REMOVED_IN = "0.25"


def _is_internal(module: object) -> bool:
    return isinstance(module, str) and (module == "opentide" or module.startswith("opentide."))


def warn_external(old: str, new: str, *, depth: int = 2) -> None:
    """Warns that *old* is deprecated for *new*, unless opentide itself called it.

    *depth* is the frame of the caller to judge, counted from this function:
    2 is the caller of the function that calls this one.
    """
    try:
        caller = sys._getframe(depth).f_globals.get("__name__")
    except ValueError:  # a stack shallower than *depth*: no caller to spare
        caller = None
    if _is_internal(caller):
        return
    warnings.warn(
        f"{old} is deprecated and will be removed in opentide {REMOVED_IN}: use {new} "
        "(the SDK's migration guide, docs/sdk/migration.md).",
        DeprecationWarning,
        stacklevel=depth + 1,
    )
