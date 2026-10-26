"""Reset the process-wide registry singletons between in-process CLI runs."""

from __future__ import annotations


def reset_opentide_singletons() -> None:
    """Forget the loaded workspace, so the next command reads its own ``--repo``."""
    from opentide.core.index_manager import IndexManager
    from opentide.core.registry import Opentide

    Opentide._initialised = False
    Opentide._objects_loaded = False
    Opentide._index = None
    Opentide._rules = {}
    Opentide._threats = {}
    Opentide._objectives = {}
    # The cache BEHIND the singleton, which resetting Opentide._index does not
    # touch (#530). Tests that exercise index behaviour assign a partial index
    # here -- `{"objects": ..., "configurations": {}}` -- and a later test
    # reading `Opentide.Configurations.Global.objects` then sees an empty
    # configuration namespace. Serially that was invisible, because the file
    # order happened to put the victims before the polluters; under xdist the
    # grouping changes and it surfaces. The metaclass cascades this assignment
    # to `_flat_cache` and `_flat_cache_index`, so clearing `_cache` is the
    # whole clear-set.
    IndexManager._cache = None
