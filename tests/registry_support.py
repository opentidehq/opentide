"""Reset the process-wide registry singletons between in-process CLI runs."""

from __future__ import annotations

import sys


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
    # The schema pipeline binds `Opentide.Configurations.Index` and the
    # vocabulary index into module globals on first use and keeps them behind
    # `_runtime_ready`. Without this a test generating schemas reused the index
    # an earlier test on the same xdist worker loaded -- one with a partial
    # configuration namespace -- and failed with `KeyError: 'systems'` in
    # `recomposition_handler`. `opentide serve` clears the same flag between
    # runs. Only when the module was imported, so the reset costs no import.
    pipeline = sys.modules.get("opentide.generation.schema_pipeline")
    if pipeline is not None:
        pipeline._runtime_ready = False
