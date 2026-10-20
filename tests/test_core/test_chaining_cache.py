"""The threat chaining graph must be memoized per snapshot, like ``FlatIndex``.

``Opentide.Models.chaining`` recomputed the whole graph on every read, and
``generation.framework.CHAINING_INDEX`` is a lazy view whose ``_data()``
re-reads that property for every lookup. Rendering a 265-object corpus measured
**4,273** ``compute_chains`` calls costing 1.5s of a 3.5s run -- the dominant
remaining cost once the vocabulary index was fixed.

``FlatIndex`` two properties above already had the correct pattern, including
automatic invalidation: ``_IndexCacheMeta.__setattr__`` clears the memo whenever
``_cache`` is set to ``None``. These tests hold ``chaining`` to the same
contract, asserting the invariant rather than a wall-clock number so they stay
meaningful on slow CI.
"""

from __future__ import annotations

from typing import Any

import pytest

from opentide.core import index_manager as index_mod
from opentide.core.registry import Opentide


def _index(*threat_names: str) -> dict[str, Any]:
    return {
        "objects": {
            "rule": {},
            "objective": {},
            "threat": {name: {"name": name, "metadata": {"uuid": name}} for name in threat_names},
            "signal": {},
        },
        "files": {},
        "configurations": {},
    }


@pytest.fixture(autouse=True)
def _reset_registry() -> Any:
    """Leave no snapshot or memo behind for the rest of the suite."""
    yield
    Opentide._index = None
    index_mod.IndexManager._cache = None


def _install(index: dict[str, Any]) -> None:
    Opentide._rules = {}
    Opentide._threats = {}
    Opentide._objectives = {}
    Opentide._initialised = True
    Opentide._index = index
    index_mod.IndexManager._cache = index


def test_chaining_is_memoized_per_snapshot() -> None:
    _install(_index("t1", "t2"))
    chains = Opentide.Models.chaining
    assert Opentide.Models.chaining is chains, "second access must return the cached graph"


def test_chaining_recomputed_once_across_many_accesses(monkeypatch: pytest.MonkeyPatch) -> None:
    """The access pattern that cost 1.5s: many reads through the lazy view."""
    calls: list[int] = []
    original = index_mod.IndexManager.compute_chains

    def counting(_cls: Any, tvm: dict[str, Any]) -> dict[str, Any]:
        calls.append(1)
        return original(tvm)

    monkeypatch.setattr(index_mod.IndexManager, "compute_chains", classmethod(counting))
    _install(_index("t1", "t2"))

    from opentide.generation.framework import CHAINING_INDEX

    # Each of these hits a different `_LazyMapping` path, and every one of them
    # used to recompute the whole graph: __contains__, get, and __iter__.
    seen = 0
    for _ in range(40):
        seen += int("t1" in CHAINING_INDEX)
        seen += int(CHAINING_INDEX.get("t1") is not None)
        seen += len(list(CHAINING_INDEX))

    assert len(calls) == 1, f"120 accesses recomputed the chaining graph {len(calls)} times"


def test_chaining_not_stale_after_cache_drop() -> None:
    """A cache drop, not reload(), must not serve the previous graph."""
    _install(_index("old-threat"))
    assert "old-threat" in Opentide.Models.chaining or Opentide.Models.chaining == {}
    first = Opentide.Models.chaining

    # The same drop the CLI and corpus helpers use.
    Opentide._index = None
    index_mod.IndexManager._cache = None
    assert index_mod.IndexManager._chain_cache is None
    assert index_mod.IndexManager._chain_cache_index is None

    _install(_index("new-threat"))
    second = Opentide.Models.chaining
    assert second is not first, "a fresh snapshot must rebuild the graph"


def test_reload_clears_the_chaining_memo() -> None:
    """`reload()` goes through `_cache = None`, so the metaclass must clear it."""
    _install(_index("t1"))
    primed = Opentide.Models.chaining
    assert primed is not None
    assert index_mod.IndexManager._chain_cache is not None

    index_mod.IndexManager._cache = None
    assert index_mod.IndexManager._chain_cache is None, (
        "the metaclass must clear the chaining memo alongside the flat one"
    )
