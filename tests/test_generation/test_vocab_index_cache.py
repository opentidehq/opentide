"""The vocabulary index must be built once per snapshot, not per access.

`generation.framework.VOCAB_INDEX` is a `_LazyMapping` whose `_data()` re-reads
`Opentide.Vocabularies.Index`, and that is a *property* calling
`VocabularyLoader.load_index(...)`. Neither layer memoized anything, so every
`[]`, `in`, `.get` and iteration rebuilt every vocabulary from scratch.

The cost was not subtle. Rendering 20 threat pages measured 2,832 index builds
and 11.5 million `_build_entry` calls; the full 265-object corpus measured
169 million, with pydantic re-validating the same vocabulary models 172 million
times. `generate docs` on a cold 20-object corpus went 46.57s -> 0.80s once the
index was built once, with byte-identical output.

These tests assert the *invariant* rather than a wall-clock number, so they stay
meaningful on slow CI: repeated access must not scale the number of builds, and
a genuinely new mapping must still be rebuilt.
"""

from __future__ import annotations

from typing import Any

import pytest

from opentide.generation import vocabulary as vocab_module
from opentide.generation.vocabulary import VocabularyLoader


@pytest.fixture(autouse=True)
def _clear_index_cache() -> Any:
    """Keep these tests independent of each other and of the rest of the suite."""
    vocab_module._INDEX_CACHE.clear()
    yield
    vocab_module._INDEX_CACHE.clear()


def _raw(*names: str) -> dict[str, Any]:
    """An index vocabs mapping, in the shape `load_index` receives it."""
    return {
        name: {
            "metadata": {"name": name.title(), "field": name, "key": "name"},
            "entries": {"Alpha": {"name": "Alpha", "description": "a"}},
        }
        for name in names
    }


def _count_builds(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every per-vocabulary load the index performs."""
    seen: list[str] = []
    original = VocabularyLoader.load

    def counting(data: Any, source: str = "") -> Any:
        seen.append(source)
        return original(data, source=source)

    monkeypatch.setattr(VocabularyLoader, "load", staticmethod(counting))
    return seen


def test_repeated_load_index_builds_once(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _count_builds(monkeypatch)
    raw = _raw("severity", "surface", "actors")

    first = VocabularyLoader.load_index(raw)
    for _ in range(50):
        VocabularyLoader.load_index(raw)

    assert len(seen) == 3, f"expected one build per vocabulary, got {len(seen)}"
    assert VocabularyLoader.load_index(raw) is first, "cache must return the same object"


def test_a_different_mapping_is_rebuilt(monkeypatch: pytest.MonkeyPatch) -> None:
    """A registry reload produces a new mapping, which must not serve a stale index."""
    seen = _count_builds(monkeypatch)
    first = VocabularyLoader.load_index(_raw("severity"))
    second = VocabularyLoader.load_index(_raw("severity"))

    assert len(seen) == 2, "a distinct mapping must be rebuilt, not served from cache"
    assert first is not second


def test_in_place_growth_invalidates(monkeypatch: pytest.MonkeyPatch) -> None:
    """`registry.builder` grows this mapping in place with `.update(...)`.

    The same object gaining entries must not keep serving the smaller index,
    which is why the cache key carries the mapping's length.
    """
    seen = _count_builds(monkeypatch)
    raw = _raw("severity")
    first = VocabularyLoader.load_index(raw)
    assert set(first) == {"severity"}

    raw.update(_raw("surface"))
    second = VocabularyLoader.load_index(raw)

    assert set(second) == {"severity", "surface"}, "in-place growth must be picked up"
    assert len(seen) == 3, f"expected 1 + 2 builds, got {len(seen)}"


def test_cache_holds_a_single_entry() -> None:
    """Unbounded growth would pin every index a long-lived process ever built."""
    VocabularyLoader.load_index(_raw("severity"))
    VocabularyLoader.load_index(_raw("surface"))
    VocabularyLoader.load_index(_raw("actors"))
    assert len(vocab_module._INDEX_CACHE) == 1


def test_empty_mapping_is_not_cached() -> None:
    """An absent index is an error path, and must not poison the cache."""
    assert VocabularyLoader.load_index({}) == {}
    assert VocabularyLoader.load_index(None) == {}
    assert not vocab_module._INDEX_CACHE


def test_lazy_vocab_index_does_not_rebuild_per_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real access pattern: many lookups through the framework's lazy view.

    This is the shape that produced millions of rebuilds — `__getitem__`,
    `__contains__`, `get` and iteration each call `_data()` separately.
    """
    seen = _count_builds(monkeypatch)
    raw = _raw("severity", "surface")

    class _Snapshot:
        @property
        def Index(self) -> dict[str, Any]:
            return VocabularyLoader.load_index(raw)

    snapshot = _Snapshot()
    from opentide.generation.framework import _LazyMapping

    view: Any = _LazyMapping(lambda: snapshot.Index)

    for _ in range(25):
        assert "severity" in view
        assert view["surface"] is not None
        view.get("severity")
        list(view)
        len(view)

    assert len(seen) == 2, (
        f"125 accesses rebuilt the index {len(seen) // 2} times instead of once "
        "— the lazy view is re-resolving an uncached property"
    )
