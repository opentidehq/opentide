"""Index loading — in-memory registry build on demand."""

from __future__ import annotations

from typing import Any, Literal, cast

from opentide.core.types import IndexSnapshot
from opentide.registry.builder import build_registry
from opentide.registry.paths import legacy_path_aliases, resolve_workspace_paths

#: What a retained snapshot was built from: the workspace and data roots, the
#: working directory, and every ``OPENTIDE_*`` variable.
RetentionKey = tuple[str, str, str, tuple[tuple[str, str], ...]]

#: ``OPENTIDE_*`` variables that change how output looks, never what the registry holds.
_PRESENTATION_VARIABLES = frozenset(
    {
        "OPENTIDE_JSON_INDENT",
        "OPENTIDE_LINKS",
        "OPENTIDE_LOG_JSON",
        "OPENTIDE_OUTPUT",
        "OPENTIDE_PROGRESS",
    }
)


def retention_key() -> RetentionKey:
    """The key :attr:`IndexManager._retained` files the snapshot built now under."""
    import os

    from opentide.core.root import get_data_root, get_repo_root

    variables = tuple(
        sorted(
            (name, value)
            for name, value in os.environ.items()
            if name.startswith("OPENTIDE_") and name not in _PRESENTATION_VARIABLES
        )
    )
    return (str(get_repo_root()), str(get_data_root()), os.getcwd(), variables)


class _IndexCacheMeta(type):
    """Drop the FlatIndex memo whenever the registry snapshot is discarded.

    Call sites clear the registry with ``IndexManager._cache = None`` rather than
    ``reload()``. The memo has to go with that snapshot. Keying it by ``id()``
    is not enough: the id is not a strong reference, so a rebuilt index can reuse
    it and serve the previous object map.
    """

    def __setattr__(cls, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if name == "_cache" and value is None:
            super().__setattr__("_flat_cache", None)
            super().__setattr__("_flat_cache_index", None)
            super().__setattr__("_chain_cache", None)
            super().__setattr__("_chain_cache_index", None)


class IndexManager(metaclass=_IndexCacheMeta):
    """Load and refresh the workspace registry in memory."""

    _cache: IndexSnapshot | None = None
    _flat_cache: dict[str, Any] | None = None
    #: Snapshot the memo belongs to. Identity, not ``id()``, so a recycled id cannot hit.
    _flat_cache_index: IndexSnapshot | None = None
    _chain_cache: dict[str, Any] | None = None
    #: Snapshot the chaining memo belongs to, on the same terms as the flat one.
    _chain_cache_index: IndexSnapshot | None = None

    #: Snapshots a long-lived host keeps between command runs (``opentide serve``),
    #: by :func:`retention_key`. ``None``, the default, keeps none: every command
    #: run that drops ``_cache`` builds the registry again.
    _retained: dict[RetentionKey, IndexSnapshot] | None = None

    @classmethod
    def load(cls) -> IndexSnapshot:
        """Build registry index (cached for process lifetime)."""
        if cls._cache is not None:
            return cls._cache
        retained = cls._retained
        key = retention_key() if retained is not None else None
        if retained is not None and key is not None:
            kept = retained.get(key)
            if kept is not None:
                cls._cache = kept
                return kept
        snapshot = cast(IndexSnapshot, build_registry())
        cls._cache = snapshot
        if retained is not None and key is not None:
            retained[key] = snapshot
        return snapshot

    @classmethod
    def reload(cls) -> IndexSnapshot:
        """Drop cached index and rebuild."""
        cls._cache = None
        return cls.load()

    @classmethod
    def reconcile_staging(cls, index: dict[str, Any]) -> IndexSnapshot:
        """Return index unchanged — staging overlay handled at deploy time."""
        return cast(IndexSnapshot, index)

    @classmethod
    def return_paths(cls, tier: Literal["all", "core", "tide"] = "all") -> dict[str, Any]:
        from opentide.core.files import resolve_configurations

        paths = resolve_workspace_paths(resolve_configurations())
        aliases = legacy_path_aliases(paths)
        if tier == "tide":
            return cast(dict[str, Any], aliases["tide"])
        if tier == "core":
            return cast(dict[str, Any], aliases["core"])
        return cast(dict[str, Any], aliases)

    @classmethod
    def compute_chains(cls, tvm: dict[str, Any]) -> dict[str, Any]:
        from opentide.core.chaining import compute_chains

        return compute_chains(tvm)
