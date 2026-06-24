"""Index loading — in-memory registry build on demand."""

from __future__ import annotations

from typing import Any, Literal, cast

from opentide.core.types import IndexSnapshot
from opentide.registry.builder import build_registry
from opentide.registry.paths import legacy_path_aliases, resolve_workspace_paths


class IndexManager:
    """Load and refresh the workspace registry in memory."""

    _cache: IndexSnapshot | None = None

    @classmethod
    def load(cls) -> IndexSnapshot:
        """Build registry index (cached for process lifetime)."""
        if cls._cache is not None:
            return cls._cache
        cls._cache = cast(IndexSnapshot, build_registry())
        return cls._cache

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
