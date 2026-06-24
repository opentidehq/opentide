"""Index loading without import-time side effects or module reload hacks."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Literal, cast

from opentide.core.root import repository_root
from opentide.core.types import IndexSnapshot


class IndexManager:
    """Load and refresh the repository index on demand."""

    _cache: IndexSnapshot | None = None

    @classmethod
    def load(cls) -> IndexSnapshot:
        """Load index from disk or build in memory."""
        if cls._cache is not None:
            return cls._cache

        root = repository_root()
        expected = root / "index.json"
        index_path = Path(os.getenv("INDEX_PATH") or expected)

        if index_path.is_file():
            index = json.loads(index_path.read_text(encoding="utf-8"))
        else:
            index = cls._build_index()

        cls._cache = cast(IndexSnapshot, cls.reconcile_staging(index))
        assert cls._cache is not None
        return cls._cache

    @classmethod
    def reload(cls) -> IndexSnapshot:
        """Drop cached index and rebuild."""
        cls._cache = None
        return cls.load()

    @classmethod
    def _build_index(cls) -> dict[str, Any]:
        import sys

        root = repository_root()
        root_str = str(root)
        if root_str not in sys.path:
            sys.path.append(root_str)
        from opentide.indexing.indexer import indexer

        index = indexer()
        if not index:
            raise RuntimeError("INDEX COULD NOT BE LOADED IN MEMORY")
        return cast(dict[str, Any], index)

    @classmethod
    def reconcile_staging(cls, index: dict[str, Any]) -> IndexSnapshot:
        """Merge staging index MDR data and refresh configurations."""
        import sys

        root = repository_root()
        root_str = str(root)
        if root_str not in sys.path:
            sys.path.append(root_str)
        from opentide.core.index_legacy import IndexManager as LegacyIndexManager

        return cast(IndexSnapshot, LegacyIndexManager.reconcile_staging(deepcopy(index)))

    @classmethod
    def return_paths(cls, tier: Literal["all", "core", "tide"] = "all") -> dict[str, Any]:
        import sys

        root = repository_root()
        root_str = str(root)
        if root_str not in sys.path:
            sys.path.append(root_str)
        from opentide.core.index_legacy import IndexManager as LegacyIndexManager

        return cast(dict[str, Any], LegacyIndexManager.return_paths(tier=tier))

    @classmethod
    def compute_chains(cls, tvm: dict[str, Any]) -> dict[str, Any]:
        import sys

        root = repository_root()
        root_str = str(root)
        if root_str not in sys.path:
            sys.path.append(root_str)
        from opentide.core.index_legacy import IndexManager as LegacyIndexManager

        return cast(dict[str, Any], LegacyIndexManager.compute_chains(tvm))
