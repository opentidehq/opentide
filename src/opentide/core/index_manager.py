"""Index loading — in-memory registry build on demand."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal, cast

from opentide.core.types import IndexSnapshot
from opentide.registry.builder import build_registry
from opentide.registry.paths import legacy_path_aliases, resolve_workspace_paths

#: What a retained snapshot was built from: the workspace and data roots, the
#: working directory, and every ``OPENTIDE_*`` variable.
RetentionKey = tuple[str, str, str, tuple[tuple[str, str], ...]]

#: What the files a snapshot was built from looked like: each file's path,
#: ``st_mtime_ns`` and ``st_size``, and each folder's path with ``-1, -1``.
Fingerprint = frozenset[tuple[str, int, int]]

#: Workspace folders the registry reads, by their key in ``snapshot["paths"]``.
_READ_FOLDERS = (
    "threat",
    "objective",
    "rule",
    "json_schemas",
    "templates",
    "custom_configurations",
)

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


def _walk(folder: Path) -> Iterator[tuple[str, int, int]]:
    """Every file and folder under *folder*, as :data:`Fingerprint` entries."""
    pending = [str(folder)]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        yield current, -1, -1
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=True):
                    pending.append(entry.path)
                    continue
                stat = entry.stat(follow_symlinks=True)
            except OSError:
                continue
            yield entry.path, stat.st_mtime_ns, stat.st_size


def _read_folders(paths: object) -> list[Path]:
    """The workspace folders a registry built with *paths* reads.

    The object folders, the schema and template folders, the workspace's
    configuration folder and the one above the workspace that
    :func:`opentide.core.files.resolve_configurations` also merges.
    """
    if not isinstance(paths, dict):
        return []
    folders: set[Path] = set()
    for key in _READ_FOLDERS:
        value = paths.get(key)
        if isinstance(value, (str, Path)):
            folders.add(Path(value))
    workspace = paths.get("_workspace_root")
    if isinstance(workspace, (str, Path)):
        folders.add(Path(workspace).parent / ".opentide" / "configurations")
    return sorted(folders)


def _fingerprint(folders: list[Path]) -> Fingerprint:
    return frozenset(entry for folder in folders for entry in _walk(folder))


def snapshot_fingerprint(snapshot: IndexSnapshot) -> Fingerprint:
    """What the workspace files *snapshot* was built from look like on disk now.

    A file added, removed or rewritten in any folder the registry reads
    changes it.
    """
    return _fingerprint(_read_folders(snapshot.get("paths")))


def _fingerprint_before_build() -> Fingerprint | None:
    """The fingerprint of the folders the next build will read, taken before it runs.

    Taken first, so a file written while the build runs makes the next run's
    fingerprint differ. ``None`` when the paths cannot be resolved: the build
    reports why.
    """
    try:
        return _fingerprint(_read_folders(legacy_path_aliases(resolve_workspace_paths())))
    except Exception:  # the build that follows raises it to the caller
        return None


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
    #: by :func:`retention_key`, each with the :func:`snapshot_fingerprint` of the
    #: files it was built from. ``None``, the default, keeps none: every command
    #: run that drops ``_cache`` builds the registry again.
    _retained: dict[RetentionKey, tuple[IndexSnapshot, Fingerprint]] | None = None

    @classmethod
    def load(cls) -> IndexSnapshot:
        """Build registry index (cached for process lifetime)."""
        if cls._cache is not None:
            return cls._cache
        retained = cls._retained
        key = retention_key() if retained is not None else None
        if retained is not None and key is not None:
            kept = retained.pop(key, None)
            # A kept snapshot is only reused while the files it was built from
            # are unchanged: a client's invalidate can arrive after the run that
            # reads the edit (a save, then the file watcher's debounced event).
            if kept is not None and snapshot_fingerprint(kept[0]) == kept[1]:
                retained[key] = kept
                cls._cache = kept[0]
                return kept[0]
        fingerprint = _fingerprint_before_build() if retained is not None else None
        snapshot = cast(IndexSnapshot, build_registry())
        cls._cache = snapshot
        if retained is not None and key is not None and fingerprint is not None:
            retained[key] = (snapshot, fingerprint)
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
