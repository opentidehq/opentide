"""Which YAML files are object instances: the catalogue (workspace 1.3, #584).

An object instance is a YAML file placed directly in its family directory
(``objects/rules/x.yaml``). A file in a subfolder (``objects/rules/team/x.yaml``)
is not an instance: it is not indexed, validated, shared, documented or
deployed, and every command that reads the catalogue warns about it once.

Every reader of object files goes through :func:`scan_object_dir` so the
registry, ``validate``, ``share``, ``lint``, docs and exports agree on what the
catalogue is. ``deploy`` keeps its own rule scan (#312) with the same rule.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opentide.core.logging import get_logger

logger = get_logger(__name__)

#: Suffixes an object file may carry.
OBJECT_SUFFIXES = (".yaml", ".yml")
#: Scratch output some tools write next to objects; never an object instance.
DEBUG_SUFFIX = ".debug.yaml"
#: Warning code shared by ``validate``, ``lint`` and the log event.
NESTED_OBJECT_FILE = "nested_object_file"
NESTED_OBJECTS_ISSUE = "https://github.com/opentidehq/opentide/issues/584"
#: Index key listing the nested files the registry skipped.
NESTED_INDEX_KEY = "nested_object_files"


@dataclass(frozen=True)
class ObjectDirScan:
    """Object files directly in a family directory, and the ones in its subfolders."""

    files: tuple[Path, ...] = ()
    nested: tuple[Path, ...] = ()


def is_object_file_name(name: str, *, include_debug: bool = False) -> bool:
    """True for a ``*.yaml``/``*.yml`` name (``*.debug.yaml`` only when asked).

    Case-sensitive, like ``deploy``'s rule scan and inflight shards: ``r.YAML``
    is not an object, so no command reads a file ``deploy`` would skip.
    """
    if not name.endswith(OBJECT_SUFFIXES):
        return False
    return include_debug or not name.endswith(DEBUG_SUFFIX)


def scan_object_dir(object_dir: Path, *, include_debug: bool = False) -> ObjectDirScan:
    """Split the YAML files under *object_dir* into catalogue files and nested files.

    Raises ``OSError`` when the directory cannot be read; a missing directory
    is an empty scan.
    """
    if not object_dir.is_dir():
        return ObjectDirScan()
    files: list[Path] = []
    nested: list[Path] = []
    for path in sorted(object_dir.rglob("*")):
        if not is_object_file_name(path.name, include_debug=include_debug):
            continue
        if not path.is_file():
            continue
        if path.parent == object_dir:
            files.append(path)
        else:
            nested.append(path)
    return ObjectDirScan(tuple(files), tuple(nested))


def catalogue_files(object_dir: Path, *, include_debug: bool = False) -> list[Path]:
    """Object files directly in *object_dir*: the catalogue for that family."""
    return list(scan_object_dir(object_dir, include_debug=include_debug).files)


def display_path(path: Path | str, root: Path | None = None) -> str:
    """*path* relative to *root* (default: the workspace), else as given."""
    candidate = Path(path)
    if root is None:
        from opentide.registry.discovery import discover_workspace

        root = discover_workspace()
    try:
        return candidate.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return candidate.as_posix()


def nested_file_message(path: str, folder: str) -> str:
    """One nested file, worded like deploy's nested-rule warning (#312)."""
    return (
        f"{path} is in a subfolder of {folder} and is not an object instance: it is not "
        f"indexed, validated, shared, documented or deployed (opentide reads only files "
        f"directly in {folder}; see {NESTED_OBJECTS_ISSUE})"
    )


def nested_files_message(paths: Iterable[str]) -> str:
    """Every nested file in one line, worded like deploy's nested-rule warning (#312)."""
    names = list(paths)
    return (
        f"{len(names)} object file(s) in subfolders of an object folder are not object "
        f"instances and are skipped (opentide reads only files directly in each object "
        f"folder; see {NESTED_OBJECTS_ISSUE}): {', '.join(names)}"
    )


def nested_entries(index: Mapping[str, Any] | None = None) -> list[dict[str, str]]:
    """Nested files the registry skipped: ``{path, folder, object_type}`` rows."""
    if index is None:
        from opentide.core.registry import Opentide

        Opentide.initialise()
        index = Opentide.Index
    rows = index.get(NESTED_INDEX_KEY) or []
    return [row for row in rows if isinstance(row, dict) and row.get("path")]


def report_nested_object_files(
    index: Mapping[str, Any] | None = None,
    *,
    warnings: list[str] | None = None,
) -> list[str]:
    """Warn once about the nested files in *index*; return their display paths.

    With *warnings* the caller prints the message, so the log line is
    info-level: a warning-level log would print it twice (as deploy does).
    """
    paths = [display_path(row["path"]) for row in nested_entries(index)]
    if not paths:
        return []
    fields = {"count": len(paths), "files": paths, "issue": NESTED_OBJECTS_ISSUE}
    if warnings is None:
        logger.warning(NESTED_OBJECT_FILE, detail=nested_files_message(paths), **fields)
    else:
        logger.info(NESTED_OBJECT_FILE, **fields)
        warnings.append(nested_files_message(paths))
    return paths


def with_nested_object_warning(payload: dict[str, Any]) -> dict[str, Any]:
    """Add the nested-file warning to a CLI payload (docs, export), once."""
    extra: list[str] = []
    report_nested_object_files(warnings=extra)
    if extra:
        existing = payload.get("warnings")
        payload["warnings"] = [*(existing if isinstance(existing, list) else []), *extra]
    return payload
