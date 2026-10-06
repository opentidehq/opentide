"""Migrate legacy CoreTide client layouts to the greenfield ``.opentide/`` + ``objects/`` tree."""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import structlog

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

logger = structlog.get_logger("opentide.cli.services.migrate_objects")

Action = Literal["move", "copy", "skip"]


@dataclass(frozen=True)
class LayoutMapping:
    """One source → destination directory mapping."""

    source: str
    destination: str


# Mirrors tests/test_cli/conftest.py::_migrate_tide_corpus_layout.
LAYOUT_MAPPINGS: tuple[LayoutMapping, ...] = (
    LayoutMapping("Configurations", ".opentide/configurations"),
    LayoutMapping(".opentide/framework/schemas", ".opentide/schemas"),
    LayoutMapping(".opentide/framework/templates", ".opentide/templates"),
    LayoutMapping("Objects/Threat Vectors", "objects/threats"),
    LayoutMapping("Objects/Detection Objectives", "objects/objectives"),
    LayoutMapping("Objects/Detection Rules", "objects/rules"),
    LayoutMapping("Models Library/Threat Vector Models", "objects/threats"),
    LayoutMapping("Models Library/Detection Objectives", "objects/objectives"),
    LayoutMapping("Models Library/Managed Detection Rules", "objects/rules"),
)

_PATH_DESTINATIONS = {
    "threat": "objects/threats",
    "tvm": "objects/threats",
    "objective": "objects/objectives",
    "dom": "objects/objectives",
    "rule": "objects/rules",
    "mdr": "objects/rules",
    "cdm": "objects/rules",
}

# Shared by Objects/, Models Library/, and global.toml paths. A non-empty
# directory is merged so a leftover tree is not skipped behind objects/.
_MERGE_DESTINATIONS = frozenset(_PATH_DESTINATIONS.values())

_EMPTY_PARENTS = ("Objects", "Models Library", ".opentide/framework")


def _is_empty_dir(path: Path) -> bool:
    return path.is_dir() and next(path.iterdir(), None) is None


def _within_root(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _plan_operation(
    root: Path,
    mapping: LayoutMapping,
    *,
    copy: bool,
) -> dict[str, object]:
    src = root / mapping.source
    dest = root / mapping.destination
    planned: Action = "copy" if copy else "move"
    base: dict[str, object] = {
        "from": mapping.source,
        "to": mapping.destination,
        "action": planned,
    }
    if not src.exists():
        return {**base, "action": "skip", "reason": "source missing"}
    if not src.is_dir():
        return {**base, "action": "skip", "reason": "source is not a directory"}
    if not _within_root(root, src) or not _within_root(root, dest):
        return {**base, "action": "skip", "reason": "path escapes repository root"}
    if src.resolve() == dest.resolve():
        return {**base, "action": "skip", "reason": "source and destination are the same"}
    if (
        dest.exists()
        and not _is_empty_dir(dest)
        and not (dest.is_dir() and mapping.destination in _MERGE_DESTINATIONS)
    ):
        return {**base, "action": "skip", "reason": "destination already exists"}
    return base


def _merge_into(src: Path, dest: Path, *, copy: bool) -> None:
    """Place *src* children into an existing *dest* directory.

    ``shutil.move`` of a directory onto an existing directory nests the source
    inside the destination. A second legacy tree that shares ``objects/…`` has
    to be merged instead.
    """
    for child in sorted(src.iterdir(), key=lambda path: path.name):
        target = dest / child.name
        if child.is_dir() and target.is_dir():
            _merge_into(child, target, copy=copy)
            continue
        if target.exists():
            logger.warning(
                "migrate_destination_exists",
                source=str(child),
                destination=str(target),
            )
            continue
        if copy:
            if child.is_dir():
                shutil.copytree(child, target)
            else:
                shutil.copy2(child, target)
        else:
            shutil.move(str(child), str(target))
    if not copy and _is_empty_dir(src):
        src.rmdir()


def _apply_operation(root: Path, operation: dict[str, object], *, copy: bool) -> None:
    src = root / str(operation["from"])
    dest = root / str(operation["to"])
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and _is_empty_dir(dest):
        dest.rmdir()
    if dest.exists() and dest.is_dir() and src.is_dir():
        _merge_into(src, dest, copy=copy)
        return
    if copy:
        shutil.copytree(src, dest)
        return
    shutil.move(str(src), str(dest))


def _cleanup_empty_parents(root: Path) -> list[str]:
    removed: list[str] = []
    for relative in _EMPTY_PARENTS:
        path = root / relative
        if _is_empty_dir(path):
            path.rmdir()
            removed.append(relative)
    return removed


def _global_toml_mappings(root: Path) -> list[LayoutMapping]:
    """Object folders named by a legacy ``Configurations/global.toml``."""
    path = root / "Configurations" / "global.toml"
    if not path.is_file():
        return []
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        logger.warning("migrate_global_toml_unreadable", path=str(path))
        return []
    tide_paths = document.get("paths", {})
    if isinstance(tide_paths, dict):
        nested = tide_paths.get("tide")
        if isinstance(nested, dict):
            tide_paths = nested
    if not isinstance(tide_paths, dict):
        return []
    mappings: list[LayoutMapping] = []
    for key, destination in _PATH_DESTINATIONS.items():
        raw = tide_paths.get(key)
        if not isinstance(raw, str) or not raw.strip():
            continue
        source = raw.strip().strip("/")
        mappings.append(LayoutMapping(source, destination))
    return mappings


def _mappings_for(root: Path) -> list[LayoutMapping]:
    seen: set[tuple[str, str]] = set()
    ordered: list[LayoutMapping] = []
    for mapping in (*LAYOUT_MAPPINGS, *_global_toml_mappings(root)):
        identity = (mapping.source, mapping.destination)
        if identity in seen:
            continue
        seen.add(identity)
        ordered.append(mapping)
    return ordered


def run_migrate_objects(
    root: Path,
    *,
    apply: bool = False,
    copy: bool = False,
) -> dict[str, object]:
    """Plan or apply legacy layout migrations under *root*."""
    target = root.resolve()
    operations = [_plan_operation(target, mapping, copy=copy) for mapping in _mappings_for(target)]
    actionable = [item for item in operations if item["action"] != "skip"]
    skipped = [item for item in operations if item["action"] == "skip"]
    removed: list[str] = []
    if apply:
        for operation in actionable:
            _apply_operation(target, operation, copy=copy)
        if not copy:
            removed = _cleanup_empty_parents(target)
    logger.debug(
        "migrate_objects",
        path=str(target),
        apply=apply,
        copy=copy,
        planned=len(actionable),
    )
    if not actionable:
        message = "No legacy layout paths to migrate"
    elif apply:
        verb = "Copied" if copy else "Migrated"
        message = f"{verb} {len(actionable)} legacy path(s)"
    else:
        message = (
            f"Planned {len(actionable)} layout migration(s) (dry-run; pass --apply to execute)"
        )
    result: dict[str, object] = {
        "message": message,
        "path": str(target),
        "dry_run": not apply,
        "copy": copy,
        "operations": operations,
        "planned": len(actionable),
        "skipped": len(skipped),
        "applied": bool(apply and actionable),
    }
    if removed:
        result["removed_empty"] = removed
    return result
