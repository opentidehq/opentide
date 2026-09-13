"""Migrate legacy CoreTide client layouts to the greenfield ``.opentide/`` + ``objects/`` tree."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import structlog

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
)

_EMPTY_PARENTS = ("Objects", ".opentide/framework")


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
    if dest.exists() and not _is_empty_dir(dest):
        return {**base, "action": "skip", "reason": "destination already exists"}
    return base


def _apply_operation(root: Path, operation: dict[str, object], *, copy: bool) -> None:
    src = root / str(operation["from"])
    dest = root / str(operation["to"])
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and _is_empty_dir(dest):
        dest.rmdir()
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


def run_migrate_objects(
    root: Path,
    *,
    apply: bool = False,
    copy: bool = False,
) -> dict[str, object]:
    """Plan or apply legacy layout migrations under *root*."""
    target = root.resolve()
    operations = [_plan_operation(target, mapping, copy=copy) for mapping in LAYOUT_MAPPINGS]
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
