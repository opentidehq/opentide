"""ID uniqueness scan helpers used by the validation session."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from opentide.validation.issues import ValidationIssue
from opentide.validation.scope import ValidationScope


@dataclass(frozen=True)
class IdScanRow:
    model_file: Path
    meta_name: str
    uuid: str
    name: str


def id_duplicate_in_scope(
    scope: ValidationScope,
    row: IdScanRow,
    original: IdScanRow,
) -> bool:
    """Return whether a duplicate ID pair should be reported for the given scope."""
    if scope.mode == "full":
        return True
    if not scope.targets:
        return True
    if scope.targets & {row.uuid, original.uuid}:
        return True
    paths = {
        row.model_file.name,
        str(row.model_file),
        original.model_file.name,
        str(original.model_file),
    }
    return bool(scope.targets & paths)


def merge_id_duplicates(
    scans: list[IdScanRow],
    scope: ValidationScope,
) -> list[ValidationIssue]:
    """Detect duplicate UUIDs across scan rows, respecting validation scope."""
    registry: dict[str, IdScanRow] = {}
    issues: list[ValidationIssue] = []
    for row in scans:
        if row.uuid not in registry:
            registry[row.uuid] = row
            continue
        original = registry[row.uuid]
        if not id_duplicate_in_scope(scope, row, original):
            continue
        issues.append(
            ValidationIssue(
                code="duplicate_id",
                severity="error",
                object_uuid=row.uuid,
                object_type=row.meta_name,
                file_path=row.model_file,
                message=(
                    f"Duplicated ID {row.uuid} on {row.name!r} @ {row.model_file.name}; "
                    f"already used by {original.name!r} @ {original.model_file.name}"
                ),
                context={
                    "original": {
                        "name": original.name,
                        "file_name": original.model_file.name,
                    }
                },
            )
        )
    return issues
