"""Validation scope resolution (full registry vs narrow targets)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from opentide.validation.issues import ValidationIssue


@dataclass(frozen=True)
class ValidationScope:
    """Defines which objects are validated (preflight always uses the full index)."""

    mode: Literal["full", "narrow"]
    targets: frozenset[str] = frozenset()
    object_types: frozenset[str] = frozenset()

    @classmethod
    def full(cls) -> ValidationScope:
        return cls(mode="full")

    @classmethod
    def narrow(
        cls,
        *,
        files: frozenset[str] | None = None,
        uuids: frozenset[str] | None = None,
        types: frozenset[str] | None = None,
    ) -> ValidationScope:
        targets: set[str] = set()
        if files:
            targets.update(files)
        if uuids:
            targets.update(uuids)
        return cls(
            mode="narrow",
            targets=frozenset(targets),
            object_types=frozenset(types or ()),
        )

    def includes_object(
        self,
        uuid: str,
        object_type: str,
        *,
        file_name: str | None = None,
    ) -> bool:
        if self.mode == "full":
            return True
        if self.object_types and object_type not in self.object_types:
            return False
        if not self.targets:
            return bool(self.object_types)
        if uuid in self.targets:
            return True
        return bool(file_name and file_name in self.targets)


def has_narrow_filter(scope: ValidationScope) -> bool:
    """Return whether the scope restricts validation to explicit targets or types."""
    return scope.mode == "narrow" and bool(scope.targets or scope.object_types)


def scope_no_match_issue(scope: ValidationScope) -> ValidationIssue:
    """Build a scope_no_match error when narrow filters match no objects."""
    return ValidationIssue(
        code="scope_no_match",
        severity="error",
        message="No objects matched the validation scope (check --file, --uuid, --type)",
        context={
            "targets": sorted(scope.targets),
            "object_types": sorted(scope.object_types),
        },
    )
