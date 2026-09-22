"""Validation scope resolution (full registry vs narrow targets)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from opentide.validation.issues import ValidationIssue


def _path_variants(target: str) -> tuple[str, str | None]:
    """Return ``(basename, resolved absolute path)`` for a ``--file`` target.

    The resolved path is ``None`` for bare basenames, which stay basename-only
    matches against the index (``files`` only stores file names).
    """
    raw = target.strip()
    as_path = Path(raw)
    if raw in {"", "."} or (as_path.name == raw and not as_path.is_absolute()):
        return raw, None
    try:
        return as_path.name, str(as_path.resolve())
    except OSError:  # pragma: no cover - unresolvable path on exotic filesystems
        return as_path.name, str(as_path)


@dataclass(frozen=True)
class ValidationScope:
    """Defines which objects are validated (preflight always uses the full index)."""

    mode: Literal["full", "narrow"]
    targets: frozenset[str] = frozenset()
    object_types: frozenset[str] = frozenset()
    # Derived from ``--file`` targets so repo-relative and absolute paths match
    # the basename-only index (issue #240).
    file_names: frozenset[str] = field(default_factory=frozenset)
    file_paths: frozenset[str] = field(default_factory=frozenset)

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
        file_names: set[str] = set()
        file_paths: set[str] = set()
        for target in files or ():
            targets.add(target)
            name, resolved = _path_variants(target)
            file_names.add(name)
            if resolved:
                file_paths.add(resolved)
        if uuids:
            targets.update(uuids)
        return cls(
            mode="narrow",
            targets=frozenset(targets),
            object_types=frozenset(types or ()),
            file_names=frozenset(file_names),
            file_paths=frozenset(file_paths),
        )

    def matches_file(self, file_name: str | None, file_path: Path | str | None = None) -> bool:
        """Match a ``--file`` target by basename, repo-relative path, or absolute path."""
        if file_path is not None and self.file_paths:
            try:
                resolved = str(Path(file_path).resolve())
            except OSError:  # pragma: no cover - unresolvable path
                resolved = str(file_path)
            if resolved in self.file_paths:
                return True
        if not file_name:
            return False
        if file_name in self.targets:
            return True
        # A path target still matches by basename when the object's own path is
        # unknown, or when the target was given relative to another working
        # directory than the one the index was built from.
        return file_name in self.file_names

    def includes_object(
        self,
        uuid: str,
        object_type: str,
        *,
        file_name: str | None = None,
        file_path: Path | str | None = None,
    ) -> bool:
        if self.mode == "full":
            return True
        if self.object_types and object_type not in self.object_types:
            return False
        if not self.targets:
            return bool(self.object_types)
        if uuid in self.targets:
            return True
        return self.matches_file(file_name, file_path)


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
