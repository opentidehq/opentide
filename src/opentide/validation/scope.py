"""Validation scope resolution (full registry vs narrow targets)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from opentide.validation.issues import ValidationIssue


def _resolve(path: Path) -> str:
    try:
        return str(path.resolve())
    except OSError:  # pragma: no cover - unresolvable path on exotic filesystems
        return str(path)


def _path_variants(target: str, roots: tuple[Path, ...]) -> tuple[str, frozenset[str]]:
    """Return ``(basename, candidate absolute paths)`` for a ``--file`` target.

    The candidate set is empty for a bare basename, which is matched by name
    against the index (``files`` only stores file names). A relative target is
    resolved against the working directory *and* every known repository root,
    because ``--repo`` lets the two differ.
    """
    raw = target.strip()
    as_path = Path(raw)
    if raw in {"", "."} or (as_path.name == raw and not as_path.is_absolute()):
        return raw, frozenset()
    if as_path.is_absolute():
        return as_path.name, frozenset({_resolve(as_path)})
    candidates = {_resolve(as_path)}
    candidates.update(_resolve(root / as_path) for root in roots)
    return as_path.name, frozenset(candidates)


def workspace_roots() -> tuple[Path, ...]:
    """Roots a repo-relative ``--file`` may be written against.

    The workspace and the working directory are routinely different — CI
    templates and MCP host configs export ``OPENTIDE_REPO_ROOT`` and the
    pre-commit hook passes ``--repo``, so resolving against the cwd alone
    would miss.
    """
    from opentide.registry.discovery import discover_workspace

    roots: list[Path] = []
    for candidate in (discover_workspace(), Path.cwd()):
        try:
            resolved = Path(candidate).resolve()
        except OSError:  # pragma: no cover - unresolvable root
            continue
        if resolved not in roots:
            roots.append(resolved)
    return tuple(roots)


@dataclass(frozen=True)
class ValidationScope:
    """Defines which objects are validated (preflight always uses the full index)."""

    mode: Literal["full", "narrow"]
    targets: frozenset[str] = frozenset()
    object_types: frozenset[str] = frozenset()
    # Derived from ``--file`` targets so repo-relative and absolute paths match
    # the basename-only index (issue #240).
    #: Basenames of targets given *without* a directory component. These are
    #: the only targets a basename match is allowed to satisfy.
    file_names: frozenset[str] = field(default_factory=frozenset)
    #: Absolute candidates for targets given *with* a directory component.
    file_paths: frozenset[str] = field(default_factory=frozenset)
    #: Basenames of those same path-qualified targets, used only when the
    #: object's own path is unknown. Matching them unconditionally would make
    #: the directory component decorative: ``--file objects/threats/x.yaml``
    #: would happily validate ``objects/rules/x.yaml`` instead.
    path_basenames: frozenset[str] = field(default_factory=frozenset)

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
        roots: tuple[Path, ...] | None = None,
    ) -> ValidationScope:
        """Scope to *files*, *uuids* and *types*.

        Relative *files* are resolved against *roots*, which default to
        :func:`workspace_roots`.
        """
        if files and roots is None:
            roots = workspace_roots()
        targets: set[str] = set()
        file_names: set[str] = set()
        file_paths: set[str] = set()
        path_basenames: set[str] = set()
        for target in files or ():
            targets.add(target.strip())
            name, resolved = _path_variants(target, roots or ())
            if resolved:
                file_paths.update(resolved)
                path_basenames.add(name)
            else:
                file_names.add(name)
        if uuids:
            targets.update(uuids)
        return cls(
            mode="narrow",
            targets=frozenset(targets),
            object_types=frozenset(types or ()),
            file_names=frozenset(file_names),
            file_paths=frozenset(file_paths),
            path_basenames=frozenset(path_basenames),
        )

    def matches_file(self, file_name: str | None, file_path: Path | str | None = None) -> bool:
        """Match a ``--file`` target by basename, repo-relative path, or absolute path."""
        if (
            file_path is not None
            and self.file_paths
            and _resolve(Path(file_path)) in self.file_paths
        ):
            return True
        if not file_name:
            return False
        if file_name in self.file_names:
            return True
        # A path-qualified target falls back to its basename only when the
        # object's own path is unknown; otherwise the directory has to agree.
        return file_path is None and file_name in self.path_basenames

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
