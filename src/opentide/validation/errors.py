"""Transform validation failures into structured :class:`ValidationIssue` records."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from opentide.validation.issues import ValidationIssue
from opentide.validation.preflight import PreflightGraph

# Leaf names of UUID-bearing cross-object fields. Nested body wrappers such as
# ``threat`` (ThreatBody) and ``objective`` (ObjectiveBody) are not refs.
_REF_LEAF_TO_TYPE: dict[str, str] = {
    "threats": "threat",
    "detection_model": "objective",
    "vector": "threat",
}

# Errors about how vocabulary names are laid out (scalar instead of list, several
# names packed into one string). Suggesting a single vocabulary name for these
# would recommend dropping the other names.
_VOCAB_SHAPE_ERRORS = frozenset({"vocab_list_type", "vocab_packed_names"})


def _leaf_field_name(field_path: tuple[str, ...]) -> str | None:
    """Return the last path segment that is not a list index."""
    for part in reversed(field_path):
        if not part.isdigit():
            return part
    return None


def _without_indexes(field_path: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(part for part in field_path if not part.isdigit())


def vocab_shape_rejections(exc: ValidationError) -> frozenset[tuple[tuple[str, ...], str]]:
    """``(field path, value)`` for each string rejected for its vocabulary layout."""
    return frozenset(
        (_without_indexes(tuple(str(part) for part in err.get("loc", ()))), err["input"])
        for err in exc.errors()
        if err.get("type") in _VOCAB_SHAPE_ERRORS and isinstance(err.get("input"), str)
    )


def is_vocab_shape_duplicate(
    issue: ValidationIssue, rejections: frozenset[tuple[tuple[str, ...], str]]
) -> bool:
    """Whether *issue* is a vocabulary finding on a value the schema check already rejected."""
    value = issue.context.get("value")
    return isinstance(value, str) and (_without_indexes(issue.field_path), value) in rejections


def _cross_object_ref_type(field_path: tuple[str, ...]) -> str | None:
    """Return the object family a path refers to, or None if it is not a UUID ref."""
    leaf = _leaf_field_name(field_path)
    if leaf is None:
        return None
    return _REF_LEAF_TO_TYPE.get(leaf)


def issues_from_pydantic(
    exc: ValidationError,
    *,
    object_uuid: str = "",
    object_type: str = "",
    file_path: Path | None = None,
    graph: PreflightGraph | None = None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for err in exc.errors():
        loc = err.get("loc", ())
        field_path = tuple(str(part) for part in loc)
        message = str(err.get("msg", "validation error"))
        suggestion = None
        code = "schema_validation"
        if graph and field_path:
            last = _leaf_field_name(field_path) or field_path[-1]
            if isinstance(err.get("input"), str):
                ref_type = _cross_object_ref_type(field_path)
                if ref_type is not None:
                    suggestion = graph.suggest_ref(ref_type, str(err["input"]))
                    code = "invalid_ref"
                if suggestion is None and err.get("type") not in _VOCAB_SHAPE_ERRORS:
                    suggestion = graph.enum_resolver.suggest(str(err["input"]), last)
                    if suggestion:
                        code = "vocab_unknown"
        issues.append(
            ValidationIssue(
                code=code,
                severity="error",
                object_uuid=object_uuid,
                object_type=object_type,
                file_path=file_path,
                field_path=field_path,
                message=message,
                suggestion=suggestion,
            )
        )
    return issues


def format_issues_for_console(issues: list[ValidationIssue]) -> str:
    """Headless grouping key for Rich renderer in CLI."""
    lines: list[str] = []
    by_file: dict[str, list[ValidationIssue]] = {}
    for issue in issues:
        key = str(issue.file_path or issue.object_uuid or "global")
        by_file.setdefault(key, []).append(issue)
    for file_key, bucket in sorted(by_file.items()):
        lines.append(f"## {file_key}")
        for issue in bucket:
            loc = ".".join(issue.field_path)
            prefix = f"{loc}: " if loc else ""
            hint = f" (suggestion: {issue.suggestion})" if issue.suggestion else ""
            lines.append(f"  [{issue.severity}] {prefix}{issue.message}{hint}")
    return "\n".join(lines)


def attach_yaml_lines(
    issues: list[ValidationIssue],
    payload: dict[str, Any],
    *,
    file_path: Path | None = None,
) -> list[ValidationIssue]:
    """Best-effort YAML line hints when ``ruamel.yaml`` is installed.

    Install ``opentide`` (or ``opentide[dev]`` for contributors) for line-level validation hints;
    without ruamel, issues are returned unchanged.
    """
    try:
        from ruamel.yaml import YAML
    except ImportError:
        return issues

    if file_path is None or not file_path.is_file():
        return issues

    yaml = YAML()
    yaml.preserve_quotes = True
    try:
        data = yaml.load(file_path.read_text(encoding="utf-8"))
    except Exception:
        return issues

    updated: list[ValidationIssue] = []
    for issue in issues:
        line = _find_line(data, issue.field_path)
        updated.append(issue.model_copy(update={"yaml_line": line, "file_path": file_path}))
    return updated


def _find_line(node: Any, path: tuple[str, ...]) -> int | None:
    if not path:
        return getattr(node, "lc", None) and node.lc.line  # type: ignore[union-attr]
    head, *tail = path
    if isinstance(node, dict) and head in node:
        child = node[head]
        if not tail:
            return getattr(child, "lc", None) and child.lc.line  # type: ignore[union-attr]
        return _find_line(child, tuple(tail))
    return None
