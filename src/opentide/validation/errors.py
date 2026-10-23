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
        value = err.get("input")
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
                context={"value": value} if code == "invalid_ref" else {},
            )
        )
    return issues


def merge_reference_findings(issues: list[ValidationIssue]) -> list[ValidationIssue]:
    """One finding per cause: drop a ``vocab_unknown`` an ``invalid_ref`` already reports.

    A reference field such as ``detection_model`` is also a vocabulary field
    whose values are the known object UUIDs, so one dangling UUID failed both
    checks. Every ``invalid_ref`` stays, one per occurrence of the value, and
    takes the vocabulary suggestion when it has none of its own.
    """
    refs = {
        key for issue in issues if issue.code == "invalid_ref" and (key := _reference_key(issue))
    }
    if not refs:
        return issues
    suggestions: dict[tuple[str, tuple[str, ...], str], str] = {}
    kept: list[ValidationIssue] = []
    for issue in issues:
        key = _reference_key(issue)
        if issue.code == "vocab_unknown" and key in refs:
            if issue.suggestion is not None and key is not None:
                suggestions.setdefault(key, issue.suggestion)
            continue
        kept.append(issue)
    return [
        issue.model_copy(update={"suggestion": suggestions[key]})
        if issue.code == "invalid_ref"
        and issue.suggestion is None
        and (key := _reference_key(issue)) in suggestions
        else issue
        for issue in kept
    ]


def _reference_key(issue: ValidationIssue) -> tuple[str, tuple[str, ...], str] | None:
    """``(object, field without list indexes, value)`` of a finding about one value."""
    value = issue.context.get("value")
    if not isinstance(value, str):
        return None
    return (issue.object_uuid, _without_indexes(issue.field_path), value)


def format_issues_for_console(issues: list[ValidationIssue]) -> str:
    """Plain grouped text for the legacy ``tide_schema`` pipeline. The CLI renders code frames."""
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
            if issue.file_path is not None and issue.yaml_line is not None:
                prefix = f"{issue.file_path}:{issue.yaml_line + 1}: {prefix}"
            hint = f" (suggestion: {issue.suggestion})" if issue.suggestion else ""
            lines.append(f"  [{issue.severity}] {prefix}{issue.message}{hint}")
    return "\n".join(lines)


def load_yaml_with_lines(file_path: Path) -> Any:
    """Round-trip load *file_path* so its mappings and lists carry line markers.

    ``ruamel.yaml`` ships with ``opentide``; the import guard keeps line hints
    best-effort. Returns ``None`` when the module or the file cannot be loaded.
    """
    try:
        from ruamel.yaml import YAML
    except ImportError:
        return None

    if not file_path.is_file():
        return None

    yaml = YAML()
    yaml.preserve_quotes = True
    try:
        return yaml.load(file_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def attach_yaml_lines(
    issues: list[ValidationIssue],
    payload: dict[str, Any],
    *,
    file_path: Path | None = None,
) -> list[ValidationIssue]:
    """Best-effort YAML line hints; issues are returned unchanged when the file cannot be loaded."""
    if file_path is None:
        return issues
    data = load_yaml_with_lines(file_path)
    if data is None:
        return issues

    updated: list[ValidationIssue] = []
    for issue in issues:
        if issue.yaml_line is not None:
            if issue.file_path is None:
                updated.append(issue.model_copy(update={"file_path": file_path}))
            else:
                updated.append(issue)
            continue
        line = _find_line(data, issue.field_path)
        updated.append(issue.model_copy(update={"yaml_line": line, "file_path": file_path}))
    return updated


def _line_marker(node: Any) -> int | None:
    marker = getattr(node, "lc", None)
    if marker is None:
        return None
    line = marker.line
    return line if isinstance(line, int) else None


def _container_child_line(node: Any, head: str) -> int | None:
    """Line of a scalar child. Strings have no ``.lc``; the parent container does."""
    marker = getattr(node, "lc", None)
    if marker is None:
        return None
    located: Any = None
    if isinstance(node, list) and head.isdigit():
        item = getattr(marker, "item", None)
        if callable(item):
            located = item(int(head))
    elif isinstance(node, dict):
        value = getattr(marker, "value", None)
        if callable(value):
            located = value(head)
    if not located:
        return None
    line = located[0]
    return line if isinstance(line, int) else None


def _child(node: Any, head: str) -> Any:
    if isinstance(node, dict) and head in node:
        return node[head]
    if isinstance(node, list) and head.isdigit():
        index = int(head)
        if 0 <= index < len(node):
            return node[index]
    return None


def _find_line(node: Any, path: tuple[str, ...]) -> int | None:
    if not path:
        return _line_marker(node)
    head, *tail = path
    child = _child(node, head)
    if child is None:
        return None
    if tail:
        return _find_line(child, tuple(tail))
    line = _line_marker(child)
    if line is not None:
        return line
    return _container_child_line(node, head)
