"""Transform validation failures into structured :class:`ValidationIssue` records."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from opentide.validation.issues import ValidationIssue
from opentide.validation.preflight import PreflightGraph


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
        if graph and len(field_path) >= 1:
            last = field_path[-1]
            if isinstance(err.get("input"), str):
                for ref_type in ("threat", "objective", "rule"):
                    if ref_type in ".".join(field_path):
                        suggestion = graph.suggest_ref(ref_type, str(err["input"]))
                        code = "invalid_ref"
                        break
                if suggestion is None and graph:
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
