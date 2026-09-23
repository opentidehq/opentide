"""Assertions shared by validation tests, in-process and through the CLI."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from opentide.validation.issues import ValidationIssue, ValidationReport

IssueLike = ValidationIssue | Mapping[str, Any]


def declared_uuid(path: Path) -> str | None:
    """Return the UUID an object file declares, or ``None`` if it declares none."""
    body = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(body, dict):
        return None
    raw = body.get("uuid") or (body.get("metadata") or {}).get("uuid")
    return str(raw) if raw else None


def _as_dicts(report: ValidationReport | Mapping[str, Any] | Iterable[IssueLike]) -> list[dict]:
    if isinstance(report, ValidationReport):
        items: Iterable[IssueLike] = [*report.issues, *report.warnings]
    elif isinstance(report, Mapping):
        items = [*report.get("issues", []), *report.get("warnings", [])]
    else:
        items = report
    return [
        item.model_dump(mode="json") if isinstance(item, ValidationIssue) else dict(item)
        for item in items
    ]


def assert_issues_point_at_their_objects(
    report: ValidationReport | Mapping[str, Any] | Iterable[IssueLike],
    *,
    root: Path | None = None,
) -> None:
    """Every issue about an object names the file that declares that object.

    ``file_path`` was once rebuilt from the object's basename, so the issues of
    ``objects/rules/other/x.yaml`` were reported against ``objects/rules/x.yaml``
    (#297). Reading the named file back and comparing its UUID catches that in
    any layout, without the test having to know where each object lives.

    *report* is a :class:`ValidationReport`, a JSON report (``issues`` and
    ``warnings``), or a plain iterable of issues. Relative paths are resolved
    against *root*.
    """
    for issue in _as_dicts(report):
        uuid = issue.get("object_uuid") or ""
        if not uuid:
            continue
        raw_path = issue.get("file_path")
        assert raw_path, f"{issue['code']} for {uuid} has no file_path: {issue}"
        path = Path(raw_path)
        if not path.is_absolute() and root is not None:
            path = root / path
        assert path.is_file(), f"{issue['code']} for {uuid} names missing file {path}"
        owner = declared_uuid(path)
        assert owner == uuid, (
            f"{issue['code']} for {uuid} is attributed to {path}, which declares {owner}"
        )
