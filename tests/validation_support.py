"""Layouts and assertions shared by validation and SDK tests, in-process and through the CLI."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

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


def assert_objects_point_at_their_files(objects: Mapping[str, BaseModel]) -> int:
    """Every loaded object that carries a ``file`` names the file that declares it.

    ``DetectionRule.file`` was once rebuilt as ``<rules folder>/<basename>``, so
    a rule in ``objects/rules/other/x.yaml`` pointed at ``objects/rules/x.yaml``
    (#297). Returns how many objects were checked, so callers can tell a real
    check from a model without a ``file`` field.
    """
    checked = 0
    for uuid, obj in objects.items():
        if "file" not in type(obj).model_fields:
            continue
        path = getattr(obj, "file", None)
        assert path is not None, f"{uuid} was loaded without a file"
        assert Path(path).is_file(), f"{uuid} points at missing file {path}"
        owner = declared_uuid(Path(path))
        assert owner == uuid, f"{uuid} points at {path}, which declares {owner}"
        checked += 1
    return checked


# --- Same-basename layout across object types and depths (#297) --------------

TWIN = "nested-twin.yaml"
DANGLING = {
    "rule": "00000000-0000-4000-8002-00000000dead",
    "objective": "00000000-0000-4000-8001-00000000dead",
    "threat": "00000000-0000-4000-8001-00000000dead",
}
#: repo-relative path -> (object type, UUID). Depth 1 is the type folder itself.
NESTED_TWIN_LAYOUT: dict[str, tuple[str, str]] = {
    f"objects/rules/{TWIN}": ("rule", "00000000-0000-4000-8003-0000000000a1"),
    f"objects/rules/team-a/{TWIN}": ("rule", "00000000-0000-4000-8003-0000000000a2"),
    f"objects/rules/team-a/emea/{TWIN}": ("rule", "00000000-0000-4000-8003-0000000000a3"),
    f"objects/rules/team-b/{TWIN}": ("rule", "00000000-0000-4000-8003-0000000000a4"),
    f"objects/threats/{TWIN}": ("threat", "00000000-0000-4000-8001-0000000000a1"),
    f"objects/threats/actors/{TWIN}": ("threat", "00000000-0000-4000-8001-0000000000a2"),
    f"objects/threats/actors/apt/{TWIN}": ("threat", "00000000-0000-4000-8001-0000000000a3"),
    f"objects/objectives/{TWIN}": ("objective", "00000000-0000-4000-8002-0000000000a1"),
    f"objects/objectives/access/{TWIN}": ("objective", "00000000-0000-4000-8002-0000000000a2"),
    f"objects/objectives/access/emea/{TWIN}": (
        "objective",
        "00000000-0000-4000-8002-0000000000a3",
    ),
}
_CORPUS_TEMPLATES = {
    "rule": ("Detection Rules/rule-0001-sentinel-kql.yaml", "00000000-0000-4000-8003-000000000001"),
    "objective": (
        "Detection Objectives/objective-0001-credential-access.yaml",
        "00000000-0000-4000-8002-000000000001",
    ),
    "threat": (
        "Threat Vectors/threat-0001-simulated-actor.yaml",
        "00000000-0000-4000-8001-000000000001",
    ),
}


def _twin_body(repo: Path, object_type: str, uuid: str) -> str:
    """A copy of a corpus object with a new UUID and one dangling reference.

    The dangling reference makes every validated twin report an issue carrying
    its UUID, so the set of UUIDs in the report is the set of objects checked.
    """
    template, template_uuid = _CORPUS_TEMPLATES[object_type]
    text = (repo / "Objects" / template).read_text(encoding="utf-8").replace(template_uuid, uuid)
    dangling = DANGLING[object_type]
    if object_type == "rule":
        return text.replace(
            "detection_model: 00000000-0000-4000-8002-000000000001", f"detection_model: {dangling}"
        )
    if object_type == "objective":
        text = text.replace("00000000-0000-4000-8099-000000000001", uuid.replace("8002", "8099"))
        return text.replace("    - 00000000-0000-4000-8001-000000000001", f"    - {dangling}")
    return text + f"  chaining:\n    - relation: enables\n      vector: {dangling}\n"


def write_nested_twins(corpus_repo: Path) -> dict[str, Path]:
    """Write :data:`NESTED_TWIN_LAYOUT` into a ``tide_corpus`` copy; return UUID -> real path."""
    real_paths: dict[str, Path] = {}
    for relative, (object_type, uuid) in NESTED_TWIN_LAYOUT.items():
        path = corpus_repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_twin_body(corpus_repo, object_type, uuid), encoding="utf-8")
        real_paths[uuid] = path.resolve()
    return real_paths
