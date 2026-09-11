"""Catalogue hygiene checks for ``opentide lint``."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog
import yaml

from opentide.cli.enums import LintCheck
from opentide.core.io import parse_yaml
from opentide.documentation.markdown.links import slugify

logger = structlog.get_logger("opentide.cli.services.lint")

_OBJECT_FAMILIES = ("threats", "objectives", "rules")
_YAML_SUFFIXES = {".yaml", ".yml"}


@dataclass
class _ObjectRecord:
    path: Path
    relative: str
    name: str | None = None
    uuid: str | None = None
    author: str | None = None
    organisation: str | None = None
    parse_error: str | None = None
    expected_stem: str | None = None


def _object_files(root: Path) -> list[Path]:
    objects = root / "objects"
    if not objects.is_dir():
        return []
    files: list[Path] = []
    for family in _OBJECT_FAMILIES:
        folder = objects / family
        if not folder.is_dir():
            continue
        for path in sorted(folder.rglob("*")):
            if path.is_file() and path.suffix.lower() in _YAML_SUFFIXES:
                files.append(path)
    return files


def _as_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _organisation_name(value: object) -> str | None:
    """Accept a string or the nested ``{name, uuid}`` metadata object."""
    named = _as_str(value)
    if named:
        return named
    if isinstance(value, dict):
        return _as_str(value.get("name"))
    return None


def _load_record(root: Path, path: Path) -> _ObjectRecord:
    relative = path.relative_to(root).as_posix()
    record = _ObjectRecord(path=path, relative=relative)
    try:
        data: Any = parse_yaml(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        record.parse_error = str(exc)
        return record
    if not isinstance(data, dict):
        record.parse_error = "object YAML is not a mapping"
        return record
    record.name = _as_str(data.get("name"))
    metadata = data.get("metadata")
    if isinstance(metadata, dict):
        record.uuid = _as_str(metadata.get("uuid"))
        record.author = _as_str(metadata.get("author"))
        record.organisation = _organisation_name(
            metadata.get("organisation")
        ) or _organisation_name(metadata.get("organization"))
    return record


def _assign_expected_stems(records: list[_ObjectRecord]) -> None:
    grouped: dict[Path, list[_ObjectRecord]] = defaultdict(list)
    for record in records:
        if record.parse_error:
            continue
        grouped[record.path.parent].append(record)
    for group in grouped.values():
        taken: set[str] = set()
        for record in group:
            if record.name and slugify(record.name) == record.path.stem:
                record.expected_stem = record.path.stem
                taken.add(record.path.stem)
        for record in group:
            if record.expected_stem or not record.name:
                continue
            stem = slugify(record.name)
            if stem not in taken:
                record.expected_stem = stem
                taken.add(stem)
                continue
            suffix = (record.uuid or "object")[:8]
            candidate = f"{stem}-{suffix}"
            index = 1
            while candidate in taken:
                candidate = f"{stem}-{suffix}-{index}"
                index += 1
            record.expected_stem = candidate
            taken.add(candidate)


def _filename_findings(
    root: Path, records: list[_ObjectRecord], *, fix: bool
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    _assign_expected_stems(records)
    for record in records:
        if record.parse_error:
            findings.append(
                {
                    "check": LintCheck.filenames.value,
                    "path": record.relative,
                    "message": f"Could not parse object YAML: {record.parse_error}",
                }
            )
            continue
        if not record.name:
            findings.append(
                {
                    "check": LintCheck.filenames.value,
                    "path": record.relative,
                    "message": "Object has no name; cannot check filename slug",
                }
            )
            continue
        expected = record.expected_stem
        if expected is None or expected == record.path.stem:
            continue
        dest = record.path.with_name(f"{expected}{record.path.suffix}")
        finding: dict[str, object] = {
            "check": LintCheck.filenames.value,
            "path": record.relative,
            "expected": dest.relative_to(root).as_posix(),
            "message": (f"Filename {record.path.name!r} does not match slugify(name)={expected!r}"),
        }
        if fix:
            if dest.exists():
                finding["fixed"] = False
                finding["message"] = (
                    f"{finding['message']}; --fix skipped because {finding['expected']} exists"
                )
            else:
                record.path.rename(dest)
                finding["fixed"] = True
                finding["from"] = record.relative
                finding["path"] = dest.relative_to(root).as_posix()
        findings.append(finding)
    return findings


def _metadata_findings(records: list[_ObjectRecord]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for record in records:
        if record.parse_error or not record.name:
            continue
        missing: list[str] = []
        if not record.author:
            missing.append("author")
        if not record.organisation:
            missing.append("organisation")
        if missing:
            findings.append(
                {
                    "check": LintCheck.metadata.value,
                    "path": record.relative,
                    "message": "Recommended metadata missing: " + ", ".join(missing),
                }
            )
    return findings


def run_lint(
    root: Path,
    *,
    checks: list[LintCheck] | None = None,
    fix: bool = False,
    strict: bool = False,
) -> dict[str, object]:
    """Run catalogue hygiene checks without a full registry rebuild."""
    target = root.resolve()
    selected = list(checks) if checks else [LintCheck.filenames, LintCheck.metadata]
    records = [_load_record(target, path) for path in _object_files(target)]
    findings: list[dict[str, object]] = []
    if LintCheck.metadata in selected:
        findings.extend(_metadata_findings(records))
    if LintCheck.filenames in selected:
        findings.extend(_filename_findings(target, records, fix=fix))
    logger.debug(
        "lint_complete",
        path=str(target),
        checks=[item.value for item in selected],
        findings=len(findings),
        fix=fix,
    )
    failed = bool(strict and findings)
    return {
        "message": ("Catalogue lint found issues" if findings else "Catalogue lint passed"),
        "path": str(target),
        "checks": [item.value for item in selected],
        "findings": findings,
        "count": len(findings),
        "fixed": sum(1 for item in findings if item.get("fixed") is True),
        "status": "failed" if failed else "completed",
        "_exit_code": 1 if failed else 0,
    }
