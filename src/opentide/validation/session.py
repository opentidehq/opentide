"""Validation session orchestrator — default full-registry pipeline."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from opentide.core.files import resolve_configurations, resolve_paths
from opentide.core.registry import OpenTide
from opentide.core.types import IndexSnapshot
from opentide.models.base import TideModel
from opentide.models.objective import DetectionObjective
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector
from opentide.validation.checks.cross_object import (
    check_chaining_for_object,
    check_references_for_object,
)
from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.errors import attach_yaml_lines, issues_from_pydantic
from opentide.validation.field_vocab import validate_object_vocab_from_metaschema
from opentide.validation.id_scan import IdScanRow, merge_id_duplicates
from opentide.validation.issues import ValidationIssue, ValidationReport
from opentide.validation.parallel import map_parallel, resolve_worker_count, sort_issues
from opentide.validation.preflight import PreflightGraph
from opentide.validation.scope import ValidationScope, has_narrow_filter, scope_no_match_issue

_MODEL_BY_TYPE: dict[str, type[TideModel]] = {
    "rule": DetectionRule,
    "objective": DetectionObjective,
    "threat": ThreatVector,
}

_DEFAULT_CHECKS = frozenset(
    {
        ValidateCheck.id_uniqueness,
        ValidateCheck.uuid_format,
        ValidateCheck.schema,
    }
)


@dataclass(frozen=True)
class ObjectWorkItem:
    """One indexed object selected for validation."""

    uuid: str
    object_type: str
    body: dict[str, Any]
    file_name: str | None


def run_validation(
    scope: ValidationScope | None = None,
    checks: frozenset[ValidateCheck] | None = None,
    *,
    index: IndexSnapshot | None = None,
    workers: int | None = None,
) -> ValidationReport:
    """Run validation checks and return a structured report."""
    started = time.perf_counter()
    scope = scope or ValidationScope.full()
    checks = checks or _DEFAULT_CHECKS

    OpenTide.initialise()
    if index is None:
        index = OpenTide.Index

    graph = PreflightGraph.build(index)
    objects = index.get("objects", {})
    metaschemas = index.get("metaschemas", {})
    files_index = index.get("files", {})

    work_items = _collect_work_items(objects, scope, files_index)
    object_workers = resolve_worker_count(len(work_items), workers=workers)
    id_paths = _id_scan_paths() if ValidateCheck.id_uniqueness in checks else []
    id_workers = resolve_worker_count(len(id_paths), workers=workers)

    issues: list[ValidationIssue] = []
    warnings: list[ValidationIssue] = []
    stats: dict[str, Any] = {
        "objects_checked": 0,
        "parallel": object_workers > 0 or id_workers > 0,
        "workers": max(object_workers, id_workers),
        "object_workers": object_workers,
        "id_workers": id_workers,
    }

    object_checks = checks & {
        ValidateCheck.uuid_format,
        ValidateCheck.schema,
    }
    if has_narrow_filter(scope) and object_checks and not work_items:
        issues.append(scope_no_match_issue(scope))

    if ValidateCheck.id_uniqueness in checks:
        issues.extend(_check_id_uniqueness(id_paths, scope=scope, workers=id_workers))

    if ValidateCheck.cve in checks:
        from opentide.validation.cve_check import check_cve_issues

        issues.extend(check_cve_issues(index, scope))

    if object_checks:
        if object_workers > 0:

            def _worker(item: ObjectWorkItem) -> list[ValidationIssue]:
                return _validate_work_item(
                    item,
                    graph=graph,
                    metaschemas=metaschemas,
                    checks=object_checks,
                )

            issues.extend(map_parallel(_worker, work_items, workers=object_workers))
        else:
            for item in work_items:
                issues.extend(
                    _validate_work_item(
                        item,
                        graph=graph,
                        metaschemas=metaschemas,
                        checks=object_checks,
                    )
                )
        stats["objects_checked"] = len(work_items)

    issues = sort_issues(issues)
    stats["wall_ms"] = round((time.perf_counter() - started) * 1000, 2)

    if issues:
        os.environ["VALIDATION_ERROR_RAISED"] = "1"
    if warnings:
        os.environ["VALIDATION_WARNING_RAISED"] = "1"

    return ValidationReport(ok=not issues, issues=issues, warnings=warnings, stats=stats)


def _collect_work_items(
    objects: dict[str, dict[str, dict[str, Any]]],
    scope: ValidationScope,
    files_index: dict[str, str],
) -> list[ObjectWorkItem]:
    items: list[ObjectWorkItem] = []
    for object_type, registry in objects.items():
        if object_type not in _MODEL_BY_TYPE:
            continue
        for uuid, body in registry.items():
            file_name = files_index.get(uuid)
            if not scope.includes_object(uuid, object_type, file_name=file_name):
                continue
            items.append(
                ObjectWorkItem(
                    uuid=str(uuid),
                    object_type=object_type,
                    body=body,
                    file_name=file_name,
                )
            )
    return items


def _validate_work_item(
    item: ObjectWorkItem,
    *,
    graph: PreflightGraph,
    metaschemas: dict[str, Any],
    checks: frozenset[ValidateCheck],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    ref = graph.resolve(item.uuid)
    file_path = ref.file_path if ref else None

    if ValidateCheck.uuid_format in checks:
        issues.extend(_uuid_issue_for_object(item, file_path))

    if ValidateCheck.schema in checks:
        try:
            if item.object_type == "rule":
                _ = DetectionRule.from_yaml_dict(item.body)
            elif item.object_type == "objective":
                _ = DetectionObjective.from_yaml_dict(item.body)
            else:
                _ = ThreatVector.from_yaml_dict(item.body)
        except ValidationError as exc:
            bucket = issues_from_pydantic(
                exc,
                object_uuid=item.uuid,
                object_type=item.object_type,
                file_path=file_path,
                graph=graph,
            )
            issues.extend(attach_yaml_lines(bucket, item.body, file_path=file_path))

        vocab_issues = validate_object_vocab_from_metaschema(
            item.body,
            metaschemas,
            item.object_type,
            graph,
            object_uuid=item.uuid,
        )
        for issue in vocab_issues:
            issues.append(issue.model_copy(update={"file_path": file_path}))

        issues.extend(check_references_for_object(item.uuid, item.object_type, item.body, graph))
        if item.object_type == "threat":
            issues.extend(check_chaining_for_object(item.uuid, item.body, graph))

    return issues


def _uuid_issue_for_object(
    item: ObjectWorkItem,
    file_path: Path | None,
) -> list[ValidationIssue]:
    raw_uuid = item.body.get("uuid") or item.body.get("metadata", {}).get("uuid")
    try:
        UUID(str(raw_uuid), version=4)
    except (ValueError, TypeError):
        return [
            ValidationIssue(
                code="invalid_uuid",
                severity="error",
                object_uuid=item.uuid,
                object_type=item.object_type,
                file_path=file_path,
                field_path=("metadata", "uuid"),
                message=f"UUID {raw_uuid!r} is not a valid UUIDv4",
                context={"name": item.body.get("name", "")},
            )
        ]
    return []


def _check_id_uniqueness(
    paths: list[tuple[Path, str]],
    *,
    scope: ValidationScope,
    workers: int,
) -> list[ValidationIssue]:
    from concurrent.futures import ThreadPoolExecutor

    if not paths:
        return []

    if workers > 0:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            scans = [row for row in pool.map(_scan_id_file, paths) if row is not None]
    else:
        scans = [row for path_row in paths if (row := _scan_id_file(path_row)) is not None]

    return merge_id_duplicates(scans, scope)


def _id_scan_paths() -> list[tuple[Path, str]]:
    """Collect all YAML model paths (ID uniqueness scans the full registry)."""
    core_config = resolve_configurations()["global"]
    metaschemas = core_config["metaschemas"]
    skips = {"logsources", "ram", "mdrv2"}
    paths = resolve_paths()
    scan_paths: list[tuple[Path, str]] = []

    for meta_name in metaschemas:
        if meta_name in skips:
            continue
        object_path = paths.get(meta_name)
        if not object_path or not object_path.exists():
            continue
        for model_file in object_path.iterdir():
            if not str(model_file).endswith(".yaml"):
                continue
            scan_paths.append((model_file, meta_name))
    return scan_paths


def _scan_id_file(path_row: tuple[Path, str]) -> IdScanRow | None:
    import yaml

    model_file, meta_name = path_row
    with model_file.open(encoding="utf-8") as handle:
        model_body = yaml.safe_load(handle)
    if not isinstance(model_body, dict):
        return None
    uuid = model_body.get("metadata", {}).get("uuid")
    if not uuid:
        return None
    return IdScanRow(
        model_file=model_file,
        meta_name=meta_name,
        uuid=str(uuid),
        name=str(model_body.get("name", "")),
    )
