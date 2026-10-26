"""Validation session orchestrator — default full-registry pipeline."""

from __future__ import annotations

import os
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from pydantic import ValidationError

from opentide.core.files import resolve_configurations, resolve_paths
from opentide.core.registry import Opentide
from opentide.models.object_types import CORE_OBJECT_TYPES
from opentide.registry.catalogue import (
    NESTED_OBJECT_FILE,
    catalogue_files,
    display_path,
    nested_entries,
    nested_file_message,
)
from opentide.validation.checks.cross_object import (
    check_chaining_for_object,
    check_references_for_object,
)
from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.disabled_platforms import (
    STRICT_EXEMPT_WARNINGS,
    platform_not_enabled_warnings,
)
from opentide.validation.errors import (
    attach_yaml_lines,
    is_vocab_shape_duplicate,
    issues_from_pydantic,
    vocab_shape_rejections,
)
from opentide.validation.field_vocab import validate_object_vocab_from_metaschema
from opentide.validation.issues import ValidationIssue, ValidationReport
from opentide.validation.parallel import resolve_worker_count, sort_issues
from opentide.validation.preflight import PreflightGraph
from opentide.validation.scope import ValidationScope

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
    file_path: Path | None = None


@dataclass(frozen=True)
class _IdScanRow:
    model_file: Path
    meta_name: str
    uuid: str
    name: str


@dataclass(frozen=True)
class _IdScanParseError:
    """A file the ID scan could not read.

    The scan and the indexer do not walk the same set — ``RegistryBuilder``
    skips ``*.debug.yaml`` while ``_id_scan_paths`` includes it — so "the index
    already reported this" was not true for every file and the parse error was
    silently dropped (#250).
    """

    model_file: Path
    meta_name: str
    error: str


def run_validation(
    scope: ValidationScope | None = None,
    checks: frozenset[ValidateCheck] | None = None,
    *,
    index: Mapping[str, Any] | None = None,
    workers: int | None = None,
) -> ValidationReport:
    """Run validation checks and return a structured report."""
    started = time.perf_counter()
    scope = scope or ValidationScope.full()
    checks = checks or _DEFAULT_CHECKS

    Opentide.initialise()
    if index is None:
        index = cast("Mapping[str, Any]", Opentide.Index)  # an IndexSnapshot TypedDict

    graph = PreflightGraph.build(index)
    objects = index.get("objects", {})
    metaschemas = index.get("metaschemas", {})
    files_index = index.get("files", {})

    work_items = _collect_work_items(objects, scope, files_index, graph)
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

    parse_errors = index.get("parse_errors", [])
    # yaml_parse belongs to schema. A named check such as cve must not fail
    # because an unrelated object file failed to parse.
    parse_issues = _yaml_parse_issues(parse_errors, scope) if ValidateCheck.schema in checks else []
    issues.extend(parse_issues)
    indexed_parse_failures = frozenset(
        _resolved_str(entry["path"]) for entry in parse_errors if entry.get("path")
    )

    object_checks = checks & {
        ValidateCheck.uuid_format,
        ValidateCheck.schema,
    }
    if _scope_has_narrow_filter(scope) and object_checks and not work_items and not parse_issues:
        issues.append(_scope_no_match_issue(scope))
    elif object_checks and scope.file_targets:
        # One matching target must not let another, unmatched one pass: the
        # production write-back validates exactly the files it is about to
        # commit, and a target that matches nothing validated nothing.
        selected: list[tuple[str | None, Path | str | None]] = [
            (item.file_name, item.file_path) for item in work_items
        ]
        selected.extend((None, issue.file_path) for issue in parse_issues if issue.file_path)
        issues.extend(
            _file_target_no_match_issue(target) for target in scope.unmatched_file_targets(selected)
        )

    if ValidateCheck.id_uniqueness in checks:
        issues.extend(
            _check_id_uniqueness(
                id_paths,
                scope=scope,
                workers=id_workers,
                already_reported=indexed_parse_failures,
            )
        )

    if ValidateCheck.cve in checks:
        from opentide.validation.cve_check import check_cve_issues

        for issue in check_cve_issues(index, scope):
            (warnings if issue.severity == "warning" else issues).append(issue)

    # Files in subfolders are not objects (#584): say so once, as warnings.
    warnings.extend(_nested_object_warnings(index, scope))

    if ValidateCheck.sharing_config in checks:
        sharing_issues, sharing_warnings = _sharing_config_issues()
        issues.extend(sharing_issues)
        warnings.extend(sharing_warnings)

    if object_checks:
        enabled_platforms = _enabled_platforms(work_items, object_checks)
        if object_workers > 0:
            from concurrent.futures import ThreadPoolExecutor

            def _worker(
                item: ObjectWorkItem,
            ) -> tuple[list[ValidationIssue], list[ValidationIssue]]:
                return _validate_work_item(
                    item,
                    graph=graph,
                    metaschemas=metaschemas,
                    checks=object_checks,
                    check_shard=scope.mode != "full",
                    enabled_platforms=enabled_platforms,
                )

            with ThreadPoolExecutor(max_workers=object_workers) as pool:
                for item_issues, item_warnings in pool.map(_worker, work_items):
                    issues.extend(item_issues)
                    warnings.extend(item_warnings)
        else:
            for item in work_items:
                item_issues, item_warnings = _validate_work_item(
                    item,
                    graph=graph,
                    metaschemas=metaschemas,
                    checks=object_checks,
                    check_shard=scope.mode != "full",
                    enabled_platforms=enabled_platforms,
                )
                issues.extend(item_issues)
                warnings.extend(item_warnings)
        stats["objects_checked"] = len(work_items)

    if ValidateCheck.schema in checks and scope.mode == "full":
        # Shards outlive their rules: an orphan is still the only handle on a
        # remote rule, so the whole directory is checked, not only shards a
        # rule points at.
        from opentide.validation.external_ids import deployment_state_issues

        issues.extend(deployment_state_issues())

    issues = sort_issues(issues)
    stats["wall_ms"] = round((time.perf_counter() - started) * 1000, 2)

    if issues:
        os.environ["VALIDATION_ERROR_RAISED"] = "1"
    # The flag fails --strict. A disabled platform's block is reported, not failed.
    if any(warning.code not in STRICT_EXEMPT_WARNINGS for warning in warnings):
        os.environ["VALIDATION_WARNING_RAISED"] = "1"

    return ValidationReport(ok=not issues, issues=issues, warnings=warnings, stats=stats)


def _enabled_platforms(
    work_items: list[ObjectWorkItem], checks: frozenset[ValidateCheck]
) -> frozenset[str] | None:
    """Platforms deploy sends to, read once per run. ``None`` when no rule is schema-checked."""
    if ValidateCheck.schema not in checks or not any(i.object_type == "rule" for i in work_items):
        return None
    from opentide.platforms.enabled import enabled_systems

    return frozenset(enabled_systems())


def _nested_object_warnings(
    index: Mapping[str, Any], scope: ValidationScope
) -> list[ValidationIssue]:
    """One ``nested_object_file`` warning per YAML file in a subfolder of an object folder.

    A narrow run warns only about the files its ``--file`` or ``--type``
    filters point at, so ``--file objects/rules/team/x.yaml`` explains why
    nothing matched.
    """
    warnings: list[ValidationIssue] = []
    for row in nested_entries(index):
        path = Path(row["path"])
        object_type = str(row.get("object_type") or "")
        if scope.mode == "narrow":
            if scope.object_types and object_type not in scope.object_types:
                continue
            if scope.file_targets and not scope.matches_file(path.name, path):
                continue
            if not scope.file_targets and not scope.object_types:
                continue
        folder = display_path(row.get("folder") or path.parent)
        warnings.append(
            ValidationIssue(
                code=NESTED_OBJECT_FILE,
                severity="warning",
                object_type=object_type,
                file_path=path,
                message=nested_file_message(display_path(path), folder),
            )
        )
    return warnings


def _sharing_config_issues() -> tuple[list[ValidationIssue], list[ValidationIssue]]:
    """Check merged ``sharing.toml``. Off unless ``sharing-config`` was requested."""
    from opentide.sharing.config import load_sharing

    loaded = load_sharing()
    errors: list[ValidationIssue] = []
    warnings: list[ValidationIssue] = []
    for finding in loaded.issues:
        field_path = tuple(
            part
            for part in (finding.integration, finding.block, finding.field_name)
            if part is not None
        )
        issue = ValidationIssue(
            code=finding.code,
            severity=finding.severity,
            file_path=loaded.source,
            field_path=field_path,
            message=finding.message,
        )
        if finding.severity == "warning":
            warnings.append(issue)
        else:
            errors.append(issue)
    return errors, warnings


def _collect_work_items(
    objects: dict[str, dict[str, dict[str, Any]]],
    scope: ValidationScope,
    files_index: dict[str, str],
    graph: PreflightGraph | None = None,
) -> list[ObjectWorkItem]:
    items: list[ObjectWorkItem] = []
    for object_type, registry in objects.items():
        if object_type not in CORE_OBJECT_TYPES:
            continue
        for uuid, body in registry.items():
            file_name = files_index.get(uuid)
            ref = graph.resolve(str(uuid)) if graph is not None else None
            if not scope.includes_object(
                uuid,
                object_type,
                file_name=file_name,
                file_path=ref.file_path if ref else None,
            ):
                continue
            items.append(
                ObjectWorkItem(
                    uuid=str(uuid),
                    object_type=object_type,
                    body=body,
                    file_name=file_name,
                    file_path=ref.file_path if ref else None,
                )
            )
    return items


def _resolved_str(path: Path | str) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:  # pragma: no cover - unresolvable path
        return str(path)


def _yaml_parse_issues(
    parse_errors: list[dict[str, str]],
    scope: ValidationScope,
) -> list[ValidationIssue]:
    """Report object files the indexer could not parse as validation issues.

    Unparseable files never reach the registry, so no other check can see them.
    Without this they were silently dropped and later crashed the ID scan with a
    raw ``yaml`` traceback (issue #250).
    """
    issues: list[ValidationIssue] = []
    for entry in parse_errors:
        raw_path = entry.get("path", "")
        path = Path(raw_path) if raw_path else None
        if scope.mode == "narrow":
            if scope.object_types and entry.get("object_type") not in scope.object_types:
                continue
            if scope.targets and not scope.matches_file(path.name if path else None, path):
                continue
        code = entry.get("code") or "yaml_parse"
        message = entry.get("message") or (
            f"Could not parse object YAML: {entry.get('error', 'unknown error')}"
        )
        issues.append(
            ValidationIssue(
                code=code,
                severity="error",
                # A parse failure may not know its family; None failed validation.
                object_type=entry.get("object_type") or "",
                file_path=path,
                message=message,
            )
        )
    return issues


def _validate_work_item(
    item: ObjectWorkItem,
    *,
    graph: PreflightGraph,
    metaschemas: dict[str, Any],
    checks: frozenset[ValidateCheck],
    check_shard: bool = True,
    enabled_platforms: frozenset[str] | None = None,
) -> tuple[list[ValidationIssue], list[ValidationIssue]]:
    issues: list[ValidationIssue] = []
    warnings: list[ValidationIssue] = []
    ref = graph.resolve(item.uuid)
    file_path = ref.file_path if ref else None

    if ValidateCheck.uuid_format in checks:
        issues.extend(_uuid_issue_for_object(item, graph, file_path))

    if ValidateCheck.schema in checks:
        from opentide.loading.object_loader import (
            SchemaIdentifierError,
            SchemaMissingError,
            load_object_for_validation,
        )

        shape_rejections: frozenset[tuple[tuple[str, ...], str]] = frozenset()
        try:
            load_object_for_validation(item.body, item.object_type, file=file_path)
        except ValidationError as exc:
            shape_rejections = vocab_shape_rejections(exc)
            bucket = issues_from_pydantic(
                exc,
                object_uuid=item.uuid,
                object_type=item.object_type,
                file_path=file_path,
                graph=graph,
            )
            from opentide.validation.external_ids import is_superseded_extra_key

            bucket = [issue for issue in bucket if not is_superseded_extra_key(issue)]
            issues.extend(attach_yaml_lines(bucket, item.body, file_path=file_path))
        except (SchemaMissingError, SchemaIdentifierError) as exc:
            issue = ValidationIssue(
                code=exc.code,
                severity="error",
                object_uuid=item.uuid,
                object_type=item.object_type,
                file_path=file_path,
                field_path=("metadata", "schema"),
                message=str(exc),
            )
            issues.extend(attach_yaml_lines([issue], item.body, file_path=file_path))
        except Exception as exc:
            issues.append(
                ValidationIssue(
                    code="schema_validation",
                    severity="error",
                    object_uuid=item.uuid,
                    object_type=item.object_type,
                    file_path=file_path,
                    message=str(exc),
                )
            )

        vocab_issues = validate_object_vocab_from_metaschema(
            item.body,
            metaschemas,
            item.object_type,
            graph,
            object_uuid=item.uuid,
        )
        for issue in vocab_issues:
            if is_vocab_shape_duplicate(issue, shape_rejections):
                continue
            issues.append(issue.model_copy(update={"file_path": file_path}))

        from opentide.validation.deprecated_fields import validate_deprecated_fields_from_metaschema

        deprecated_issues = validate_deprecated_fields_from_metaschema(
            item.body,
            metaschemas,
            item.object_type,
            object_uuid=item.uuid,
        )
        for issue in deprecated_issues:
            warnings.append(issue.model_copy(update={"file_path": file_path}))

        if item.object_type == "rule" and enabled_platforms is not None:
            warnings.extend(
                issue.model_copy(update={"file_path": file_path})
                for issue in platform_not_enabled_warnings(
                    item.body, enabled_platforms, object_uuid=item.uuid
                )
            )

        from opentide.validation.external_ids import external_id_issues

        issues.extend(
            external_id_issues(
                item.body,
                object_uuid=item.uuid,
                object_type=item.object_type,
                file_path=file_path,
                check_shard=check_shard,
            )
        )
        issues.extend(check_references_for_object(item.uuid, item.object_type, item.body, graph))
        if item.object_type == "threat":
            issues.extend(check_chaining_for_object(item.uuid, item.body, graph))

    if file_path is not None:
        issues = attach_yaml_lines(issues, item.body, file_path=file_path)
        warnings = attach_yaml_lines(warnings, item.body, file_path=file_path)

    return issues, warnings


def _uuid_issue_for_object(
    item: ObjectWorkItem,
    graph: PreflightGraph,
    file_path: Path | None,
) -> list[ValidationIssue]:
    metadata = item.body.get("metadata")
    raw_uuid = item.body.get("uuid") or (
        metadata.get("uuid") if isinstance(metadata, dict) else None
    )
    if not _is_uuid_v4(raw_uuid):
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


def _is_uuid_v4(raw: object) -> bool:
    """Whether *raw* is a version 4 UUID written as ``8-4-4-4-12`` hex digits.

    ``UUID(raw, version=4)`` overwrites the version and variant bits instead of
    checking them, so version 1 and 5 UUIDs, the nil UUID and braced, ``urn:``
    or unhyphenated spellings all passed. Hex digits may be either case, as
    RFC 9562 reads them.
    """
    text = str(raw)
    try:
        parsed = UUID(text)
    except ValueError:
        return False
    return parsed.version == 4 and str(parsed) == text.lower()


def _scope_has_narrow_filter(scope: ValidationScope) -> bool:
    return scope.mode == "narrow" and bool(scope.targets or scope.object_types)


def _scope_no_match_issue(scope: ValidationScope) -> ValidationIssue:
    return ValidationIssue(
        code="scope_no_match",
        severity="error",
        message="No objects matched the validation scope (check --file, --uuid, --type)",
        context={
            "targets": sorted(scope.targets),
            "object_types": sorted(scope.object_types),
        },
    )


def _file_target_no_match_issue(target: str) -> ValidationIssue:
    return ValidationIssue(
        code="scope_no_match",
        severity="error",
        message=f"--file {target!r} matched no object, so it was not validated",
        context={"targets": [target], "object_types": []},
    )


def _id_duplicate_in_scope(
    scope: ValidationScope,
    row: _IdScanRow,
    original: _IdScanRow,
) -> bool:
    if scope.mode == "full":
        return True
    if not scope.targets:
        return True
    if scope.targets & {row.uuid, original.uuid}:
        return True
    return any(scope.matches_file(r.model_file.name, r.model_file) for r in (row, original))


def _check_id_uniqueness(
    paths: list[tuple[Path, str]],
    *,
    scope: ValidationScope,
    workers: int,
    already_reported: frozenset[str] = frozenset(),
) -> list[ValidationIssue]:
    from concurrent.futures import ThreadPoolExecutor

    if not paths:
        return []

    if workers > 0:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(_scan_id_file, paths))
    else:
        results = [_scan_id_file(path_row) for path_row in paths]

    scans = [row for result in results if isinstance(result, list) for row in result]
    failures = [result for result in results if isinstance(result, _IdScanParseError)]
    issues = _id_scan_parse_issues(failures, scope=scope, already_reported=already_reported)
    issues.extend(_merge_id_duplicates(scans, scope))
    return issues


def _id_scan_parse_issues(
    failures: list[_IdScanParseError],
    *,
    scope: ValidationScope,
    already_reported: frozenset[str],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for failure in failures:
        try:
            resolved = str(failure.model_file.resolve())
        except OSError:  # pragma: no cover - unresolvable path
            resolved = str(failure.model_file)
        if resolved in already_reported:
            continue
        if scope.mode == "narrow":
            if scope.object_types and failure.meta_name not in scope.object_types:
                continue
            if scope.targets and not scope.matches_file(
                failure.model_file.name, failure.model_file
            ):
                continue
        issues.append(
            ValidationIssue(
                code="yaml_parse",
                severity="error",
                object_type=failure.meta_name,
                file_path=failure.model_file,
                message=f"Could not parse object YAML: {failure.error}",
            )
        )
    return issues


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
        # The same catalogue as ``RegistryBuilder`` (direct children only, #584),
        # plus ``*.debug.yaml`` so an unparseable one is still reported (#250).
        for model_file in catalogue_files(object_path, include_debug=True):
            scan_paths.append((model_file, meta_name))
    return scan_paths


def _scan_id_file(path_row: tuple[Path, str]) -> list[_IdScanRow] | _IdScanParseError:
    import yaml

    from opentide.core.io import load_yaml

    model_file, meta_name = path_row
    try:
        model_body = load_yaml(model_file)
    # RecursionError: a pathologically nested document is unreadable too, and
    # must be reported rather than take the whole run down.
    except (yaml.YAMLError, OSError, UnicodeDecodeError, RecursionError) as exc:
        return _IdScanParseError(
            model_file=model_file,
            meta_name=meta_name,
            error=str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__,
        )
    if not isinstance(model_body, dict):
        return []
    rows: list[_IdScanRow] = []
    metadata = model_body.get("metadata")
    # A scalar `metadata` is a schema error the schema check reports; here it
    # only means there is no uuid to compare.
    uuid = metadata.get("uuid") if isinstance(metadata, dict) else None
    if uuid:
        rows.append(
            _IdScanRow(
                model_file=model_file,
                meta_name=meta_name,
                uuid=str(uuid),
                name=str(model_body.get("name", "")),
            )
        )
    if meta_name == "objective":
        rows.extend(_signal_id_rows(model_file, model_body))
    return rows


def _signal_id_rows(model_file: Path, body: dict[str, Any]) -> list[_IdScanRow]:
    """One row per ``objective.signals[*].uuid``.

    ``RegistryBuilder`` indexes each signal under its own UUID beside the
    objects, so a copied objective that kept its signals silently re-parented
    them to the copy unless the scan compares their UUIDs too.
    """
    objective = body.get("objective")
    signals = objective.get("signals") if isinstance(objective, dict) else None
    if not isinstance(signals, list):
        return []
    return [
        _IdScanRow(
            model_file=model_file,
            meta_name="signal",
            uuid=str(signal["uuid"]),
            name=str(signal.get("name", "")),
        )
        for signal in signals
        if isinstance(signal, dict) and signal.get("uuid")
    ]


def _merge_id_duplicates(scans: list[_IdScanRow], scope: ValidationScope) -> list[ValidationIssue]:
    registry: dict[str, _IdScanRow] = {}
    issues: list[ValidationIssue] = []
    for row in scans:
        if row.uuid not in registry:
            registry[row.uuid] = row
            continue
        original = registry[row.uuid]
        if not _id_duplicate_in_scope(scope, row, original):
            continue
        issues.append(
            ValidationIssue(
                code="duplicate_id",
                severity="error",
                object_uuid=row.uuid,
                object_type=row.meta_name,
                file_path=row.model_file,
                message=(
                    f"Duplicated ID {row.uuid} on {row.name!r} @ {row.model_file.name}; "
                    f"already used by {original.name!r} @ {original.model_file.name}"
                ),
                context={
                    "original": {
                        "name": original.name,
                        "file_name": original.model_file.name,
                    }
                },
            )
        )
    return issues
