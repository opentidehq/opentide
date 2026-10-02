"""``opentide share`` — select objects, validate, and call the MISP connector."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from opentide.cli.context import CliContext
from opentide.core.logging import get_logger
from opentide.core.registry import OpenTide
from opentide.sharing.config import MispBlock, SharingConfig, load_sharing
from opentide.sharing.constants import (
    INTEGRATION_MISP,
    OBJECT_FAMILIES,
    REDACTION_MARKER,
)
from opentide.sharing.document import TideDocument, load_document
from opentide.sharing.engine import ShareFilters, run_misp
from opentide.sharing.ledger import ShareLedger, ledger_path
from opentide.sharing.report import ShareRun
from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.scope import ValidationScope
from opentide.validation.session import run_validation

log = get_logger(__name__)

_PREFLIGHT = {
    "scope_no_match": "No sharing target matched the request",
    "api_key_unset": "An enabled sharing target has no API key",
    "retract_unconfirmed": "Pass --yes to delete the remote event",
    "organisation_uuid_mismatch": "The configured organisation does not match the API key",
    "sharing_config": "sharing.toml failed validation",
    "changed_outside_ci": (
        "opentide share push --changed runs only in GitHub Actions, GitLab CI, or Azure Pipelines"
    ),
    "changed_on_pull_request": "opentide share push --changed does not run on a pull request",
    "changed_diff": "Could not calculate the changed objects",
}

_OBJECT_SUFFIXES = frozenset({".yaml", ".yml"})
_NO_ENABLED_TARGET = "No enabled sharing target"
_NO_CHANGED_OBJECTS = "No changed objects to share"


def run_share(
    cli: CliContext,
    *,
    mode: str,
    targets: list[str] | None = None,
    uuids: list[str] | None = None,
    types: list[str] | None = None,
    files: list[str] | None = None,
    dry_run: bool = False,
    publish: bool | None = None,
    workers: int = 1,
    delete: bool = False,
    confirmed: bool = False,
    changed: bool = False,
) -> dict[str, Any]:
    """Run one share command and return a CLI payload, including ``_exit_code``."""
    if workers < 1:
        return _failed("workers must be at least 1", exit_code=2)
    unknown = sorted(set(types or []) - set(OBJECT_FAMILIES))
    if unknown:
        listed = ", ".join(unknown)
        return _failed(
            f"Unknown object type(s): {listed}. Choose threat, objective, or rule.",
            exit_code=2,
        )
    config = load_sharing(cli.repo)
    secrets = _secrets(config.blocks)
    if config.errors:
        message = _PREFLIGHT["sharing_config"]
        return _redact(
            _result(
                message,
                exit_code=1,
                status="failed",
                preflight="sharing_config",
                issues=[issue.message for issue in config.errors],
                warnings=tuple(
                    issue.message for issue in config.issues if issue.severity == "warning"
                ),
            ),
            secrets,
        )
    if mode == "targets":
        return _redact(_targets_payload(config), secrets)

    if changed and mode == "push":
        problem = _changed_context()
        if problem is not None:
            return _redact(_preflight(problem, config), secrets)

    effective = "preview" if dry_run and mode == "push" else mode
    selected, problem = _select_blocks(config.blocks, targets)
    if problem is not None or selected is None:
        if changed and mode == "push" and not targets and problem == "scope_no_match":
            return _redact(_quiet(_NO_ENABLED_TARGET, config), secrets)
        return _redact(_preflight(problem or "scope_no_match", config), secrets)
    documents = _catalogue()
    filters = _filters(cli.repo, uuids, types, files)
    if changed and mode == "push":
        filters, stop = _changed_files(cli.repo, filters)
        if stop == "empty":
            return _redact(_quiet(_NO_CHANGED_OBJECTS, config), secrets)
        if stop is not None:
            return _redact(_preflight("changed_diff", config, message=stop), secrets)
    validate = _validator(documents) if effective in {"push", "preview"} else None
    outcome = run_misp(
        documents,
        selected,
        mode=effective,  # type: ignore[arg-type]
        ledger=ShareLedger.load(ledger_path(cli.repo)),
        filters=filters,
        publish=publish,
        workers=workers,
        delete=delete,
        confirmed=confirmed,
        validate=validate,
    )
    log.info(
        "share.completed", mode=effective, exit_code=outcome.exit_code, records=len(outcome.records)
    )
    return _redact(_from_run(outcome, config), secrets)


def render_share(payload: dict[str, Any]) -> None:
    """Print the share table. JSON mode skips this and uses the payload."""
    from rich.table import Table

    from opentide.core.logging.config import get_stdout_console

    console = get_stdout_console()
    rows = payload.get("targets")
    if isinstance(rows, list):
        table = Table(title="Sharing targets")
        for column in ("integration", "name", "enabled", "max_tlp", "url"):
            table.add_column(column)
        for row in rows:
            if isinstance(row, dict):
                table.add_row(
                    *(
                        str(row.get(column, ""))
                        for column in ("integration", "name", "enabled", "max_tlp", "url")
                    )
                )
        console.print(table)
        return
    records = payload.get("records")
    if not isinstance(records, list) or not records:
        return
    table = Table(title="Share")
    for column in ("object_uuid", "target", "action", "remote_event_id", "reason"):
        table.add_column(column)
    for record in records:
        if not isinstance(record, dict):
            continue
        table.add_row(
            str(record.get("object_uuid", "")),
            str(record.get("target", "")),
            str(record.get("action", "")),
            "" if record.get("remote_event_id") is None else str(record.get("remote_event_id")),
            str(record.get("reason") or ""),
        )
    console.print(table)


def _catalogue() -> list[TideDocument]:
    OpenTide.initialise()
    index = OpenTide.Index
    objects = index.get("objects") or {}
    paths = index.get("file_paths") or {}
    documents: list[TideDocument] = []
    seen: set[Path] = set()
    for family in OBJECT_FAMILIES:
        family_objects = objects.get(family) or {}
        if not isinstance(family_objects, dict):
            continue
        for uuid in family_objects:
            raw = paths.get(uuid) if isinstance(paths, dict) else None
            path = Path(raw) if isinstance(raw, str) and raw else None
            if path is not None:
                seen.add(path.resolve())
            documents.append(_read(path))
    for entry in index.get("parse_errors") or []:
        if not isinstance(entry, dict):
            continue
        raw_path = entry.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            continue
        path = Path(raw_path)
        if path.resolve() in seen:
            continue
        seen.add(path.resolve())
        documents.append(_read(path))
    return documents


def _read(path: Path | None) -> TideDocument:
    if path is None or not path.is_file():
        return TideDocument("", {}, path, "missing")
    return load_document(path.read_bytes(), path=path)


def _select_blocks(
    blocks: tuple[MispBlock, ...],
    targets: list[str] | None,
) -> tuple[tuple[MispBlock, ...] | None, str | None]:
    if targets:
        by_name = {block.name: block for block in blocks}
        chosen: list[MispBlock] = []
        for name in targets:
            block = by_name.get(name)
            if block is None or not block.enabled:
                return None, "scope_no_match"
            if block not in chosen:
                chosen.append(block)
        return tuple(chosen), None
    enabled = tuple(block for block in blocks if block.enabled)
    if not enabled:
        return None, "scope_no_match"
    return enabled, None


def _changed_context() -> str | None:
    """Preflight for ``--changed`` before any git diff or HTTP call.

    Platform order matches :class:`opentide.deployment.ci.CIEnvironment`:
    Azure, then GitHub, then GitLab.
    """
    from opentide.deployment.ci import CIEnvironment

    environment = CIEnvironment().environment
    platforms = CIEnvironment.CIPlatforms
    if environment is platforms.AzurePipeline:
        if os.getenv("BUILD_REASON") == "PullRequest":
            return "changed_on_pull_request"
        return None
    if environment is platforms.GitHubActions:
        if os.getenv("GITHUB_EVENT_NAME") in {"pull_request", "pull_request_target"}:
            return "changed_on_pull_request"
        return None
    if environment is platforms.GitlabCI:
        if os.getenv("CI_PIPELINE_SOURCE") == "merge_request_event":
            return "changed_on_pull_request"
        return None
    return "changed_outside_ci"


def _changed_files(
    workspace: Path, filters: ShareFilters | None
) -> tuple[ShareFilters | None, str | None]:
    """Narrow *filters* to the production diff.

    The second value is ``None`` when *filters* is ready, ``"empty"`` when the
    diff selects nothing, or the diff error text.
    """
    from opentide.deployment.git_repo import diff_calculation
    from opentide.models.deployment_enums import DeploymentStrategy

    try:
        changed = diff_calculation(DeploymentStrategy.PRODUCTION)
    except Exception as exc:
        text = str(exc).strip()
        return None, text or _PREFLIGHT["changed_diff"]
    paths = _direct_object_files(workspace, changed)
    paths = _intersect_changed(workspace, paths, filters)
    if not paths:
        return None, "empty"
    return (
        ShareFilters(
            uuids=None if filters is None else filters.uuids,
            types=None if filters is None else filters.types,
            files=frozenset(paths),
        ),
        None,
    )


def _object_directories(workspace: Path) -> dict[str, Path]:
    from opentide.registry.paths import resolve_workspace_paths

    resolved = resolve_workspace_paths(workspace=workspace)
    found: dict[str, Path] = {}
    for key in ("threat", "objective", "rule"):
        path = resolved.get(key)
        if isinstance(path, Path):
            found[key] = path.resolve()
    return found


def _direct_object_files(workspace: Path, changed: object) -> list[Path]:
    """YAML documents that are direct children of a configured object directory."""
    if not isinstance(changed, list):
        return []
    allowed = set(_object_directories(workspace).values())
    selected: list[Path] = []
    seen: set[Path] = set()
    for raw in changed:
        if not isinstance(raw, (str, Path)):
            continue
        text = os.fspath(raw)
        if not text:
            continue
        path = Path(text)
        if not path.is_absolute():
            path = workspace / path
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved.suffix.lower() not in _OBJECT_SUFFIXES:
            continue
        if resolved.parent not in allowed:
            continue
        if not resolved.is_file():
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        selected.append(resolved)
    return selected


def _intersect_changed(
    workspace: Path, paths: list[Path], filters: ShareFilters | None
) -> list[Path]:
    if filters is None:
        return paths
    chosen = paths
    if filters.files is not None:
        chosen = [path for path in chosen if path in filters.files]
    if filters.types is not None:
        directories = _object_directories(workspace)
        allowed = {directories[name] for name in filters.types if name in directories}
        chosen = [path for path in chosen if path.parent in allowed]
    if filters.uuids is not None:
        wanted = filters.uuids
        matched: list[Path] = []
        for path in chosen:
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            if load_document(raw, path=path).uuid in wanted:
                matched.append(path)
        chosen = matched
    return chosen


def _filters(
    workspace: Path,
    uuids: list[str] | None,
    types: list[str] | None,
    files: list[str] | None,
) -> ShareFilters | None:
    if not uuids and not types and not files:
        return None
    resolved: frozenset[Path] | None = None
    if files:
        paths: set[Path] = set()
        for item in files:
            path = Path(item)
            if not path.is_absolute():
                path = workspace / path
            paths.add(path.resolve())
        resolved = frozenset(paths)
    return ShareFilters(
        uuids=frozenset(uuids) if uuids else None,
        types=frozenset(types) if types else None,
        files=resolved,
    )


def _validator(documents: list[TideDocument]):
    uuids = frozenset(document.uuid for document in documents if document.uuid)
    if not uuids:
        return None
    previous = (
        os.environ.get("VALIDATION_ERROR_RAISED"),
        os.environ.get("VALIDATION_WARNING_RAISED"),
    )
    try:
        report = run_validation(
            scope=ValidationScope.narrow(uuids=uuids),
            checks=frozenset({ValidateCheck.schema, ValidateCheck.uuid_format}),
        )
    finally:
        _restore_validation_env(previous)
    by_uuid = report.legacy_errors_by_uuid()

    def validate(document: TideDocument) -> str | None:
        messages = list(by_uuid.get(document.uuid or "", []))
        if document.path is not None:
            wanted = document.path.resolve()
            for issue in report.errors:
                if issue.file_path is not None and issue.file_path.resolve() == wanted:
                    text = issue.to_legacy_string()
                    if text not in messages:
                        messages.append(text)
        if not messages:
            for issue in report.errors:
                if issue.code == "scope_no_match":
                    messages.append(issue.to_legacy_string())
                    break
        if not messages:
            return None
        return "; ".join(messages)

    return validate


def _restore_validation_env(previous: tuple[str | None, str | None]) -> None:
    for name, value in zip(
        ("VALIDATION_ERROR_RAISED", "VALIDATION_WARNING_RAISED"),
        previous,
        strict=True,
    ):
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _from_run(outcome: ShareRun, config: SharingConfig) -> dict[str, Any]:
    if outcome.preflight:
        return _preflight(outcome.preflight, config, outcome)
    records = [record.as_dict() for record in outcome.records]
    code = outcome.exit_code
    failed = code != 0
    created = sum(1 for record in outcome.records if record.action == "created")
    updated = sum(1 for record in outcome.records if record.action == "updated")
    message = f"Share finished: {len(records)} record(s), {created} created, {updated} updated"
    return _result(
        message,
        exit_code=code,
        status="failed" if failed else "completed",
        records=records,
        warnings=tuple(issue.message for issue in config.issues if issue.severity == "warning"),
    )


def _preflight(
    code: str,
    config: SharingConfig,
    outcome: ShareRun | None = None,
    *,
    message: str | None = None,
) -> dict[str, Any]:
    records = [] if outcome is None else [record.as_dict() for record in outcome.records]
    return _result(
        message or _PREFLIGHT.get(code, code),
        exit_code=1,
        status="failed",
        preflight=code,
        records=records,
        warnings=tuple(issue.message for issue in config.issues if issue.severity == "warning"),
    )


def _quiet(message: str, config: SharingConfig) -> dict[str, Any]:
    return _result(
        message,
        exit_code=0,
        status="completed",
        records=[],
        warnings=tuple(issue.message for issue in config.issues if issue.severity == "warning"),
    )


def _targets_payload(config: SharingConfig) -> dict[str, Any]:
    rows = [
        {
            "integration": INTEGRATION_MISP,
            "name": block.name,
            "enabled": block.enabled,
            "max_tlp": block.max_tlp,
            "url": block.url,
        }
        for block in config.blocks
    ]
    return _result(
        f"{len(rows)} sharing target(s)",
        exit_code=0,
        status="completed",
        targets=rows,
        warnings=tuple(issue.message for issue in config.issues if issue.severity == "warning"),
    )


def _result(
    message: str,
    *,
    exit_code: int,
    status: str,
    **data: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"message": message, "status": status, "_exit_code": exit_code}
    warnings = data.pop("warnings", ())
    if warnings:
        payload["warnings"] = list(warnings)
    payload.update(data)
    return payload


def _failed(message: str, *, exit_code: int) -> dict[str, Any]:
    return _result(message, exit_code=exit_code, status="failed", error=message)


def _secrets(blocks: tuple[MispBlock, ...]) -> tuple[str, ...]:
    return tuple(block.api_key for block in blocks if block.api_key)


def _redact(payload: dict[str, Any], secrets: tuple[str, ...]) -> dict[str, Any]:
    if not secrets:
        return payload
    return _redact_value(payload, secrets)


def _redact_value(value: Any, secrets: tuple[str, ...]) -> Any:
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, REDACTION_MARKER)
        return value
    if isinstance(value, list):
        return [_redact_value(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: _redact_value(item, secrets) for key, item in value.items()}
    return value
