"""``opentide share`` — select objects, validate, and call the MISP connector."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from opentide.cli.context import CliContext
from opentide.cli.ui.contract import USAGE_INVALID_CHOICE, USAGE_INVALID_VALUE, did_you_mean
from opentide.core.logging import get_logger
from opentide.core.registry import Opentide
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

#: ``failure.code`` for a run that reached the destination, by exit code.
_RUN_FAILURE_CODES = {1: "share_failed", 2: "share_unreachable", 3: "share_partial"}

_OBJECT_SUFFIXES = frozenset({".yaml", ".yml"})
#: The ``share`` subcommands; ``targets`` lists destinations and calls no engine.
ShareMode = Literal["push", "preview", "status", "retract", "targets"]

_NO_ENABLED_TARGET = "No enabled sharing target"
#: When sharing.toml holds no target at all: what to add, and where.
_NO_TARGET = "No sharing target is configured"
_ADD_TARGET = (
    "add a [[misp]] block to .opentide/configurations/sharing.toml (see docs/cli/share.md)"
)
_NO_CHANGED_OBJECTS = "No changed objects to share"


def run_share(
    cli: CliContext,
    *,
    mode: ShareMode,
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
        return _failed(
            "workers must be at least 1",
            exit_code=2,
            code=USAGE_INVALID_VALUE,
            argument="--workers",
        )
    unknown = sorted(set(types or []) - set(OBJECT_FAMILIES))
    if unknown:
        listed = ", ".join(unknown)
        return _failed(
            f"Unknown object type(s): {listed}. Choose threat, objective, or rule.",
            exit_code=2,
            code=USAGE_INVALID_CHOICE,
            argument="--type",
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
    names = [block.name for block in config.blocks]
    missing = [name for name in targets or () if name not in names]
    if missing:
        listed = ", ".join(names) or "none configured"
        payload = _failed(
            f"Unknown sharing target {missing[0]!r}. Configured targets: {listed}.",
            exit_code=2,
            code=USAGE_INVALID_CHOICE,
            argument="--target",
        )
        # A usage error, but still the scope_no_match preflight scripts read.
        payload["preflight"] = "scope_no_match"
        payload["records"] = []
        warnings = [issue.message for issue in config.issues if issue.severity == "warning"]
        if warnings:
            payload["warnings"] = warnings
        payload["_failure_suggestion"] = did_you_mean(missing[0], names)
        return _redact(payload, secrets)
    selected, problem = _select_blocks(config.blocks, targets)
    if problem is not None or selected is None:
        if changed and mode == "push" and not targets and problem == "scope_no_match":
            return _redact(_quiet(_NO_ENABLED_TARGET, config), secrets)
        if not config.blocks:
            # "No sharing target matched the request" said nothing about the
            # file to write when there is none (post-merge end-to-end run).
            payload = _preflight("scope_no_match", config, message=_NO_TARGET)
            payload["advice"] = _ADD_TARGET
            return _redact(payload, secrets)
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
        mode=effective,
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
    return _redact(_from_run(outcome, config, mode=effective), secrets)


#: Record action → (glyph name, label in a preview, label after a push, style).
_SHARE_ROWS: dict[str, tuple[str, str, str, str]] = {
    "created": ("create", "create", "created", "bold green"),
    "updated": ("update", "update", "updated", "bold yellow"),
    "unchanged": ("skip", "unchanged", "unchanged", "dim"),
    "retracted": ("delete", "retract", "retracted", "bold red"),
    "skipped_tlp": ("skip", "skip", "skipped", "dim"),
    "skipped_status": ("skip", "skip", "skipped", "dim"),
    "skipped_type": ("skip", "skip", "skipped", "dim"),
    "failed": ("failed", "fail", "failed", "bold red"),
}

#: Why an object was skipped, in words (the record keeps the code).
#: Short, so a row fits 100 columns beside a long name (a sentence wrapped mid-word).
_SKIP_REASONS = {
    "max_tlp": "TLP above max_tlp",
    "object_type": "type not shared",
    "rule_status": "status not shared",
}


def _object_names() -> dict[str, str]:
    """Object names by UUID, from the registry the run has already loaded."""
    try:
        objects = Opentide.Index.get("objects") or {}
    except Exception:
        return {}
    names: dict[str, str] = {}
    for family in objects.values():
        if not isinstance(family, dict):
            continue
        for uuid, body in family.items():
            name = body.get("name") if isinstance(body, dict) else None
            if isinstance(name, str) and name:
                names[str(uuid)] = name
    return names


def render_share(payload: dict[str, Any]) -> None:
    """Print the targets, or what a share did or would do, as plan rows. JSON skips this.

    The table this replaces dumped the records: snake_case actions
    (``skipped_status``), raw keys as headers, an empty ``remote_event_id``
    column, full UUIDs, and ``created`` for a preview that sent nothing.
    """
    from rich.text import Text

    from opentide.cli.ui.glyphs import glyph
    from opentide.cli.ui.layout import columns
    from opentide.cli.ui.plan import short_uuid
    from opentide.core.logging.config import get_stdout_console

    console = get_stdout_console()
    encoding = console.encoding or "utf-8"
    separator = f" {glyph('separator', encoding=encoding)} "
    rows = payload.get("targets")
    if isinstance(rows, list):
        listed = [
            (
                Text(str(row.get("name", "")), style="bold"),
                Text(str(row.get("integration", "")), style="dim"),
                Text("enabled" if row.get("enabled") else "disabled", style="dim"),
                Text(f"max TLP {row.get('max_tlp')}" if row.get("max_tlp") else "", style="dim"),
                Text(str(row.get("url") or ""), style="dim"),
            )
            for row in rows
            if isinstance(row, dict)
        ]
        if listed:
            console.print(columns(listed), soft_wrap=True)
        return
    records = payload.get("records")
    if not isinstance(records, list) or not records:
        return
    preview = payload.get("_outcome_kind") == "plan"
    names = _object_names()
    targets: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if isinstance(record, dict):
            targets.setdefault(str(record.get("target", "")), []).append(record)
    for target, members in targets.items():
        title = Text(target, style="bold")
        if preview:
            title.append(separator + "dry run, nothing is sent", style="dim")
        console.print(title, soft_wrap=True)
        lines = []
        for record in members:
            action = str(record.get("action", ""))
            mark, planned, done, style = _SHARE_ROWS.get(action, ("skip", action, action, "dim"))
            uuid = str(record.get("object_uuid", ""))
            reason = record.get("reason")
            why = _SKIP_REASONS.get(str(reason), str(reason).replace("_", " ")) if reason else ""
            lines.append(
                (
                    Text(
                        f"{glyph(mark, encoding=encoding)} {planned if preview else done}",
                        style=style,
                    ),
                    Text(names.get(uuid, uuid), style="bold"),
                    Text(short_uuid(uuid, encoding), style="dim"),
                    Text(why, style="dim"),
                )
            )
        console.print(columns(lines, indent=2), soft_wrap=True)
        console.print()


def _catalogue() -> list[TideDocument]:
    Opentide.initialise()
    index = Opentide.Index
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
    """Preflight for ``--changed`` before any git diff or HTTP call."""
    from opentide.deployment.ci import CIEnvironment, is_change_request

    environment = CIEnvironment().environment
    if environment is CIEnvironment.CIPlatforms.LocalDebug:
        return "changed_outside_ci"
    if is_change_request(environment):
        return "changed_on_pull_request"
    return None


def _changed_files(
    workspace: Path, filters: ShareFilters | None
) -> tuple[ShareFilters | None, str | None]:
    """Narrow *filters* to the production diff.

    The second value is ``None`` when *filters* is ready, ``"empty"`` when the
    diff selects nothing, or the diff error text.
    """
    from opentide.deployment.git_repo import DiffSource, diff_calculation

    try:
        changed = diff_calculation(DiffSource.PUSH)
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


def _validator(documents: list[TideDocument]) -> Callable[[TideDocument], str | None] | None:
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


#: Record action → the word the outcome line counts it under.
_ACTION_WORDS = {
    "created": "new",
    "updated": "updated",
    "unchanged": "unchanged",
    "retracted": "retracted",
    "skipped_tlp": "skipped",
    "skipped_status": "skipped",
    "skipped_type": "skipped",
    "failed": "failed",
}


#: Actions that send something to the destination.
_SENT_ACTIONS = frozenset({"created", "updated", "retracted"})


def share_outcome(mode: str, outcome: ShareRun) -> tuple[str, dict[str, int]]:
    """``Shared 4 objects to misp-prod · 3 new, 1 updated``, and the counts behind it."""
    from collections import Counter

    from opentide.cli.ui.progress import plural

    records = outcome.records
    targets = ", ".join(sorted({record.target for record in records})) or "no target"
    counts = Counter(_ACTION_WORDS.get(record.action, record.action) for record in records)
    # "unchanged" succeeds but sends nothing, so it is not a shared object.
    done = len({record.object_uuid for record in records if record.action in _SENT_ACTIONS})
    objects = plural(done, "object")
    lead = {
        "push": f"Shared {objects} to {targets}",
        "preview": f"Would share {objects} to {targets}",
        "retract": f"Retracted {objects} from {targets}",
    }.get(mode, f"{plural(len({r.object_uuid for r in records}), 'object')} on {targets}")
    if not done and records and mode in ("push", "preview", "retract"):
        lead = "Nothing to retract" if mode == "retract" else "Nothing to share"
    order = ("new", "updated", "unchanged", "retracted", "skipped", "failed")
    facts = ", ".join(f"{counts[word]} {word}" for word in order if counts.get(word))
    summary = {"objects": done, **{word: counts.get(word, 0) for word in order}}
    return (f"{lead} · {facts}" if facts else lead), summary


def _from_run(outcome: ShareRun, config: SharingConfig, *, mode: str = "push") -> dict[str, Any]:
    if outcome.preflight:
        return _preflight(outcome.preflight, config, outcome)
    records = [record.as_dict() for record in outcome.records]
    code = outcome.exit_code
    failed = code != 0
    message, summary = share_outcome(mode, outcome)
    payload = _result(
        message,
        exit_code=code,
        status="failed" if failed else "completed",
        records=records,
        warnings=tuple(issue.message for issue in config.issues if issue.severity == "warning"),
    )
    payload["_summary"] = summary
    if failed:
        payload["_failure_code"] = _RUN_FAILURE_CODES.get(code, "share_failed")
    elif mode == "preview":
        # "Would share …": nothing was sent, so the line takes no ✓.
        payload["_outcome_kind"] = "plan"
    return payload


def _preflight(
    code: str,
    config: SharingConfig,
    outcome: ShareRun | None = None,
    *,
    message: str | None = None,
) -> dict[str, Any]:
    records = [] if outcome is None else [record.as_dict() for record in outcome.records]
    payload = _result(
        message or _PREFLIGHT.get(code, code),
        exit_code=1,
        status="failed",
        preflight=code,
        records=records,
        warnings=tuple(issue.message for issue in config.issues if issue.severity == "warning"),
    )
    payload["_failure_code"] = code
    return payload


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
    payload = _result(
        f"{len(rows)} sharing target{'' if len(rows) == 1 else 's'}",
        exit_code=0,
        status="completed",
        targets=rows,
        warnings=tuple(issue.message for issue in config.issues if issue.severity == "warning"),
    )
    if not rows:
        # Not "✓ 0 sharing targets" under an empty table: nothing is set up yet.
        payload["status"] = "skipped"
        payload["_outcome"] = _NO_TARGET
        payload["advice"] = _ADD_TARGET
    return payload


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


def _failed(message: str, *, exit_code: int, code: str, argument: str) -> dict[str, Any]:
    payload = _result(message, exit_code=exit_code, status="failed", error=message)
    payload["_failure_code"] = code
    payload["_failure_argument"] = argument
    return payload


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
