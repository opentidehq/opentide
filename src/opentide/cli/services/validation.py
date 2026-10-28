"""Validation services for the CLI."""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping, Sequence
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import structlog

from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS, QueriesMode, ValidateCheck
from opentide.cli.ui.contract import (
    ISSUES_FOUND,
    NO_WORKSPACE_STEP,
    USAGE_ERROR,
    USAGE_INVALID_CHOICE,
    USAGE_INVALID_VALUE,
    USAGE_MISSING_OPTION,
    NextAction,
)
from opentide.cli.ui.diagnostics import (
    REPORTED_AS_WARNING_NOTE,
    Diagnostic,
    annotate_report,
    explain_command,
    relative_path,
)
from opentide.cli.ui.fixes import FixPlan, plan_fixes
from opentide.cli.ui.glyphs import glyph
from opentide.registry.builder import parse_errors_reported_by_caller
from opentide.registry.discovery import discover_workspace
from opentide.validation.configuration import CONFIGURATION_OBJECT_TYPE
from opentide.validation.issues import ValidationIssue, ValidationReport
from opentide.validation.scope import ValidationScope
from opentide.validation.session import run_validation

logger = structlog.get_logger("opentide.cli.services.validation")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext
    from opentide.deployment.git_repo import RuleScope
    from opentide.models.deployment_enums import RunStrategies
    from opentide.platforms.transport import TenantUnreachableError


def _reset_validation_env() -> None:
    os.environ["VALIDATION_ERROR_RAISED"] = ""
    os.environ["VALIDATION_WARNING_RAISED"] = ""


def _build_scope(
    *,
    files: list[str] | None = None,
    uuids: list[str] | None = None,
    object_types: list[str] | None = None,
) -> ValidationScope:
    if not files and not uuids and not object_types:
        return ValidationScope.full()
    return ValidationScope.narrow(
        files=frozenset(files or []),
        uuids=frozenset(uuids or []),
        types=frozenset(object_types or []),
    )


def _checks_for(
    check: ValidateCheck | None, *, queries: QueriesMode = QueriesMode.error
) -> frozenset[ValidateCheck]:
    """The checks a run performs: one named check, or the defaults (``queries`` unless off)."""
    if check is None:
        return frozenset(ValidateCheck(name) for name in default_check_names(queries))
    return frozenset({check})


def run_id_uniqueness(scope: ValidationScope | None = None) -> ValidationReport:
    from opentide.cli.enums import ValidateCheck as VC

    return run_validation(
        scope=scope or ValidationScope.full(), checks=frozenset({VC.id_uniqueness})
    )


def run_uuid_format(scope: ValidationScope | None = None) -> ValidationReport:
    from opentide.cli.enums import ValidateCheck as VC

    return run_validation(scope=scope or ValidationScope.full(), checks=frozenset({VC.uuid_format}))


def run_schema_validation(scope: ValidationScope | None = None) -> ValidationReport:
    from opentide.cli.enums import ValidateCheck as VC

    return run_validation(scope=scope or ValidationScope.full(), checks=frozenset({VC.schema}))


def run_cve_validation() -> None:
    from opentide.validation import cve

    cve.run()


# Issue codes produced by each named check. JSON status is per-check, not overall ok.
_CHECK_ISSUE_CODES: dict[str, frozenset[str]] = {
    ValidateCheck.id_uniqueness.value: frozenset({"duplicate_id"}),
    ValidateCheck.uuid_format.value: frozenset({"invalid_uuid"}),
    ValidateCheck.schema.value: frozenset(
        {
            "schema_validation",
            "schema_missing",
            "yaml_parse",
            "missing_uuid",
            "invalid_ref",
            "vocab_unknown",
            "config_enum_unknown",
            "chaining_relation_unknown",
            "external_id_in_rule",
            "external_id_shape",
            "deployment_state_uuid_mismatch",
            "deployment_state_platform",
            "deployment_state_shape",
        }
    ),
    ValidateCheck.cve.value: frozenset({"invalid_cve"}),
    # The engine's own codes (kql_parse_error, ...) come from the engine, not
    # from this table: `_issues_for_check` selects them by source, and
    # `opentide explain` pages them from the engine's descriptions.
    ValidateCheck.queries.value: frozenset({"engine_unavailable", "yaml_parse", "scope_no_match"}),
    ValidateCheck.sharing_config.value: frozenset(
        {
            "missing_field",
            "duplicate_name",
            "name_invalid",
            "unknown_key",
            "max_tlp_unknown",
            "organisation_uuid_invalid",
            "object_type_unknown",
            "sharing_directory",
            "config_parse",
            "url_invalid",
            "invalid_value",
            "rule_status_unknown",
        }
    ),
    # Shares codes with sharing-config; `_issues_for_check` tells them apart by
    # object type. The responder variants of these codes are warnings.
    ValidateCheck.configuration.value: frozenset(
        {
            "missing_field",
            "unknown_key",
            "schema_validation",
            "promotion_target_unknown",
            "config_parse",
            # Reported by the per-file helper an editor calls, not by `validate`.
            "identifier_mismatch",
        }
    ),
}

#: Warning codes each check can report. They never fail the check's status.
_CHECK_WARNING_CODES: dict[str, frozenset[str]] = {
    ValidateCheck.schema.value: frozenset({"deprecated_field", "platform_not_enabled"}),
    ValidateCheck.sharing_config.value: frozenset({"api_key_literal", "unknown_connector"}),
    ValidateCheck.configuration.value: frozenset({"asset_unknown", "not_a_configuration_file"}),
    ValidateCheck.cve.value: frozenset({"cve_lookup_unavailable"}),
}

#: Every code a ``validate`` finding can carry. ``tests/test_cli/test_explain.py``
#: requires an ``opentide explain`` page for each, and fails on a code emitted
#: in the source but missing here.
VALIDATION_CODES: frozenset[str] = frozenset(
    # ``nested_object_file`` (#584) belongs to no check: every run reports it.
    {"scope_no_match", "nested_object_file"}.union(
        *_CHECK_ISSUE_CODES.values(), *_CHECK_WARNING_CODES.values()
    )
)

_OBJECT_CHECKS = frozenset({ValidateCheck.uuid_format.value, ValidateCheck.schema.value})


def _issues_for_check(issues: list[ValidationIssue], check_name: str) -> list[ValidationIssue]:
    # Configuration findings share codes (`unknown_key`, `missing_field`) with
    # sharing-config; the object type tells them apart.
    if check_name == ValidateCheck.configuration.value:
        return [issue for issue in issues if issue.object_type == CONFIGURATION_OBJECT_TYPE]
    if check_name == ValidateCheck.queries.value:
        from opentide.validation.queries import ENGINE_SOURCE

        # Its own findings, and the files and targets it could not read.
        shared = _CHECK_ISSUE_CODES[check_name]
        return [
            issue
            for issue in issues
            if issue.context.get("source") == ENGINE_SOURCE or issue.code in shared
        ]
    codes = _CHECK_ISSUE_CODES.get(check_name, frozenset())
    matched = [
        issue
        for issue in issues
        if issue.code in codes and issue.object_type != CONFIGURATION_OBJECT_TYPE
    ]
    if check_name in _OBJECT_CHECKS and any(issue.code == "scope_no_match" for issue in issues):
        matched.extend(issue for issue in issues if issue.code == "scope_no_match")
    return matched


def _status_for_check(report: ValidationReport, check_name: str) -> str:
    """Status for one named check based on that check's issues, not overall ok."""
    return "failed" if _issues_for_check(report.issues, check_name) else "passed"


def _dump_check_issues(issues: list[ValidationIssue]) -> list[dict[str, object]]:
    payload = ValidationReport(ok=not issues, issues=issues).model_dump_json_ready()
    return list(payload.get("issues", []))


#: The checks a bare ``validate`` runs, and the key order of ``checks``.
DEFAULT_CHECK_NAMES: tuple[str, ...] = (
    ValidateCheck.id_uniqueness.value,
    ValidateCheck.uuid_format.value,
    ValidateCheck.schema.value,
    ValidateCheck.configuration.value,
    ValidateCheck.queries.value,
)


def default_check_names(queries: QueriesMode = QueriesMode.error) -> tuple[str, ...]:
    """The default checks, without ``queries`` under ``--queries off``."""
    if queries is QueriesMode.off:
        return tuple(name for name in DEFAULT_CHECK_NAMES if name != ValidateCheck.queries.value)
    return DEFAULT_CHECK_NAMES


def _validate_payload(report: ValidationReport, check_names: Sequence[str]) -> dict[str, object]:
    """Build the one JSON shape every ``validate`` invocation emits.

    ``checks`` always maps a check name to that check's verdict, and the full
    report always lives under ``report``. Selecting a single check narrows
    ``checks`` to one entry; it must not move the report or otherwise change the
    document's shape, because a consumer has to parse both the same way.
    """
    return {
        "checks": {
            name: {"check": name, "status": _status_for_check(report, name)} for name in check_names
        },
        "report": report.model_dump_json_ready(),
    }


def run_validate_check(
    check: ValidateCheck,
    *,
    scope: ValidationScope | None = None,
) -> dict[str, object]:
    """Run a single validation check."""
    report = run_validation(scope=scope or ValidationScope.full(), checks=frozenset({check}))
    if not report.ok:
        os.environ["VALIDATION_ERROR_RAISED"] = "1"
    payload = _validate_payload(report, (check.value,))
    payload["check"] = check.value
    payload["status"] = "passed" if report.ok else "failed"
    return payload


def run_validate_all(*, scope: ValidationScope | None = None) -> dict[str, object]:
    """Run all default validation checks."""
    _reset_validation_env()
    report = run_validation(scope=scope or ValidationScope.full())
    results: dict[str, object] = {}
    for name in DEFAULT_CHECK_NAMES:
        check_issues = _issues_for_check(report.issues, name)
        results[name] = {
            "check": name,
            "status": _status_for_check(report, name),
            "issues": _dump_check_issues(check_issues),
        }
    return results


def run_validate(
    ctx: CliContext,
    *,
    check: ValidateCheck | None = None,
    strict: bool = False,
    file: str | None = None,
    files: list[str] | None = None,
    uuids: list[str] | None = None,
    object_types: list[str] | None = None,
    queries: QueriesMode = QueriesMode.error,
) -> dict[str, object]:
    """Entry point for validate command.

    *queries* is ``--queries``: how the queries check reports a query the
    engine rejects (an error, a warning), or ``off`` to leave it out.

    Besides the JSON document, the result carries ``_diagnostics`` (one
    :class:`Diagnostic` per issue and warning, for the code frames) and
    ``_summary``; the command pops both before rendering.
    """
    file_list = list(files or [])
    if file:
        file_list.append(file)
    scope = _build_scope(files=file_list or None, uuids=uuids, object_types=object_types)
    checks = _checks_for(check, queries=queries)
    # The schema check turns each unreadable object file into a yaml_parse or
    # missing_uuid diagnostic, so the registry need not also log it. Any other
    # check would not report the file at all: then the log line stays.
    reported = (
        parse_errors_reported_by_caller() if ValidateCheck.schema in checks else nullcontext()
    )
    with reported:
        ctx.apply_environment()
        _reset_validation_env()
        report = run_validation(
            scope=scope, checks=checks, queries_as_warnings=queries is QueriesMode.warn
        )
    if not report.ok:
        os.environ["VALIDATION_ERROR_RAISED"] = "1"

    # Both branches build the SAME document. A single check only narrows
    # `checks`; it used to relocate the report to `issues` (so consumers read
    # `issues.issues`) and bolt on a legacy `errors` map, which meant one
    # command emitted two incompatible shapes.
    if check is not None:
        names: tuple[str, ...] = (check.value,)
    else:
        names = default_check_names(queries)
    result: dict[str, object] = _validate_payload(report, names)
    if check is not None:
        result["check"] = check.value
    workspace = discover_workspace()
    result["workspace"] = str(workspace)
    diagnostics = _annotate_report(result, report, workspace)

    from opentide.cli.exit_codes import validation_outcome

    outcome = validation_outcome(strict=strict)
    result["status"] = "failed" if outcome.failed else "passed"
    if outcome.failed:
        result["message"] = "Validation failed"
    elif check is None and scope.mode == "full" and report.stats.get("objects_checked") == 0:
        # Not a failure: an empty catalogue exits 0, even under --strict. The
        # path is what exposes a run that looked in the wrong directory.
        result["message"] = (
            "Validation passed, but no detection objects were found under "
            + _shown_directory(workspace)
        )
        from opentide.core.root import is_workspace_root

        if not is_workspace_root(workspace):
            # Outside any workspace the pass says nothing about a catalogue
            # (post-merge end-to-end run): point at the command that makes one.
            result["_next_actions"] = [NO_WORKSPACE_STEP]
    else:
        result["message"] = "Validation passed"
    warnings = ["Validation reported warnings"] if outcome.warned else []
    warnings.extend(_exempt_warning_lines(report))
    if warnings:
        result["warnings"] = warnings
    result["_exit_code"] = outcome.exit_code
    if outcome.failed:
        result["_failure_code"] = ISSUES_FOUND
        result["_next_actions"] = _failure_next_actions(ctx, diagnostics, queries=queries)
    plan = plan_fixes(diagnostics)
    result["_summary"] = {**_summary(report, diagnostics), "fixable": len(plan.changes)}
    result["_diagnostics"] = diagnostics
    result["_fix_plan"] = plan
    if plan:
        # Applying the safe fixes comes first; a failed run's explain and
        # validate-again steps follow it.
        result["_next_actions"] = [
            NextAction(
                fix_command(
                    check=check,
                    files=file_list,
                    uuids=uuids,
                    object_types=object_types,
                    queries=queries,
                ),
                _apply_reason(len(plan.changes)),
            ),
            *cast(list[NextAction], result.get("_next_actions", [])),
        ]
    return result


def run_validate_fix(
    ctx: CliContext,
    *,
    dry_run: bool = False,
    check: ValidateCheck | None = None,
    strict: bool = False,
    files: list[str] | None = None,
    uuids: list[str] | None = None,
    object_types: list[str] | None = None,
    queries: QueriesMode = QueriesMode.error,
) -> dict[str, object]:
    """``validate --fix``: apply every safe fix, then validate again.

    The result is the second run's, plus ``fixed`` (one entry per value
    replaced) and ``summary.fixed``. With *dry_run* nothing is written: the
    result is the first run's, plus ``would_fix`` and ``diff``.
    """
    scope: dict[str, Any] = {
        "check": check,
        "strict": strict,
        "files": files,
        "uuids": uuids,
        "object_types": object_types,
        "queries": queries,
    }
    result = run_validate(ctx, **scope)
    plan = cast(FixPlan, result["_fix_plan"])
    if dry_run:
        result["would_fix"] = [change.to_dict() for change in plan.changes]
        result["diff"] = plan.diff()
        if plan:
            # The same command without --dry-run applies them.
            result["_next_actions"] = [
                NextAction(
                    fix_command(
                        check=check,
                        files=files,
                        uuids=uuids,
                        object_types=object_types,
                        queries=queries,
                    ),
                    _apply_reason(len(plan.changes)),
                )
            ]
        return result
    unwritten: list[str] = []
    planned = len(plan.changes)
    if plan:
        plan, unwritten = plan.write()
        # run_validate rebuilds the registry, so it reads the files just written.
        result = run_validate(ctx, **scope)
        # A fix this run could not apply would not apply on the next one either.
        remaining = [
            action
            for action in cast(list[Any], result.pop("_next_actions", []))
            if not _is_fix_action(action)
        ]
        if remaining:
            result["_next_actions"] = remaining
    if unwritten:
        warnings = cast(list[str], result.setdefault("warnings", []))
        warnings.extend(f"Could not write the fix to {line}" for line in unwritten)
        result["_unwritten"] = unwritten
        result["_unwritten_fixes"] = planned - len(plan.changes)
    summary = cast(dict[str, int], result["_summary"])
    summary["fixed"] = len(plan.changes)
    result["fixed"] = [change.to_dict() for change in plan.changes]
    result["_fixed"] = plan
    return result


def _is_fix_action(action: NextAction | dict[str, object]) -> bool:
    command = action.command if isinstance(action, NextAction) else action.get("command")
    return str(command).startswith("opentide validate --fix")


def _apply_reason(count: int) -> str:
    return f"apply {count} safe fix" if count == 1 else f"apply {count} safe fixes"


def fix_command(
    *,
    check: ValidateCheck | None = None,
    files: Sequence[str] | None = None,
    uuids: Sequence[str] | None = None,
    object_types: Sequence[str] | None = None,
    queries: QueriesMode = QueriesMode.error,
) -> str:
    """``opentide validate --fix`` with the scope of the run that found the fixes."""
    words = ["opentide", "validate", "--fix"]
    if check is not None:
        words += ["--check", check.value]
    words += queries_flag(queries)
    for flag, values in (("--file", files), ("--uuid", uuids), ("--type", object_types)):
        for value in values or ():
            words += [flag, value]
    return shlex.join(words)


def _shown_directory(path: Path) -> str:
    """*path* as ``./sub`` (or ``./``) inside the current directory, ``../..`` above it.

    Anywhere else it stays absolute.
    """
    cwd = Path.cwd()
    shown = relative_path(path, cwd)
    if not Path(shown).is_absolute():
        return "./" if shown == "." else f"./{shown}"
    if relative_path(cwd, path) != cwd.as_posix():
        return os.path.relpath(path, cwd) + "/"
    return shown


def queries_flag(queries: QueriesMode) -> list[str]:
    """``--queries MODE`` when *queries* is not the default, so a rerun keeps it."""
    return [] if queries is QueriesMode.error else ["--queries", queries.value]


def _failure_next_actions(
    ctx: CliContext,
    diagnostics: Sequence[Diagnostic],
    *,
    queries: QueriesMode = QueriesMode.error,
) -> list[NextAction]:
    """What to run after a failed validation: the first finding's page, then validate again.

    The same two steps MCP's ``validation_report`` gives. Errors come before
    warnings, so a run that fails on errors points at an error.
    """
    ordered = sorted(diagnostics, key=lambda item: item.severity != "error")
    actions: list[NextAction] = []
    if ordered:
        code = ordered[0].code
        actions.append(NextAction(explain_command(code), "how to fix it"))
    rerun = ["opentide", "--json", "validate"] if ctx.json_output else ["opentide", "validate"]
    actions.append(NextAction(shlex.join(rerun + queries_flag(queries)), "check again"))
    return actions


def _annotate_report(
    result: dict[str, object], report: ValidationReport, workspace: Path
) -> list[Diagnostic]:
    """Add the diagnostic fields to each JSON issue and warning; return the diagnostics."""
    return annotate_report(cast(dict[str, Any], result["report"]), report, workspace=workspace)


def _summary(report: ValidationReport, diagnostics: Sequence[Diagnostic]) -> dict[str, int]:
    """Counts behind the outcome line.

    ``files`` counts the files with an error; ``warning_files`` those with a
    warning (a file can be in both). ``queries`` is there when the queries
    check ran.
    """

    def files_with(severity: str) -> int:
        return len(
            {
                item.path
                for item in diagnostics
                if item.path is not None and item.severity == severity
            }
        )

    summary = {
        "objects": int(report.stats.get("objects_checked") or 0),
        "errors": len(report.errors),
        "warnings": len(report.warnings),
        "files": files_with("error"),
        "warning_files": files_with("warning"),
    }
    if "queries_checked" in report.stats:
        summary["queries"] = int(report.stats["queries_checked"])
    return summary


def plural(count: int, noun: str) -> str:
    """``1 error``, ``2 errors``."""
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def validate_outcome_line(
    summary: Mapping[str, int],
    *,
    failed: bool,
    seconds: float,
    fix: str | None = None,
) -> str:
    """``3 objects valid · 0.9s`` or ``2 errors in 1 file · 3 objects checked · 0.9s``.

    *fix* is what ``--fix`` did (``Fixed 3 values in 2 files``): it leads a
    passing line and follows the count of a failing one. Without it, a run
    with safe fixes says ``3 fixable with --fix``.
    """
    sep = f" {glyph('separator')} "
    objects = plural(summary.get("objects", 0), "object")
    errors, warnings = summary.get("errors", 0), summary.get("warnings", 0)
    fixable = summary.get("fixable", 0)
    took = f"{seconds:.1f}s"
    if not failed and not summary.get("objects"):
        # A check that reads no object (id-uniqueness, cve, sharing-config).
        return f"Validation passed{sep}{took}"
    hint = f"{sep}{fixable} fixable with --fix" if fixable and fix is None else ""
    queries = ""
    if "queries" in summary:
        count = summary["queries"]
        queries = f"{sep}{count} {'query' if count == 1 else 'queries'}"
    if not failed:
        line = f"{objects} valid{queries}"
        if warnings:
            line += f"{sep}{plural(warnings, 'warning')}"
        line += hint
        if fix:
            line = f"{fix}{sep}{line}"
        return f"{line}{sep}{took}"
    # Under --strict a run can fail on warnings alone; count where they are.
    if errors:
        counted, files = plural(errors, "error"), summary.get("files", 0)
    else:
        counted, files = plural(warnings, "warning"), summary.get("warning_files", 0)
    where = f" in {plural(files, 'file')}" if files else ""
    done = f"{sep}{fix[0].lower()}{fix[1:]}" if fix else ""
    checked = f"{sep}{objects} checked" if summary.get("objects") else ""
    return f"{counted}{where}{done}{hint}{checked}{queries}{sep}{took}"


def fix_phrase(count: int, files: int, *, dry_run: bool = False, unwritten: int = 0) -> str:
    """``Fixed 3 values in 2 files``, ``Would fix 1 value in 1 file``, ``No safe fix to apply``.

    *unwritten* counts the fixes whose file could not be written:
    ``Could not write 1 fix``, or ``Fixed 1 value in 1 file · could not write 1 fix``.
    """
    failed = (
        f"could not write {unwritten} fix"
        if unwritten == 1
        else f"could not write {unwritten} fixes"
    )
    if not count:
        return failed.capitalize() if unwritten else "No safe fix to apply"
    verb = "Would fix" if dry_run else "Fixed"
    done = f"{verb} {plural(count, 'value')} in {plural(files, 'file')}"
    return f"{done} {glyph('separator')} {failed}" if unwritten else done


def _exempt_warning_lines(report: ValidationReport) -> list[str]:
    """Spell out warnings that ``--strict`` ignores, which nothing else would print (#413)."""
    from opentide.validation.disabled_platforms import STRICT_EXEMPT_WARNINGS

    lines: list[str] = []
    for warning in report.warnings:
        if warning.code not in STRICT_EXEMPT_WARNINGS:
            continue
        location = str(warning.file_path or warning.object_uuid)
        if warning.file_path is not None and warning.yaml_line is not None:
            location = f"{location}:{warning.yaml_line + 1}"
        lines.append(f"{location}: {'.'.join(warning.field_path)}: {warning.message}")
    return lines


#: Every vendor SDK ships with ``pip install opentide``: there are no extras. An
#: SDK that will not import means the environment is incomplete or damaged.
INCOMPLETE_INSTALL_ADVICE = "reinstall opentide: pip install --force-reinstall opentide"


def _missing_sdk_result(platform: str, exc: ModuleNotFoundError) -> dict[str, object]:
    """Structured result for a live check whose vendor SDK will not import."""
    return {
        "platform": platform,
        "mode": "live",
        "supported": True,
        "status": "failed",
        "message": (
            f"Live query validation for {platform} could not import {exc.name or exc}: "
            "the opentide install is incomplete"
        ),
        "advice": INCOMPLETE_INSTALL_ADVICE,
        "_exit_code": 1,
    }


def _unreachable_tenant_result(exc: TenantUnreachableError) -> dict[str, object]:
    """A tenant the live check could not reach (DNS, refused, TLS, timeout): no traceback."""
    from opentide.platforms.enabled import platform_config_path

    return {
        "platform": exc.platform,
        "mode": "live",
        "supported": True,
        "status": "failed",
        "tenant": exc.tenant,
        "host": exc.host,
        "message": str(exc),
        "advice": (
            f"check the '{exc.tenant}' tenant in {platform_config_path(exc.platform)} and the "
            f"network path to {exc.host}; behind a proxy, pass opentide --proxy"
        ),
        "_exit_code": 1,
    }


def _offline_unsupported_result(platform: str) -> dict[str, object]:
    """A platform whose query language the engine does not parse (S1QL): the check is ``--live``."""
    return {
        "platform": platform,
        "mode": "offline",
        "supported": True,
        "status": "failed",
        "message": (
            f"{platform} queries are checked on the tenant only; the offline engine does not "
            "parse them. Re-run with --live."
        ),
        "_exit_code": 2,
        "_failure_code": USAGE_MISSING_OPTION,
        "_failure_argument": "--live",
    }


def _query_scope_refused(
    platform: str | None, message: str, *, exit_code: int, mode: str = "live"
) -> dict[str, object]:
    return {
        "platform": platform,
        "mode": mode,
        "status": "failed",
        "supported": True,
        "message": message,
        "_exit_code": exit_code,
        **({"_failure_code": USAGE_ERROR} if exit_code == 2 else {}),
    }


def _selected_rule_scope(files: Sequence[str], uuids: Sequence[str]) -> tuple[RuleScope, list[str]]:
    """The rule files ``--file`` and ``--uuid`` select, and each target that selects none.

    Candidates are the files deploy reads: those directly in the rules folder.
    ``--file`` matches as in ``opentide validate``.
    """
    from opentide.core.io import load_yaml
    from opentide.core.object_refs import object_uuid
    from opentide.deployment.git_repo import RuleScope, local_rule_scope

    by_file = ValidationScope.narrow(files=frozenset(files))
    wanted = {uuid.strip().lower(): uuid for uuid in uuids}
    found: set[str] = set()
    selected: list[Path] = []
    candidates = local_rule_scope().files
    for path in candidates:
        chosen = bool(files) and by_file.matches_file(path.name, path)
        if wanted:
            try:
                uuid = object_uuid(load_yaml(path)).strip().lower()
            except Exception:
                uuid = ""
            if uuid in wanted:
                found.add(uuid)
                chosen = True
        if chosen:
            selected.append(path)
    unmatched = by_file.unmatched_file_targets([(path.name, path) for path in candidates])
    unmatched.extend(raw for key, raw in wanted.items() if key not in found)
    return RuleScope(tuple(selected)), unmatched


def _query_rule_scope(
    platform: str | None,
    *,
    changed: bool,
    files: Sequence[str],
    uuids: Sequence[str],
    mode: str = "live",
) -> tuple[RuleScope | None, str | None, dict[str, object] | None]:
    """``(scope, label, refusal)`` for ``--changed``, ``--file`` and ``--uuid``.

    No flag reads every rule file (``None``). ``label`` names the
    narrowing in the result. A refusal is returned instead of a scope.
    """
    if not (changed or files or uuids):
        return None, None, None
    if changed and (files or uuids):
        message = "--changed cannot be combined with --file or --uuid"
        return None, None, _query_scope_refused(platform, message, exit_code=2, mode=mode)
    if changed:
        from opentide.deployment.git_repo import MissingGitCheckout, changed_rule_scope

        try:
            scope, diff = changed_rule_scope()
        except MissingGitCheckout as exc:
            message = f"--changed needs a git checkout; no .git was found from {exc.searched}"
            return None, None, _query_scope_refused(platform, message, exit_code=1, mode=mode)
        except Exception as exc:
            message = str(exc).strip() or f"{type(exc).__name__} while computing the changed rules"
            return None, None, _query_scope_refused(platform, message, exit_code=1, mode=mode)
        logger.info("query_scope_changed", diff=diff.name, rules=len(scope.files))
        return scope, "changed", None
    scope, unmatched = _selected_rule_scope(files, uuids)
    if unmatched:
        from opentide.deployment.git_repo import rules_folder_in_repo

        message = (
            f"No rule file directly in {rules_folder_in_repo()} matched: {', '.join(unmatched)}"
        )
        result = _query_scope_refused(platform, message, exit_code=1, mode=mode)
        result["unmatched"] = unmatched
        return None, None, result
    return scope, "selected", None


def validate_query_platform(
    ctx: CliContext,
    platform: str | None,
    *,
    strategies: Sequence[str] = (),
    wide: bool = False,
    live: bool = False,
    changed: bool = False,
    files: Sequence[str] = (),
    uuids: Sequence[str] = (),
    strict: bool = False,
    queries: QueriesMode = QueriesMode.error,
) -> dict[str, object]:
    """Validate rule queries: offline with the analysis engine, or on the tenants.

    Without ``live`` the engine checks each query in its platform's language
    (:func:`validate_query_offline`); *platform* ``None`` checks every platform
    it parses. ``live=True`` sends the queries of one platform to its tenants.

    A rule is checked on the tenants a deploy would send it to: those
    accepting a run strategy that deploys its status's strategy. *strategies*
    (``--strategy``) narrows the run strategies; the default is ``PREVIEW``
    and ``RELEASE``, so every rule is checked wherever it is deployed.
    ``DISABLEMENT`` and ``DELETION`` rules send no query. ``changed`` checks
    only the rule files this run changed, and *files* and *uuids* only the
    rules they select; without them every rule file is read.
    """
    ctx.apply_environment()
    if platform is not None and platform not in QUERY_VALIDATION_PLATFORMS:
        # Returned rather than emitted directly: a raw `emit` skips the
        # ok/status envelope every other command promises, so a caller parsing
        # `--json` got a differently-shaped document for this one branch.
        return {
            "platform": platform,
            "valid": None,
            "supported": False,
            "status": "failed",
            "message": f"query validation not supported for {platform}",
            "_exit_code": 1,
        }
    if not live:
        return validate_query_offline(
            ctx,
            platform,
            changed=changed,
            files=files,
            uuids=uuids,
            strict=strict,
            queries=queries,
        )
    if platform is None:
        return {
            "platform": None,
            "mode": "live",
            "status": "failed",
            "supported": True,
            "message": "--live checks one platform's tenants: pass --platform",
            "_exit_code": 2,
            "_failure_code": USAGE_MISSING_OPTION,
            "_failure_argument": "--platform",
        }
    from opentide.cli.services.deploy import removed_plan_error, resolve_run_strategies
    from opentide.deployment import make_deploy_plan
    from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES

    _reset_validation_env()
    failed = {"platform": platform, "mode": "live", "status": "failed", "supported": True}
    removed = removed_plan_error()
    if removed is not None:
        return {
            **failed,
            "message": removed,
            "_exit_code": 2,
            "_failure_code": USAGE_INVALID_VALUE,
        }
    try:
        run = resolve_run_strategies(strategies) if strategies else DEPLOYABLE_STRATEGIES
    except ValueError as exc:
        return {
            **failed,
            "message": str(exc),
            "_exit_code": 2,
            "_failure_code": USAGE_INVALID_CHOICE,
        }
    rule_scope, scope_label, refusal = _query_rule_scope(
        platform, changed=changed, files=files, uuids=uuids
    )
    if refusal is not None:
        return refusal
    try:
        deployment_list = make_deploy_plan(
            run,
            wide_scope=wide,
            keep_deprecated=False,
            scope=rule_scope,
            all_files=rule_scope is None,
        )
    except Exception as exc:
        message = str(exc).strip() or (f"{type(exc).__name__} while selecting the rules to deploy")
        return {**failed, "message": message, "_exit_code": 1}
    if platform not in deployment_list:
        from opentide.platforms.enabled import enable_platform_command, enabled_systems

        if platform not in set(enabled_systems()):
            return {
                "platform": platform,
                "mode": "live",
                "status": "skipped",
                "platform_enabled": False,
                "message": (
                    f"Platform {platform} is disabled in configurations, so no rule is "
                    "checked for it"
                ),
                "advice": f"enable it with '{enable_platform_command(platform)}'",
            }
        skipped: dict[str, object] = {
            "platform": platform,
            "mode": "live",
            "status": "skipped",
            "strategies": [strategy.name for strategy in run],
            "message": _NO_RULES_MESSAGES[scope_label],
        }
        if scope_label is not None:
            skipped["scope"] = scope_label
        return skipped
    from opentide.platforms.enabled import MissingTenantsError, systems_without_tenants

    if systems_without_tenants([platform]):
        missing = MissingTenantsError(platform)
        return {
            **failed,
            "message": f"Cannot run live query validation: {missing}",
            "advice": missing.advice,
            "missing_tenants": {platform: missing.config_path},
            "_exit_code": 1,
        }
    from contextlib import nullcontext

    from opentide.deployment.planning import wide_scope

    with wide_scope() if wide else nullcontext():
        try:
            reach = queries_per_tenant(platform, deployment_list[platform], run)
        except Exception as exc:
            message = str(exc).strip() or f"{type(exc).__name__} while resolving tenants"
            return {**failed, "message": message, "_exit_code": 1}
        if not reach:
            rules = deployment_list[platform]
            # An explicit --strategy narrowing a rule's tenants away (a rule only
            # PREVIEW tenants take, checked with --strategy RELEASE) is an
            # ordinary skip. Only a rule that reaches no tenant at all means
            # the check could never run.
            if run != DEPLOYABLE_STRATEGIES and queries_per_tenant(
                platform, rules, DEPLOYABLE_STRATEGIES
            ):
                return _scoped(_strategy_reaches_none(platform, run, len(rules)), scope_label)
            return _scoped(_no_tenant_reached(platform, run, len(rules)), scope_label)
        return _scoped(
            _run_live_validator(ctx, platform, deployment_list[platform], run, reach),
            scope_label,
        )


def validate_query_offline(
    ctx: CliContext,
    platform: str | None,
    *,
    changed: bool = False,
    files: Sequence[str] = (),
    uuids: Sequence[str] = (),
    strict: bool = False,
    queries: QueriesMode = QueriesMode.error,
) -> dict[str, object]:
    """Check rule queries with the analysis engine: no tenant, no credentials.

    Every query of every rule file directly in the rules folder (or the files
    ``--changed``, ``--file`` and ``--uuid`` select), whatever its status, for
    *platform* or every platform the engine parses. A ``--file`` with a query
    extension (``.kql``, ``.spl``, ...) is one query in that language.

    The engine's errors are reported, as ``validate``'s queries check reports
    them: they fail the run, or are warnings under ``--queries warn`` (which
    fail it under *strict*). Its warnings and notes are ``opentide lint``'s.
    """
    from opentide.analysis import (
        OFFLINE_QUERY_PLATFORMS,
        EngineUnavailableError,
        QueryCheck,
        UnreadableFile,
        check_queries,
        check_query_file,
        engine_versions,
        is_query_file,
        query_file_language,
    )
    from opentide.cli.services.engine import (
        engine_unavailable_result,
        findings_outcome,
        findings_summary,
    )
    from opentide.cli.ui.diagnostics import diagnostic_from_engine
    from opentide.deployment.git_repo import local_rule_scope

    if platform is not None and platform not in OFFLINE_QUERY_PLATFORMS:
        return _offline_unsupported_result(platform)
    query_files = [Path(target) for target in files if is_query_file(target)]
    rule_targets = [target for target in files if not is_query_file(target)]
    if changed and query_files:
        message = "--changed cannot be combined with --file or --uuid"
        return _query_scope_refused(platform, message, exit_code=2, mode="offline")
    missing = [str(path) for path in query_files if not path.is_file()]
    if missing:
        result = _query_scope_refused(
            platform, f"No such query file: {', '.join(missing)}", exit_code=2, mode="offline"
        )
        result["unmatched"] = missing
        return result
    if platform is not None:
        from opentide.analysis import OFFLINE_QUERY_LANGUAGES

        languages = OFFLINE_QUERY_LANGUAGES[platform]
        other = [
            f"{path} ({query_file_language(path)})"
            for path in query_files
            if query_file_language(path) not in languages
        ]
        if other:
            message = (
                f"--platform {platform} checks {', '.join(languages)}: "
                f"not {', '.join(other)}"
            )
            refused = _query_scope_refused(platform, message, exit_code=2, mode="offline")
            refused["_failure_argument"] = "--file"
            return refused
    workspace = discover_workspace()
    platforms = sorted([platform] if platform else OFFLINE_QUERY_PLATFORMS)
    base: dict[str, object] = {"platform": platform, "mode": "offline", "supported": True}
    rule_files: list[Path] = []
    scope_label: str | None = "selected"
    if rule_targets or uuids or changed or not query_files:
        rule_scope, scope_label, refusal = _query_rule_scope(
            platform, changed=changed, files=rule_targets, uuids=uuids, mode="offline"
        )
        if refusal is not None:
            return refusal
        rule_files = list((rule_scope or local_rule_scope()).files)
    try:
        run = check_queries(rule_files, root=workspace, platforms=platforms)
        from_files = [check_query_file(path, platform=platform) for path in query_files]
        engine = engine_versions()
    except EngineUnavailableError as exc:
        return engine_unavailable_result(exc, **base)
    cannot_read = [item for item in from_files if isinstance(item, UnreadableFile)]
    if cannot_read:
        listed = "; ".join(f"{item.file_path}: {item.problem}" for item in cannot_read)
        return {**base, "status": "failed", "message": f"Cannot check {listed}", "_exit_code": 1}
    from opentide.validation.queries import is_placeholder_query

    # A placeholder query is lint's finding; a query file has no marker.
    lines: dict[Path, list[str]] = {}
    checks = [check for check in run.checks if not is_placeholder_query(check, lines)]
    checks += [item for item in from_files if isinstance(item, QueryCheck)]
    unreadable = [
        Diagnostic(
            code="yaml_parse",
            severity="error",
            message=f"cannot check this file's queries: {item.problem}",
            path=relative_path(item.file_path, workspace),
            file_path=item.file_path,
            line=item.line,
            column=item.column,
            end_column=None if item.column is None else item.column + 1,
            help="opentide validate reports the file; fix it, then check its queries again",
        )
        for item in run.unreadable
    ]
    if not checks and not unreadable:
        target = f"{platform} " if platform else ""
        where = {None: "", "changed": "changed ", "selected": "selected "}[scope_label]
        return _scoped(
            {
                **base,
                "status": "skipped",
                "queries_validated": 0,
                "message": f"No {where}rule has a {target}query the engine checks",
                "_summary": {"queries": 0, "files": 0},
            },
            scope_label,
        )
    rejected = [
        reported_query_error(
            diagnostic_from_engine(finding, file_path=check.file_path, workspace=workspace),
            queries=queries,
        )
        for check in checks
        for finding in check.findings
        if finding.severity == "error"
    ]
    diagnostics = unreadable + rejected
    counts = findings_summary(diagnostics)
    summary = {
        "queries": len(checks),
        "files": len({check.file_path for check in checks}),
        **counts,
    }
    failed = bool(counts["errors"] or (strict and counts["warnings"]))
    count = len(checks)
    checked = f"{count} {'query' if count == 1 else 'queries'}"
    outcome_line, outcome_kind = findings_outcome(
        summary, checked=checked, failed=failed, clean=f"{checked} valid"
    )
    result: dict[str, object] = {
        **base,
        "status": "failed" if failed else "passed",
        "message": "Queries rejected offline" if failed else f"{checked} valid",
        "platforms": sorted({check.platform for check in checks if check.platform}),
        "queries_validated": count,
        "queries": [
            {
                "path": relative_path(check.file_path, workspace),
                "platform": check.platform,
                "language": check.language,
                "field_path": list(check.field_path),
                "line": check.line,
                "column": check.column,
                "errors": check.errors,
            }
            for check in checks
        ],
        "diagnostics": [item.to_dict() for item in diagnostics],
        "engine": engine,
        "_summary": summary,
        "_diagnostics": diagnostics,
        "_outcome": outcome_line,
    }
    if outcome_kind is not None:
        result["_outcome_kind"] = outcome_kind
    if failed:
        rerun = ["opentide", "validate", "query"]
        if platform:
            rerun += ["--platform", platform]
        rerun += ["--changed"] if changed else []
        rerun += [word for target in files for word in ("--file", target)]
        rerun += [word for target in uuids for word in ("--uuid", target)]
        rerun += queries_flag(queries)
        rerun += ["--strict"] if strict else []
        actions = _failure_next_actions(ctx, diagnostics)[:1]
        actions.append(NextAction(shlex.join(rerun), "check again"))
        result.update({"_exit_code": 1, "_failure_code": ISSUES_FOUND, "_next_actions": actions})
    return _scoped(result, scope_label)


def reported_query_error(diagnostic: Diagnostic, *, queries: QueriesMode) -> Diagnostic:
    """An engine error as ``--queries`` reports it: as is, or a warning with a note."""
    if queries is not QueriesMode.warn:
        return diagnostic
    return replace(
        diagnostic,
        severity="warning",
        notes=(*diagnostic.notes, ("note", REPORTED_AS_WARNING_NOTE)),
    )


#: The skip message when no rule is checked for the platform, by scope label.
_NO_RULES_MESSAGES: dict[str | None, str] = {
    None: "No rule for this platform has a status that maps to the run's strategies",
    "changed": "No changed rule for this platform has a status that maps to the run's strategies",
    "selected": (
        "None of the selected rules has a status for this platform that maps to the run's "
        "strategies"
    ),
}


def _scoped(result: dict[str, object], label: str | None) -> dict[str, object]:
    """Name the narrowed rule scope (``changed`` or ``selected``) in *result*."""
    if label is not None:
        result["scope"] = label
    return result


def queries_per_tenant(
    platform: str, rules: Sequence[str], strategies: RunStrategies
) -> dict[str, int]:
    """How many rule queries a live check sends to each tenant.

    The same resolution the platform validator runs, so a tenant listed here
    is one the validator connects to. Tenants that receive no rule are absent.
    """
    from opentide.deployment import TideDeployment
    from opentide.models.deployment_enums import DetectionPlatforms

    deployment = TideDeployment(
        deployment=list(rules), system=DetectionPlatforms[platform.upper()], strategies=strategies
    )
    reach: dict[str, int] = {}
    for batch in deployment.rule_deployment:
        if batch.rules:
            reach[batch.tenant.name] = reach.get(batch.tenant.name, 0) + len(batch.rules)
    return reach


def _names(strategies: Sequence[Any]) -> list[str]:
    return [strategy.name for strategy in strategies]


def _strategy_reaches_none(
    platform: str, strategies: Sequence[Any], rules: int
) -> dict[str, object]:
    """Every rule reaches a tenant, but none accepting *strategies*: nothing to check here."""
    names = " and ".join(_names(strategies))
    return {
        "platform": platform,
        "mode": "live",
        "status": "skipped",
        "supported": True,
        "strategies": _names(strategies),
        "queries_validated": 0,
        "queries_per_tenant": {},
        "message": (
            f"None of the {rules} {platform} rule(s) goes to a tenant accepting {names}; "
            "they are checked by a run with the strategy that deploys them, or without --strategy"
        ),
    }


def _no_tenant_reached(platform: str, strategies: Sequence[Any], rules: int) -> dict[str, object]:
    """No query was sent, so the check did not run. Exit 2, like the CI credential guard."""
    from opentide.platforms.enabled import platform_config_path

    config = platform_config_path(platform)
    return {
        "platform": platform,
        "mode": "live",
        "status": "skipped",
        "supported": True,
        "strategies": _names(strategies),
        "queries_validated": 0,
        "queries_per_tenant": {},
        "message": (
            f"No query was sent: none of the {rules} {platform} rule(s) goes to a tenant in "
            f"{config}"
        ),
        "advice": (
            "a tenant takes a rule only when its 'strategies' accept the run strategy that "
            "deploys the rule's status; a 'manual' tenant only when the rule lists it under "
            "tenants; and a rule's tenants list must name a tenant configured for this platform"
        ),
        "_exit_code": 2,
        "_failure_code": "no_tenant_reached",
    }


def _run_live_validator(
    ctx: CliContext,
    platform: str,
    rules: Sequence[str],
    strategies: RunStrategies,
    reach: dict[str, int],
) -> dict[str, object]:
    from opentide.core.registry import Opentide as LegacyOpentide
    from opentide.platforms.plugins import DeployTide
    from opentide.platforms.transport import TenantUnreachableError

    counts: dict[str, object] = {
        "strategies": _names(strategies),
        "queries_validated": sum(reach.values()),
        "queries_per_tenant": dict(reach),
    }
    try:
        query_validators = cast(dict[str, Any], DeployTide().query_validation_for(platform))
    except ValueError as exc:
        # Config parsing (a retired tenant ``proxy`` key) raises ValueError inside
        # engine load. Returning it keeps the FATAL panel instead of a traceback.
        return {
            "platform": platform,
            "mode": "live",
            "status": "failed",
            "supported": True,
            "message": str(exc),
            "_exit_code": 1,
        }
    if platform not in query_validators:
        return {
            "platform": platform,
            "mode": "live",
            "status": "skipped",
            "message": f"No query validation engine for {platform}",
        }
    try:
        system_name = LegacyOpentide.Configurations.Systems.Index[platform]["tide"]["name"]
    except Exception:
        system_name = LegacyOpentide.Configurations.Systems.Index[platform]["platform"]["name"]
    from opentide.cli.ui.progress import Checklist

    validator = cast(Any, query_validators[platform])
    early: dict[str, object] | None = None
    with (
        Checklist(total=1) as checklist,
        checklist.step(f"{system_name} queries", unit="rule") as step,
    ):
        step.done(len(rules))
        # No retry on TypeError: the pre-strategy `validate(deployment=...)` that
        # was retried exists on no engine, and its own TypeError hid the real one.
        try:
            validator.validate(mdr_deployment=rules, strategies=strategies)
        except ModuleNotFoundError as exc:
            early = _missing_sdk_result(platform, exc)
        except TenantUnreachableError as exc:
            early = _unreachable_tenant_result(exc)
        except ValueError as exc:
            # Unsubstituted ``$VAR`` credentials raise before the vendor client runs.
            early = {
                "platform": platform,
                "mode": "live",
                "status": "failed",
                "supported": True,
                "message": str(exc),
                "_exit_code": 1,
            }
        except Exception as exc:
            detail = str(exc).strip()
            error = f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__
            logger.error("query_validation_failed", system=platform, detail=error)
            early = {
                "platform": platform,
                "mode": "live",
                "status": "failed",
                "supported": True,
                **counts,
                "message": f"Query validation for {platform} failed: {error}",
                "_exit_code": 1,
            }
        if early is not None:
            step.status = "skipped" if early.get("status") == "skipped" else "failed"
    if early is not None:
        return early
    from opentide.cli.exit_codes import validation_outcome
    from opentide.cli.ui.progress import plural

    outcome = validation_outcome()
    queries = sum(reach.values())
    # The validators report a rejection as a run flag, not per query, so a
    # failure counts what was checked rather than what was rejected.
    message = (
        f"Queries rejected on {platform} · {queries} checked on {plural(len(reach), 'tenant')}"
        if outcome.failed
        else f"{plural(queries, 'query', 'queries')} valid on {plural(len(reach), 'tenant')}"
    )
    result: dict[str, object] = {
        "platform": platform,
        "mode": "live",
        "status": "failed" if outcome.failed else "passed",
        "supported": True,
        **counts,
        "message": message,
        "_summary": {"queries": queries, "tenants": len(reach)},
        "_exit_code": outcome.exit_code,
    }
    if outcome.failed:
        result["error"] = message
    if outcome.warned:
        result["warnings"] = [f"Query validation reported warnings for {platform}"]
    return result
