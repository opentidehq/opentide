"""Validation services for the CLI."""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, cast

import structlog

from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS, ValidateCheck
from opentide.cli.ui.contract import (
    USAGE_ERROR,
    USAGE_INVALID_CHOICE,
    USAGE_INVALID_VALUE,
    USAGE_MISSING_OPTION,
)
from opentide.core.logging.config import get_stdout_console
from opentide.core.logging.console import emit_section
from opentide.registry.discovery import discover_workspace
from opentide.validation.errors import format_issues_for_console
from opentide.validation.issues import ValidationIssue, ValidationReport
from opentide.validation.scope import ValidationScope
from opentide.validation.session import run_validation

logger = structlog.get_logger("opentide.cli.services.validation")
if TYPE_CHECKING:
    from pathlib import Path

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


def _checks_for(check: ValidateCheck | None) -> frozenset[ValidateCheck]:
    if check is None:
        return frozenset(
            {
                ValidateCheck.id_uniqueness,
                ValidateCheck.uuid_format,
                ValidateCheck.schema,
            }
        )
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
            "deployment_state_uuid_mismatch",
            "deployment_state_platform",
            "deployment_state_shape",
        }
    ),
    ValidateCheck.cve.value: frozenset({"invalid_cve"}),
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
}

_OBJECT_CHECKS = frozenset({ValidateCheck.uuid_format.value, ValidateCheck.schema.value})


def _issues_for_check(issues: list[ValidationIssue], check_name: str) -> list[ValidationIssue]:
    codes = _CHECK_ISSUE_CODES.get(check_name, frozenset())
    matched = [issue for issue in issues if issue.code in codes]
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
)


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
    for check in (ValidateCheck.id_uniqueness, ValidateCheck.uuid_format, ValidateCheck.schema):
        check_issues = _issues_for_check(report.issues, check.value)
        results[check.value] = {
            "check": check.value,
            "status": _status_for_check(report, check.value),
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
) -> dict[str, object]:
    """Entry point for validate command."""
    ctx.apply_environment()
    _reset_validation_env()

    file_list = list(files or [])
    if file:
        file_list.append(file)
    scope = _build_scope(files=file_list or None, uuids=uuids, object_types=object_types)
    checks = _checks_for(check)

    report = run_validation(scope=scope, checks=checks)
    if not report.ok:
        os.environ["VALIDATION_ERROR_RAISED"] = "1"

    # Both branches build the SAME document. A single check only narrows
    # `checks`; it used to relocate the report to `issues` (so consumers read
    # `issues.issues`) and bolt on a legacy `errors` map, which meant one
    # command emitted two incompatible shapes.
    names = DEFAULT_CHECK_NAMES if check is None else (check.value,)
    result: dict[str, object] = _validate_payload(report, names)
    if check is not None:
        result["check"] = check.value
    workspace = discover_workspace()
    result["workspace"] = str(workspace)

    if not ctx.json_output and report.issues:
        from rich.panel import Panel
        from rich.text import Text

        get_stdout_console().print(
            Panel(
                Text(format_issues_for_console(report.issues)),
                title="[bold red]Validation issues[/]",
                border_style="red",
            )
        )

    from opentide.cli.exit_codes import validation_outcome

    outcome = validation_outcome(strict=strict)
    result["status"] = "failed" if outcome.failed else "passed"
    if outcome.failed:
        result["message"] = "Validation failed"
    elif check is None and scope.mode == "full" and report.stats.get("objects_checked") == 0:
        # Not a failure: an empty catalogue exits 0, even under --strict. The
        # path is what exposes a run that looked in the wrong directory.
        result["message"] = (
            f"Validation passed, but no detection objects were found under {workspace}"
        )
    else:
        result["message"] = "Validation passed"
    warnings = ["Validation reported warnings"] if outcome.warned else []
    warnings.extend(_exempt_warning_lines(report))
    if warnings:
        result["warnings"] = warnings
    result["_exit_code"] = outcome.exit_code
    return result


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


def _live_required_result(platform: str) -> dict[str, object]:
    """Bare ``validate query`` does not scan. The tenant check is ``--live``."""
    return {
        "platform": platform,
        "supported": True,
        "status": "failed",
        "message": "Query validation checks the tenant. Re-run with --live.",
        "_exit_code": 2,
        "_failure_code": USAGE_MISSING_OPTION,
        "_failure_argument": "--live",
    }


def _query_scope_refused(platform: str, message: str, *, exit_code: int) -> dict[str, object]:
    return {
        "platform": platform,
        "mode": "live",
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
    platform: str, *, changed: bool, files: Sequence[str], uuids: Sequence[str]
) -> tuple[RuleScope | None, str | None, dict[str, object] | None]:
    """``(scope, label, refusal)`` for ``--changed``, ``--file`` and ``--uuid``.

    No flag reads every rule file (``None``). ``label`` names the
    narrowing in the result. A refusal is returned instead of a scope.
    """
    if not (changed or files or uuids):
        return None, None, None
    if changed and (files or uuids):
        message = "--changed cannot be combined with --file or --uuid"
        return None, None, _query_scope_refused(platform, message, exit_code=2)
    if changed:
        from opentide.deployment.git_repo import MissingGitCheckout, changed_rule_scope

        try:
            scope, diff = changed_rule_scope()
        except MissingGitCheckout as exc:
            message = f"--changed needs a git checkout; no .git was found from {exc.searched}"
            return None, None, _query_scope_refused(platform, message, exit_code=1)
        except Exception as exc:
            message = str(exc).strip() or f"{type(exc).__name__} while computing the changed rules"
            return None, None, _query_scope_refused(platform, message, exit_code=1)
        logger.info("query_scope_changed", diff=diff.name, rules=len(scope.files))
        return scope, "changed", None
    scope, unmatched = _selected_rule_scope(files, uuids)
    if unmatched:
        from opentide.deployment.git_repo import rules_folder_in_repo

        message = (
            f"No rule file directly in {rules_folder_in_repo()} matched: {', '.join(unmatched)}"
        )
        result = _query_scope_refused(platform, message, exit_code=1)
        result["unmatched"] = unmatched
        return None, None, result
    return scope, "selected", None


def validate_query_platform(
    ctx: CliContext,
    platform: str,
    *,
    strategies: Sequence[str] = (),
    wide: bool = False,
    live: bool = False,
    changed: bool = False,
    files: Sequence[str] = (),
    uuids: Sequence[str] = (),
) -> dict[str, object]:
    """Validate queries for a single platform.

    Without ``live`` the command refuses and names ``--live``. ``live=True``
    runs the platform engine against the tenant.

    A rule is checked on the tenants a deploy would send it to: those
    accepting a run strategy that deploys its status's strategy. *strategies*
    (``--strategy``) narrows the run strategies; the default is ``PREVIEW``
    and ``RELEASE``, so every rule is checked wherever it is deployed.
    ``DISABLEMENT`` and ``DELETION`` rules send no query. ``changed`` checks
    only the rule files this run changed, and *files* and *uuids* only the
    rules they select; without them every rule file is read.
    """
    ctx.apply_environment()
    if platform not in QUERY_VALIDATION_PLATFORMS:
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
        return _live_required_result(platform)
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
    emit_section(f"Query Validation - {system_name}")
    validator = cast(Any, query_validators[platform])
    # No retry on TypeError: the pre-strategy `validate(deployment=...)` that
    # was retried exists on no engine, and its own TypeError hid the real one.
    try:
        validator.validate(mdr_deployment=rules, strategies=strategies)
    except ModuleNotFoundError as exc:
        return _missing_sdk_result(platform, exc)
    except TenantUnreachableError as exc:
        return _unreachable_tenant_result(exc)
    except ValueError as exc:
        # Unsubstituted ``$VAR`` credentials raise before the vendor client runs.
        return {
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
        return {
            "platform": platform,
            "mode": "live",
            "status": "failed",
            "supported": True,
            **counts,
            "message": f"Query validation for {platform} failed: {error}",
            "_exit_code": 1,
        }
    from opentide.cli.exit_codes import validation_outcome

    outcome = validation_outcome()
    message = (
        f"Query validation failed for {platform}"
        if outcome.failed
        else f"Query validation passed for {platform}"
    )
    result: dict[str, object] = {
        "platform": platform,
        "mode": "live",
        "status": "failed" if outcome.failed else "passed",
        "supported": True,
        **counts,
        "message": message,
        "_exit_code": outcome.exit_code,
    }
    if outcome.failed:
        result["error"] = message
    if outcome.warned:
        result["warnings"] = [f"Query validation reported warnings for {platform}"]
    return result
