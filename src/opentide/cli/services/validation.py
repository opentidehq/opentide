"""Validation services for the CLI."""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, cast

import structlog

from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS, ValidateCheck
from opentide.core.logging.config import get_stdout_console
from opentide.core.logging.console import emit_section
from opentide.registry.discovery import discover_workspace
from opentide.validation.errors import format_issues_for_console
from opentide.validation.issues import ValidationIssue, ValidationReport
from opentide.validation.scope import ValidationScope
from opentide.validation.session import run_validation

logger = structlog.get_logger("opentide.cli.services.validation")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext
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
        "_exit_code": 1,
    }


def validate_query_platform(
    ctx: CliContext,
    platform: str,
    *,
    plan: str | None = None,
    wide: bool = False,
    live: bool = False,
) -> dict[str, object]:
    """Validate queries for a single platform.

    Without ``live`` the command refuses and names ``--live``. ``live=True``
    runs the platform engine against the tenant.
    """
    ctx.apply_environment()
    if plan is not None:
        ctx.set_deployment_plan(plan)
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
    from opentide.deployment import DeploymentStrategy, make_deploy_plan

    _reset_validation_env()
    try:
        deployment_plan = DeploymentStrategy.load_from_environment()
    except ValueError as exc:
        return {
            "platform": platform,
            "mode": "live",
            "status": "failed",
            "supported": True,
            "message": str(exc),
            "_exit_code": 1,
        }
    try:
        deployment_list = make_deploy_plan(deployment_plan, wide_scope=wide, keep_deprecated=False)
    except Exception as exc:
        message = str(exc).strip() or (f"{type(exc).__name__} while compiling the deployment plan")
        return {
            "platform": platform,
            "mode": "live",
            "status": "failed",
            "supported": True,
            "message": message,
            "_exit_code": 1,
        }
    if platform not in deployment_list:
        from opentide.platforms.enabled import enable_platform_command, enabled_systems

        if platform not in set(enabled_systems()):
            return {
                "platform": platform,
                "mode": "live",
                "status": "skipped",
                "platform_enabled": False,
                "message": (
                    f"Platform {platform} is disabled in configurations, so the "
                    "deployment plan contains no rules for it"
                ),
                "advice": f"enable it with '{enable_platform_command(platform)}'",
            }
        return {
            "platform": platform,
            "mode": "live",
            "status": "skipped",
            "message": "No rules to validate for this platform in the current plan",
        }
    from opentide.platforms.enabled import MissingTenantsError, systems_without_tenants

    if systems_without_tenants([platform]):
        missing = MissingTenantsError(platform)
        return {
            "platform": platform,
            "mode": "live",
            "status": "failed",
            "supported": True,
            "message": f"Cannot run live query validation: {missing}",
            "advice": missing.advice,
            "missing_tenants": {platform: missing.config_path},
            "_exit_code": 1,
        }
    from opentide.deployment.planning import read_only_tenant_resolution

    # Only reads: every tenant a rule reaches is checked under FULL (#547).
    with read_only_tenant_resolution():
        try:
            reach = queries_per_tenant(platform, deployment_list[platform], deployment_plan)
        except Exception as exc:
            message = str(exc).strip() or f"{type(exc).__name__} while resolving tenants"
            return {
                "platform": platform,
                "mode": "live",
                "status": "failed",
                "supported": True,
                "message": message,
                "_exit_code": 1,
            }
        if not reach:
            rules = deployment_list[platform]
            from opentide.deployment import DeploymentStrategy

            if deployment_plan in (DeploymentStrategy.STAGING, DeploymentStrategy.PRODUCTION):
                # An explicit plan narrowing a rule out (a staging-only rule under
                # PRODUCTION) is an ordinary skip. Only a rule that reaches no
                # configured tenant at all means the check could never run.
                if queries_per_tenant(platform, rules, DeploymentStrategy.FULL):
                    return _plan_reaches_none(platform, deployment_plan.name, len(rules))
            return _no_tenant_reached(platform, deployment_plan.name, len(rules))
        return _run_live_validator(ctx, platform, deployment_list[platform], deployment_plan, reach)


def queries_per_tenant(platform: str, rules: Sequence[Any], plan: Any) -> dict[str, int]:
    """How many rule queries a live check sends to each tenant.

    The same resolution the platform validator runs, so a tenant listed here
    is one the validator connects to. Tenants that receive no rule are absent.
    """
    from opentide.deployment import TideDeployment
    from opentide.models.deployment_enums import DetectionPlatforms

    deployment = TideDeployment(
        deployment=list(rules), system=DetectionPlatforms[platform.upper()], strategy=plan
    )
    reach: dict[str, int] = {}
    for batch in deployment.rule_deployment:
        if batch.rules:
            reach[batch.tenant.name] = reach.get(batch.tenant.name, 0) + len(batch.rules)
    return reach


def _plan_reaches_none(platform: str, plan: str, rules: int) -> dict[str, object]:
    """Every rule targets a tenant, but none that *plan* deploys to: nothing to check here."""
    return {
        "platform": platform,
        "mode": "live",
        "status": "skipped",
        "supported": True,
        "plan": plan,
        "queries_validated": 0,
        "queries_per_tenant": {},
        "message": (
            f"No {plan} tenant is targeted by the {rules} {platform} rule(s) in the plan; "
            "they are checked by the plan that deploys them, or by validate without --plan"
        ),
    }


def _no_tenant_reached(platform: str, plan: str, rules: int) -> dict[str, object]:
    """No query was sent, so the check did not run. Exit 2, like the CI credential guard."""
    from opentide.platforms.enabled import platform_config_path

    config = platform_config_path(platform)
    return {
        "platform": platform,
        "mode": "live",
        "status": "skipped",
        "supported": True,
        "plan": plan,
        "queries_validated": 0,
        "queries_per_tenant": {},
        "message": (
            f"No query was sent: none of the {rules} {platform} rule(s) in the "
            f"{plan} plan resolves to a tenant in {config}"
        ),
        "advice": (
            "a MANUAL tenant is reached only when a rule lists it under tenants, and a "
            "rule's tenants list must name a tenant configured for this platform"
        ),
        "_exit_code": 2,
    }


def _run_live_validator(
    ctx: CliContext,
    platform: str,
    rules: Sequence[Any],
    deployment_plan: Any,
    reach: dict[str, int],
) -> dict[str, object]:
    from opentide.core.registry import OpenTide as LegacyOpenTide
    from opentide.platforms.plugins import DeployTide
    from opentide.platforms.transport import TenantUnreachableError

    counts: dict[str, object] = {
        "plan": deployment_plan.name,
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
        system_name = LegacyOpenTide.Configurations.Systems.Index[platform]["tide"]["name"]
    except Exception:
        system_name = LegacyOpenTide.Configurations.Systems.Index[platform]["platform"]["name"]
    emit_section(f"Query Validation - {system_name}")
    validator = cast(Any, query_validators[platform])
    try:
        try:
            validator.validate(mdr_deployment=rules, deployment_plan=deployment_plan)
        except TypeError:
            logger.warning("trying_mdrv3_style_method")
            validator.validate(deployment=rules)
    except ModuleNotFoundError as exc:
        return _missing_sdk_result(platform, exc)
    except TenantUnreachableError as exc:
        return _unreachable_tenant_result(exc)
    except ValueError as exc:
        # Unsubstituted ``$VAR`` credentials raise before the vendor client runs.
        # TypeError stays uncaught here so the legacy validator signature retry works.
        return {
            "platform": platform,
            "mode": "live",
            "status": "failed",
            "supported": True,
            "message": str(exc),
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
