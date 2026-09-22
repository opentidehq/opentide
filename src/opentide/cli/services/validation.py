"""Validation services for the CLI."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, cast

import structlog

from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS, ValidateCheck
from opentide.cli.output import emit, emit_error
from opentide.core.logging.config import get_stdout_console
from opentide.core.logging.console import emit_section
from opentide.validation.errors import format_issues_for_console
from opentide.validation.issues import ValidationIssue, ValidationReport
from opentide.validation.scope import ValidationScope
from opentide.validation.session import run_validation

logger = structlog.get_logger("opentide.cli.services.validation")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext


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
            "invalid_ref",
            "vocab_unknown",
            "chaining_relation_unknown",
        }
    ),
    ValidateCheck.cve.value: frozenset({"invalid_cve"}),
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


def _report_payload(report: ValidationReport) -> dict[str, object]:
    return {
        "status": "passed" if report.ok else "failed",
        "errors": report.legacy_errors_by_uuid(),
        "issues": report.model_dump_json_ready(),
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
    payload = _report_payload(report)
    payload["check"] = check.value
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

    if check is None:
        result: dict[str, object] = {
            "checks": {
                name: {
                    "check": name,
                    "status": _status_for_check(report, name),
                }
                for name in (
                    ValidateCheck.id_uniqueness.value,
                    ValidateCheck.uuid_format.value,
                    ValidateCheck.schema.value,
                )
            },
            "report": report.model_dump_json_ready(),
        }
    else:
        result = _report_payload(report)
        result["check"] = check.value

    if not ctx.json_output and report.issues:
        from rich.panel import Panel

        get_stdout_console().print(
            Panel(
                format_issues_for_console(report.issues),
                title="[bold red]Validation issues[/]",
                border_style="red",
            )
        )

    from opentide.cli.exit_codes import validation_outcome

    outcome = validation_outcome(strict=strict)
    result["status"] = "failed" if outcome.failed else "passed"
    result["message"] = "Validation failed" if outcome.failed else "Validation passed"
    if outcome.warned:
        result["warnings"] = ["Validation reported warnings"]
    result["_exit_code"] = outcome.exit_code
    return result


#: Vendor SDKs each live query validator imports, and the extra that installs them.
QUERY_VALIDATION_EXTRAS: dict[str, tuple[str, tuple[str, ...]]] = {
    "sentinel": ("opentide[sentinel]", ("azure-identity", "azure-monitor-query")),
    "splunk": ("opentide[splunk]", ("splunk-sdk",)),
    "carbon_black_cloud": ("opentide[carbon-black]", ("carbon-black-cloud-sdk",)),
}


def _missing_sdk_result(platform: str, exc: ModuleNotFoundError) -> dict[str, object]:
    """Structured result for a live check whose vendor SDK is not installed."""
    extra, packages = QUERY_VALIDATION_EXTRAS.get(platform, (f"opentide[{platform}]", ()))
    advice = f"install {extra}"
    if packages:
        advice += f" (provides {', '.join(packages)})"
    return {
        "platform": platform,
        "mode": "live",
        "supported": True,
        "status": "failed",
        "message": f"Live query validation for {platform} needs a vendor SDK: {exc}",
        "advice": advice,
        "_exit_code": 1,
    }


def _offline_query_result(
    platform: str, *, uuids: frozenset[str] | None = None
) -> dict[str, object]:
    """Language-aware syntax check that needs no SDK, credentials, or network."""
    from opentide.core.registry import OpenTide
    from opentide.platforms.enabled import enabled_systems
    from opentide.validation.query_syntax import language_label, validate_platform_queries

    OpenTide.reload()
    report = validate_platform_queries(platform, OpenTide.Models.rules, uuids=uuids)
    label = language_label(report.language)
    result: dict[str, object] = {
        "platform": platform,
        "mode": "offline-syntax",
        "language": report.language,
        "supported": True,
        "rules": report.rules,
        "checked": report.checked,
        "findings": report.findings,
    }
    warnings: list[str] = []
    if platform not in set(enabled_systems()):
        result["platform_enabled"] = False
        warnings.append(
            f"Platform {platform} is disabled in configurations; "
            "checked query syntax only, nothing would deploy"
        )
    if report.checked == 0:
        result["status"] = "skipped"
        result["message"] = f"No {platform} queries found to validate"
        if warnings:
            result["warnings"] = warnings
        return result
    scope = (
        f"{report.checked} quer{'y' if report.checked == 1 else 'ies'} across "
        f"{report.rules} rule{'' if report.rules == 1 else 's'}"
    )
    if report.ok:
        result["status"] = "passed"
        result["message"] = f"Offline {label} syntax validation passed for {platform} ({scope})"
    else:
        result["status"] = "failed"
        result["message"] = (
            f"Offline {label} syntax validation found {len(report.findings)} "
            f"problem(s) for {platform} ({scope})"
        )
        result["_exit_code"] = 1
        for finding in report.findings:
            logger.error(
                "query_syntax_error",
                detail=f"{finding['rule']} ({finding['uuid']})",
                context=f"{finding['field']}:{finding['line']}:{finding['column']}",
                advice=finding["message"],
            )
    if warnings:
        result["warnings"] = warnings
    return result


def validate_query_platform(
    ctx: CliContext,
    platform: str,
    *,
    plan: str | None = None,
    wide: bool = False,
    live: bool = False,
) -> dict[str, object]:
    """Validate queries for a single platform.

    Offline by default: the tutorial and generated CI pipelines must not require
    tenant credentials. ``live=True`` runs the platform engine against the tenant.
    """
    ctx.apply_environment()
    if plan is not None:
        ctx.set_deployment_plan(plan)
    if platform not in QUERY_VALIDATION_PLATFORMS:
        message = f"query validation not supported for {platform}"
        if ctx.json_output:
            emit(ctx, {"valid": None, "supported": False, "message": message}, exit_code=1)
        emit_error(ctx, message, exit_code=1)
    if not live:
        return _offline_query_result(platform)
    from opentide.core.registry import OpenTide as LegacyOpenTide
    from opentide.deployment import DeploymentStrategy, make_deploy_plan
    from opentide.platforms.plugins import DeployTide

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
        from opentide.platforms.enabled import enabled_systems

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
                "advice": f"enable it with 'opentide setup platforms --{platform}'",
            }
        return {
            "platform": platform,
            "mode": "live",
            "status": "skipped",
            "message": "No rules to validate for this platform in the current plan",
        }
    query_validators = cast(dict[str, Any], DeployTide().query_validation_for(platform))
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
            validator.validate(
                mdr_deployment=deployment_list[platform], deployment_plan=deployment_plan
            )
        except TypeError:
            logger.warning("trying_mdrv3_style_method")
            validator.validate(deployment=deployment_list[platform])
    except ModuleNotFoundError as exc:
        return _missing_sdk_result(platform, exc)
    if os.environ.get("VALIDATION_ERROR_RAISED"):
        emit_error(ctx, f"Query validation failed for {platform}", exit_code=1)
    from opentide.cli.exit_codes import validation_outcome

    outcome = validation_outcome()
    result: dict[str, object] = {
        "platform": platform,
        "mode": "live",
        "status": "failed" if outcome.failed else "passed",
        "supported": True,
        "message": (
            f"Query validation failed for {platform}"
            if outcome.failed
            else f"Query validation passed for {platform}"
        ),
        "_exit_code": outcome.exit_code,
    }
    if outcome.warned:
        result["warnings"] = [f"Query validation reported warnings for {platform}"]
    return result
