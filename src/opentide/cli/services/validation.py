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
from opentide.validation.issues import ValidationReport
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
        results[check.value] = {
            "check": check.value,
            "status": "passed" if report.ok else "failed",
            "issues": report.model_dump_json_ready(),
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
                    "status": "passed" if report.ok else "failed",
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


def validate_query_platform(
    ctx: CliContext, platform: str, *, plan: str | None = None, wide: bool = False
) -> dict[str, object]:
    """Validate queries for a deployment plan on a single platform."""
    ctx.apply_environment()
    if plan is not None:
        ctx.set_deployment_plan(plan)
    if platform not in QUERY_VALIDATION_PLATFORMS:
        message = f"query validation not supported for {platform}"
        if ctx.json_output:
            emit(ctx, {"valid": None, "supported": False, "message": message}, exit_code=1)
        emit_error(ctx, message, exit_code=1)
    from opentide.core.registry import OpenTide as LegacyOpenTide
    from opentide.deployment import DeploymentStrategy, make_deploy_plan
    from opentide.platforms.plugins import DeployTide

    _reset_validation_env()
    try:
        deployment_plan = DeploymentStrategy.load_from_environment()
    except ValueError as exc:
        return {
            "platform": platform,
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
            "status": "failed",
            "supported": True,
            "message": message,
            "_exit_code": 1,
        }
    if platform not in deployment_list:
        return {
            "platform": platform,
            "status": "skipped",
            "message": "No rules to validate for this platform in the current plan",
        }
    query_validators = cast(dict[str, Any], DeployTide().query_validation)
    if platform not in query_validators:
        return {
            "platform": platform,
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
        validator.validate(
            mdr_deployment=deployment_list[platform], deployment_plan=deployment_plan
        )
    except TypeError:
        logger.warning("trying_mdrv3_style_method")
        validator.validate(deployment=deployment_list[platform])
    if os.environ.get("VALIDATION_ERROR_RAISED"):
        emit_error(ctx, f"Query validation failed for {platform}", exit_code=1)
    from opentide.cli.exit_codes import validation_outcome

    outcome = validation_outcome()
    result: dict[str, object] = {
        "platform": platform,
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
