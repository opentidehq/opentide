"""Validation services for the CLI."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, cast

from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS, ValidateCheck
from opentide.cli.output import emit, emit_error
from opentide.core.logging import log
from opentide.core.registry import OpenTide
from opentide.validation.pipeline import validate_all_objects

if TYPE_CHECKING:
    from opentide.cli.context import CliContext


def _reset_validation_env() -> None:
    os.environ["VALIDATION_ERROR_RAISED"] = ""
    os.environ["VALIDATION_WARNING_RAISED"] = ""


def run_id_uniqueness() -> None:
    from opentide.validation import id_uniqueness

    id_uniqueness.run()


def run_uuid_format() -> None:
    from opentide.validation import uuid_v4

    uuid_v4.run()


def run_schema_validation() -> dict[str, list[str]]:
    """Pydantic schema validation across all indexed objects."""
    OpenTide.initialise()
    return validate_all_objects(OpenTide.Index["objects"])


def run_cve_validation() -> None:
    from opentide.validation import cve

    cve.run()


def run_validate_check(check: ValidateCheck) -> dict[str, object]:
    """Run a single validation check."""
    if check is ValidateCheck.id_uniqueness:
        run_id_uniqueness()
        return {"check": check.value, "status": "completed"}
    if check is ValidateCheck.uuid_format:
        run_uuid_format()
        return {"check": check.value, "status": "completed"}
    if check is ValidateCheck.schema:
        errors = run_schema_validation()
        if errors:
            os.environ["VALIDATION_ERROR_RAISED"] = "1"
            return {"check": check.value, "status": "failed", "errors": errors}
        return {"check": check.value, "status": "passed", "errors": {}}
    if check is ValidateCheck.cve:
        run_cve_validation()
        return {"check": check.value, "status": "completed"}
    raise ValueError(f"Unknown check: {check}")


def run_validate_all() -> dict[str, object]:
    """Run all default validation checks (Orchestration/validate.py parity)."""
    _reset_validation_env()
    results: dict[str, object] = {}
    for check in (ValidateCheck.id_uniqueness, ValidateCheck.uuid_format, ValidateCheck.schema):
        results[check.value] = run_validate_check(check)
    return results


def run_validate(
    ctx: CliContext,
    *,
    check: ValidateCheck | None = None,
    strict: bool = False,
) -> dict[str, object]:
    """Entry point for validate command."""
    ctx.apply_environment()
    _reset_validation_env()

    if check is None:
        result = run_validate_all()
    else:
        result = {check.value: run_validate_check(check)}

    from opentide.cli.exit_codes import exit_on_validation_errors, exit_on_validation_warnings

    exit_on_validation_errors()
    if strict:
        exit_on_validation_warnings()
    else:
        exit_on_validation_warnings()

    if not ctx.json_output:
        if os.environ.get("VALIDATION_WARNING_RAISED"):
            log("WARNING", "Passed validation, but with some warnings")
        else:
            log("SUCCESS", "All content successfully passed validation")

    return {"checks": result}


def validate_query_platform(
    ctx: CliContext,
    platform: str,
    *,
    plan: str | None = None,
    wide: bool = False,
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
    deployment_plan = DeploymentStrategy.load_from_environment()
    deployment_list = make_deploy_plan(
        deployment_plan,
        wide_scope=wide,
        keep_deprecated=False,
    )

    if platform not in deployment_list:
        return {
            "platform": platform,
            "status": "skipped",
            "message": "No rules to validate for this platform in the current plan",
        }

    query_validators = cast(dict[str, Any], DeployTide.query_validation)
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

    log("TITLE", f"Query Validation - {system_name}")
    validator = cast(Any, query_validators[platform])
    try:
        validator.validate(deployment=deployment_list[platform])
    except Exception:
        log("WARNING", "Trying MDRv4 style method")
        validator.validate(
            mdr_deployment=deployment_list[platform],
            deployment_plan=deployment_plan,
        )

    from opentide.cli.exit_codes import exit_on_validation_errors, exit_on_validation_warnings

    exit_on_validation_errors()
    exit_on_validation_warnings()

    return {"platform": platform, "status": "passed", "supported": True}
