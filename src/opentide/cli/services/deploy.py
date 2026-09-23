"""Deployment services for the CLI."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, cast

import structlog

from opentide.cli.enums import DetectionPlatform
from opentide.core.index_manager import IndexManager
from opentide.core.logging.config import get_stdout_console
from opentide.core.logging.console import emit_section

logger = structlog.get_logger("opentide.cli.services.deploy")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext


def _nothing_to_deploy(message: str, *, dry_run: bool, **fields: object) -> dict[str, object]:
    """A skipped deploy, in the same envelope as one that planned rules."""
    result: dict[str, object] = {
        **fields,
        "status": "skipped",
        "message": message,
        "deployed": [],
        "dry_run": dry_run,
        "plan": {},
    }
    if dry_run:
        result["payloads"] = {}
    return result


def run_deploy(
    ctx: CliContext,
    *,
    platform: DetectionPlatform | None = None,
    plan: str | None = None,
    dry_run: bool = False,
    skip_promotion: bool = False,
    keep_deprecated: bool = False,
    wide: bool = False,
) -> dict[str, object]:
    """Deploy detection rules (Orchestration/deploy.py parity)."""
    plan_warnings: list[str] = []
    result = _deploy(
        ctx,
        plan_warnings,
        platform=platform,
        plan=plan,
        dry_run=dry_run,
        skip_promotion=skip_promotion,
        keep_deprecated=keep_deprecated,
        wide=wide,
    )
    if plan_warnings:
        result["warnings"] = [*plan_warnings, *cast(list[str], result.get("warnings", []))]
    return result


def _deploy(
    ctx: CliContext,
    plan_warnings: list[str],
    *,
    platform: DetectionPlatform | None,
    plan: str | None,
    dry_run: bool,
    skip_promotion: bool,
    keep_deprecated: bool,
    wide: bool,
) -> dict[str, object]:
    ctx.apply_environment()
    os.environ["INDEX_OUTPUT"] = "cache"
    if plan is not None:
        ctx.set_deployment_plan(plan)
    from opentide.core.registry import OpenTide
    from opentide.deployment import (
        CIEnvironment,
        DeploymentStrategy,
        make_deploy_plan,
        modified_mdr_files,
    )
    from opentide.mutation.promotion import PromoteMDR
    from opentide.platforms.plugins import DeployTide

    OpenTide.reload()
    try:
        deployment_plan = DeploymentStrategy.load_from_environment()
        local_debug = CIEnvironment().environment is CIEnvironment.CIPlatforms.LocalDebug
        if (
            deployment_plan is DeploymentStrategy.PRODUCTION
            and not skip_promotion
            and not dry_run
            and not local_debug
        ):
            pre_deployment = modified_mdr_files(deployment_plan)
            emit_section("Pre-deployment Routine")
            PromoteMDR().promote(pre_deployment)
        deployment_list = make_deploy_plan(
            deployment_plan,
            wide_scope=wide,
            keep_deprecated=keep_deprecated,
            warnings=plan_warnings,
        )
    except ValueError as exc:
        return {"status": "failed", "message": str(exc), "_exit_code": 1}
    except Exception as exc:
        message = str(exc).strip() or (f"{type(exc).__name__} while compiling the deployment plan")
        return {"status": "failed", "message": message, "_exit_code": 1}
    if platform is not None:
        platform_key = platform.value
        if platform_key not in deployment_list:
            return _nothing_to_deploy(
                "No rules to deploy for this platform", dry_run=dry_run, platform=platform_key
            )
        deployment_list = {platform_key: deployment_list[platform_key]}
    if len(deployment_list) == 0:
        environment = CIEnvironment().environment
        if environment is CIEnvironment.CIPlatforms.GitHubActions and not ctx.json_output:
            # GitHub only parses workflow commands from stdout, and never wrapped.
            get_stdout_console().print(
                "::warning::No rules matched this deployment plan",
                markup=False,
                highlight=False,
                soft_wrap=True,
            )
        return _nothing_to_deploy("No rules matched this deployment plan", dry_run=dry_run)
    deployed: list[str] = []
    plan_payload: dict[str, list[str]] = {
        system: list(uuids) for system, uuids in deployment_list.items()
    }
    from opentide.platforms.enabled import MissingTenantsError, systems_without_tenants

    tenantless = [
        MissingTenantsError(system) for system in systems_without_tenants(deployment_list)
    ]
    missing_tenants = {error.system: error.config_path for error in tenantless}
    tenants_advice = "; ".join(error.advice for error in tenantless)
    if tenantless and not dry_run:
        return {
            "status": "failed",
            "message": "Cannot deploy: " + "; ".join(str(error) for error in tenantless),
            "advice": tenants_advice,
            "missing_tenants": missing_tenants,
            "deployed": deployed,
            "dry_run": False,
            "plan": plan_payload,
            "_exit_code": 1,
        }
    IndexManager.reload()
    try:
        mdr_deployers = cast(dict[str, Any], DeployTide().mdr_for(deployment_list))
    except Exception as exc:
        message = str(exc).strip() or f"{type(exc).__name__} while loading deployment engines"
        return {"status": "failed", "message": message, "deployed": deployed, "_exit_code": 1}
    payloads: dict[str, list[dict[str, object]]] = {}
    for system, uuids in deployment_list.items():
        if system not in mdr_deployers:
            return {
                "status": "failed",
                "message": f"Cannot find a deployment engine for {system}",
                "deployed": deployed,
                "_exit_code": 1,
            }
        emit_section("MDR Deployment")
        deployer = cast(Any, mdr_deployers[system])
        if dry_run:
            logger.info("event", detail=f"Dry-run: would deploy {len(uuids)} rule(s) to {system}")
            from opentide.deployment.preview import preview_platform_deployment

            payloads[system] = preview_platform_deployment(system, uuids)
            if system not in missing_tenants:
                deployed.append(system)
            continue
        try:
            deployer.deploy(mdr_deployment=uuids, deployment_plan=deployment_plan)
        except TypeError:
            logger.warning("switching_to_mdrv3_legacy_methods")
            deployer.deploy(deployment=uuids)
        deployed.append(system)
    from opentide.cli.exit_codes import deployment_outcome

    outcome = deployment_outcome()
    result: dict[str, object] = {
        "message": "Deployment finished with errors" if outcome.failed else "Deployment completed",
        "status": "failed" if outcome.failed else "completed",
        "deployed": deployed,
        "dry_run": dry_run,
        "plan": plan_payload,
        "_exit_code": outcome.exit_code,
    }
    warnings = [f"{error}, so a real deploy would stop" for error in tenantless]
    if outcome.warned:
        warnings.append("Some rules reported deployment warnings")
    if warnings:
        result["warnings"] = warnings
    if dry_run:
        result["payloads"] = payloads
        if missing_tenants:
            result["missing_tenants"] = missing_tenants
            result["advice"] = tenants_advice
    return result
