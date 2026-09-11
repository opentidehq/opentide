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
            deployment_plan, wide_scope=wide, keep_deprecated=keep_deprecated
        )
    except ValueError as exc:
        return {"status": "failed", "message": str(exc), "_exit_code": 1}
    except Exception as exc:
        message = str(exc).strip() or (f"{type(exc).__name__} while compiling the deployment plan")
        return {"status": "failed", "message": message, "_exit_code": 1}
    if platform is not None:
        platform_key = platform.value
        if platform_key not in deployment_list:
            return {
                "status": "skipped",
                "platform": platform_key,
                "message": "No rules to deploy for this platform",
            }
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
        return {
            "status": "skipped",
            "message": "No rules matched this deployment plan",
            "deployed": [],
        }
    IndexManager.reload()
    mdr_deployers = cast(dict[str, Any], DeployTide().mdr)
    deployed: list[str] = []
    plan_payload: dict[str, list[str]] = {
        system: list(uuids) for system, uuids in deployment_list.items()
    }
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
    if outcome.warned:
        result["warnings"] = ["Some rules reported deployment warnings"]
    if dry_run:
        result["payloads"] = payloads
    return result
