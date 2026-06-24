"""Deployment services for the CLI."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, cast

import structlog

from opentide.cli.enums import DetectionPlatform
from opentide.core.index_manager import IndexManager
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
    from opentide.deployment import (
        CIEnvironment,
        DeploymentStrategy,
        make_deploy_plan,
        modified_mdr_files,
    )
    from opentide.mutation.promotion import PromoteMDR
    from opentide.platforms.plugins import DeployTide
    from opentide.core.registry import OpenTide

    OpenTide.reload()
    deployment_plan = DeploymentStrategy.load_from_environment()
    if deployment_plan is DeploymentStrategy.PRODUCTION and (not skip_promotion):
        pre_deployment = modified_mdr_files(deployment_plan)
        emit_section("Pre-deployment Routine")
        PromoteMDR().promote(pre_deployment)
    deployment_list = make_deploy_plan(
        deployment_plan, wide_scope=wide, keep_deprecated=keep_deprecated
    )
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
        logger.error("nothing_could_deploy_no_mdr_can_be_addressed_within_this_deploym")
        if environment is CIEnvironment.CIPlatforms.GitlabCI:
            raise SystemExit(19)
        if environment is CIEnvironment.CIPlatforms.GitHubActions:
            print("::warning::No deployment was identified in this context")
            return {"status": "empty", "deployed": []}
        raise SystemExit(0)
    IndexManager.reload()
    mdr_deployers = cast(dict[str, Any], DeployTide().mdr)
    deployed: list[str] = []
    plan_payload: dict[str, list[str]] = {
        system: list(uuids) for system, uuids in deployment_list.items()
    }
    payloads: dict[str, list[dict[str, object]]] = {}
    for system, uuids in deployment_list.items():
        if system not in mdr_deployers:
            logger.critical("fatal_error", detail=f"Cannot find a deployment engine for {system}")
            raise SystemExit(1)
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
    from opentide.cli.exit_codes import exit_on_deployment_errors, exit_on_deployment_warnings

    exit_on_deployment_errors()
    exit_on_deployment_warnings()
    if not ctx.json_output:
        logger.info("all_content_passed_deployment")
    result: dict[str, object] = {
        "status": "completed",
        "deployed": deployed,
        "dry_run": dry_run,
        "plan": plan_payload,
    }
    if dry_run:
        result["payloads"] = payloads
    return result
