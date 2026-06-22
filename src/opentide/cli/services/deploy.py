"""Deployment services for the CLI."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, cast

from opentide.cli.enums import DetectionPlatform
from opentide.core.index_manager import IndexManager
from opentide.core.logging import log

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

    from Engines.modules.deployment import (
        CIEnvironment,
        DeploymentStrategy,
        make_deploy_plan,
        modified_mdr_files,
    )
    from Engines.modules.plugins import DeployTide
    from Engines.mutation.promotion import PromoteMDR

    deployment_plan = DeploymentStrategy.load_from_environment()

    if deployment_plan is DeploymentStrategy.PRODUCTION and not skip_promotion:
        pre_deployment = modified_mdr_files(deployment_plan)
        log("TITLE", "Pre-deployment Routine")
        PromoteMDR().promote(pre_deployment)

    deployment_list = make_deploy_plan(deployment_plan, wide_scope=wide, keep_deprecated=keep_deprecated)

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
        log(
            "FAILURE",
            "Nothing could deploy, no MDR can be addressed within this deployment context",
        )
        if environment is CIEnvironment.CIPlatforms.GitlabCI:
            raise SystemExit(19)
        if environment is CIEnvironment.CIPlatforms.GitHubActions:
            print("::warning::No deployment was identified in this context")
            return {"status": "empty", "deployed": []}
        raise SystemExit(0)

    IndexManager.reload()

    mdr_deployers = cast(dict[str, Any], DeployTide.mdr)
    deployed: list[str] = []
    for system, uuids in deployment_list.items():
        if system not in mdr_deployers:
            log("FATAL", f"Cannot find a deployment engine for {system}")
            raise SystemExit(1)

        log("TITLE", "MDR Deployment")
        deployer = cast(Any, mdr_deployers[system])
        if dry_run:
            log("INFO", f"Dry-run: would deploy {len(uuids)} rule(s) to {system}")
            deployed.append(system)
            continue

        try:
            deployer.deploy(deployment=uuids)
        except Exception:
            log("WARNING", "Switching to MDRv4 new methods")
            deployer.deploy(mdr_deployment=uuids, deployment_plan=deployment_plan)
        deployed.append(system)

    from opentide.cli.exit_codes import exit_on_deployment_errors, exit_on_deployment_warnings

    exit_on_deployment_errors()
    exit_on_deployment_warnings()

    if not ctx.json_output:
        log("SUCCESS", "All content passed deployment")

    return {"status": "completed", "deployed": deployed, "dry_run": dry_run}
