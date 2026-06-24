from __future__ import annotations

import os
from pathlib import Path

from opentide.core.debug import DebugEnvironment
from opentide.core.io import load_yaml
from opentide.core.logging import get_logger
from opentide.core.object_refs import object_uuid
from opentide.core.registry import DebugHelpers, OpenTide
from opentide.deployment.git_repo import modified_mdr_files
from opentide.models.deployment_enums import DeploymentStrategy, StatusStrategy
from opentide.platforms.enabled import enabled_systems

logger = get_logger(__name__)

SYSTEMS_CONFIGS_INDEX = OpenTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)

__all__ = [
    "DEPRECATED_STATUSES",
    "SYSTEMS_CONFIGS_INDEX",
    "ExternalIdHelper",
    "Proxy",
    "check_status",
    "enabled_systems",
    "make_deploy_plan",
]


def check_status(status_name: str) -> StatusStrategy:
    statuses_definitions = OpenTide.Configurations.Deployment.statuses
    for status in statuses_definitions:
        if status.name == status_name:
            if type(status.strategy) is str:
                return StatusStrategy[status.name]
            if type(status.strategy) is StatusStrategy:
                return status.strategy
            logger.critical(
                "could_not_return_status_strategy",
                detail=str(status),
                strategy_type=str(type(status.strategy)),
            )
            raise Exception

    logger.critical(
        "status_lookup_failed",
        detail=f"Requested status: {status_name}",
        available=str(statuses_definitions),
    )
    raise Exception


def make_deploy_plan(
    plan: DeploymentStrategy,
    wide_scope: bool = False,
    keep_deprecated: bool = True,
) -> dict[str, list[str]]:
    """Assemble MDR UUIDs to deploy, organized per system."""
    systems_deployment = enabled_systems()

    logger.info("compiling_deploy_plan", plan=plan.name, wide_scope=wide_scope)
    if wide_scope:
        logger.warning(
            "wide_scope_enabled",
            detail="Assembling plan without status filtering.",
        )

    mdr_files: list[Path]
    deploy_mdr: dict[str, list[str]] = {}

    if plan == "FULL":
        mdr_path = Path(OpenTide.Configurations.Global.Paths.Tide.rule)
        mdr_files = [mdr_path / mdr for mdr in os.listdir(mdr_path)]
        logger.info("full_redeploy_scope", mdr_count=len(mdr_files))
    else:
        mdr_files = modified_mdr_files(plan)

    for rule in mdr_files:
        data = load_yaml(rule)
        name = data["name"]
        conf_data = data["configurations"]
        mdr_uuid = object_uuid(data)

        for system in conf_data:
            platform_status = conf_data[system]["status"]

            if system not in systems_deployment:
                logger.error(
                    "system_disabled_for_deploy",
                    system=system.upper(),
                    rule=name,
                )
                continue

            if (
                keep_deprecated is False
                and check_status(platform_status) in DEPRECATED_STATUSES
            ):
                logger.info(
                    "skip_deprecated_status",
                    system=system,
                    status=platform_status,
                )
                continue

            if wide_scope:
                deploy_mdr.setdefault(system, []).append(mdr_uuid)
                continue

            if plan is DeploymentStrategy.PRODUCTION:
                allowed = (
                    StatusStrategy.RELEASE,
                    StatusStrategy.UNIVERSAL,
                    StatusStrategy.DISABLEMENT,
                    StatusStrategy.DELETION,
                )
            elif plan is DeploymentStrategy.STAGING:
                allowed = (StatusStrategy.PREVIEW, StatusStrategy.UNIVERSAL)
            else:
                allowed = ()

            if check_status(platform_status) in allowed:
                deploy_mdr.setdefault(system, []).append(mdr_uuid)
                logger.info(
                    "mdr_selected_for_deploy",
                    system=system.upper(),
                    status=platform_status,
                    plan=plan.name,
                    rule=name,
                )
            else:
                logger.warning(
                    "mdr_skipped_for_plan",
                    system=system.upper(),
                    status=platform_status,
                    plan=plan.name,
                    rule=name,
                )

    return deploy_mdr


class Proxy:
    """Encapsulates proxy setup for environment variables."""

    @staticmethod
    def set_proxy() -> None:
        if DebugEnvironment.ENABLED and not DebugEnvironment.PROXY_ENABLED:
            return

        logger.info("setting_proxy_from_ci_variables")
        proxy_config = DebugHelpers.fetch_config_envvar(
            OpenTide.Configurations.Deployment.proxy
        )
        proxy_user = proxy_config.get("proxy_user")
        proxy_pass = proxy_config.get("proxy_password")
        proxy_host = proxy_config.get("proxy_host")
        proxy_port = proxy_config.get("proxy_port")

        if proxy_host and proxy_port:
            if proxy_user and proxy_pass:
                proxy = f"http://{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_port}"
            else:
                proxy = f"http://{proxy_host}:{proxy_port}"

            os.environ["HTTP_PROXY"] = proxy
            os.environ["HTTPS_PROXY"] = proxy
            logger.info("proxy_setup_successful")
        else:
            logger.error(
                "proxy_setup_failed",
                detail="proxy_host and proxy_port are required in CI variables",
            )

    @staticmethod
    def unset_proxy() -> None:
        os.environ["HTTP_PROXY"] = ""
        os.environ["HTTPS_PROXY"] = ""
        logger.info("proxy_reset")


class ExternalIdHelper:
    """Utility class to help processing external rule IDs in MDR files."""

    @staticmethod
    def remove_id(rule_id: int | str, tenant_name: str, mdr_uuid: str) -> None:
        file_path = (
            OpenTide.Configurations.Global.Paths.Tide.rule
            / OpenTide.Models.files[mdr_uuid]
        )
        content = file_path.read_text(encoding="utf-8").splitlines(keepends=True)
        updated = [
            line
            for line in content
            if line.strip() != f"rule_id::{tenant_name}: {rule_id}"
        ]
        file_path.write_text("".join(updated), encoding="utf-8")
        logger.info("external_id_removed", tenant=tenant_name)

    @staticmethod
    def insert_id(
        rule_id: int | str,
        tenant_name: str,
        mdr_uuid: str,
        system_name: str,
    ) -> None:
        file_path = (
            OpenTide.Configurations.Global.Paths.Tide.rule
            / OpenTide.Models.files[mdr_uuid]
        )
        content = file_path.read_text(encoding="utf-8").splitlines(keepends=True)
        updated: list[str] = []
        for line in content:
            if line.strip().removesuffix(":").strip() == system_name:
                updated.append(line)
                updated.append(f"    rule_id::{tenant_name}: {rule_id}\n")
            else:
                updated.append(line)

        file_path.write_text("".join(updated), encoding="utf-8")
        logger.info(
            "external_id_inserted",
            tenant=tenant_name,
            rule_id=str(rule_id),
        )
