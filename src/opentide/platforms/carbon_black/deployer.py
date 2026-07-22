from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import structlog

from opentide.core.debug import DebugEnvironment
from opentide.core.registry import DetectionPlatforms, OpenTide
from opentide.deployment import TideDeployment, check_status
from opentide.generation.framework import techniques_resolver
from opentide.models.deployment_enums import DeploymentStrategy, StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.carbon_black.client import (
    CarbonBlackCloudConnection,
    CarbonBlackCloudService,
)
from opentide.platforms.plugins import RuleDeployer

if TYPE_CHECKING:
    from cbc_sdk.rest_api import CBCloudAPI

logger = structlog.get_logger(__name__)


class CarbonBlackCloudDeploy(CarbonBlackCloudConnection, RuleDeployer):
    def _deploy_to_org(
        self,
        *,
        service: CBCloudAPI,
        data: DetectionRule,
        org: str,
        config_data: dict[str, object],
    ) -> bool:
        from cbc_sdk.enterprise_edr import IOC_V2, Report, Watchlist

        uuid = data.metadata.uuid
        name = data.name.strip()
        description = (data.description or "").strip()
        status = str(config_data["status"])
        query = str(config_data["query"]).replace("\n", " ")
        deployment = check_status(status) not in (
            StatusStrategy.DISABLEMENT,
            StatusStrategy.DELETION,
        )
        removal = not deployment

        tags: list[str] = [status]
        if data.detection_model:
            techniques = techniques_resolver(str(uuid))
            tags.append(str(data.detection_model))
            tags.extend(techniques)
        if config_tags := config_data.get("tags"):
            tags.extend(list(config_tags))  # type: ignore[arg-type]

        alert_severity = data.response.alert_severity if data.response else "Low"
        severity = self.SEVERITY_MAPPING[str(alert_severity)]
        selected_watchlist = config_data.get("watchlist") or self.DEFAULT_WATCHLIST
        selected_report = config_data.get("report") or name

        watchlist_list = service.select(Watchlist)
        report = None
        watchlist = None
        if watchlist_list:
            for item in watchlist_list:
                if item.name == selected_watchlist:
                    watchlist = item
            if watchlist:
                for item in watchlist.reports:
                    if item.title == selected_report:
                        report = item
            else:
                raise RuntimeError(
                    f"The CBC Deployer cannot create a detection in a nonexistent Watchlist: "
                    f"{selected_watchlist}. Create it on the console before retriggering deployment."
                )

        ioc = IOC_V2.create_query(service, uuid, query)
        if report:
            if selected_report == name:
                if deployment:
                    report.remove_iocs_by_id(str(uuid))
                    report.append_iocs([ioc])
                    if severity != report.severity:
                        report.update(description=description, tags=tags, severity=severity)
                        logger.info("upgraded_severity_for_report", severity=str(severity))
                    else:
                        report.update(description=description, tags=tags)
                    logger.info("rolled_out_ioc_to_report", report=selected_report)
                elif removal:
                    report.delete()
                    logger.warning("report_deleted_with_rule", report=selected_report)
            elif deployment:
                report.remove_iocs_by_id(uuid)
                report.append_iocs([ioc])
                tags.extend(tag for tag in report.tags if tag not in tags)
                if severity > report.severity:
                    report.update(description=description, tags=tags, severity=severity)
                    logger.info("upgraded_severity_for_report", severity=str(severity))
                else:
                    report.update(description=description, tags=tags)
                logger.info("deployed_ioc_to_report", report=selected_report)
            elif removal:
                if len(report.iocs_) > 1:
                    report.remove_iocs_by_id(uuid)
                    report.update()
                    logger.info("deleted_ioc_from_report", report=selected_report)
                else:
                    report.delete()
                    logger.warning("report_auto_deleted", report=selected_report)
        elif deployment:
            report_builder = Report.create(service, selected_report, description, severity)
            report_builder.add_ioc(ioc)
            for tag in tags:
                report_builder.add_tag(str(tag).strip())
            new_report = report_builder.build()
            new_report.save_watchlist()
            watchlist.add_reports([new_report])
            logger.info("created_report_and_deployed_ioc", report=selected_report)
        elif removal:
            logger.info("no_report_to_delete", report=selected_report)
        return True

    def deploy_mdr(
        self,
        data: DetectionRule,
        service: CBCloudAPI,
        tenant_config: ConfigurationModels.Systems.CarbonBlackCloud.Tenant,
    ) -> bool | None:
        """Deploy a single typed MDR to Carbon Black Cloud."""
        config = data.configurations.carbon_black_cloud
        if not config or not config.query:
            logger.info("mdr_skipped", mdr_name=data.name, reason="no typed CBC configuration")
            return None

        config_data = {
            "status": config.status,
            "query": config.query,
            "watchlist": config.watchlist,
            "report": config.report,
            "tags": config.tags,
        }
        return self._deploy_to_org(
            service=service,
            data=data,
            org=tenant_config.name,
            config_data=config_data,
        )

    def deploy(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        """Deploy CBC MDRs through TideDeployment tenant routing."""
        if not deployment_plan:
            raise ValueError("deployment_plan is required for CBC deployment")

        self.configure_proxy()
        loaded_mdr: list[DetectionRule] = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded_mdr.append(OpenTide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)
        if not loaded_mdr:
            logger.info("no_mdrs_to_deploy_for_carbon_black_cloud")
            return

        tide_deployment = TideDeployment(
            deployment=loaded_mdr,
            system=DetectionPlatforms.CARBON_BLACK_CLOUD,
            strategy=deployment_plan,
        )
        for tenant_deployment in tide_deployment.rule_deployment:
            logger.info("currently_targeting_tenant", tenant=tenant_deployment.tenant.name)
            cbc_service = CarbonBlackCloudService(tenant_deployment.tenant)
            for mdr in tenant_deployment.rules:
                logger.info("processing_rule", mdr_name=mdr.name, uuid=mdr.metadata.uuid)
                self.deploy_mdr(
                    data=mdr,
                    service=cbc_service.service,
                    tenant_config=tenant_deployment.tenant,
                )


def declare():
    return CarbonBlackCloudDeploy()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    CarbonBlackCloudDeploy().deploy(
        DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG
    )
