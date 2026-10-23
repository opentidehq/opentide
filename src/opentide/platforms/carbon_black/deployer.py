from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import structlog

from opentide.core.debug import DebugEnvironment
from opentide.core.registry import DetectionPlatforms, Opentide
from opentide.deployment import TideDeployment, check_status
from opentide.deployment.external_ids import without_legacy_external_ids
from opentide.generation.framework import techniques_resolver
from opentide.models.deployment_enums import RunStrategies, StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels, batch_tenant
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
        config_tags = config_data.get("tags")
        if isinstance(config_tags, (list, tuple)):
            tags.extend(str(tag) for tag in config_tags)

        alert_severity = data.alert_severity if data.response else "Low"
        severity = self.SEVERITY_MAPPING[str(alert_severity)]
        selected_watchlist = str(config_data.get("watchlist") or "")
        selected_report = config_data.get("report") or name

        watchlist_list = service.select(Watchlist)
        report = None
        watchlist = None
        for item in watchlist_list or []:
            if item.name == selected_watchlist:
                watchlist = item
        # An org with no watchlist at all used to fall through and fail later
        # with AttributeError on None.
        if watchlist is None:
            raise RuntimeError(
                "The CBC Deployer cannot create a detection in a nonexistent Watchlist: "
                f"{selected_watchlist}. Create it on the console before retriggering "
                "deployment."
            )
        for item in watchlist.reports:
            if item.title == selected_report:
                report = item

        ioc = IOC_V2.create_query(service, uuid, query)
        # remove_iocs_by_id takes a list: given the string it removed nothing,
        # since a set of its characters matches no IOC id.
        own_ioc = [str(uuid)]
        if report:
            if selected_report == name:
                if deployment:
                    report.remove_iocs_by_id(own_ioc)
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
                report.remove_iocs_by_id(own_ioc)
                report.append_iocs([ioc])
                tags.extend(tag for tag in report.tags if tag not in tags)
                if severity > report.severity:
                    report.update(description=description, tags=tags, severity=severity)
                    logger.info("upgraded_severity_for_report", severity=str(severity))
                else:
                    report.update(description=description, tags=tags)
                logger.info("deployed_ioc_to_report", report=selected_report)
            elif removal:
                # A shared report holds other rules' IOCs: delete it only once
                # this rule's IOC was the last one, never for a lone IOC that
                # belongs to another rule.
                report.remove_iocs_by_id(own_ioc)
                if report.iocs_:
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
        config = data.platform_configs().carbon_black_cloud
        if not config or not config.query:
            logger.info("mdr_skipped", mdr_name=data.name, reason="no typed CBC configuration")
            return None

        config_data = {
            "status": config.status,
            "query": config.query,
            # The tenant's own watchlist, not DEFAULT_WATCHLIST: that one is
            # the first tenant's, and every other tenant has its own.
            "watchlist": config.watchlist or tenant_config.setup.watchlist,
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
        mdr_deployment: Sequence[DetectionRule] | Sequence[str],
        strategies: RunStrategies | None = None,
    ) -> None:
        """Deploy CBC MDRs through TideDeployment tenant routing."""
        if not strategies:
            raise ValueError("run strategies are required for CBC deployment")

        loaded_mdr: list[DetectionRule] = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded_mdr.append(Opentide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)
        loaded_mdr = without_legacy_external_ids(loaded_mdr, platform="carbon_black_cloud")
        if not loaded_mdr:
            logger.info("no_mdrs_to_deploy_for_carbon_black_cloud")
            return

        tide_deployment = TideDeployment(
            deployment=loaded_mdr,
            system=DetectionPlatforms.CARBON_BLACK_CLOUD,
            strategies=strategies,
        )
        for tenant_deployment in tide_deployment.rule_deployment:
            tenant_config = batch_tenant(
                tenant_deployment, ConfigurationModels.Systems.CarbonBlackCloud.Tenant
            )
            logger.info("currently_targeting_tenant", tenant=tenant_config.name)
            cbc_service = CarbonBlackCloudService(tenant_config)
            for mdr in tenant_deployment.rules:
                logger.info("processing_rule", mdr_name=mdr.name, uuid=mdr.metadata.uuid)
                self.deploy_mdr(
                    data=mdr,
                    service=cbc_service.service,
                    tenant_config=tenant_config,
                )


def declare():
    return CarbonBlackCloudDeploy()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    CarbonBlackCloudDeploy().deploy(
        DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, (StatusStrategy.PREVIEW,)
    )
