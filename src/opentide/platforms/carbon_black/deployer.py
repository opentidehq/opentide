from __future__ import annotations

from collections.abc import Sequence

import structlog
from cbc_sdk.enterprise_edr import IOC_V2, Report, Watchlist
from cbc_sdk.rest_api import CBCloudAPI

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

logger = structlog.get_logger(__name__)


class CarbonBlackCloudDeploy(CarbonBlackCloudConnection, RuleDeployer):
    def _deploy_to_org(
        self,
        *,
        service: CBCloudAPI,
        data: dict[str, object] | DetectionRule,
        org: str,
        config_data: dict[str, object],
    ) -> bool:
        uuid = (
            data.metadata.uuid
            if isinstance(data, DetectionRule)
            else str(data.get("uuid") or data["metadata"]["uuid"])  # type: ignore[index]
        )
        name = (
            data.name.strip() if isinstance(data, DetectionRule) else str(data["name"]).strip()  # type: ignore[index]
        )
        description = (
            data.description.strip()
            if isinstance(data, DetectionRule)
            else str(data["description"]).strip()  # type: ignore[index]
        )
        status = str(config_data["status"])
        query = str(config_data["query"]).replace("\n", " ")
        deployment = check_status(status) not in (
            StatusStrategy.DISABLEMENT,
            StatusStrategy.DELETION,
        )
        removal = not deployment

        tags: list[str] = [status]
        detection_model = (
            data.detection_model if isinstance(data, DetectionRule) else data.get("detection_model")  # type: ignore[union-attr]
        )
        if detection_model:
            techniques = techniques_resolver(str(uuid))
            tags.append(str(detection_model))
            tags.extend(techniques)
        if config_tags := config_data.get("tags"):
            tags.extend(list(config_tags))  # type: ignore[arg-type]

        alert_severity = (
            data.response.alert_severity
            if isinstance(data, DetectionRule) and data.response
            else data["response"]["alert_severity"]  # type: ignore[index]
        )
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

    def deploy_mdr(self, data: dict[str, object]) -> bool:
        """MDRv3 deployment routine using dict-based MDR access."""
        # TODO: DEPRECATED [carbon-black-cloud-mdrv4]
        custom_orgs = data["configurations"][self.DEPLOYER_IDENTIFIER].get("organization")  # type: ignore[index]
        deploy_orgs = custom_orgs or self.ORGANIZATIONS
        for org in deploy_orgs:
            logger.info("deploying_mdr_on_organization", mdr_name=data["name"], org=org)
            org = str(org).strip()
            org_secrets = self.CBC_SECRETS.get(org)
            if not org_secrets:
                logger.critical("organization_missing_from_secrets", org=org)
                raise KeyError(org)
            org_key = org_secrets.get("org_key")
            token = org_secrets.get("token")
            if not org_key or not token:
                logger.critical("missing_org_credentials", org=org)
                raise KeyError(org)
            try:
                service = CBCloudAPI(
                    url=self.CBC_URL,
                    token=token,
                    org_key=org_key,
                    ssl_verify=self.SSL_ENABLED,
                )
                logger.info("connected_to_cbc_tenant", org=org)
            except Exception as exc:
                raise RuntimeError(f"Service could not be reached for organization {org}") from exc
            config_data = data["configurations"][self.DEPLOYER_IDENTIFIER]  # type: ignore[index]
            self._deploy_to_org(service=service, data=data, org=org, config_data=config_data)
        return True

    def deploy_mdr_v4(
        self,
        data: DetectionRule,
        service: CBCloudAPI,
        tenant_config: ConfigurationModels.Systems.CarbonBlackCloud.Tenant,
    ) -> bool | None:
        """MDRv4 typed deployment for a single MDR on a single tenant."""
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
        mdr_deployment: Sequence[DetectionRule] | list[str] | None = None,
        deployment_plan: DeploymentStrategy | None = None,
        deployment: list[str] | None = None,
    ) -> None:
        """Deploy CBC MDRs — supports MDRv3 (UUID list) and MDRv4 (typed) signatures."""
        self.configure_proxy()

        if mdr_deployment is not None:
            loaded_mdr: list[DetectionRule] = []
            for mdr in mdr_deployment:
                if isinstance(mdr, str):
                    loaded_mdr.append(OpenTide.Rules[mdr])
                elif isinstance(mdr, DetectionRule):
                    loaded_mdr.append(mdr)
            if not loaded_mdr:
                logger.info("no_mdrs_to_deploy_for_carbon_black_cloud")
                return
            if not deployment_plan:
                raise ValueError("deployment_plan is required for MDRv4 CBC deployment")

            tide_deployment = TideDeployment(
                deployment=loaded_mdr,
                system=DetectionPlatforms.CARBON_BLACK_CLOUD,
                strategy=deployment_plan,
            )
            for tenant_deployment in tide_deployment.rule_deployment:
                tenant_deployment = tenant_deployment  # type: TenantDeployment.CarbonBlackCloud
                logger.info("currently_targeting_tenant", tenant=tenant_deployment.tenant.name)
                cbc_service = CarbonBlackCloudService(tenant_deployment.tenant)
                for mdr in tenant_deployment.rules:
                    logger.info("processing_rule", mdr_name=mdr.name, uuid=mdr.metadata.uuid)
                    self.deploy_mdr_v4(
                        data=mdr,
                        service=cbc_service.service,
                        tenant_config=tenant_deployment.tenant,
                    )
            return

        # TODO: DEPRECATED [carbon-black-cloud-mdrv4]
        if not deployment:
            raise ValueError("DEPLOYMENT NOT FOUND")
        for mdr in deployment:
            mdr_data = OpenTide.Models.rules[mdr]
            if self.DEPLOYER_IDENTIFIER in mdr_data["configurations"]:
                self.deploy_mdr(mdr_data)
            else:
                logger.info(
                    "mdr_skipped",
                    mdr_name=mdr_data.get("name"),
                    reason="no CBC rule configuration",
                )


def declare():
    return CarbonBlackCloudDeploy()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    CarbonBlackCloudDeploy().deploy(deployment=DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)
