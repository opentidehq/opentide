import sys
from collections.abc import Sequence

import structlog

from opentide.core import deploy_events
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import DetectionPlatforms, Opentide
from opentide.deployment import TideDeployment, check_status
from opentide.deployment.external_ids import (
    ExternalIdAction,
    plan_external_id,
    record_created,
    record_deleted,
    report_failure,
    screen_tenant,
)
from opentide.models.deployment_enums import RunStrategies, StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels, batch_tenant
from opentide.platforms.plugins import RuleDeployer
from opentide.platforms.sentinel_one.client import DetectionRule as SentinelOneApiRule
from opentide.platforms.sentinel_one.client import SentinelOneService, SeverityMapping
from opentide.states.deployment import DeploymentStateError

logger = structlog.get_logger("opentide.platforms.sentinel_one.deployer")
PLATFORM = "sentinel_one"


class SentinelOneDeploy(RuleDeployer):
    def compile_deployment(
        self, data: DetectionRule, tenant_config: ConfigurationModels.Systems.SentinelOne.Tenant
    ) -> SentinelOneApiRule:
        """
        Builds the Detection Rule call made to the API
        """

        def _convert_to_minutes(timespan: str) -> int:
            """
            Helper class to normalize all time expression to minutes
            """
            if timespan.endswith("m"):
                timespan_in_minute = timespan.removesuffix("m")
            elif timespan.endswith("h"):
                timespan_in_minute = int(timespan.removesuffix("h")) * 60
            else:
                raise ValueError(
                    f"SentinelOne expects a duration in minutes (30m) or hours (2h), "
                    f"got {timespan!r}"
                )
            return int(timespan_in_minute)

        mdr_config = data.platform_configs().sentinel_one
        if not mdr_config:
            sys.exit(1)
        rule_name = data.name
        rule_description = data.description
        rule_expiration_mode = "Permanent"
        rule_severity = SeverityMapping[data.alert_severity].value
        rule_expiration = None
        rule_status = (
            "Disabled"
            if check_status(mdr_config.status) is StatusStrategy.DISABLEMENT
            else "Active"
        )
        if details := mdr_config.details:
            if details.name:
                rule_name = details.name
            if details.description:
                rule_description = details.description
            if details.severity:
                rule_severity = details.severity
            if details.expiration:
                rule_expiration_mode = "Temporary"
                rule_expiration = details.expiration
        if mdr_config.response:
            treat_as_threat = mdr_config.response.treat_as_threat
            network_quarantine = mdr_config.response.network_quarantine
            if treat_as_threat is False:
                treat_as_threat = "UNDEFINED"
        else:
            treat_as_threat = None
            network_quarantine = None
        cool_off = None
        if mdr_config.condition.cool_off:
            cool_off = SentinelOneApiRule.Data.CoolOffSettings(
                renotifyMinutes=_convert_to_minutes(mdr_config.condition.cool_off)
            )
        if mdr_config.condition.type not in ["Single Event", "Correlation"]:
            raise Exception
        if mdr_config.condition.type == "Single Event":
            single_event_data = mdr_config.condition.single_event
            if not single_event_data:
                logger.error("missing_single_event_section_in_rule", detail=data.metadata.uuid)
                raise Exception
            query = single_event_data.query
            rule_data = SentinelOneApiRule.Data(
                name=rule_name,
                queryType="events",
                s1ql=query,
                severity=rule_severity,
                status=rule_status,
                expirationMode=rule_expiration_mode,
                expiration=rule_expiration,
                description=rule_description,
                networkQuarantine=network_quarantine,
                treatAsThreat=treat_as_threat,
                coolOffSetting=cool_off,
            )
        elif mdr_config.condition.type == "Correlation":
            correlation_data = mdr_config.condition.correlation
            if not correlation_data:
                logger.error("missing_correlation_section_in_rule", detail=data.metadata.uuid)
                raise Exception
            sub_queries = []
            for sub_query in correlation_data.sub_queries:
                sub_queries.append(
                    SentinelOneApiRule.Data.CorrelationParams.SubQueries(
                        matchesRequired=sub_query.matches_required, subQuery=sub_query.query
                    )
                )
            time_window_config = None
            if correlation_data.time_window:
                time_window_data = correlation_data.time_window
                time_window_config = SentinelOneApiRule.Data.CorrelationParams.TimeWindow(
                    windowMinutes=_convert_to_minutes(time_window_data)
                )
            correlation_config = SentinelOneApiRule.Data.CorrelationParams(
                entity=correlation_data.entity,
                matchInOrder=correlation_data.match_in_order,
                subQueries=sub_queries,
                timeWindow=time_window_config,
            )
            rule_data = SentinelOneApiRule.Data(
                name=rule_name,
                queryType="correlation",
                correlationParams=correlation_config,
                severity=rule_severity,
                status=rule_status,
                expirationMode=rule_expiration_mode,
                expiration=rule_expiration,
                description=rule_description,
                networkQuarantine=network_quarantine,
                treatAsThreat=treat_as_threat,
                coolOffSetting=cool_off,
            )
        if tenant_config.setup.site_id:
            deployment_filter = SentinelOneApiRule.Filter(
                siteIds=[str(tenant_config.setup.site_id)]
            )
        elif tenant_config.setup.account_id:
            deployment_filter = SentinelOneApiRule.Filter(
                accountIds=[str(tenant_config.setup.account_id)]
            )
        return SentinelOneApiRule(data=rule_data, filter=deployment_filter)

    def deploy_mdr(
        self,
        data: DetectionRule,
        service: SentinelOneService,
        tenant_config: ConfigurationModels.Systems.SentinelOne.Tenant,
        action: ExternalIdAction | None = None,
    ):
        """
        Deploys the detection rule : creation, update, deletion and disabling.
        """
        mdr_config = data.platform_configs().sentinel_one
        if not mdr_config:
            raise Exception
        rule = self.compile_deployment(data=data, tenant_config=tenant_config)
        object_uuid = str(data.metadata.uuid)
        tenant = tenant_config.name
        if action is None:
            try:
                action = plan_external_id(
                    object_uuid=object_uuid,
                    platform=PLATFORM,
                    tenant_name=tenant,
                    status=mdr_config.status,
                )
            except DeploymentStateError as error:
                report_failure(
                    error, object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant
                )
                return
        if action.kind == "delete":
            logger.info(
                "step_in_progress",
                detail=f"Proceeding with deletion of rule against tenant {tenant}",
                context=str(action.external_id),
            )
            service.delete_detection_rule(rule_id=int(action.known_id()))
            try:
                record_deleted(object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant)
            except DeploymentStateError as error:
                report_failure(
                    error, object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant
                )
        elif action.kind == "update":
            logger.info("event", detail=str(action.external_id), advice="Going to update the rule")
            service.create_update_detection_rule(rule, int(action.known_id()))
        else:
            logger.info(
                "event",
                detail=f"No ID recorded for tenant {tenant}",
                advice="Will create a new rule, and record its ID in .opentide/states/deployment/",
            )
            rule_id = service.create_update_detection_rule(rule)
            try:
                record_created(
                    object_uuid=object_uuid,
                    platform=PLATFORM,
                    tenant_name=tenant,
                    external_id=rule_id,
                )
            except DeploymentStateError as error:
                report_failure(
                    error, object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant
                )

    def deploy(
        self,
        mdr_deployment: Sequence[DetectionRule] | Sequence[str],
        strategies: RunStrategies | None = None,
    ) -> None:
        """
        Triggers the deployment sequence for a series of MDR uuids or DetectionRule objects
        """
        logger.info("received_deployment_information", detail=str(mdr_deployment))
        loaded_mdr = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded_mdr.append(Opentide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr
        deployment = TideDeployment(
            deployment=mdr_deployment, system=DetectionPlatforms.SENTINEL_ONE, strategies=strategies
        )
        for tenant_deployment in deployment.rule_deployment:
            tenant_config = batch_tenant(
                tenant_deployment, ConfigurationModels.Systems.SentinelOne.Tenant
            )
            # Plan against the deployment state before the client exists, so a
            # refused rule makes no HTTP call.
            planned = screen_tenant(
                list(tenant_deployment.rules),
                platform=PLATFORM,
                tenant_name=tenant_config.name,
                status_of=lambda mdr: mdr.platform_configs().sentinel_one.status,
                strategies=strategies,
            )
            if not planned:
                continue
            service = SentinelOneService(tenant_config)
            for mdr, action in planned:
                with deploy_events.deploying(
                    PLATFORM, tenant_config.name, mdr.metadata.uuid, mdr.name
                ):
                    self.deploy_mdr(
                        data=mdr, service=service, tenant_config=tenant_config, action=action
                    )


def declare():
    return SentinelOneDeploy()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SentinelOneDeploy().deploy(
        DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, (StatusStrategy.PREVIEW,)
    )
