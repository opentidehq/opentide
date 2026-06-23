import sys
from typing import Sequence
from dataclasses import asdict
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide, DetectionPlatforms, ObjectLoader
from opentide.platforms.plugins import RuleDeployer
from opentide.models.rule import DetectionRule
from opentide.models.legacy import DeploymentStrategy
from opentide.deployment import TideDeployment, ExternalIdHelper, check_status
from opentide.models.legacy import ConfigurationModels, StatusStrategy
from opentide.platforms.sentinel_one.client import SentinelOneService, DetectionRule as SentinelOneApiRule, SeverityMapping
import structlog
logger = structlog.get_logger('opentide.platforms.sentinel_one.deployer')

class SentinelOneDeploy(RuleDeployer):

    def compile_deployment(self, data: DetectionRule, tenant_config: ConfigurationModels.Systems.SentinelOne.Tenant) -> SentinelOneApiRule:
        """
        Builds the Detection Rule call made to the API
        """

        def _convert_to_minutes(timespan: str) -> int:
            """
            Helper class to normalize all time expression to minutes
            """
            if timespan.endswith('m'):
                timespan_in_minute = timespan.removesuffix('m')
            elif timespan.endswith('h'):
                timespan_in_minute = int(timespan.removesuffix('h')) * 60
            return int(timespan_in_minute)
        mdr_config = data.configurations.sentinel_one
        if not mdr_config:
            exit()
        rule_name = data.name
        rule_description = data.description
        rule_expiration_mode = 'Permanent'
        rule_severity = SeverityMapping[data.response.alert_severity].value
        rule_expiration = None
        rule_status = 'Disabled' if check_status(mdr_config.status) is StatusStrategy.DISABLEMENT else 'Active'
        if (details := mdr_config.details):
            if details.name:
                rule_name = details.name
            if details.description:
                rule_description = details.description
            if details.severity:
                rule_severity = details.severity
            if details.expiration:
                rule_expiration_mode = 'Temporary'
                rule_expiration = details.expiration
        if mdr_config.response:
            treat_as_threat = mdr_config.response.treat_as_threat
            network_quarantine = mdr_config.response.network_quarantine
            if treat_as_threat is False:
                treat_as_threat = 'UNDEFINED'
        else:
            treat_as_threat = None
            network_quarantine = None
        cool_off = mdr_config.condition.cool_off
        if cool_off is str:
            cool_off = SentinelOneApiRule.Data.CoolOffSettings(renotifyMinutes=_convert_to_minutes(cool_off))
        if mdr_config.condition.type not in ['Single Event', 'Correlation']:
            raise Exception
        if mdr_config.condition.type == 'Single Event':
            single_event_data = mdr_config.condition.single_event
            if not single_event_data:
                logger.error('missing_single_event_section_in_mdr', detail=data.metadata.uuid)
                raise Exception
            query = single_event_data.query
            rule_data = SentinelOneApiRule.Data(name=rule_name, queryType='events', s1ql=query, severity=rule_severity, status=rule_status, expirationMode=rule_expiration_mode, expiration=rule_expiration, description=rule_description, networkQuarantine=network_quarantine, treatAsThreat=treat_as_threat, coolOffSetting=cool_off)
        elif mdr_config.condition.type == 'Correlation':
            correlation_data = mdr_config.condition.correlation
            if not correlation_data:
                logger.error('missing_correlation_section_in_mdr', detail=data.metadata.uuid)
                raise Exception
            sub_queries = []
            for sub_query in correlation_data.sub_queries:
                sub_queries.append(SentinelOneApiRule.Data.CorrelationParams.SubQueries(matchesRequired=sub_query.matches_required, subQuery=sub_query.query))
            time_window_config = None
            if correlation_data.time_window:
                time_window_data = correlation_data.time_window
                time_window_config = SentinelOneApiRule.Data.CorrelationParams.TimeWindow(windowMinutes=_convert_to_minutes(time_window_data))
            correlation_config = SentinelOneApiRule.Data.CorrelationParams(entity=correlation_data.entity, matchInOrder=correlation_data.match_in_order, subQueries=sub_queries, timeWindow=time_window_config)
            rule_data = SentinelOneApiRule.Data(name=rule_name, queryType='correlation', correlationParams=correlation_config, severity=rule_severity, status=rule_status, expirationMode=rule_expiration_mode, expiration=rule_expiration, description=rule_description, networkQuarantine=network_quarantine, treatAsThreat=treat_as_threat, coolOffSetting=cool_off)
        if tenant_config.setup.site_id:
            deployment_filter = SentinelOneApiRule.Filter(siteIds=[str(tenant_config.setup.site_id)])
        elif tenant_config.setup.account_id:
            deployment_filter = SentinelOneApiRule.Filter(accountIds=[str(tenant_config.setup.account_id)])
        return SentinelOneApiRule(data=rule_data, filter=deployment_filter)

    def deploy_mdr(self, data: DetectionRule, service: SentinelOneService, tenant_config: ConfigurationModels.Systems.SentinelOne.Tenant):
        """
        Deploys the detection rule : creation, update, deletion and disabling.
        """
        mdr_config = data.configurations.sentinel_one
        if not mdr_config:
            raise Exception
        rule = self.compile_deployment(data=data, tenant_config=tenant_config)
        if mdr_config.rule_id_bundle:
            mdr_config.rule_id_bundle
            rule_id = mdr_config.rule_id_bundle.get(tenant_config.name.strip())
            if rule_id:
                logger.info('event', detail=f'Retrieved ID for tenant {tenant_config.name} in MDR', context=str(rule_id), advice='Will perform an update')
            else:
                logger.info('event', detail=f'Could not retrieve ID for tenant {tenant_config.name} in MDR existing rule IDs', context=str(mdr_config.rule_id_bundle), advice='Will create a new rule, and write back the ID to the file')
        else:
            logger.info('event', detail=f'Could not retrieve ID for tenant {tenant_config.name} in MDR', context_1='Will create a new rule, and write back the ID to the file')
            rule_id = None
        if check_status(mdr_config.status) is StatusStrategy.DELETION:
            if not rule_id:
                logger.critical('cannot_remove_the_rule_as_a_rule_id_could_not_be_found_in_the_fi', detail='You will need to manually check the target system to remove the rule')
            else:
                logger.info('step_in_progress', detail=f'Proceeding with deletion of rule against tenant {tenant_config.name}', context=str(rule_id))
                service.delete_detection_rule(rule_id=rule_id)
                ExternalIdHelper.remove_id(rule_id=rule_id, tenant_name=tenant_config.name, mdr_uuid=data.metadata.uuid)
        elif rule_id:
            logger.info('event', detail=str(rule_id), advice='Going to update the rule')
            service.create_update_detection_rule(rule, rule_id)
        else:
            rule_id = service.create_update_detection_rule(rule)
            ExternalIdHelper.insert_id(rule_id=rule_id, tenant_name=tenant_config.name, mdr_uuid=data.metadata.uuid, system_name=OpenTide.Configurations.Systems.SentinelOne.platform.identifier)

    def deploy(self, mdr_deployment: Sequence[DetectionRule] | list[str], deployment_plan: DeploymentStrategy):
        """
        Triggers the deployment sequence for a series of MDR uuids or DetectionRule objects
        """
        logger.info('received_deployment_information', detail=str(mdr_deployment))
        loaded_mdr = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded_mdr.append(OpenTide.Models.MDR[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr
        deployment = TideDeployment(deployment=mdr_deployment, system=DetectionPlatforms.SENTINEL_ONE, strategy=deployment_plan)
        for tenant_deployment in deployment.rule_deployment:
            service = SentinelOneService(tenant_deployment.tenant)
            for mdr in tenant_deployment.rules:
                self.deploy_mdr(data=mdr, service=service, tenant_config=tenant_deployment.tenant)

def declare():
    return SentinelOneDeploy()
if __name__ == '__main__' and DebugEnvironment.ENABLED:
    SentinelOneDeploy().deploy(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)
