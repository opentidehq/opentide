from typing import Sequence
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide, DetectionPlatforms
from opentide.platforms.plugins import RuleDeployer
from opentide.models.rule import DetectionRule
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.deployment import TideDeployment, ExternalIdHelper, check_status
from opentide.models.system_config import ConfigurationModels
from opentide.models.deployment_enums import StatusStrategy
from opentide.core.errors import Errors
from opentide.platforms.crowdstrike.client import CrowdstrikeService, DetectionRule as CrowdstrikeRule
import structlog
logger = structlog.get_logger('opentide.platforms.crowdstrike.deployer')

class CrowdstrikeDeploy(RuleDeployer):

    def compile_deployment(self, data: DetectionRule, tenant_config: ConfigurationModels.Systems.Crowdstrike.Tenant) -> CrowdstrikeRule:
        """
        Builds the Detection Rule call made to the API
        """

        def map_severity(severity: str) -> int:
            match severity:
                case 'Informational':
                    return 10
                case 'Low':
                    return 30
                case 'Medium':
                    return 50
                case 'High':
                    return 70
                case 'Critical':
                    return 90
                case _:
                    logger.critical('could_not_map_severity_to_expected_crowdstrike_values', detail='Expected Informational, Low, Medium, High or Critical')
                    raise Errors.TideConfigurationErrors('Invalid Severity')
            raise AssertionError('unreachable')
        configuration = data.configurations.crowdstrike
        if not configuration:
            logger.critical('fatal_error', detail=f'[{data.metadata.uuid}] {data.name} does not contain a crowdstrike section')
            raise Errors.TideConfigurationErrors('Missing Crowdstrike Section')
        name = configuration.details.name or data.name
        description = configuration.details.description or data.description
        customer_id = tenant_config.setup.customer_id.split('-')[0].lower()
        tactic = configuration.details.tactic
        technique = configuration.details.technique
        status = 'active' if check_status(configuration.status) is StatusStrategy.DISABLEMENT else 'inactive'
        severity = configuration.details.severity or data.response.alert_severity
        severity = map_severity(severity)
        filter = configuration.query
        lookback = configuration.schedule.lookback
        outcome = configuration.details.outcome.lower()
        trigger_mode = configuration.details.trigger.lower()
        if outcome not in ['detection', 'incident']:
            logger.critical('outcome_value_not_expected', detail=str(outcome), advice='Expects detection or incident')
            raise Errors.TideConfigurationErrors('Invalid Crowdstrike outcome value')
        if trigger_mode not in ['verbose', 'summary']:
            logger.critical('trigger_value_not_expected', detail=str(outcome), advice='Expects verbose or summary')
            raise Errors.TideConfigurationErrors('Invalid Crowdstrike outcome value')
        search = DetectionRule.Search(outcome=outcome, filter=filter, lookback=lookback, trigger_mode=trigger_mode)
        definition = configuration.schedule.frequency
        schedule = DetectionRule.Operation.Schedule(definition=f'@every {definition}')

        def fix_datetime(timestamp: str) -> str:
            """
            Fixes edge case in YAML where the user doesn't encapsulate the timestamp
            as a string, which will mess it up during serialization.
            
            For example

            * `2025-04-15T19:00:00Z` in YAML will be stored as a datetime type with string
            representation `2025-04-15 19:00:00+00:00`. This function transforms it back into 
            `2025-04-15T19:00:00Z`
            * `"2025-04-15T19:00:00Z"` in YAML will be correctly serialized, and left untouched 
            
            -> This function always returns the expected `YYYY-MM-DDTHH:MM:SSZ` format
            """
            timestamp = str(timestamp)
            if 'Z' not in timestamp:
                return timestamp.replace(' ', 'T').split('+')[0] + 'Z'
            else:
                return timestamp
        start_on = configuration.schedule.start
        start_on = fix_datetime(start_on) if start_on else None
        stop_on = configuration.schedule.end
        stop_on = fix_datetime(stop_on) if stop_on else None
        operation = DetectionRule.Operation(schedule=schedule, start_on=start_on, stop_on=stop_on)
        contributors = configuration.contributors
        author = contributors or [data.metadata.author]
        author = ', '.join(author)
        comment = f'Updated by OpenTide Crowdstrike Deployer - Author(s) : {author}'
        return CrowdstrikeRule(name=name, description=description, customer_id=customer_id, tactic=tactic, technique=technique, status=status, severity=severity, search=search, operation=operation, comment=comment)

    def deploy_mdr(self, data: DetectionRule, service: CrowdstrikeService, tenant_config: ConfigurationModels.Systems.Crowdstrike.Tenant):
        """
        Deploys the detection rule : creation, update, deletion and disabling.
        """
        mdr_config = data.configurations.crowdstrike
        if not mdr_config:
            raise Errors.TideSystemConfigurationErrors('Missing Crowdstrike')
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
            service.update_detection_rule(rule=rule, rule_id=rule_id)
        else:
            rule_id = service.create_detection_rule(rule)
            ExternalIdHelper.insert_id(rule_id=rule_id, tenant_name=tenant_config.name, mdr_uuid=data.metadata.uuid, system_name=OpenTide.Configurations.Systems.Crowdstrike.platform.identifier)

    def deploy(self, mdr_deployment: Sequence[DetectionRule] | list[str], deployment_plan: DeploymentStrategy):
        """
        Triggers the deployment sequence for a series of MDR uuids or DetectionRule Objects
        """
        loaded_mdr = []
        for mdr in mdr_deployment:
            if type(mdr) is str:
                loaded_mdr.append(OpenTide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr
        deployment = TideDeployment(deployment=mdr_deployment, system=DetectionPlatforms.CROWDSTRIKE, strategy=deployment_plan)
        for tenant_deployment in deployment.rule_deployment:
            logger.info('currently_targeting_tenant', detail=tenant_deployment.tenant.name)
            service = CrowdstrikeService(tenant_deployment.tenant)
            for mdr in tenant_deployment.rules:
                logger.info('processing_rule', detail=mdr.name, advice=mdr.metadata.uuid)
                self.deploy_mdr(data=mdr, service=service, tenant_config=tenant_deployment.tenant)

def declare():
    return CrowdstrikeDeploy()
if __name__ == '__main__' and DebugEnvironment.ENABLED:
    CrowdstrikeDeploy().deploy(['8e9d2ad5-6488-48b5-bedd-f971303f5d38'], DeploymentStrategy.DEBUG)
