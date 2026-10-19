from __future__ import annotations
import json
from typing import TYPE_CHECKING, Any, Sequence
from opentide.generation.framework import get_vocab_entry, techniques_resolver
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide, DetectionPlatforms
from opentide.platforms.plugins import RuleDeployer
from opentide.models.rule import DetectionRule
from opentide.models.deployment_enums import DeploymentStrategy, StatusStrategy
from opentide.models.system_config import ConfigurationModels
from opentide.deployment import check_status
from opentide.platforms.kql import compile_kql_query
from opentide.core.errors import Errors
import structlog
logger = structlog.get_logger('opentide.platforms.sentinel.deployer')

if TYPE_CHECKING:
    from opentide.models.system_config import TenantDeployment

def _missing_field(data: DetectionRule, field: str, requirement: str) -> Errors.TideMDRDataModelErrors:
    return Errors.TideMDRDataModelErrors(
        f'Rule {data.metadata.uuid} ({data.name}): configurations.sentinel.{field} is missing; {requirement}'
    )


class SentinelDeploy(RuleDeployer):

    def compile_deployment(self, service: Any, data: DetectionRule, tenant: str) -> dict[str, Any]:
        """Compile a rule into the ARM alert-rule request body for one tenant.

        The body is the ``Microsoft.SecurityInsights/alertRules`` PUT payload:
        ``kind`` plus camelCase ``properties``, with unset fields left out.
        ``service`` is kept for API compatibility.
        """
        from opentide.platforms.sentinel.client import duration_isoformat, iso_duration_timedelta

        def duration(value: str) -> str:
            return duration_isoformat(iso_duration_timedelta(value))

        configuration = data.configurations.sentinel
        if not configuration:
            raise Errors.TideMDRDataModelErrors(
                f'Rule {data.metadata.uuid} ({data.name}): configurations.sentinel is missing'
            )
        # Checked before anything is built so the failure names the rule and the
        # field rather than surfacing as an AttributeError on None (#549).
        if not configuration.grouping:
            raise _missing_field(data, 'grouping', 'Sentinel deploy requires grouping.event and grouping.alert')
        if not configuration.grouping.alert:
            raise _missing_field(data, 'grouping.alert', 'Sentinel deploy requires incident grouping (grouping.alert.enabled)')
        rule: dict[str, Any] = {'kind': 'Scheduled'}
        properties: dict[str, Any] = {}
        status = configuration.status
        properties['enabled'] = True
        query = compile_kql_query(configuration.query, configuration.exclusions, tenant)
        logger.info('final_compiled_query', arg0=query)
        properties['query'] = query
        if check_status(status) is StatusStrategy.DISABLEMENT:
            properties['enabled'] = False
        if configuration.template:
            properties['alertRuleTemplateName'] = configuration.template.uuid
            properties['templateVersion'] = configuration.template.version
        suppression = configuration.alert.suppression
        if type(suppression) is str:
            properties['suppressionEnabled'] = True
            properties['suppressionDuration'] = duration(suppression)
        elif suppression is False:
            properties['suppressionEnabled'] = False
            properties['suppressionDuration'] = duration('1h')
        else:
            raise Errors.TideMDRDataModelErrors('Suppression set to true, must be false or int')
        if configuration.scheduling.nrt is True:
            rule['kind'] = 'NRT'
        else:
            if not configuration.scheduling.frequency:
                raise _missing_field(data, 'scheduling.frequency', 'required unless scheduling.nrt is true')
            if not configuration.scheduling.lookback:
                raise _missing_field(data, 'scheduling.lookback', 'required unless scheduling.nrt is true')
            properties['queryFrequency'] = duration(configuration.scheduling.frequency)
            properties['queryPeriod'] = duration(configuration.scheduling.lookback)
            if configuration.trigger:
                properties['triggerThreshold'] = configuration.trigger.threshold
                properties['triggerOperator'] = configuration.trigger.operator
        details_overrides: dict[str, Any] = {}
        if (alert_title := configuration.alert.title):
            details_overrides['alertDisplayNameFormat'] = alert_title
        if (alert_description := configuration.alert.description):
            details_overrides['alertDescriptionFormat'] = alert_description
        if (dynamic_properties := configuration.alert.dynamic_properties):
            alert_dynamic_properties = []
            for property in dynamic_properties:
                if property.property == 'Tactics':
                    details_overrides['alertTacticsColumnName'] = property.column
                    continue
                if property.property == 'Severity':
                    details_overrides['alertSeverityColumnName'] = property.column
                    continue
                alert_dynamic_properties.append({'alertProperty': property.property, 'value': property.column})
            if alert_dynamic_properties:
                details_overrides['alertDynamicProperties'] = alert_dynamic_properties
        properties['alertDetailsOverride'] = details_overrides
        if (techniques := configuration.alert.techniques):
            properties['techniques'] = techniques
        if (tactics := configuration.alert.tactics):
            properties['tactics'] = tactics
        if (custom_details := configuration.alert.custom_details):
            properties['customDetails'] = {detail.key: detail.column for detail in custom_details}
        logger.info('event_grouping_configuration', detail=configuration.grouping.event)
        properties['eventGroupingSettings'] = {'aggregationKind': configuration.grouping.event}
        alert_enabled = configuration.alert.create_incident
        logger.info('alert_enabled', detail=str(alert_enabled))
        grouping_enabled = configuration.grouping.alert.enabled
        logger.info('alert_grouping_enabled', detail=str(grouping_enabled))
        grouping_lookback = configuration.grouping.alert.grouping_lookback
        if grouping_enabled and not grouping_lookback:
            raise _missing_field(data, 'grouping.alert.grouping_lookback', 'required when grouping.alert.enabled is true')
        grouping_configuration = {
            'enabled': grouping_enabled,
            'lookbackDuration': duration(grouping_lookback or '1h'),
            'reopenClosedIncident': configuration.grouping.alert.reopen_closed_incidents or False,
            'matchingMethod': configuration.grouping.alert.matching or 'AllEntities',
            'groupByEntities': configuration.grouping.alert.group_by_entities,
            'groupByAlertDetails': configuration.grouping.alert.group_by_alert_details,
            'groupByCustomDetails': configuration.grouping.alert.group_by_custom_details,
        }
        properties['incidentConfiguration'] = {
            'createIncident': alert_enabled,
            'groupingConfiguration': {key: value for key, value in grouping_configuration.items() if value is not None},
        }
        # ARM rejects an empty entityMappings list (length must be 1-10), so a
        # rule without entities leaves the property unset (#549).
        if (entity_data := configuration.entities):
            properties['entityMappings'] = [
                {
                    'entityType': entity.entity,
                    'fieldMappings': [{'identifier': field.identifier, 'columnName': field.column} for field in entity.mappings],
                }
                for entity in entity_data
            ]
        severity = configuration.alert.severity or data.response.alert_severity
        if severity == 'Critical':
            severity = 'High'
        properties['severity'] = severity
        properties['displayName'] = data.name
        properties['description'] = data.description
        techniques = techniques_resolver(data.metadata.uuid)
        if techniques:
            tactics = list()
            for t in techniques:
                vocab_tactics = [t.title().replace(' ', '').strip() for t in get_vocab_entry('att&ck', t, 'tide.vocab.stages')]
                tactics.extend(vocab_tactics)
            techniques = [t.split('.')[0] for t in techniques]
            techniques = list(dict.fromkeys(techniques))
            tactics = list(dict.fromkeys(tactics))
            properties['tactics'] = tactics
            properties['techniques'] = techniques
        rule['properties'] = {key: value for key, value in properties.items() if value is not None}
        logger.info('compiled_rule', detail=json.dumps(rule))
        return rule

    def deploy_mdr(self, data: DetectionRule, service: Any, tenant_config: ConfigurationModels.Systems.Sentinel.Tenant):
        """
        Deploys the detection rule : creation, update, deletion and disabling.
        """
        if not data.configurations.sentinel:
            raise Errors.TideSystemConfigurationErrors('Missing Sentinel')
        mdr_name = data.name
        mdr_uuid = data.metadata.uuid
        if check_status(data.configurations.sentinel.status) is StatusStrategy.DELETION:
            logger.warning('the_rule_will_be_removed_from_the_sentinel_workspace', arg0=mdr_name)
            service.alert_rules.delete(resource_group_name=tenant_config.setup.resource_group, workspace_name=tenant_config.setup.workspace_name, rule_id=mdr_uuid)
            logger.info('deleted_rule_from_workspace')
            return True
        logger.info('compiling_scheduled_alert_object')
        alert_rule = self.compile_deployment(data=data, service=service, tenant=tenant_config.name)
        logger.info('deploying_rule_to_sentinel')
        service.alert_rules.create_or_update(resource_group_name=tenant_config.setup.resource_group, workspace_name=tenant_config.setup.workspace_name, rule_id=mdr_uuid, alert_rule=alert_rule)
        logger.info('deployed_mdr_successfully', arg0=mdr_name)
        return True

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
        from opentide.deployment.external_ids import without_legacy_external_ids
        # Sentinel addresses rules by metadata.uuid, but a rule that still
        # carries a vendor id on any block is unmigrated and refused on every
        # platform (RFC 0010), including direct SDK/MCP calls that skip planning.
        mdr_deployment = without_legacy_external_ids(loaded_mdr, platform='sentinel')
        if not mdr_deployment:
            return
        from opentide.deployment import TideDeployment
        from opentide.platforms.sentinel.client import SentinelService
        deployment = TideDeployment(deployment=mdr_deployment, system=DetectionPlatforms.SENTINEL, strategy=deployment_plan)
        for tenant_deployment in deployment.rule_deployment:
            tenant_deployment: TenantDeployment.Sentinel
            logger.info('currently_targeting_tenant', detail=tenant_deployment.tenant.name)
            service = SentinelService(tenant_deployment.tenant).connect()
            for mdr in tenant_deployment.rules:
                logger.info('processing_rule', detail=mdr.name, advice=mdr.metadata.uuid)
                self.deploy_mdr(data=mdr, service=service, tenant_config=tenant_deployment.tenant)

def declare():
    return SentinelDeploy()
if __name__ == '__main__' and DebugEnvironment.ENABLED:
    SentinelDeploy().deploy(['5e791284-684c-4245-9ac7-cf00a1d041d6'], DeploymentStrategy.DEBUG)
