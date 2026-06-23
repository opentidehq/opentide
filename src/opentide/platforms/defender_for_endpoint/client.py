import sys
import os
import requests
import json
from dataclasses import dataclass, asdict
from typing import Literal, ClassVar, Sequence, overload, Any, Optional
from opentide.core.typing import Never
from enum import Enum, auto
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide
from opentide.models.legacy import ConfigurationModels
from opentide.deployment import Proxy
from opentide.core.errors import Errors
import structlog
logger = structlog.get_logger('opentide.platforms.defender_for_endpoint.client')

class Severity(str, Enum):
    informational = 'informational'
    low = 'low'
    medium = 'medium'
    high = 'high'

class SeverityMapping(Enum):
    Informational = Severity.informational
    Low = Severity.low
    Medium = Severity.medium
    High = Severity.high
    Critical = Severity.high

@dataclass
class DetectionRule:

    @dataclass
    class QueryCondition:
        queryText: str

    @dataclass
    class Schedule:
        period: Literal['0', '1H', '3H', '12H', '24H']

    @dataclass
    class DetectionAction:

        @dataclass
        class AlertTemplate:

            @dataclass
            class ImpactedAsset:
                odata_type: str
                identifier: str
            title: str
            description: str
            severity: Severity
            category: str
            mitreTechniques: Optional[Sequence[Never] | Sequence[str]] = None
            impactedAssets: Optional[Sequence[Never] | Sequence[ImpactedAsset]] = None
            recommendedActions: Optional[str] = None

        @dataclass
        class ResponseAction:
            odata_type: str
            identifier: Any = 'deviceId'

        @dataclass
        class ResponseActionIsolateDevice(ResponseAction):
            isolationType: str = ''

        @dataclass
        class ResponseActionFileActions(ResponseAction):
            deviceGroupNames: Optional[Sequence[str]] = None

        @dataclass
        class OrganizationalScope:
            scopeType = 'deviceGroup'
            scopeNames = Sequence[str]
        alertTemplate: AlertTemplate
        responseActions: Sequence[ResponseAction]
        organizationalScope: Optional[OrganizationalScope] = None
    displayName: str
    queryCondition: QueryCondition
    schedule: Schedule
    detectionAction: DetectionAction
    isEnabled: bool = False

class DefenderForEndpointService:
    """
    Interface to connect and deploy MDRs to MDE. Initialized on a single
    tenant basis.
    """

    def __init__(self, tenant_config: ConfigurationModels.Systems.DefenderForEndpoint.Tenant) -> None:
        self.DEBUG = DebugEnvironment.ENABLED
        self.DEPLOYER_IDENTIFIER = OpenTide.Configurations.Systems.DefenderForEndpoint.platform.identifier
        self.OAUTH_TOKEN_ENDPOINT = 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        self.GRAPH_API_ENDPOINT = 'https://graph.microsoft.com/beta/security'
        self.DETECTION_RULES_ENDPOINT = self.GRAPH_API_ENDPOINT + '/rules/detectionRules'
        self.HUNTING_QUERY_ENDPOINT = self.GRAPH_API_ENDPOINT + '/runHuntingQuery'
        self.tenant_config = tenant_config
        if tenant_config.setup.proxy:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()
        self.access_token = self._connect_to_tenant(self.tenant_config.setup.client_id, self.tenant_config.setup.tenant_id, self.tenant_config.setup.client_secret)
        self.session = requests.Session()
        self.session.headers.update({'Authorization': f'Bearer {self.access_token}', 'Content-Type': 'application/json'})

    def _connect_to_tenant(self, client_id: str, tenant_id: str, client_secret: str):
        data = {'client_id': client_id, 'client_secret': client_secret, 'grant_type': 'client_credentials', 'scope': 'https://graph.microsoft.com/.default'}
        response = requests.post(data=data, url=self.OAUTH_TOKEN_ENDPOINT.format(tenant_id=tenant_id))
        if response.status_code == 200:
            logger.debug('event', detail=f'Successfully authenticated against {self.tenant_config.name}', context=str(response.json()))
            return response.json()['access_token']
        else:
            logger.critical('fatal_error', detail=f'Cannot authenticate against {self.tenant_config.name}', context=str(response.json()), advice=f'client_id: {client_id}, tenant_id: {tenant_id}, client_secret: {client_secret[:10]}...')
            raise Errors.TenantConnectionError('Cannot authenticate with the tenant configuration')

    def _safer_configuation(self, rule: DetectionRule) -> DetectionRule:
        """
        Reconfigures a deployment to remove all known problematic identifiers
        and attempt deployment in a minimal but functional state
        """
        if rule.detectionAction.alertTemplate.impactedAssets:
            logger.info('reassigning_impacted_entities_to_device_with_deviceid_identifier')
            ImpactedAssets = DetectionRule.DetectionAction.AlertTemplate.ImpactedAsset
            rule.detectionAction.alertTemplate.impactedAssets = [ImpactedAssets(odata_type='#microsoft.graph.security.impactedDeviceAsset', identifier='deviceId')]
        if (response_actions := rule.detectionAction.responseActions):
            new_response_actions = []
            RISKY_RESPONSE_ACTIONS = ['#microsoft.graph.security.markUserAsCompromisedResponseAction', '#microsoft.graph.security.disableUserResponseAction', '#microsoft.graph.security.forceUserPasswordResetResponseAction']
            for action in response_actions:
                if action.odata_type not in RISKY_RESPONSE_ACTIONS:
                    new_response_actions.append(action)
                else:
                    logger.info('event', detail=action.odata_type)
            rule.detectionAction.responseActions = new_response_actions
        return rule

    def run_hunting_query(self, query: str, timespan: str='PT1H') -> dict:
        """
        Runs a hunting query against the MDE tenant via the runHuntingQuery
        Graph API endpoint.
        Returns the full JSON response body on success.
        Raises on permission or query execution errors.
        """
        request = self.session.post(url=self.HUNTING_QUERY_ENDPOINT, verify=self.tenant_config.setup.ssl, json={'Query': query, 'Timespan': timespan})
        if request.status_code == 200:
            logger.info('query_was_able_to_run_on_tenant', detail=self.tenant_config.name)
            return request.json()
        if request.status_code == 403:
            logger.critical('fatal_error', detail=f'Missing permissions to run query against tenant {self.tenant_config.name} - Error Code {request.status_code}', context=str(request.json()), advice='Add the permissions mentioned above to the service principal to fix this')
            raise Exception(f'Permission denied (403) on tenant {self.tenant_config.name}')
        error_message = request.json().get('error', {}).get('message') or request.json()
        logger.critical('fatal_error', detail=f'Error Code {request.status_code} - {error_message}', context_1='The query could not run due to a syntax error. Confirm that it can run on the console and try again', advice=query)
        raise Exception(f'Hunting query failed with status {request.status_code}: {error_message}')

    def create_detection_rule(self, rule: DetectionRule) -> int:
        rule_body = json.dumps(asdict(rule))
        rule_body = rule_body.replace('odata_type', '@odata.type')
        rule_body = json.loads(rule_body)
        request = self.session.post(url=self.DETECTION_RULES_ENDPOINT, verify=self.tenant_config.setup.ssl, json=rule_body)
        if request.status_code == 201:
            logger.info('created_rule_in_mde', detail=str(request.json()))
            return int(request.json()['id'])
        else:
            logger.critical('fatal_error', detail=f'Failed to create detection rule in tenant {self.tenant_config.name}', context=str(request.json()), advice='Will attempt redeployment, with minimal configurations : impacted_entitieswill be set to Device with DeviceId mapping, user response actions will beremoved as they can lead to mapping issues. If successful, this pipeline willfail with warning, and you will need to check the GUI to see which identifiersare available based on your query')
            rule = self._safer_configuation(rule)
            rule_body = json.dumps(asdict(rule))
            rule_body = rule_body.replace('odata_type', '@odata.type')
            rule_body = json.loads(rule_body)
            logger.info('attempting_redeployment_with_safer_configuration', detail=str(rule_body))
            request = self.session.post(url=self.GRAPH_API_ENDPOINT, json=rule_body)
            if request.status_code == 201:
                logger.info('created_rule_in_mde', detail=str(request.json()))
                logger.warning('this_is_a_partial_deployment_check_the_mde_gui_to_see_the_availa')
                os.environ['DEPLOYMENT_WARNING_RAISED']
                return int(request.json()['id'])
            else:
                raise Errors.DetectionRuleCreationFailed

    def update_detection_rule(self, rule: DetectionRule, rule_id: int):
        rule_body = json.dumps(asdict(rule))
        rule_body = rule_body.replace('odata_type', '@odata.type')
        rule_body = json.loads(rule_body)
        url = self.DETECTION_RULES_ENDPOINT + f'/{rule_id}'
        request = self.session.patch(url=url, verify=self.tenant_config.setup.ssl, json=rule_body)
        if request.status_code == 200:
            logger.info('updated_rules_in_mde', detail=str(request.json()))
        else:
            logger.critical('fatal_error', detail=f'Failed to update detection rule with id {rule_id} in tenant {self.tenant_config.name} ({url})', context=str(request.json()), advice=str(rule_body))
            raise Errors.DetectionRuleUpdateFailed

    def delete_detection_rule(self, rule_id: int):
        request = self.session.delete(url=self.DETECTION_RULES_ENDPOINT + f'/{rule_id}', verify=self.tenant_config.setup.ssl)
        if request.status_code == 204:
            logger.info('removed_detection_rule_from_mde_tenant')
        else:
            logger.critical('fatal_error', detail=f'Failed to delete detection rule with id {rule_id} in tenant {self.tenant_config.name}', context_1='Double check scope permissions, and whether the ID actually exists')
            raise Errors.DetectionRuleDeletionFailed
