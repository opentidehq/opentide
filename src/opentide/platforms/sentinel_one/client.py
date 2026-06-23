import sys
import os
import requests
import json
from dataclasses import dataclass, asdict
from typing import Literal, ClassVar, Sequence, overload, Any, Optional
from opentide.core.typing import Never
from enum import Enum, auto
from datetime import datetime, timedelta
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide
from opentide.models.system_config import ConfigurationModels
from opentide.deployment import Proxy
from opentide.core.errors import Errors
import structlog
logger = structlog.get_logger('opentide.platforms.sentinel_one.client')

class SeverityMapping(Enum):
    Informational = 'Low'
    Low = 'Low'
    Medium = 'Medium'
    High = 'High'
    Critical = 'Critical'

@dataclass
class DetectionRule:

    @dataclass
    class Data:

        @dataclass
        class CoolOffSettings:
            renotifyMinutes: int

        @dataclass
        class CorrelationParams:

            @dataclass
            class SubQueries:
                matchesRequired: int
                subQuery: str

            @dataclass
            class TimeWindow:
                windowMinutes: int
            entity: str
            matchInOrder: bool
            subQueries: SubQueries
            timeWindow: Optional[TimeWindow] = None
        expirationMode: Literal['Permanent', 'Temporary']
        name: str
        description: str
        queryType: Literal['correlation', 'events']
        severity: str
        status: Literal['Active', 'Disabled']
        networkQuarantine: Optional[bool] = None
        treatAsThreat: Optional[Literal['UNDEFINED', 'Suspicious', 'Malicious']] = None
        queryLang: Literal['1.0', '2.0'] = '2.0'
        s1ql: Optional[str] = None
        expiration: Optional[str] = None
        coolOffSetting: Optional[CoolOffSettings] = None
        correlationParams: Optional[CorrelationParams] = None

    @dataclass
    class Filter:
        accountIds: Optional[list[str]] = None
        siteIds: Optional[list[str]] = None
    data: Data
    filter: Filter

class SentinelOneService:
    """
    Interface to connect and deploy MDRs to SentinelOne. Initialized on a single
    tenant basis.
    """

    def __init__(self, tenant_config: ConfigurationModels.Systems.SentinelOne.Tenant) -> None:
        self.DEBUG = DebugEnvironment.ENABLED
        self.DEPLOYER_IDENTIFIER = OpenTide.Configurations.Systems.SentinelOne.platform.identifier
        self.tenant_config = tenant_config
        self.CUSTOM_DETECTION_RULES_ENDPOINT = self.tenant_config.setup.url + '/web/api/v2.1/cloud-detection/rules'
        self.CREATE_QUERY_ENDPOINT = self.tenant_config.setup.url + '/web/api/v2.1/dv/events/pq'
        self.session = requests.Session()
        self.session.headers.update({'Authorization': f'ApiToken {self.tenant_config.setup.api_token}', 'Content-Type': 'application/json'})
        if tenant_config.setup.proxy:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()

    def _http_errors(self, response: requests.Response, error):
        match response.status_code:
            case 400:
                logger.critical('received_code_400_invalid_user_input_received', detail=str(response.text))
                raise error
            case 401:
                logger.critical('received_code_401_unauthorized_access', detail=str(response.text), advice='Check your configuration and API permissions again')
                raise Errors.TideTenantConfigurationMissingPermissions
            case 404:
                logger.critical('fatal_error', detail=str(response.text), advice='Go to SentinelOne Console and check if your rule still exists. If not, remove the rule id entry from the MDR file')
                raise error
            case _:
                logger.critical('fatal_error', detail=f'Unforeseen error with code [{response.status_code}]', context=str(response.json()))
                raise error

    def validate_query(self, query: str) -> bool:
        """
        Performs a Power Query against the SentinelOne tenant to validate if the query is able to run
        May not be able to catch every edge cases, but will replicate most frontend errors
        """
        request = {}
        request['accountIds'] = str(self.tenant_config.setup.account_id)
        if (site_id := self.tenant_config.setup.site_id):
            request['site_id'] = str(site_id)
        request['query'] = query
        now = datetime.now()
        from_date = now - timedelta(minutes=1)
        request['toDate'] = str(now.isoformat()) + 'Z'
        request['fromDate'] = str(from_date.isoformat()) + 'Z'
        request = json.dumps(request, indent=4)
        response = self.session.post(url=self.CREATE_QUERY_ENDPOINT, verify=self.tenant_config.setup.ssl, data=request)
        match response.status_code:
            case 200:
                logger.info('the_query_was_able_to_run')
                return True
            case 400:
                try:
                    error = response.json().get('errors')[0].get('detail')
                except:
                    error = str(response.json())
                logger.critical('fatal_error', detail=f'The query failed to be validated on tenant {self.tenant_config.name}', arg0=error, advice='Double check your query on the Sentinel One Event Search interface')
                return False
            case _:
                self._http_errors(response, error=Errors.TideQueryValidationError)

    def create_update_detection_rule(self, rule: DetectionRule, rule_id: Optional[int]=None) -> int:

        def _remove_nulls(value):
            if isinstance(value, dict):
                return {k: _remove_nulls(v) for k, v in value.items() if v is not None}
            elif isinstance(value, list):
                return [_remove_nulls(item) for item in value if item is not None]
            else:
                return value
        rule_body = json.dumps(_remove_nulls(asdict(rule)))
        logger.info('event', detail=str(rule_body))
        endpoint = self.CUSTOM_DETECTION_RULES_ENDPOINT
        if rule_id:
            logger.info('executing_api_call_to_update_star_custom_rule_with_id', detail=str(rule_id))
            endpoint += f'/{rule_id}'
            error = Errors.DetectionRuleCreationFailed
            request = self.session.put(url=endpoint, verify=self.tenant_config.setup.ssl, data=rule_body)
        else:
            logger.info('executing_api_call_to_create_star_custom_rule')
            error = Errors.DetectionRuleCreationFailed
            request = self.session.post(url=endpoint, verify=self.tenant_config.setup.ssl, data=rule_body)
        match request.status_code:
            case 200:
                logger.info('created_rule_in_sentinelone', detail=str(request.json()))
                return int(request.json()['data']['id'])
            case _:
                self._http_errors(request, error=error)

    def disable_detection_rule(self, rule_id: int):
        filter = {'filter': {'ids': [rule_id]}}
        filter = json.dumps(filter)
        logger.info('disabling_rule_with_id', detail=str(rule_id))
        request = self.session.put(url=self.CUSTOM_DETECTION_RULES_ENDPOINT, verify=self.tenant_config.setup.ssl, data=filter)
        match request.status_code:
            case 200:
                logger.info('step_completed', detail=f'Disabled rule with id {rule_id} in SentinelOne', context=str(request.json()))
            case _:
                self._http_errors(request, error=Errors.DetectionRuleDisablingFailed)

    def delete_detection_rule(self, rule_id: int):
        filter = {'filter': {'ids': [rule_id]}}
        filter = json.dumps(filter)
        logger.info('deleting_rule_with_id', detail=str(rule_id))
        request = self.session.delete(url=self.CUSTOM_DETECTION_RULES_ENDPOINT, verify=self.tenant_config.setup.ssl, data=filter)
        match request.status_code:
            case 200:
                logger.info('step_completed', detail=f'Deleted rule with id {rule_id} in SentinelOne', context=str(request.json()))
            case _:
                self._http_errors(request, error=Errors.DetectionRuleDeletionFailed)
