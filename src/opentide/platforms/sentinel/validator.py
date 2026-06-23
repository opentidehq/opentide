import os
from typing import Sequence
from datetime import timedelta
from azure.identity import ClientSecretCredential, CredentialUnavailableError
from azure.monitor.query import LogsQueryClient
from azure.core.exceptions import HttpResponseError, ClientAuthenticationError, ServiceRequestError
from opentide.platforms.plugins import QueryValidator
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels, TenantDeployment
from opentide.core.errors import Errors
from opentide.deployment import TideDeployment, DetectionPlatforms, DeploymentStrategy, Proxy
import structlog
logger = structlog.get_logger('opentide.platforms.sentinel.validator')

class SentinelQueryValidator(QueryValidator):

    def check_query(self, mdr: DetectionRule, tenant_config: ConfigurationModels.Systems.Sentinel.Tenant, service: LogsQueryClient):
        mdr_uuid = mdr.metadata.uuid
        if not mdr.configurations.sentinel:
            raise Errors.TideMDRDataModelErrors('Missing Sentinel')
        query: str = mdr.configurations.sentinel.query
        if not query:
            os.environ['VALIDATION_ERROR_RAISED'] = 'True'
            logger.critical('missing_query_in_mdr', detail=f'{mdr.name} ({mdr_uuid})')
            return
        query += ' | limit 1'
        try:
            service.query_workspace(workspace_id=tenant_config.setup.workspace_id, query=query, timespan=timedelta(minutes=1))
            logger.info('the_query_is_a_valid_sentinel_kql', detail=f'{mdr.name} ({mdr_uuid})')
        except CredentialUnavailableError as error:
            logger.critical('fatal_error', detail=f'Azure credential unavailable for : {mdr.name} ({mdr_uuid})', context=str(error), advice='The credential provider could not authenticate. Check that tenant_id, client_id and client_secret are correctly configured.')
            os.environ['VALIDATION_ERROR_RAISED'] = 'True'
        except ClientAuthenticationError as error:
            logger.critical('fatal_error', detail=f'Azure authentication failed for : {mdr.name} ({mdr_uuid})', context=str(error.message), advice='The service principal credentials may be expired or invalid. Verify the client secret has not expired in Entra ID.')
            os.environ['VALIDATION_ERROR_RAISED'] = 'True'
        except ServiceRequestError as error:
            logger.critical('fatal_error', detail=f'Network error reaching Azure Monitor for : {mdr.name} ({mdr_uuid})', context=str(error), advice='Could not connect to the Azure Monitor endpoint. Check network connectivity, proxy settings and SSL configuration.')
            os.environ['VALIDATION_ERROR_RAISED'] = 'True'
        except HttpResponseError as error:
            logger.debug('full_error_message', detail=str(error))
            try:
                logger.critical('fatal_error', detail=f'The KQL query is invalid for : {mdr.name} ({mdr_uuid})', context_1=error.error.innererror['innererror']['message'], advice=f'Review the error and ensure your search can work in the relevant Sentinel workspace ({tenant_config.setup.workspace_name})')
            except Exception:
                logger.error('not_able_to_parse_out_the_error_message', detail='This may mean that there is a more complex problem', advice='Will print out the full error package now')
                print(error)
            os.environ['VALIDATION_ERROR_RAISED'] = 'True'
        except Exception as error:
            logger.critical('fatal_error', detail=f'Unexpected error during query validation for : {mdr.name} ({mdr_uuid})', context_1=f'{type(error).__name__}: {error}', advice='An unhandled exception occurred. Review the error details above.')
            os.environ['VALIDATION_ERROR_RAISED'] = 'True'

    def validate(self, mdr_deployment: Sequence[DetectionRule] | list[str], deployment_plan: DeploymentStrategy):
        loaded_mdr = []
        for mdr in mdr_deployment:
            if type(mdr) is str:
                loaded_mdr.append(OpenTide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr
        deployment = TideDeployment(deployment=mdr_deployment, system=DetectionPlatforms.SENTINEL, strategy=deployment_plan)
        for tenant_deployment in deployment.rule_deployment:
            tenant_deployment: TenantDeployment.Sentinel
            tenant_setup = tenant_deployment.tenant.setup
            if tenant_setup.proxy:
                Proxy.set_proxy()
            else:
                Proxy.unset_proxy()
            logger.info('acquiring_azure_credentials_for_tenant', detail=tenant_deployment.tenant.name)
            credentials = ClientSecretCredential(tenant_setup.azure_tenant_id, tenant_setup.azure_client_id, tenant_setup.azure_client_secret)
            logger.info('azure_credentials_prepared_for_tenant', detail=tenant_deployment.tenant.name, advice='Note: credentials are validated lazily on first API call')
            logger.info('initialising_logsqueryclient_for_tenant', detail=tenant_deployment.tenant.name)
            service = LogsQueryClient(credential=credentials, connection_verify=tenant_setup.ssl)
            logger.info('logsqueryclient_ready_for_tenant', detail=tenant_deployment.tenant.name)
            for mdr in tenant_deployment.rules:
                logger.info('validating_kql_query', detail=f'{mdr.name} ({mdr.metadata.uuid})')
                logger.info('sending_query_to_azure_monitor_workspace', detail=f'{mdr.name} ({mdr.metadata.uuid})')
                self.check_query(mdr=mdr, service=service, tenant_config=tenant_deployment.tenant)

def declare():
    return SentinelQueryValidator()
if __name__ == '__main__' and DebugEnvironment.ENABLED:
    SentinelQueryValidator().validate(['5e791284-684c-4245-9ac7-cf00a1d041d6'], DeploymentStrategy.DEBUG)
