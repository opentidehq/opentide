import os
import sys
from abc import ABC
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide, DebugHelpers
from opentide.deployment import Proxy
import structlog
logger = structlog.get_logger('opentide.platforms.carbon_black.client')

class CarbonBlackCloudConnection(ABC):
    """
    Utility class used to initialize all constant relevant to operations with Carbon Black Cloud 
    """

    def __init__(self):
        self.DEBUG = DebugEnvironment.ENABLED
        self.DEPLOYER_IDENTIFIER = 'carbon_black_cloud'
        CBC_CONFIG = OpenTide.Configurations.Systems.CarbonBlackCloud
        CBC_SETUP = DebugHelpers.fetch_config_envvar(CBC_CONFIG.setup)
        self.DEFAULT_WATCHLIST = CBC_SETUP['watchlist']
        self.CBC_URL = CBC_SETUP['url']
        self.SSL_ENABLED = CBC_SETUP['ssl']
        if self.DEBUG:
            self.SSL_ENABLED = DebugEnvironment.SSL_ENABLED
        logger.info('ssl_has_been_set_to', detail=str(self.SSL_ENABLED), advice='This can be adjusted in carbon_black_cloud.toml with the setup.ssl keyword')
        secrets = {}
        cbc_secrets_error_flag = False
        for org in CBC_CONFIG.secrets:
            tenant_secrets = DebugHelpers.fetch_config_envvar(CBC_CONFIG.secrets[org])
            if 'org_key' not in tenant_secrets:
                logger.critical('could_not_fetch_organization_key_for_organization', arg0=org, advice='Double check that there is a namespaced entry for this organization in the TOML config')
                cbc_secrets_error_flag = True
            if 'token' not in tenant_secrets:
                logger.critical('target_organization_is_not_present_in_secrets_configuration', arg0=org, advice='Double check that there is a namespaced entry for this organization in the TOML config')
                cbc_secrets_error_flag = True
            if not cbc_secrets_error_flag:
                secrets[org] = {}
                secrets[org]['org_key'] = tenant_secrets['org_key']
                secrets[org]['token'] = tenant_secrets['token']
        if cbc_secrets_error_flag:
            logger.critical('the_secrets_configuration_was_not_setup_correctly', detail='Review the previous errors to understand what attribute was missing')
            raise KeyError
        self.CBC_SECRETS = secrets
        self.ORGANIZATIONS = CBC_SETUP['organizations']
        self.VALIDATION_ORGANIZATION = CBC_CONFIG.validation['organization']
        self.SEVERITY_MAPPING = {'Informational': 1, 'Low': 3, 'Medium': 6, 'High': 8, 'Critical': 10}
        self.PROXY_ENABLED = CBC_SETUP['proxy']

    def configure_proxy(self):
        """Applies the proxy configuration for this system.
        Called before operational methods (deploy/validate) to avoid
        global proxy state conflicts during plugin loading."""
        if self.PROXY_ENABLED:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()
