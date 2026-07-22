from abc import ABC

import structlog

from opentide.core.debug import DebugEnvironment
from opentide.core.registry import DebugHelpers, OpenTide
from opentide.deployment import Proxy
from opentide.models.system_config import ConfigurationModels

logger = structlog.get_logger("opentide.platforms.carbon_black.client")


class CarbonBlackCloudConnection(ABC):
    """Utility class used to initialize constants for Carbon Black Cloud operations."""

    def __init__(self):
        self.DEBUG = DebugEnvironment.ENABLED
        self.DEPLOYER_IDENTIFIER = "carbon_black_cloud"
        CBC_CONFIG = OpenTide.Configurations.Systems.CarbonBlackCloud

        self.SEVERITY_MAPPING = {
            "Informational": 1,
            "Low": 3,
            "Medium": 6,
            "High": 8,
            "Critical": 10,
        }

        tenants = getattr(CBC_CONFIG, "tenants", None)
        if tenants:
            self._init_from_tenants(CBC_CONFIG)
        else:
            self._init_from_legacy(CBC_CONFIG)

        if self.DEBUG:
            self.SSL_ENABLED = DebugEnvironment.SSL_ENABLED

        logger.info(
            "ssl_has_been_set_to",
            detail=str(self.SSL_ENABLED),
            advice="This can be adjusted in carbon_black_cloud.toml with the setup.ssl keyword",
        )

    def _init_from_tenants(self, cbc_config) -> None:
        """Initialise from MDRv4 typed tenant configuration."""
        first_tenant = cbc_config.tenants[0]
        self.DEFAULT_WATCHLIST = first_tenant.setup.watchlist or ""
        self.CBC_URL = first_tenant.setup.url
        self.SSL_ENABLED = first_tenant.setup.ssl
        self.PROXY_ENABLED = first_tenant.setup.proxy

        secrets: dict[str, dict[str, str]] = {}
        organizations: list[str] = []
        for tenant in cbc_config.tenants:
            org_name = tenant.name
            organizations.append(org_name)
            secrets[org_name] = {
                "org_key": tenant.setup.org_key,
                "token": tenant.setup.token,
            }

        self.CBC_SECRETS = secrets
        self.ORGANIZATIONS = (
            list(first_tenant.setup.organizations)
            if first_tenant.setup.organizations
            else organizations
        )
        self.VALIDATION_ORGANIZATION = organizations[0] if organizations else ""

    def _init_from_legacy(self, cbc_config) -> None:
        """Initialise from legacy setup/secrets configuration."""
        CBC_SETUP = DebugHelpers.fetch_config_envvar(getattr(cbc_config, "setup", {}) or {})
        self.DEFAULT_WATCHLIST = CBC_SETUP.get("watchlist", "")
        self.CBC_URL = CBC_SETUP.get("url", "")
        self.SSL_ENABLED = CBC_SETUP.get("ssl", True)
        self.PROXY_ENABLED = CBC_SETUP.get("proxy", False)

        secrets: dict[str, dict[str, str]] = {}
        cbc_secrets_error_flag = False
        raw_secrets = getattr(cbc_config, "secrets", {}) or {}
        for org in raw_secrets:
            tenant_secrets = DebugHelpers.fetch_config_envvar(raw_secrets[org])
            if "org_key" not in tenant_secrets:
                logger.critical(
                    "could_not_fetch_organization_key_for_organization",
                    arg0=org,
                    advice="Double check that there is a namespaced entry for this organization in the TOML config",
                )
                cbc_secrets_error_flag = True
            if "token" not in tenant_secrets:
                logger.critical(
                    "target_organization_is_not_present_in_secrets_configuration",
                    arg0=org,
                    advice="Double check that there is a namespaced entry for this organization in the TOML config",
                )
                cbc_secrets_error_flag = True
            if not cbc_secrets_error_flag:
                secrets[org] = {
                    "org_key": tenant_secrets["org_key"],
                    "token": tenant_secrets["token"],
                }
        if cbc_secrets_error_flag:
            logger.critical(
                "the_secrets_configuration_was_not_setup_correctly",
                detail="Review the previous errors to understand what attribute was missing",
            )
            raise KeyError
        self.CBC_SECRETS = secrets
        self.ORGANIZATIONS = CBC_SETUP.get("organizations", [])
        validation = getattr(cbc_config, "validation", {}) or {}
        self.VALIDATION_ORGANIZATION = validation.get("organization", "")

    def configure_proxy(self):
        """Applies the proxy configuration for this system."""
        if self.PROXY_ENABLED:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()


class CarbonBlackCloudService:
    """Connect to Carbon Black Cloud for a specific tenant configuration."""

    def __init__(self, tenant: ConfigurationModels.Systems.CarbonBlackCloud.Tenant):
        from cbc_sdk.rest_api import CBCloudAPI

        self.tenant = tenant
        self.service = CBCloudAPI(
            url=tenant.setup.url,
            token=tenant.setup.token,
            org_key=tenant.setup.org_key,
            ssl_verify=tenant.setup.ssl,
        )
