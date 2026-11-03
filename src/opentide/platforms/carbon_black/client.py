import structlog

from opentide.core.debug import DebugEnvironment
from opentide.core.registry import Opentide
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.transport import tenant_tls_verify

logger = structlog.get_logger("opentide.platforms.carbon_black.client")


class CarbonBlackCloudConnection:
    """Utility class used to initialize constants for Carbon Black Cloud operations."""

    def __init__(self):
        self.DEBUG = DebugEnvironment.ENABLED
        self.DEPLOYER_IDENTIFIER = "carbon_black_cloud"
        CBC_CONFIG = Opentide.Configurations.Systems.CarbonBlackCloud

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
            # No tenant to reach: deploy refuses the platform before any call.
            self.DEFAULT_WATCHLIST = ""
            self.CBC_URL = ""
            self.CBC_SECRETS: dict[str, dict[str, str]] = {}
            self.ORGANIZATIONS: list[str] = []
            self.VALIDATION_ORGANIZATION = ""

    def _init_from_tenants(self, cbc_config) -> None:
        """Initialise from MDRv4 typed tenant configuration."""
        first_tenant = cbc_config.tenants[0]
        self.DEFAULT_WATCHLIST = first_tenant.setup.watchlist or ""
        self.CBC_URL = first_tenant.setup.url

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


class CarbonBlackCloudService:
    """Connect to Carbon Black Cloud for a specific tenant configuration."""

    def __init__(self, tenant: ConfigurationModels.Systems.CarbonBlackCloud.Tenant):
        from cbc_sdk.rest_api import CBCloudAPI

        self.tenant = tenant
        self.service = CBCloudAPI(
            url=tenant.setup.url,
            token=tenant.setup.token,
            org_key=tenant.setup.org_key,
            ssl_verify=tenant_tls_verify(
                tenant.setup.ssl, platform="carbon_black_cloud", tenant=tenant.name
            ),
        )
