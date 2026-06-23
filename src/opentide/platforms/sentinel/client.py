from datetime import timedelta
from azure.mgmt.securityinsight import SecurityInsights
from azure.identity import ClientSecretCredential
from opentide.deployment import Proxy
from opentide.models.system_config import ConfigurationModels
import structlog
logger = structlog.get_logger('opentide.platforms.sentinel.client')

class SentinelService:

    def __init__(self, tenant_config: ConfigurationModels.Systems.Sentinel.Tenant):
        self.setup = tenant_config.setup
        if self.setup.proxy:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()

    def connect(self) -> SecurityInsights:
        credentials = ClientSecretCredential(self.setup.azure_tenant_id, self.setup.azure_client_id, self.setup.azure_client_secret)
        client = SecurityInsights(credentials, self.setup.azure_subscription_id, connection_verify=self.setup.ssl)
        return client

def iso_duration_timedelta(duration: str) -> timedelta:
    """
    Converts an simple duration into an ISO 8601 compliant time duration.
    See https://tc39.es/proposal-temporal/docs/duration.html for more information.
    """
    unit = duration[-1]
    count = int(duration[:-1])
    match unit:
        case 'm':
            delta = timedelta(minutes=count)
        case 'h':
            delta = timedelta(hours=count)
        case 'd':
            delta = timedelta(days=count)
        case _:
            raise Exception(f'[FATAL] Duration {duration} is not in supported unit (m, h or d)')
    return delta
