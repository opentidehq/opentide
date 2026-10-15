from __future__ import annotations

import re
from datetime import timedelta
from typing import TYPE_CHECKING
from opentide.models.system_config import ConfigurationModels
import structlog
logger = structlog.get_logger('opentide.platforms.sentinel.client')

if TYPE_CHECKING:
    from azure.mgmt.securityinsight import SecurityInsights

class SentinelService:

    def __init__(self, tenant_config: ConfigurationModels.Systems.Sentinel.Tenant):
        self.setup = tenant_config.setup

    def connect(self) -> SecurityInsights:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.securityinsight import SecurityInsights

        from opentide.core.environment import reject_unsubstituted_placeholders
        reject_unsubstituted_placeholders(
            self.setup.azure_tenant_id,
            self.setup.azure_client_id,
            self.setup.azure_client_secret,
            self.setup.azure_subscription_id,
            client='Azure',
        )
        credentials = ClientSecretCredential(self.setup.azure_tenant_id, self.setup.azure_client_id, self.setup.azure_client_secret)
        client = SecurityInsights(credentials, self.setup.azure_subscription_id, connection_verify=self.setup.ssl)
        return client

_SHORTHAND_DURATION = re.compile(r'^(\d+)([mhd])$')
_ISO_DURATION = re.compile(
    r'^P(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?'
    r'(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$',
    re.IGNORECASE,
)
_SHORTHAND_UNITS = {'m': 'minutes', 'h': 'hours', 'd': 'days'}


def iso_duration_timedelta(duration: str) -> timedelta:
    """Parse a rule duration into a timedelta.

    Accepts the ISO 8601 form the Sentinel platform contract documents (``PT1H``,
    ``PT30M``, ``P1D``) and the shorthand older catalogues use (``30m``, ``1h``,
    ``1d``). The SDK serialises the result back to an ISO 8601 duration.
    """
    from opentide.core.errors import Errors

    text = str(duration).strip()
    if (shorthand := _SHORTHAND_DURATION.match(text)):
        count, unit = shorthand.groups()
        return timedelta(**{_SHORTHAND_UNITS[unit]: int(count)})
    iso = _ISO_DURATION.match(text)
    if iso and not text.upper().endswith('T'):
        parts = {name: int(value) for name, value in iso.groupdict().items() if value}
        if parts:
            return timedelta(**parts)
    raise Errors.TideMDRDataModelErrors(
        f'Duration {duration!r} is not an ISO 8601 duration (PT1H, PT30M, P1D) '
        'or a shorthand duration (30m, 1h, 1d)'
    )
