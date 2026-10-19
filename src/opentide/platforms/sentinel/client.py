"""Azure Sentinel (SecurityInsights) client and SDK compatibility helpers.

``azure-mgmt-securityinsight`` changed shape across its 2.0 pre-releases:

* 2.0.0b2 is an msrest-generated SDK. The client is ``SecurityInsights`` and
  models serialise through ``Model.serialize()``.
* 2.0.0b3 and later are TypeSpec-generated. The client is
  ``SecurityInsightsMgmtClient``, models are mappings that hold the REST shape,
  and operation groups no longer expose a ``models`` attribute.

The helpers below hide those differences from the deployer, the dry-run
preview and the importer. Azure imports stay inside functions so the platform
plugin loads without the ``sentinel`` extra.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from types import ModuleType
from typing import Any

import structlog

from opentide.models.system_config import ConfigurationModels

logger = structlog.get_logger('opentide.platforms.sentinel.client')

# Fields that are maps of user-chosen keys. Their keys are data, not REST
# property names, so they are never case-converted.
_MAP_FIELDS = frozenset({'customDetails', 'custom_details'})


def securityinsight_models() -> ModuleType:
    """Return ``azure.mgmt.securityinsight.models``. Raises ImportError without the SDK."""
    from azure.mgmt.securityinsight import models

    return models


def securityinsights_client_class() -> type:
    """Return the SecurityInsights management client class for the installed SDK."""
    import azure.mgmt.securityinsight as securityinsight

    for name in ('SecurityInsightsMgmtClient', 'SecurityInsights'):
        client_class = getattr(securityinsight, name, None)
        if client_class is not None:
            return client_class
    raise ImportError(
        'azure-mgmt-securityinsight exposes neither SecurityInsightsMgmtClient nor SecurityInsights; '
        "install a supported SDK with pip install 'opentide[sentinel]'"
    )


def alert_rule_request_body(rule: Any) -> dict[str, Any]:
    """Serialise a compiled alert rule to the JSON body sent to the ARM API."""
    if hasattr(rule, 'serialize'):
        # msrest models (2.0.0b2): what AlertRulesOperations.create_or_update sends.
        return rule.serialize(keep_readonly=False)
    # TypeSpec models (2.0.0b3+): the encoder create_or_update uses.
    from azure.mgmt.securityinsight._utils.model_base import SdkJSONEncoder

    return json.loads(json.dumps(rule, cls=SdkJSONEncoder, exclude_readonly=True))


def _snake_case(name: str) -> str:
    return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()


def _snake_keys(value: Any) -> Any:
    if isinstance(value, list):
        return [_snake_keys(item) for item in value]
    if isinstance(value, dict):
        return {
            _snake_case(key): (item if key in _MAP_FIELDS else _snake_keys(item))
            for key, item in value.items()
        }
    return value


def alert_rule_as_flat_dict(rule: Any) -> dict[str, Any]:
    """Return an alert rule as a flat snake_case dict, whatever the SDK generation.

    msrest models already flatten ``properties`` in ``as_dict()``. TypeSpec models
    return the REST shape, so ``properties`` is merged up and keys are converted.
    """
    if hasattr(rule, 'serialize'):
        return rule.as_dict()
    data = dict(rule.as_dict())
    properties = data.pop('properties', None) or {}
    return _snake_keys({**data, **properties})


class SentinelService:

    def __init__(self, tenant_config: ConfigurationModels.Systems.Sentinel.Tenant):
        self.setup = tenant_config.setup

    def connect(self) -> Any:
        from azure.identity import ClientSecretCredential

        from opentide.core.environment import reject_unsubstituted_placeholders
        reject_unsubstituted_placeholders(
            self.setup.azure_tenant_id,
            self.setup.azure_client_id,
            self.setup.azure_client_secret,
            self.setup.azure_subscription_id,
            client='Azure',
        )
        credentials = ClientSecretCredential(self.setup.azure_tenant_id, self.setup.azure_client_id, self.setup.azure_client_secret)
        client_class = securityinsights_client_class()
        return client_class(credentials, self.setup.azure_subscription_id, connection_verify=self.setup.ssl)


_SHORTHAND_DURATION = re.compile(
    r'^(?:(?P<days>\d+)d)?(?:(?P<hours>\d+)h)?(?:(?P<minutes>\d+)m)?$',
    re.IGNORECASE,
)
_ISO_DURATION = re.compile(
    r'^P(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?'
    r'(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$',
    re.IGNORECASE,
)


def iso_duration_timedelta(duration: str) -> timedelta:
    """Parse a rule duration into a timedelta.

    Accepts the ISO 8601 form the Sentinel platform contract documents (``PT1H``,
    ``PT30M``, ``P1D``) and the shorthand older catalogues use (``30m``, ``1h``,
    ``1h10m``, ``1d``). The SDK serialises the result back to an ISO 8601 duration.
    """
    from opentide.core.errors import Errors

    text = str(duration).strip()
    shorthand = _SHORTHAND_DURATION.match(text)
    if shorthand and any(shorthand.groups()):
        parts = {name: int(value) for name, value in shorthand.groupdict().items() if value}
        return timedelta(**parts)
    iso = _ISO_DURATION.match(text)
    if iso and not text.upper().endswith('T'):
        parts = {name: int(value) for name, value in iso.groupdict().items() if value}
        if parts:
            return timedelta(**parts)
    raise Errors.TideMDRDataModelErrors(
        f'Duration {duration!r} is not an ISO 8601 duration (PT1H, PT30M, P1D) '
        'or a shorthand duration (30m, 1h, 1d)'
    )
