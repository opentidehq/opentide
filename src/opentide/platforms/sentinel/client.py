"""Azure Sentinel client: the ARM ``alertRules`` REST API, called directly.

opentide sends alert rules to Azure Resource Manager with ``requests`` and an
``azure-identity`` token rather than through ``azure-mgmt-securityinsight``.
That SDK has published only pre-releases since 2.0, and 1.0.0 lacks the alert
property mapping the deployer sends (#545). A pre-release cannot be a
dependency of ``pip install opentide``: uv refuses a transitive pre-release, so
``uv tool install opentide`` and ``uvx opentide`` would not resolve. The REST
body is the documented ARM shape, so nothing is lost by building it here.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from urllib.parse import quote

import requests
import structlog
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from opentide.models.system_config import ConfigurationModels
from opentide.platforms.transport import tenant_tls_verify

logger = structlog.get_logger('opentide.platforms.sentinel.client')

ARM_ENDPOINT = 'https://management.azure.com'
ARM_SCOPE = f'{ARM_ENDPOINT}/.default'
# NRT rules exist only in the preview API versions: 2025-09-01, the newest
# stable version, accepts no `kind: NRT`. This is the version
# azure-mgmt-securityinsight 2.0.0b4 called, which 0.15.0 deployed with.
ALERT_RULES_API_VERSION = '2025-10-01-preview'

# Fields that are maps of user-chosen keys. Their keys are data, not REST
# property names, so they are never case-converted.
_MAP_FIELDS = frozenset({'customDetails', 'custom_details'})


class SentinelApiError(RuntimeError):
    """ARM answered an alert-rule request with an error status."""

    def __init__(self, method: str, url: str, response: requests.Response):
        self.status_code = response.status_code
        code, message = _arm_error(response)
        self.code = code
        self.message = message
        super().__init__(f'{method} {url.split("?", 1)[0]} failed with HTTP {response.status_code} {code}: {message}')


def _arm_error(response: requests.Response) -> tuple[str, str]:
    try:
        error = response.json().get('error') or {}
    except ValueError:
        return '', response.text.strip()[:500]
    return str(error.get('code') or ''), str(error.get('message') or response.text.strip()[:500])


def duration_isoformat(duration: timedelta) -> str:
    """Format a duration the way azure-mgmt-securityinsight 2.0.0b4 serialised it.

    Whole units keep their zero-padded time fields (``PT01H00M00S``, ``PT30M00S``)
    and whole days stay bare (``P1D``), so dry-run previews and logged request
    bodies are unchanged from the SDK-based deployer.
    """
    seconds = int(duration.total_seconds())
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    text = 'P'
    if days:
        text += f'{days}D'
    if hours or minutes or seconds:
        text += 'T'
        bigger = bool(days or hours)
        if bigger:
            text += f'{hours:02}H'
        bigger = bigger or bool(minutes)
        if bigger:
            text += f'{minutes:02}M'
        text += f'{seconds:02}S'
    return text if text != 'P' else 'PT0S'


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


def alert_rule_as_flat_dict(rule: dict[str, Any]) -> dict[str, Any]:
    """Return a listed alert rule as a flat snake_case dict.

    ARM nests the rule under ``properties``; it is merged up and the keys are
    converted, so ``properties.displayName`` reads as ``display_name``.
    """
    data = dict(rule)
    properties = data.pop('properties', None) or {}
    return _snake_keys({**data, **properties})


class AlertRules:
    """The ``Microsoft.SecurityInsights/alertRules`` operations of one subscription."""

    def __init__(self, session: requests.Session, credential: Any, subscription_id: str, timeout: float = 60):
        self._session = session
        self._credential = credential
        self._subscription_id = subscription_id
        self._timeout = timeout

    def _url(self, resource_group_name: str, workspace_name: str, rule_id: str | None = None) -> str:
        url = (
            f'{ARM_ENDPOINT}/subscriptions/{quote(self._subscription_id, safe="")}'
            f'/resourceGroups/{quote(resource_group_name, safe="")}'
            f'/providers/Microsoft.OperationalInsights/workspaces/{quote(workspace_name, safe="")}'
            '/providers/Microsoft.SecurityInsights/alertRules'
        )
        if rule_id is not None:
            url += f'/{quote(rule_id, safe="")}'
        return url

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        # azure-identity caches the token and refreshes it before it expires.
        token = self._credential.get_token(ARM_SCOPE).token
        params = None if 'api-version=' in url else {'api-version': ALERT_RULES_API_VERSION}
        response = self._session.request(
            method,
            url,
            params=params,
            headers={'Authorization': f'Bearer {token}'},
            timeout=self._timeout,
            **kwargs,
        )
        if response.status_code >= 400:
            raise SentinelApiError(method, url, response)
        return response

    def create_or_update(self, resource_group_name: str, workspace_name: str, rule_id: str, alert_rule: dict[str, Any]) -> dict[str, Any]:
        response = self._request('PUT', self._url(resource_group_name, workspace_name, rule_id), json=alert_rule)
        return response.json() if response.content else {}

    def delete(self, resource_group_name: str, workspace_name: str, rule_id: str) -> None:
        self._request('DELETE', self._url(resource_group_name, workspace_name, rule_id))

    def list(self, resource_group_name: str, workspace_name: str) -> Iterator[dict[str, Any]]:
        url: str | None = self._url(resource_group_name, workspace_name)
        while url:
            page = self._request('GET', url).json()
            yield from page.get('value') or []
            url = page.get('nextLink')


class SentinelClient:
    """What :meth:`SentinelService.connect` returns: the alert-rule operations."""

    def __init__(self, credential: Any, subscription_id: str, verify: bool = True):
        session = requests.Session()
        session.verify = verify
        session.headers.update({'Accept': 'application/json'})
        retries = Retry(
            total=3,
            backoff_factor=0.8,
            status_forcelist=[408, 429, 500, 502, 503, 504],
            allowed_methods=['GET', 'PUT', 'DELETE'],
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        session.mount('https://', HTTPAdapter(max_retries=retries))
        self.alert_rules = AlertRules(session, credential, subscription_id)


class SentinelService:

    def __init__(self, tenant_config: ConfigurationModels.Systems.Sentinel.Tenant):
        self.setup = tenant_config.setup
        self.tenant_name = tenant_config.name

    def connect(self) -> SentinelClient:
        from azure.identity import ClientSecretCredential

        from opentide.core.environment import reject_unsubstituted_placeholders
        reject_unsubstituted_placeholders(
            self.setup.azure_tenant_id,
            self.setup.azure_client_id,
            self.setup.azure_client_secret,
            self.setup.azure_subscription_id,
            client='Azure',
        )
        verify = tenant_tls_verify(self.setup.ssl, platform='sentinel', tenant=self.tenant_name)
        # The tenant's ssl covers the Entra ID token request as well as ARM.
        credentials = ClientSecretCredential(self.setup.azure_tenant_id, self.setup.azure_client_id, self.setup.azure_client_secret, connection_verify=verify)
        return SentinelClient(credentials, self.setup.azure_subscription_id, verify=verify)


# Case-sensitive, like the Elastic parser: an upper-case `M` reads as months.
_SHORTHAND_DURATION = re.compile(
    r'^(?:(?P<days>\d+)d)?(?:(?P<hours>\d+)h)?(?:(?P<minutes>\d+)m)?(?:(?P<seconds>\d+)s)?$'
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
    ``1h10m``, ``1d``). :func:`duration_isoformat` writes the result back as ISO 8601.
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
    raise Errors.TideRuleDataModelErrors(
        f'Duration {duration!r} is not an ISO 8601 duration (PT1H, PT30M, P1D) '
        'or a shorthand duration (30m, 1h, 1d, 1h10m)'
    )
