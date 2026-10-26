from __future__ import annotations

import re
import ssl
import urllib.request
from collections.abc import Callable
from io import BytesIO
from random import randrange
from typing import TYPE_CHECKING, Any, Literal
from urllib.error import HTTPError
from urllib.parse import urlsplit

import structlog

from opentide.core.time import utc_now

if TYPE_CHECKING:
    from splunklib.client import Service

from opentide.core.debug import DebugEnvironment
from opentide.core.registry import DebugHelpers, Opentide
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.transport import DEFAULT_TIMEOUT

logger = structlog.get_logger("opentide.platforms.splunk.client")


class SplunkConnection:
    """
    Utility class used to initialize all constant relevant to operations with Splunk
    """

    #: The tenant whose setup the per-tenant settings were last taken from.
    _tenant: ConfigurationModels.Systems.Splunk.Tenant | None = None

    def __init__(self):
        self.DEBUG = DebugEnvironment.ENABLED
        self.DEBUG_STEP = bool(self.DEBUG)
        SPLUNK_CONFIG = Opentide.Configurations.Systems.Splunk
        self.DEPLOYER_IDENTIFIER = "splunk"

        tenants = getattr(SPLUNK_CONFIG, "tenants", None)
        if tenants:
            self._init_from_tenants(SPLUNK_CONFIG, tenants[0])
        else:
            self._init_from_legacy(SPLUNK_CONFIG)

        self.SPLUNK_SUBSCHEMA = Opentide.TideSchemas.subschemas["systems"][
            self.DEPLOYER_IDENTIFIER
        ]["properties"]
        self.ALERT_SEVERITY_MAPPING = {
            "Informational": 2,
            "Low": 3,
            "Medium": 4,
            "High": 5,
            "Critical": 6,
        }

    def _init_from_tenants(self, splunk_config, first_tenant) -> None:
        self.DEFAULT_CONFIG = getattr(splunk_config, "defaults", {}) or {}
        self.STATUS_MODIFIERS = getattr(splunk_config, "modifiers", None) or []
        self.use_tenant(first_tenant)

    def use_tenant(self, tenant: ConfigurationModels.Systems.Splunk.Tenant) -> None:
        """Take the actions, scheduling, skew and offset of the rules built next from *tenant*.

        A deploy calls this for every tenant it reaches; these used to come
        from the first tenant only, whatever tenant a rule went to.
        """
        if tenant is self._tenant:
            # Resolving the same tenant again would repeat its warnings.
            return
        setup = DebugHelpers.fetch_config_envvar(
            {
                "url": tenant.setup.url,
                "port": tenant.setup.port,
                "app": tenant.setup.app,
                "correlation_searches": tenant.setup.correlation_searches,
                "frequency_scheduling": tenant.setup.frequency_scheduling,
                "actions_enabled": tenant.setup.actions_enabled or [],
                "default_actions": tenant.setup.default_actions or [],
                "allow_skew": tenant.setup.allow_skew,
                "schedule_offset": tenant.setup.schedule_offset,
            }
        )
        self._apply_setup(setup, token=tenant.setup.token)
        self._tenant = tenant

    def _init_from_legacy(self, splunk_config) -> None:
        SPLUNK_SETUP = DebugHelpers.fetch_config_envvar(splunk_config.setup)
        SPLUNK_SECRETS = DebugHelpers.fetch_config_envvar(splunk_config.secrets)
        self.DEFAULT_CONFIG = getattr(splunk_config, "defaults", {}) or {}
        self.STATUS_MODIFIERS = getattr(splunk_config, "modifiers", None) or []
        # A legacy [setup] table without frequency_scheduling has always
        # scheduled at the current time; a new default would move deployed searches.
        self._apply_setup(
            SPLUNK_SETUP, token=SPLUNK_SECRETS.get("token", ""), unset_frequency="current"
        )

    def _apply_setup(
        self,
        setup: dict,
        *,
        token: str,
        unset_frequency: Literal["random", "current", "custom"] = "random",
    ) -> None:
        self.SPLUNK_URL = setup.get("url", "")
        try:
            self.SPLUNK_PORT = int(setup.get("port", 8089))
        except Exception:
            self.SPLUNK_PORT = setup.get("port", 8089)
        self.SPLUNK_APP = setup.get("app", "search")
        self.SPLUNK_TOKEN = token
        self.CORRELATION_SEARCHES = setup.get("correlation_searches", True)
        self.SPLUNK_ACTIONS = setup.get("actions_enabled") or []
        self.SPLUNK_DEFAULT_ACTIONS = setup.get("default_actions") or []
        self.TIMERANGE_MODE = correct_timerange_mode(
            setup.get("frequency_scheduling"), unset=unset_frequency
        )
        skewing = setup.get("allow_skew")
        if skewing:
            self.SKEWING_VALUE = float(str(skewing).replace("%", "e-2"))
        else:
            self.SKEWING_VALUE = 0
        self.OFFSET = int(setup.get("schedule_offset", 0))


def correct_timerange_mode(
    timerange: str | None, *, unset: Literal["random", "current", "custom"] = "random"
) -> Literal["random", "current", "custom"]:
    """Resolve ``frequency_scheduling``; an unset value means *unset*, without a warning."""
    if not timerange:
        return unset
    if timerange not in ("random", "current", "custom"):
        logger.warning(
            "frequency_scheduling_is_not_valid",
            detail=f"Got {timerange!r}, using current",
            advice="Set frequency_scheduling to random, current, or custom in splunk.toml",
        )
        return "current"
    return timerange  # type: ignore[return-value]


def splunk_timerange(time: str, skewing: float | int = 1, offset: int = 0) -> str:
    """
    Converts a Nd, Nh or Nm format into an splunk compatible earliest_at equivalent.
    Optionally supports skewing and offset
    """
    skewing += 1
    unit = time[-1]
    count = int(time[:-1])
    if unit == "h":
        count = count * 60
    elif unit == "d":
        count = count * 1440
    elif unit != "m":
        raise Exception(
            "[FATAL] Time Unit not supported by splunk earliest at converter (expects m, h or d)"
        )
    converted = offset + round(count * skewing)
    return f"-{converted}m@m"


def cron_to_timeframe(
    frequency: str,
    mode: Literal["random", "current", "custom"] = "random",
    custom_time: str | None = None,
) -> str:
    unit = frequency[-1]
    count = int(frequency[:-1])
    min_val = hour = ""
    if (unit == "m" and count > 59) or (unit == "h" and count > 23) or (unit == "d" and count > 30):
        logger.warning(
            "time_boundaries_were_bypassed_expected_usage_1_59m_1_23h_or_1_30",
            detail="Proceeding, but note that behaviour is not guaranteed",
        )
    if mode == "random":
        min_val = str(randrange(60))
        hour = str(randrange(24))
    if mode == "current":
        now = utc_now()
        min_val = now.strftime("%M")
        hour = now.strftime("%H")
    if mode == "custom":
        if not custom_time:
            raise Exception(
                "[FATAL] When selecting a custom time, you need to input a time in the "
                "correct format : HHhmm."
            )
        hour, min_val = custom_time.split("h")
    match unit:
        case "m":
            cron = f"*/{count} * * * *"
        case "h":
            cron = f"{min_val} */{count} * * *"
        case "d":
            cron = f"{min_val} {hour} */{count} * *"
        case _:
            raise Exception(
                "[FATAL] Time Unit not supported by crontab converter (expects m, h or d)"
            )
    return cron


#: Status a handler reports for an HTTP error when the caller asked to see
#: errors as responses (query validation reads the parse errors from the body).
HTTP_ERROR_STATUS = 19

RequestHandler = Callable[[str, dict[str, Any]], dict[str, Any]]

_HTML_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class SplunkAnsweredHtmlError(ConnectionError):
    """The address answered with an HTML page, which the Splunk REST API never sends.

    Behind a proxy that is the proxy's own page (a block page, a login page):
    splunklib used to fail on it with ``xml.etree.ElementTree.ParseError:
    mismatched tag``, which reads like a TLS fault. A ``ConnectionError``, so
    a live query check reports it as the tenant's result.
    """


def splunk_route(url: str) -> str | None:
    """The proxy ``urllib`` sends *url* through, without credentials; ``None`` if direct."""
    parts = urlsplit(url)
    proxy = urllib.request.getproxies().get(parts.scheme)
    if not proxy or urllib.request.proxy_bypass(parts.netloc):
        return None
    proxy_parts = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
    return f"{proxy_parts.scheme}://{proxy_parts.netloc.rpartition('@')[2]}"


def _looks_like_html(headers: Any, body: bytes) -> bool:
    """An HTML page; a body Splunk labels XML, JSON or text is trusted whatever it starts with."""
    content_type = str(headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if content_type == "text/html":
        return True
    if content_type:
        return False
    return body.lstrip()[:15].lower().startswith((b"<!doctype html", b"<html"))


def _html_answer(url: str, body: bytes) -> SplunkAnsweredHtmlError:
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    title = _HTML_TITLE.search(body)
    page = f" (page title: {title.group(1).decode(errors='replace').strip()!r})" if title else ""
    proxy = splunk_route(url)
    if proxy:
        return SplunkAnsweredHtmlError(
            f"Splunk at {origin} answered with an HTML page, not its REST API{page}. "
            f"The request went through the proxy {proxy}, so the page is most likely the "
            "proxy's (a block or sign-in page). If this tenant is reached directly, add its "
            f"host to NO_PROXY and no_proxy (NO_PROXY={parts.hostname}); otherwise check the "
            "tenant's port: 8089 is the REST API, 8000 Splunk Web."
        )
    return SplunkAnsweredHtmlError(
        f"Splunk at {origin} answered with an HTML page, not its REST API{page}. "
        "Check the tenant's url and port: the REST API listens on the management port "
        "(8089 by default), while 8000 serves Splunk Web."
    )


def request_handler(*, verify: bool, allow_http_errors: bool = False) -> RequestHandler:
    """A splunklib ``handler`` bound to one tenant's connection settings.

    splunklib's own handler opens ``http.client`` connections, which ignore
    ``HTTPS_PROXY`` and ``NO_PROXY``; ``urllib`` honours both, which
    ``--proxy`` relies on. *verify* and *allow_http_errors* are captured
    here rather than read from the process environment, so two tenants with
    different ``ssl`` settings never share them.
    """
    context = None
    if not verify:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    def handle(url: str, message: dict[str, Any]) -> dict[str, Any]:
        # splunklib sends a body with POST, PUT and PATCH only. urllib picks
        # GET for a request without a body unless told the method, which sent
        # every DELETE as a GET and left retired saved searches in place.
        method = message["method"].upper()
        data = message.get("body")
        headers = dict(message.get("headers", []))
        req = urllib.request.Request(url, data, headers, method=method)
        failed = False
        try:
            response = urllib.request.urlopen(req, context=context, timeout=DEFAULT_TIMEOUT)
            status = response.code
        except HTTPError as error:
            # Includes a 307 answering a POST, which urllib does not follow.
            response = error
            status = error.code
            failed = True
        body = response.read()
        if _looks_like_html(response.headers, body):
            raise _html_answer(url, body)
        answer = {
            "status": HTTP_ERROR_STATUS if failed and allow_http_errors else status,
            "reason": response.msg,
            "headers": dict(response.headers),
            "body": BytesIO(body),
        }
        if failed and not allow_http_errors:
            from splunklib.binding import HTTPError as SplunkHTTPError
            from splunklib.data import record

            logger.critical(
                "fatal_error",
                detail=f"Received HTTP Error Code {status} {response.msg}",
                context=str(body),
            )
            # splunklib raises only for a status of 400 or more, so a 307 a
            # gateway answers for a timed-out search head read as a deployed
            # rule. Raise splunklib's own error, which carries the body.
            raise SplunkHTTPError(record(answer))
        return answer

    return handle


def connect_splunk(
    host: str,
    port: str | int,
    token: str,
    app: str,
    allow_http_errors: bool = False,
    ssl_enabled: bool | str = True,
) -> Service:
    from opentide.core.environment import reject_unsubstituted_placeholders

    reject_unsubstituted_placeholders(host, port, token, app, ssl_enabled, client="Splunk")
    from splunklib import client

    if not isinstance(ssl_enabled, bool):
        raise ValueError(
            f"Splunk tenant ssl must be true or false, got {ssl_enabled!r}. "
            "Set ssl in the tenant's [tenants.setup] table in splunk.toml."
        )
    port = int(port)
    if allow_http_errors:
        logger.info(
            "http_errors_will_be_returned_with_error_code_19",
            detail="Ensure to handle them appropriately",
        )
    if not ssl_enabled:
        logger.info(
            "splunk_tls_verification_disabled",
            host=host,
            advice="Set ssl = true in the tenant's setup once its certificate is trusted",
        )
    proxy = splunk_route(f"https://{host}:{port}/")
    logger.info("splunk_tenant_route", host=host, port=port, via=proxy or "direct")
    service = client.connect(
        handler=request_handler(verify=ssl_enabled, allow_http_errors=allow_http_errors),
        host=host,
        port=port,
        token=token,
        autologin=True,
        app=app,
        sharing="app",
    )
    logger.info("successfully_connected_to_splunk")
    return service


def create_query(data: DetectionRule) -> str:
    """Build the final SPL query from a typed DetectionRule."""
    uuid = data.metadata.uuid
    splunk_config = data.platform_configs().splunk
    if not splunk_config or not splunk_config.query:
        raise ValueError("Missing Splunk query in typed MDR")
    status = splunk_config.status
    spl = splunk_config.query.strip()
    macro = (
        f'| eval MDR_UUID="{uuid}", MDR_status="{status}" \n|`soc_macro_auto_mdr_mapping(MDR_UUID)`'
    )
    return spl + "\n" + macro
