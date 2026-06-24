from __future__ import annotations

import os
import ssl
import urllib.request
from abc import ABC
from datetime import datetime
from io import BytesIO
from random import randrange
from typing import TYPE_CHECKING, Literal
from urllib.error import HTTPError

import structlog

if TYPE_CHECKING:
    from splunklib.client import Service

from opentide.core.debug import DebugEnvironment
from opentide.core.registry import DebugHelpers, OpenTide
from opentide.deployment import Proxy
from opentide.models.rule import DetectionRule

logger = structlog.get_logger("opentide.platforms.splunk.client")


class SplunkConnection(ABC):
    """
    Utility class used to initialize all constant relevant to operations with Splunk
    """

    def __init__(self):
        self.DEBUG = DebugEnvironment.ENABLED
        self.DEBUG_STEP = bool(self.DEBUG)
        SPLUNK_CONFIG = OpenTide.Configurations.Systems.Splunk
        self.DEPLOYER_IDENTIFIER = "splunk"

        tenants = getattr(SPLUNK_CONFIG, "tenants", None)
        if tenants:
            self._init_from_tenants(SPLUNK_CONFIG, tenants[0])
        else:
            self._init_from_legacy(SPLUNK_CONFIG)

        if self.DEBUG:
            self.SSL_ENABLED = DebugEnvironment.SSL_ENABLED

        self.SPLUNK_SUBSCHEMA = OpenTide.TideSchemas.subschemas["systems"][
            self.DEPLOYER_IDENTIFIER
        ]["properties"]
        self.ALERT_SEVERITY_MAPPING = {
            "Informational": 2,
            "Low": 3,
            "Medium": 4,
            "High": 5,
            "Critical": 6,
        }
        logger.info(
            "ssl_has_been_set_to",
            detail=str(self.SSL_ENABLED),
            advice="This can be adjusted in splunk.toml with the setup.ssl keyword",
        )

    def _init_from_tenants(self, splunk_config, first_tenant) -> None:
        setup = DebugHelpers.fetch_config_envvar(
            {
                "proxy": first_tenant.setup.proxy,
                "ssl": first_tenant.setup.ssl,
                "url": first_tenant.setup.url,
                "port": first_tenant.setup.port,
                "app": first_tenant.setup.app,
                "correlation_searches": first_tenant.setup.correlation_searches,
                "frequency_scheduling": first_tenant.setup.frequency_scheduling,
                "actions_enabled": first_tenant.setup.actions_enabled or [],
                "default_actions": first_tenant.setup.default_actions or [],
                "allow_skew": first_tenant.setup.allow_skew,
                "schedule_offset": first_tenant.setup.schedule_offset,
            }
        )
        self.DEFAULT_CONFIG = getattr(splunk_config, "defaults", {}) or {}
        self.STATUS_MODIFIERS = getattr(splunk_config, "modifiers", {}) or {}
        self._apply_setup(setup, token=first_tenant.setup.token)

    def _init_from_legacy(self, splunk_config) -> None:
        SPLUNK_SETUP = DebugHelpers.fetch_config_envvar(splunk_config.setup)
        SPLUNK_SECRETS = DebugHelpers.fetch_config_envvar(splunk_config.secrets)
        self.DEFAULT_CONFIG = splunk_config.defaults
        self.STATUS_MODIFIERS = splunk_config.modifiers
        self._apply_setup(SPLUNK_SETUP, token=SPLUNK_SECRETS.get("token", ""))

    def _apply_setup(self, setup: dict, *, token: str) -> None:
        self.SSL_ENABLED: bool = setup.get("ssl", True)
        self.SPLUNK_URL = setup["url"]
        try:
            self.SPLUNK_PORT = int(setup["port"])
        except Exception:
            self.SPLUNK_PORT = setup["port"]
        self.SPLUNK_APP = setup["app"]
        self.SPLUNK_TOKEN = token
        self.PROXY_ENABLED = setup.get("proxy", False)
        self.CORRELATION_SEARCHES = setup.get("correlation_searches", True)
        self.SPLUNK_ACTIONS = setup.get("actions_enabled") or []
        self.SPLUNK_DEFAULT_ACTIONS = setup.get("default_actions") or []
        self.TIMERANGE_MODE = correct_timerange_mode(setup.get("frequency_scheduling", ""))
        skewing = setup.get("allow_skew")
        if skewing:
            self.SKEWING_VALUE = float(str(skewing).replace("%", "e-2"))
        else:
            self.SKEWING_VALUE = 0
        self.OFFSET = int(setup.get("schedule_offset", 0))

    def configure_proxy(self):
        """Applies the proxy configuration for this system."""
        if self.PROXY_ENABLED:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()


def correct_timerange_mode(timerange: str) -> Literal["random", "current", "custom"]:
    corrected_timerange: Literal["random", "current", "custom"]
    if timerange not in ["random", "current", "custom"]:
        logger.warning(
            "the_frequency_scheduling_setting_was_not_correct_set",
            detail="hard setting it to current",
            advice="Expected values are random, current, or custom",
        )
        corrected_timerange = "current"
    else:
        corrected_timerange = timerange  # type: ignore[assignment]
    return corrected_timerange


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
    if unit == "m" and count > 59 or (unit == "h" and count > 23) or (unit == "d" and count > 30):
        logger.warning(
            "time_boundaries_were_bypassed_expected_usage_1_59m_1_23h_or_1_30",
            detail="Proceeding, but note that behaviour is not guaranteed",
        )
    if mode == "random":
        min_val = str(randrange(60))
        hour = str(randrange(24))
    if mode == "current":
        now = datetime.now()
        min_val = now.strftime("%M")
        hour = now.strftime("%H")
    if mode == "custom":
        if not custom_time:
            raise Exception(
                "[FATAL] When selecting a custom time, you need to input a time in the correct format : HHhmm."
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


def custom_request_handler(url, message):
    method = message["method"].lower()
    data = message.get("body", "") if method == "post" else None
    headers = dict(message.get("headers", []))
    req = urllib.request.Request(url, data, headers)
    response = None
    try:
        if os.environ["TIDE_SPLUNK_SSL_ENABLED"]:
            response = urllib.request.urlopen(req)
        else:
            response = urllib.request.urlopen(req, context=ssl._create_unverified_context())
    except HTTPError as error:
        response = error
        if os.getenv("TIDE_SPLUNK_PLUGIN_ALLOW_HTTP_ERRORS") == "True":
            response.code = 19
        else:
            logger.critical(
                "fatal_error",
                detail=f"Received HTTP Error Code {repr(error)}",
                context=str(response.read()),
            )
    return {
        "status": response.code,
        "reason": response.msg,
        "headers": dict(response.info()),
        "body": BytesIO(response.read()),
    }


def connect_splunk(
    host: str,
    port: str | int,
    token: str,
    app: str,
    allow_http_errors: bool = False,
    ssl_enabled: bool = True,
) -> Service:
    from splunklib import client

    port = int(port)
    if allow_http_errors:
        os.environ["TIDE_SPLUNK_PLUGIN_ALLOW_HTTP_ERRORS"] = "True"
        logger.info(
            "http_errors_will_be_returned_with_error_code_19",
            detail="Ensure to handle them appropriately",
        )
    os.environ["TIDE_SPLUNK_SSL_ENABLED"] = "True" if ssl_enabled else "False"
    service = client.connect(
        handler=custom_request_handler,
        host=host,
        port=port,
        token=token,
        autologin=True,
        app=app,
        sharing="app",
    )
    logger.info("successfully_connected_to_splunk")
    return service


def create_query(data: dict) -> str:
    """Build SPL from a legacy dict-based MDR."""
    # TODO: DEPRECATED [splunk-mdrv4]
    uuid = data.get("uuid") or data["metadata"]["uuid"]
    mdr_splunk = data["configurations"]["splunk"]
    status = mdr_splunk["status"]
    spl = mdr_splunk["query"].strip()
    macro = (
        f'| eval MDR_UUID="{uuid}", MDR_status="{status}" \n|`soc_macro_auto_mdr_mapping(MDR_UUID)`'
    )
    return spl + "\n" + macro


def create_query_v4(data: DetectionRule) -> str:
    """Build the final SPL query from a typed DetectionRule."""
    uuid = data.metadata.uuid
    splunk_config = data.configurations.splunk
    if not splunk_config or not splunk_config.query:
        raise ValueError("Missing Splunk query in typed MDR")
    status = splunk_config.status
    spl = splunk_config.query.strip()
    macro = (
        f'| eval MDR_UUID="{uuid}", MDR_status="{status}" \n|`soc_macro_auto_mdr_mapping(MDR_UUID)`'
    )
    return spl + "\n" + macro
