"""Platform configuration parsing — replaces PlatformConfigLoader."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, cast

from opentide.models.platform import (
    CarbonBlackConfig,
    CrowdstrikeConfig,
    DefenderConfig,
    HarfangLabConfig,
    PlatformConfigBase,
    SentinelConfig,
    SentinelOneConfig,
    SplunkConfig,
)
from opentide.models.platform_configs import (
    DefenderAllowBlockAction,
    DefenderAllowBlockGroupScoping,
    DefenderDeviceActions,
    DefenderFileActions,
    DefenderUserActions,
    HarfangLabSigma,
    HarfangLabSigmaLogSource,
    HarfangLabSigmaSelection,
    HarfangLabYara,
    HarfangLabYaraMeta,
    SentinelAlert,
    SentinelAlertGrouping,
    SentinelCustomDetails,
    SentinelDynamicProperties,
    SentinelEntityMapping,
    SentinelExclusion,
    SentinelGrouping,
    SentinelMappingEntry,
    SentinelOneCondition,
    SentinelOneCorrelation,
    SentinelOneSingleEvent,
    SentinelOneSubQuery,
    SentinelScheduling,
    SentinelTemplate,
    SentinelTrigger,
    SplunkActions,
    SplunkEmail,
    SplunkEmailInclude,
    SplunkNotable,
    SplunkNotableDrilldown,
    SplunkNotableEvent,
    SplunkRisk,
    SplunkRiskObject,
    SplunkSchedule,
    SplunkScheduling,
    SplunkThreatObject,
    SplunkThrottling,
    SplunkTimerange,
    SplunkTrigger,
)


def _base_configuration(mdr_config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract shared platform fields from a configuration block."""
    config = deepcopy(mdr_config)
    base = {
        "schema": config.pop("schema", None),
        "status": config.pop("status", None),
        "tenants": config.pop("tenants", None),
        "flags": config.pop("flags", None),
        "contributors": config.pop("contributors", None),
        "enabled": config.pop("enabled", False),
        "name": config.pop("name", ""),
    }
    return (config, base)


def _external_rule_id(mdr_config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Normalise rule_id:: tenant keys into a bundle mapping."""
    config = deepcopy(mdr_config)
    if "rule_id_bundle" in config:
        return (config, cast(dict[str, Any], config.pop("rule_id_bundle")))
    bundle: dict[str, Any] = {}
    for key in list(config):
        if key.startswith("rule_id::"):
            tenant = key.split("rule_id::", 1)[1]
            bundle[tenant] = config.pop(key)
    return (config, bundle)


def load_sentinel_config(mdr_config: dict[str, Any]) -> SentinelConfig:
    remaining, base = _base_configuration(mdr_config)
    query = remaining.pop("query")
    template = remaining.pop("template", None)
    trigger = remaining.pop("trigger", None)
    scheduling = SentinelScheduling.model_validate(remaining.pop("scheduling", {}))
    alert_raw = remaining.pop("alert", None) or {}
    custom_details = alert_raw.pop("custom_details", None)
    dynamic_properties = alert_raw.pop("dynamic_properties", None)
    alert = SentinelAlert.model_validate(
        {
            **alert_raw,
            "custom_details": [SentinelCustomDetails.model_validate(d) for d in custom_details]
            if custom_details
            else None,
            "dynamic_properties": [
                SentinelDynamicProperties.model_validate(d) for d in dynamic_properties
            ]
            if dynamic_properties
            else None,
        }
    )
    grouping = None
    if grouping_raw := remaining.pop("grouping", None):
        alert_grouping = grouping_raw.pop("alert", None)
        grouping = SentinelGrouping(
            event=grouping_raw["event"],
            alert=SentinelAlertGrouping.model_validate(alert_grouping) if alert_grouping else None,
        )
    entities = None
    if entity_list := remaining.pop("entities", None):
        entities = [
            SentinelEntityMapping(
                entity=mapping["entity"],
                mappings=[SentinelMappingEntry.model_validate(e) for e in mapping["mappings"]],
            )
            for mapping in entity_list
        ]
    exclusions = None
    if exclusions_raw := remaining.pop("exclusions", None):
        exclusions = [SentinelExclusion.model_validate(e) for e in exclusions_raw]
    return SentinelConfig(
        **base,
        query=query,
        template=SentinelTemplate.model_validate(template) if template else None,
        trigger=SentinelTrigger.model_validate(trigger) if trigger else None,
        scheduling=scheduling,
        alert=alert,
        grouping=grouping,
        entities=entities,
        exclusions=exclusions,
    )


def load_defender_config(mdr_config: dict[str, Any]) -> DefenderConfig:
    remaining, base = _base_configuration(mdr_config)
    rule_id_bundle: dict[str, int] = {}
    for key in list(remaining):
        if key.startswith("rule_id::"):
            tenant = key.split("rule_id::", 1)[1]
            rule_id_bundle[tenant] = remaining.pop(key)
    rule_id = rule_id_bundle or remaining.pop("rule_id", None)
    from opentide.models.platform_configs import (
        DefenderAlert,
        DefenderExclusion,
        DefenderGroupScoping,
        DefenderImpactedEntities,
        DefenderResponseActions,
    )

    alert = DefenderAlert.model_validate(remaining.pop("alert"))
    impacted_entities = DefenderImpactedEntities.model_validate(remaining.pop("impacted_entities"))
    scope = DefenderGroupScoping.model_validate(remaining.pop("scope"))
    actions_raw = remaining.pop("actions", None)
    response_actions = None
    if actions_raw:
        devices = (
            DefenderDeviceActions.model_validate(actions_raw["devices"])
            if actions_raw.get("devices")
            else None
        )
        files = None
        if files_raw := actions_raw.get("files"):
            allow_block = dict(files_raw.get("allow_block") or {})
            allow_block_action = None
            if allow_block:
                groups = allow_block.pop("groups", None)
                allow_block_action = DefenderAllowBlockAction(
                    **allow_block,
                    groups=DefenderAllowBlockGroupScoping.model_validate(groups)
                    if groups
                    else None,
                )
            files = DefenderFileActions(
                allow_block=allow_block_action,
                quarantine_file=files_raw.get("quarantine_files")
                or files_raw.get("quarantine_file"),
            )
        users = (
            DefenderUserActions.model_validate(actions_raw["users"])
            if actions_raw.get("users")
            else None
        )
        if devices or files or users:
            response_actions = DefenderResponseActions(devices=devices, files=files, users=users)
    exclusions = None
    if exclusions_raw := remaining.pop("exclusions", None):
        exclusions = [DefenderExclusion.model_validate(e) for e in exclusions_raw]
    return DefenderConfig(
        **base,
        **remaining,
        alert=alert,
        impacted_entities=impacted_entities,
        scope=scope,
        rule_id=rule_id,
        actions=response_actions,
        exclusions=exclusions,
    )


def load_crowdstrike_config(mdr_config: dict[str, Any]) -> CrowdstrikeConfig:
    remaining, base = _base_configuration(mdr_config)
    remaining, rule_id_bundle = _external_rule_id(remaining)
    from opentide.models.platform_configs import CrowdstrikeDetails, CrowdstrikeSchedule

    return CrowdstrikeConfig(
        **base,
        details=CrowdstrikeDetails.model_validate(remaining.pop("details")),
        schedule=CrowdstrikeSchedule.model_validate(remaining.pop("schedule")),
        query=remaining.pop("query"),
        rule_id_bundle=rule_id_bundle or None,
    )


def load_sentinel_one_config(mdr_config: dict[str, Any]) -> SentinelOneConfig:
    remaining, base = _base_configuration(mdr_config)
    remaining, rule_id_bundle = _external_rule_id(remaining)
    details = None
    if details_raw := remaining.pop("details", None):
        from opentide.models.platform_configs import SentinelOneDetails

        details = SentinelOneDetails.model_validate(details_raw)
    condition_raw = remaining.pop("condition")
    rule_type = condition_raw.pop("type")
    single_event = None
    if single_event_raw := condition_raw.pop("single_event", None):
        single_event = SentinelOneSingleEvent.model_validate(single_event_raw)
    correlation = None
    if correlation_raw := condition_raw.pop("correlation", None):
        sub_queries = [
            SentinelOneSubQuery.model_validate(sub) for sub in correlation_raw.pop("sub_queries")
        ]
        correlation = SentinelOneCorrelation(**correlation_raw, sub_queries=sub_queries)
    from opentide.models.platform_configs import SentinelOneResponse

    condition = SentinelOneCondition(
        type=rule_type,
        single_event=single_event,
        correlation=correlation,
        cool_off=condition_raw.pop("cool_off", None),
    )
    response = (
        SentinelOneResponse.model_validate(remaining.pop("response"))
        if remaining.get("response")
        else None
    )
    return SentinelOneConfig(
        **base,
        details=details,
        condition=condition,
        response=response,
        rule_id_bundle=rule_id_bundle or None,
    )


def load_harfanglab_config(mdr_config: dict[str, Any]) -> HarfangLabConfig:
    remaining, base = _base_configuration(mdr_config)
    remaining, rule_id_bundle = _external_rule_id(remaining)
    sigma = None
    if sigma_raw := remaining.pop("sigma", None):
        logsource = HarfangLabSigmaLogSource.model_validate(sigma_raw.pop("logsource"))
        selections = [
            HarfangLabSigmaSelection.model_validate(sel) for sel in sigma_raw.pop("selections", [])
        ]
        sigma = HarfangLabSigma(
            logsource=logsource,
            selections=selections,
            condition=sigma_raw.pop("condition"),
            false_positives=sigma_raw.pop("false_positives", None),
        )
    yara = None
    if yara_raw := remaining.pop("yara", None):
        meta = HarfangLabYaraMeta.model_validate(yara_raw.pop("meta"))
        yara = HarfangLabYara(
            meta=meta,
            strings=yara_raw.pop("strings"),
            condition=yara_raw.pop("condition"),
            imports=yara_raw.pop("imports", None),
        )
    return HarfangLabConfig(
        **base,
        maturity=remaining.pop("maturity", "Experimental"),
        confidence=remaining.pop("confidence", "Moderate"),
        action=remaining.pop("action", "Alert"),
        tags=remaining.pop("tags", None),
        sigma=sigma,
        yara=yara,
        rule_id_bundle=rule_id_bundle or None,
    )


def _normalize_splunk_v2(config: dict[str, Any]) -> dict[str, Any]:
    """Normalise flat splunk::2.x layout into nested v3/v4 structure."""
    normalized = deepcopy(config)

    scheduling_data = normalized.pop("scheduling", None)
    if scheduling_data:
        if "schedule" not in scheduling_data and (
            "frequency" in scheduling_data
            or "cron" in scheduling_data
            or "custom_time" in scheduling_data
        ):
            schedule_dict: dict[str, Any] = {}
            for key in ("frequency", "cron", "custom_time"):
                value = scheduling_data.pop(key, None)
                if value is not None:
                    schedule_dict[key] = value
            if schedule_dict:
                scheduling_data["schedule"] = schedule_dict
        if "timerange" not in scheduling_data and "lookback" in scheduling_data:
            scheduling_data["timerange"] = {"lookback": scheduling_data.pop("lookback")}

    trigger_data = normalized.pop("trigger", None)
    if trigger_data is None:
        throttling_data = normalized.pop("throttling", None)
        threshold_val = normalized.pop("threshold", None)
        if throttling_data or threshold_val is not None:
            trigger_data = {}
            if throttling_data:
                trigger_data["throttling"] = throttling_data
            if threshold_val is not None:
                trigger_data["threshold"] = threshold_val

    actions_data = normalized.pop("actions", None)
    if actions_data is None:
        notable_data = normalized.pop("notable", None)
        risk_data = normalized.pop("risk", None)
        email_data = normalized.pop("email", None)
        if notable_data or risk_data or email_data:
            actions_data = {}
            if notable_data:
                actions_data["notable"] = notable_data
            if risk_data:
                actions_data["risk"] = risk_data
            if email_data:
                actions_data["email"] = email_data

    if scheduling_data:
        normalized["scheduling"] = scheduling_data
    if trigger_data:
        normalized["trigger"] = trigger_data
    if actions_data:
        normalized["actions"] = actions_data
    return normalized


def _parse_splunk_scheduling(scheduling_data: dict[str, Any] | None) -> SplunkScheduling | None:
    if not scheduling_data:
        return None
    schedule = None
    if schedule_data := scheduling_data.pop("schedule", None):
        schedule = SplunkSchedule.model_validate(schedule_data)
    timerange = None
    if timerange_data := scheduling_data.pop("timerange", None):
        timerange = SplunkTimerange.model_validate(timerange_data)
    # Only pass fields SplunkScheduling accepts (extra="forbid" on TideModel).
    _scheduling_fields = {"type", "expires"}
    scheduling_kwargs = {k: v for k, v in scheduling_data.items() if k in _scheduling_fields}
    return SplunkScheduling(**scheduling_kwargs, schedule=schedule, timerange=timerange)


def _parse_splunk_trigger(trigger_data: dict[str, Any] | None) -> SplunkTrigger | None:
    if not trigger_data:
        return None
    throttling = None
    if throttling_data := trigger_data.pop("throttling", None):
        throttling = SplunkThrottling.model_validate(throttling_data)
    return SplunkTrigger(**trigger_data, throttling=throttling)


def _parse_splunk_actions(actions_data: dict[str, Any] | None) -> SplunkActions | None:
    if not actions_data:
        return None
    notable = None
    if notable_data := actions_data.pop("notable", None):
        event = None
        if event_data := notable_data.pop("event", None):
            event = SplunkNotableEvent.model_validate(event_data)
        drilldown = None
        if drilldown_data := notable_data.pop("drilldown", None):
            drilldown = SplunkNotableDrilldown.model_validate(drilldown_data)
        notable = SplunkNotable(**notable_data, event=event, drilldown=drilldown)
    risk = None
    if risk_data := actions_data.pop("risk", None):
        risk_objects = None
        if ro := risk_data.pop("risk_objects", None):
            risk_objects = [SplunkRiskObject.model_validate(item) for item in ro]
        threat_objects = None
        if to := risk_data.pop("threat_objects", None):
            threat_objects = [SplunkThreatObject.model_validate(item) for item in to]
        risk = SplunkRisk(**risk_data, risk_objects=risk_objects, threat_objects=threat_objects)
    email = None
    if email_data := actions_data.pop("email", None):
        include = None
        if include_data := email_data.pop("include", None):
            include = SplunkEmailInclude.model_validate(include_data)
        email = SplunkEmail(**email_data, include=include)
    return SplunkActions(notable=notable, risk=risk, email=email)


def load_splunk_config(mdr_config: dict[str, Any]) -> SplunkConfig:
    remaining, base = _base_configuration(_normalize_splunk_v2(mdr_config))
    query = remaining.pop("query", None)
    correlation_search = remaining.pop("correlation_search", None)
    advanced = remaining.pop("advanced", None)
    scheduling = _parse_splunk_scheduling(remaining.pop("scheduling", None))
    trigger = _parse_splunk_trigger(remaining.pop("trigger", None))
    actions = _parse_splunk_actions(remaining.pop("actions", None))
    return SplunkConfig(
        **base,
        query=query,
        scheduling=scheduling,
        trigger=trigger,
        actions=actions,
        correlation_search=correlation_search,
        advanced=advanced,
        **remaining,
    )


def load_carbon_black_config(mdr_config: dict[str, Any]) -> CarbonBlackConfig:
    remaining, base = _base_configuration(mdr_config)
    remaining, rule_id_bundle = _external_rule_id(remaining)
    query = remaining.pop("query", None)
    organizations = remaining.pop("organizations", None) or remaining.pop("organization", None)
    watchlist = remaining.pop("watchlist", None)
    report = remaining.pop("report", None)
    tags = remaining.pop("tags", None)
    return CarbonBlackConfig(
        **base,
        query=query,
        organizations=organizations,
        watchlist=watchlist,
        report=report,
        tags=tags,
        rule_id_bundle=rule_id_bundle or None,
        **remaining,
    )


_PLATFORM_LOADERS = {
    "sentinel": load_sentinel_config,
    "defender_for_endpoint": load_defender_config,
    "splunk": load_splunk_config,
    "sentinel_one": load_sentinel_one_config,
    "crowdstrike": load_crowdstrike_config,
    "harfanglab": load_harfanglab_config,
    "carbon_black_cloud": load_carbon_black_config,
}


def load_platform_config(platform: str, payload: dict[str, Any]) -> PlatformConfigBase:
    """Parse a raw platform configuration dict into a typed model."""
    loader = _PLATFORM_LOADERS.get(platform)
    if loader is None:
        raise ValueError(f"Unknown platform {platform!r}")
    return cast(PlatformConfigBase, loader(payload))
