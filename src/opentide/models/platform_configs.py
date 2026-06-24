"""Nested per-platform configuration models for detection rules."""

from __future__ import annotations

from typing import Any, Literal

from opentide.models.base import TideModel


class SentinelTemplate(TideModel):
    uuid: str
    version: str


class SentinelTrigger(TideModel):
    operator: str
    threshold: int


class SentinelScheduling(TideModel):
    nrt: bool | None = None
    frequency: str | None = None
    lookback: str | None = None


class SentinelCustomDetails(TideModel):
    key: str
    column: str


class SentinelDynamicProperties(TideModel):
    property: str
    column: str


class SentinelAlert(TideModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    suppression: str | bool = False
    create_incident: bool = True
    tactics: list[str] | None = None
    techniques: list[str] | None = None
    custom_details: list[SentinelCustomDetails] | None = None
    dynamic_properties: list[SentinelDynamicProperties] | None = None


class SentinelAlertGrouping(TideModel):
    enabled: bool
    reopen_closed_incidents: bool | None = None
    grouping_lookback: str | None = None
    matching: str | None = None
    group_by_entities: list[str] | None = None
    group_by_alert_details: list[str] | None = None
    group_by_custom_details: list[str] | None = None


class SentinelGrouping(TideModel):
    event: str
    alert: SentinelAlertGrouping | None = None


class SentinelMappingEntry(TideModel):
    identifier: str
    column: str


class SentinelEntityMapping(TideModel):
    entity: str
    mappings: list[SentinelMappingEntry]


class SentinelExclusion(TideModel):
    query: str
    reason: str
    tenant: str | None = None
    let: dict[str, Any] | None = None


class DefenderAlert(TideModel):
    category: str
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    recommendation: str | None = None
    techniques: list[str] | None = None


class DefenderImpactedEntities(TideModel):
    device: str | None = None
    mailbox: str | None = None
    user: str | None = None


class DefenderGroupScoping(TideModel):
    selection: Literal["All", "Specific"]
    device_groups: list[str] | None = None


class DefenderAllowBlockGroupScoping(TideModel):
    selection: Literal["All", "Specific"]
    device_groups: list[str] | None = None


class DefenderAllowBlockAction(TideModel):
    action: Literal["Allow", "Block"]
    identifier: str
    groups: DefenderAllowBlockGroupScoping | None = None


class DefenderFileActions(TideModel):
    allow_block: DefenderAllowBlockAction | None = None
    quarantine_file: str | None = None


class DefenderDeviceActions(TideModel):
    isolate_device: str | None = None
    collect_investigation_package: bool = False
    run_antivirus_scan: bool = False
    initiate_investigation: bool = False
    restrict_app_execution: bool = False


class DefenderUserActions(TideModel):
    mark_as_compromised: str | None = None
    disable_user: str | None = None
    force_password_reset: str | None = None


class DefenderResponseActions(TideModel):
    devices: DefenderDeviceActions | None = None
    files: DefenderFileActions | None = None
    users: DefenderUserActions | None = None


class DefenderExclusion(TideModel):
    query: str
    reason: str
    tenant: str | None = None
    let: dict[str, Any] | None = None


class CrowdstrikeDetails(TideModel):
    trigger: str
    outcome: str
    name: str | None = None
    description: str | None = None
    severity: str | None = None
    tactic: str | None = None
    technique: str | None = None


class CrowdstrikeSchedule(TideModel):
    frequency: str
    lookback: str
    start: str | None = None
    end: str | None = None


class SentinelOneDetails(TideModel):
    name: str | None = None
    description: str | None = None
    severity: str | None = None
    expiration: str | None = None


class SentinelOneSingleEvent(TideModel):
    query: str


class SentinelOneSubQuery(TideModel):
    query: str
    matches_required: int


class SentinelOneCorrelation(TideModel):
    entity: str
    match_in_order: bool
    time_window: str
    sub_queries: list[SentinelOneSubQuery]


class SentinelOneCondition(TideModel):
    type: Literal["Single Event", "Correlation"]
    single_event: SentinelOneSingleEvent | None = None
    correlation: SentinelOneCorrelation | None = None
    cool_off: str | None = None


class SentinelOneResponse(TideModel):
    treat_as_threat: Literal[False, "Malicious", "Suspicious"]
    network_quarantine: bool


class HarfangLabSigmaLogSource(TideModel):
    category: str
    product: str


class HarfangLabSigmaSelection(TideModel):
    name: str
    field: str
    value: str | list[str] | bool | int | float
    modifiers: list[str] | None = None


class HarfangLabSigma(TideModel):
    logsource: HarfangLabSigmaLogSource
    selections: list[HarfangLabSigmaSelection]
    condition: str
    false_positives: list[str] | None = None


class HarfangLabYaraMeta(TideModel):
    context: list[str]
    os: str
    arch: list[str] | None = None
    score: str | None = None
    classification: str | None = None


class HarfangLabYara(TideModel):
    meta: HarfangLabYaraMeta
    strings: str
    condition: str
    imports: list[str] | None = None


class SplunkSchedule(TideModel):
    frequency: str | None = None
    cron: str | None = None
    custom_time: str | None = None


class SplunkTimerange(TideModel):
    lookback: str | None = None
    earliest: str | None = None
    latest: str | None = None


class SplunkScheduling(TideModel):
    type: str | None = None
    expires: str | None = None
    schedule: SplunkSchedule | None = None
    timerange: SplunkTimerange | None = None


class SplunkThrottling(TideModel):
    fields: list[str] | None = None
    duration: str | None = None
    group_name: str | None = None


class SplunkTrigger(TideModel):
    condition: str | None = None
    comparator: str | None = None
    threshold: int | None = None
    severity: int | None = None
    custom_condition: str | None = None
    type: str | None = None
    throttling: SplunkThrottling | None = None


class SplunkNotableEvent(TideModel):
    title: str | None = None
    description: str | None = None


class SplunkNotableDrilldown(TideModel):
    name: str | None = None
    search: str | None = None


class SplunkNotable(TideModel):
    event: SplunkNotableEvent | None = None
    drilldown: SplunkNotableDrilldown | None = None
    security_domain: str | None = None


class SplunkRiskObject(TideModel):
    field: str
    type: str
    score: int


class SplunkThreatObject(TideModel):
    field: str
    type: str


class SplunkRisk(TideModel):
    message: str | None = None
    risk_objects: list[SplunkRiskObject] | None = None
    threat_objects: list[SplunkThreatObject] | None = None


class SplunkEmailInclude(TideModel):
    results_link: bool | None = None
    search_string: bool | None = None
    trigger_condition: bool | None = None
    trigger_time: bool | None = None


class SplunkEmail(TideModel):
    to: str | None = None
    cc: str | None = None
    bcc: str | None = None
    priority: str | None = None
    subject: str | None = None
    message: str | None = None
    content_type: str | None = None
    send_csv: bool | None = None
    send_pdf: bool | None = None
    inline_results: bool | None = None
    include: SplunkEmailInclude | None = None


class SplunkActions(TideModel):
    notable: SplunkNotable | None = None
    risk: SplunkRisk | None = None
    email: SplunkEmail | None = None
