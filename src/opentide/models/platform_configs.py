"""Nested per-platform configuration models for detection rules."""

from __future__ import annotations

from typing import Any, Literal

from opentide.models.base import TideField, TideModel


class SentinelTemplate(TideModel):
    uuid: str
    """Sentinel alert-rule template name."""
    version: str
    """Template version."""


class SentinelTrigger(TideModel):
    operator: str
    """Sentinel trigger operator."""
    threshold: int
    """Sentinel trigger threshold."""


class SentinelScheduling(TideModel):
    nrt: bool | None = None
    """`true` deploys `kind: NRT` and skips frequency, lookback, and trigger."""
    frequency: str | None = None
    """Duration: ISO 8601, or shorthand converted to ISO 8601. How often a scheduled rule runs
    (`PT1H`). Required at deploy unless `nrt` is true."""
    lookback: str | None = None
    """Duration: ISO 8601, or shorthand converted to ISO 8601. Query window (`PT2H`). Required at
    deploy unless `nrt` is true."""


class SentinelCustomDetails(TideModel):
    key: str
    """Alert property name."""
    column: str
    """Result column."""


class SentinelDynamicProperties(TideModel):
    property: str
    """Sentinel alert property. `Tactics` and `Severity` are sent as the tactics and severity column
    overrides. Any other value is an alert dynamic property."""
    column: str
    """Result column."""


class SentinelAlert(TideModel):
    title: str | None = None
    """Alert display-name format. Empty leaves the Sentinel default. The rule `name` is still the
    analytics-rule display name."""
    description: str | None = None
    """Alert description format."""
    severity: str | None = None
    """Sentinel severity. When omitted, deploy uses `response.alert_severity`. `Critical` is sent as
    `High`."""
    suppression: str | bool = False
    """`false` disables suppression and sends a one-hour duration. A duration, ISO 8601 or
    shorthand, enables suppression for that long. Boolean `true` fails deploy."""
    create_incident: bool = True
    """Whether a firing alert opens an incident."""
    tactics: list[str] | None = None
    """Sentinel tactic names (the ARM `AttackTactic` enum). Replaced when the rule's ATT&CK
    techniques resolve to tactics: each `att&ck` stage maps to the tactic of the same name.
    Stealth, Defense Impairment, and the ICS Evasion tactic map to `DefenseEvasion`. A stage with
    no Sentinel tactic is dropped."""
    techniques: list[str] | None = None
    """Technique ids. Replaced by the rule's resolved techniques when those exist."""
    custom_details: list[SentinelCustomDetails] | None = None
    """Extra alert properties."""
    dynamic_properties: list[SentinelDynamicProperties] | None = None
    """Column-driven alert properties."""


class SentinelAlertGrouping(TideModel):
    enabled: bool
    """Group alerts into one incident."""
    reopen_closed_incidents: bool | None = None
    """Reopen a matching closed incident. Deploy sends `false` when omitted."""
    grouping_lookback: str | None = None
    """Duration: ISO 8601, or shorthand converted to ISO 8601. Required at deploy when `enabled` is
    true. When `enabled` is false and this is omitted, deploy sends `PT1H`."""
    matching: str | None = None
    """Sentinel matching method. Deploy sends `AllEntities` when omitted."""
    group_by_entities: list[str] | None = None
    """Entity types used when matching is selective."""
    group_by_alert_details: list[str] | None = None
    """Alert-detail fields used when matching is selective."""
    group_by_custom_details: list[str] | None = None
    """Custom-detail keys used when matching is selective."""


class SentinelGrouping(TideModel):
    event: str
    """Sentinel `aggregationKind`. `SingleAlert` groups events into one alert. `AlertPerResult`
    emits one alert per row."""
    alert: SentinelAlertGrouping | None = None
    """Incident grouping. Required at deploy."""


class SentinelMappingEntry(TideModel):
    identifier: str
    """Entity identifier (`Name`, `Address`, …)."""
    column: str
    """Result column."""


class SentinelEntityMapping(TideModel):
    entity: str
    """Sentinel entity type (`Account`, `Host`, `IP`, `URL`, …)."""
    mappings: list[SentinelMappingEntry]
    """Column bindings for that entity."""


class SentinelExclusion(TideModel):
    query: str = TideField(schema_extra={"tide.template.multiline": True})
    """KQL fragment appended after the base query. The key is required. An empty string is accepted
    (this field is not the non-blank rule `query`)."""
    reason: str
    """Why the exclusion exists. Not sent to Sentinel."""
    tenant: str | None = None
    """Limit the exclusion to one tenant name."""
    let: dict[str, Any] | None = None
    """KQL `let` bindings prepended to the query. Values may be string, number, or boolean. Other
    types are skipped. The last definition of a name wins."""


class DefenderAlert(TideModel):
    category: str
    """Defender alert category. Deploy removes spaces (`Suspicious Activity` is sent as
    `SuspiciousActivity`)."""
    title: str | None = None
    """Alert title. Deploy uses the rule `name` when omitted."""
    description: str | None = None
    """Alert description. Deploy uses the rule `description` when omitted."""
    severity: str | None = None
    """`Informational`, `Low`, `Medium`, `High`, or `Critical`. Deploy uses
    `response.alert_severity` when omitted. `Critical` is sent as `high`."""
    recommendation: str | None = None
    """Recommended actions text."""
    techniques: list[str] | None = None
    """Accepted on the block. The current deployer sends an empty technique list."""


class DefenderImpactedEntities(TideModel):
    device: str | None = None
    """Device column."""
    mailbox: str | None = None
    """Mailbox column."""
    user: str | None = None
    """User column."""


class DefenderGroupScoping(TideModel):
    selection: Literal["All", "Specific"]
    """`All` or `Specific`."""
    device_groups: list[str] | None = None
    """Group names. Used when `selection` is `Specific`."""


class DefenderAllowBlockGroupScoping(TideModel):
    selection: Literal["All", "Specific"]
    """`All` or `Specific`."""
    device_groups: list[str] | None = None
    """Group names. Used when `selection` is `Specific`."""


class DefenderAllowBlockAction(TideModel):
    action: Literal["Allow", "Block"]
    """`Allow` or `Block`."""
    identifier: str
    """Column identifying the file. Deploy lowercases the first character."""
    groups: DefenderAllowBlockGroupScoping | None = None
    """Device groups the allow or block applies to."""


class DefenderFileActions(TideModel):
    allow_block: DefenderAllowBlockAction | None = None
    """Allow or block a file identifier."""
    quarantine_file: str | None = None
    """Column identifying the file to quarantine. Loader alias: `quarantine_files`."""


class DefenderDeviceActions(TideModel):
    isolate_device: str | None = None
    """Isolation type. Deploy lowercases the first character (`Full` is sent as `full`)."""
    collect_investigation_package: bool = False
    """Collect an investigation package."""
    run_antivirus_scan: bool = False
    """Run an antivirus scan."""
    initiate_investigation: bool = False
    """Start an automated investigation."""
    restrict_app_execution: bool = False
    """Restrict app execution."""


class DefenderUserActions(TideModel):
    mark_as_compromised: str | None = None
    """User column."""
    disable_user: str | None = None
    """User column."""
    force_password_reset: str | None = None
    """User column."""


class DefenderResponseActions(TideModel):
    devices: DefenderDeviceActions | None = None
    """Device actions: isolate, collect an investigation package, scan, investigate or restrict app
    execution."""
    files: DefenderFileActions | None = None
    """File actions: allow or block, and quarantine."""
    users: DefenderUserActions | None = None
    """User actions: mark as compromised, disable, or force a password reset."""


class DefenderExclusion(TideModel):
    query: str = TideField(schema_extra={"tide.template.multiline": True})
    """KQL fragment appended after the base query. The key is required. An empty string is
    accepted."""
    reason: str
    """Why the exclusion exists. Not sent to Defender."""
    tenant: str | None = None
    """Limit the exclusion to one tenant name."""
    let: dict[str, Any] | None = None
    """KQL `let` bindings. String, number, or boolean."""


class CrowdstrikeDetails(TideModel):
    trigger: str
    """`verbose` or `summary`, any case. Deploy lowercases the value."""
    outcome: str
    """`detection` or `incident`, any case. Deploy lowercases the value."""
    name: str | None = None
    """Falcon rule name. Deploy uses the Tide rule `name` when omitted."""
    description: str | None = None
    """Falcon description. Deploy uses the Tide rule `description` when omitted."""
    severity: str | None = None
    """`Informational`, `Low`, `Medium`, `High`, or `Critical`. Deploy uses
    `response.alert_severity` when omitted."""
    tactic: str | None = None
    """Falcon tactic. Sent as given."""
    technique: str | None = None
    """Falcon technique. Sent as given."""


class CrowdstrikeSchedule(TideModel):
    frequency: str
    """Run interval. Deploy sends it as `@every <frequency>` (`@every 1h`)."""
    lookback: str
    """How far back each run searches. Sent as the search lookback."""
    start: str | None = None
    """Do not run before this UTC time."""
    end: str | None = None
    """Stop running at this UTC time."""


class SentinelOneDetails(TideModel):
    name: str | None = None
    """STAR rule name. Deploy uses the Tide rule `name` when omitted."""
    description: str | None = None
    """STAR description. Deploy uses the Tide rule `description` when omitted."""
    severity: str | None = None
    """Sent as the STAR severity string. When omitted, deploy maps `response.alert_severity`:
    `Informational` and `Low` become `Low`; `Medium`, `High`, and `Critical` keep those names."""
    expiration: str | None = None
    """When set, the rule is `Temporary` and this value is the expiration. When omitted, the rule is
    `Permanent`."""


class SentinelOneSingleEvent(TideModel):
    query: str = TideField(schema_extra={"tide.template.multiline": True})
    """S1QL. Multiline. Sent as `queryType: events`."""


class SentinelOneSubQuery(TideModel):
    query: str = TideField(schema_extra={"tide.template.multiline": True})
    """S1QL sub-query. Multiline."""
    matches_required: int
    """Number of matches this sub-query needs within the correlation window."""


class SentinelOneCorrelation(TideModel):
    entity: str
    """Entity the sub-queries correlate on (`host`, `user`, …)."""
    match_in_order: bool
    """Whether sub-queries must match in list order."""
    time_window: str
    """Correlation window (`1h`, `30m`)."""
    sub_queries: list[SentinelOneSubQuery]
    """Each item has `query` (S1QL) and `matches_required` (int)."""


class SentinelOneCondition(TideModel):
    type: Literal["Single Event", "Correlation"]
    """`Single Event` or `Correlation`."""
    single_event: SentinelOneSingleEvent | None = None
    """Required at deploy when `type` is `Single Event`."""
    correlation: SentinelOneCorrelation | None = None
    """Required at deploy when `type` is `Correlation`."""
    cool_off: str | None = None
    """Renotify window (`30m`, `1h`). Intended to become `renotifyMinutes`. The current deployer
    does not convert it."""


class SentinelOneResponse(TideModel):
    treat_as_threat: Literal[False, "Malicious", "Suspicious"]
    """`false` is sent as `UNDEFINED`."""
    network_quarantine: bool
    """Quarantine the endpoint from the network."""


class HarfangLabSigmaLogSource(TideModel):
    category: str
    """Sigma logsource category (`process_creation`)."""
    product: str
    """Sigma logsource product (`windows`)."""


class HarfangLabSigmaSelection(TideModel):
    name: str
    """Selection name used by `condition`."""
    field: str
    """Event field (`Image`, `CommandLine`)."""
    value: str | list[str] | bool | int | float
    """Match value. A list is a Sigma list."""
    modifiers: list[str] | None = None
    """Sigma modifiers (`contains`, `endswith`). Empty when omitted."""


class HarfangLabSigma(TideModel):
    logsource: HarfangLabSigmaLogSource
    """Sigma logsource: `category` and `product`."""
    selections: list[HarfangLabSigmaSelection]
    """Named selections."""
    condition: str
    """Sigma condition expression (`selection`, `selection1 and selection2`)."""
    false_positives: list[str] | None = None
    """Sigma false-positive notes."""


class HarfangLabYaraMeta(TideModel):
    context: list[str]
    """Scan contexts. The value `file` is rewritten from `os`: `Windows` → `file.pe`, `MacOS` →
    `file.macho`, `Linux` → `file.elf`. Other context values are kept."""
    os: str
    """`Windows`, `MacOS`, or `Linux`. Also written to meta `os`."""
    arch: list[str] | None = None
    """Architectures, joined with commas."""
    score: str | None = None
    """`Informational`, `Low`, `Medium`, `High`, or `Critical`. A known value overrides the score
    taken from `response.alert_severity`. An unknown value falls back to that severity, then to
    50."""
    classification: str | None = None
    """Free-form classification written to meta."""


class HarfangLabYara(TideModel):
    meta: HarfangLabYaraMeta
    """Scan context, OS, and optional score override."""
    strings: str
    """YARA string section body, one definition per line, without the `strings:` header."""
    condition: str
    """YARA condition body, without the `condition:` header."""
    imports: list[str] | None = None
    """YARA modules (`pe`, `elf`). Each becomes `import "<module>"`."""


class SplunkSchedule(TideModel):
    frequency: str | None = None
    """`Nm`, `Nh`, or `Nd` (`5m`, `1h`, `1d`). Expected ranges are 1–59 minutes, 1–23 hours, 1–30
    days. Values outside the range still convert, with a warning."""
    cron: str | None = None
    """Cron expression. Wins over `frequency` when both are set."""
    custom_time: str | None = None
    """Anchor for `frequency` when the tenant mode is `custom`. Format `HHhmm` (`09h15`). Required
    at deploy for that mode."""


class SplunkTimerange(TideModel):
    lookback: str | None = None
    """`Nm`, `Nh`, or `Nd`. Deploy converts it to a Splunk earliest time (`-90m@m`), including the
    tenant skew and offset."""
    earliest: str | None = None
    """Raw Splunk earliest time. Wins over `lookback`."""
    latest: str | None = None
    """Raw Splunk latest time."""


class SplunkScheduling(TideModel):
    type: str | None = None
    """`Real Time` deploys `dispatch.earliest_time` and `dispatch.latest_time` as `rt`. Any other
    non-empty value, or a `schedule` with no `type`, deploys `is_scheduled = 1`."""
    expires: str | None = None
    """Splunk `alert.expires` (`2h`, `1d`)."""
    schedule: SplunkSchedule | None = None
    """When the search runs."""
    timerange: SplunkTimerange | None = None
    """Window the search covers."""


class SplunkThrottling(TideModel):
    fields: list[str] | None = None
    """`alert.suppress.fields`, joined with commas."""
    duration: str | None = None
    """`alert.suppress.period`. When set, deploy also sets `alert.suppress` true."""
    group_name: str | None = None
    """`alert.suppress.group_name`."""


class SplunkTrigger(TideModel):
    condition: str | None = None
    """Splunk `counttype` (`number of events`, `number of hosts`, …)."""
    comparator: str | None = None
    """Splunk `relation` (`greater than`, `less than`, …)."""
    threshold: int | None = None
    """Splunk `quantity`."""
    severity: int | None = None
    """Splunk `alert.severity` (1–6). When omitted, deploy maps `response.alert_severity`."""
    custom_condition: str | None = None
    """Splunk `alert_condition` search."""
    type: str | None = None
    """`once` (any case) sets `alert.digest_mode` true. Any other value sets it false."""
    throttling: SplunkThrottling | None = None
    """Suppression window."""


class SplunkNotableEvent(TideModel):
    title: str | None = None
    """`action.notable.param.rule_title`."""
    description: str | None = None
    """`action.notable.param.rule_description`."""


class SplunkNotableDrilldown(TideModel):
    name: str | None = None
    """`action.notable.param.drilldown_name`."""
    search: str | None = None
    """`action.notable.param.drilldown_search`."""


class SplunkNotable(TideModel):
    event: SplunkNotableEvent | None = None
    """Notable event title and description."""
    drilldown: SplunkNotableDrilldown | None = None
    """Drilldown search name and query."""
    security_domain: str | None = None
    """`action.notable.param.security_domain`, lowercased."""


class SplunkRiskObject(TideModel):
    field: str
    """Result field holding the risk object."""
    type: str
    """Risk object type (`system`, `user`, `other`)."""
    score: int
    """Risk score added to the object."""


class SplunkThreatObject(TideModel):
    field: str
    """Result field holding the threat object."""
    type: str
    """Threat object type (`ip_address`, `domain`, …)."""


class SplunkRisk(TideModel):
    message: str | None = None
    """`action.risk.param._risk_message`."""
    risk_objects: list[SplunkRiskObject] | None = None
    """Each item requires `field` (string), `type` (string), and `score` (int)."""
    threat_objects: list[SplunkThreatObject] | None = None
    """Each item requires `field` (string) and `type` (string)."""


class SplunkEmailInclude(TideModel):
    results_link: bool | None = None
    """`action.email.include.results_link`."""
    search_string: bool | None = None
    """`action.email.include.search`."""
    trigger_condition: bool | None = None
    """`action.email.include.trigger`."""
    trigger_time: bool | None = None
    """`action.email.include.trigger_time`."""


class SplunkEmail(TideModel):
    to: str | None = None
    """Recipients."""
    cc: str | None = None
    """Carbon-copy recipients."""
    bcc: str | None = None
    """Blind carbon-copy recipients."""
    priority: str | None = None
    """Mail priority."""
    subject: str | None = None
    """Subject line. Deploy key `action.email.subject`."""
    message: str | None = None
    """Body. Deploy key `action.email.message.alert`."""
    content_type: str | None = None
    """`action.email.content_type`."""
    send_csv: bool | None = None
    """`action.email.sendcsv` as 1 or 0."""
    send_pdf: bool | None = None
    """`action.email.sendpdf` as 1 or 0."""
    inline_results: bool | None = None
    """`action.email.inline` as 1 or 0."""
    include: SplunkEmailInclude | None = None
    """What the email includes: results link, search string, trigger condition and trigger time."""


class SplunkActions(TideModel):
    notable: SplunkNotable | None = None
    """Enterprise Security notable event. Sent only when the tenant has Enterprise Security
    enabled."""
    risk: SplunkRisk | None = None
    """Enterprise Security risk action. Sent only when the tenant has Enterprise Security
    enabled."""
    email: SplunkEmail | None = None
    """Email action."""


# --------------------------------------------------------------------------
# Elastic Security platform models (RFC 0007 / platform::elastic::1.0)
# --------------------------------------------------------------------------

Duration = str

FieldType = Literal[
    "keyword",
    "constant_keyword",
    "wildcard",
    "text",
    "match_only_text",
    "long",
    "integer",
    "short",
    "byte",
    "unsigned_long",
    "double",
    "float",
    "half_float",
    "scaled_float",
    "date",
    "date_nanos",
    "boolean",
    "ip",
    "version",
    "binary",
    "geo_point",
    "geo_shape",
    "object",
    "flattened",
    "nested",
]


class ElasticSuppression(TideModel):
    group_by: list[str] | None = None
    """1–3 field names. Required for every type except `threshold`, where it is forbidden."""
    duration: Duration | None = None
    """Suppression window. Required for `threshold`. Omitted on other types suppresses for the rule
    execution only."""
    missing_fields_strategy: Literal["suppress", "doNotSuppress"] = "suppress"
    """`suppress` or `doNotSuppress`: whether alerts missing a `group_by` field are suppressed
    together. Not sent for `threshold`."""


class ElasticCardinality(TideModel):
    field: str
    """Field whose distinct values are counted."""
    value: int
    """Minimum number of distinct values."""


class ElasticThreshold(TideModel):
    field: list[str] = []
    """Group by, 0–5 fields. `[]` counts all matches."""
    value: int
    """Threshold, at least 1."""
    cardinality: ElasticCardinality | None = None
    """Count: alert only when `field` has at least `value` distinct values."""


class ElasticRequiredField(TideModel):
    name: str
    """Field name."""
    type: FieldType
    """Elasticsearch mapping type: `keyword`, `constant_keyword`, `wildcard`, `text`,
    `match_only_text`, `long`, `integer`, `short`, `byte`, `unsigned_long`, `double`, `float`,
    `half_float`, `scaled_float`, `date`, `date_nanos`, `boolean`, `ip`, `version`, `binary`,
    `geo_point`, `geo_shape`, `object`, `flattened`, or `nested`."""


class ElasticIntegration(TideModel):
    package: str
    """Integration package, for example `windows`, `endpoint`, `aws`."""
    integration: str | None = None
    """Policy template inside the package, for example `cloudtrail`."""
    version: str = "*"
    """Semver range, for example `^2.0.0`."""


class ElasticSeverityMapping(TideModel):
    field: str
    """Source event field."""
    value: str
    """Value to match."""
    operator: Literal["equals"] = "equals"
    """`equals` is the only operator."""
    severity: Literal["low", "medium", "high", "critical"]
    """Kibana severity: `low`, `medium`, `high`, or `critical`."""


class ElasticRiskScoreMapping(TideModel):
    field: str
    """Source event field holding a score."""
    operator: Literal["equals"] = "equals"
    """`equals` is the only operator."""
    value: str = ""
    """Kibana sends an empty string."""


class ElasticThreatEntry(TideModel):
    field: str
    """Event field."""
    value: str
    """Indicator field."""
    type: Literal["mapping"] = "mapping"
    """`mapping` is the only type."""
    negate: bool | None = None
    """`true` is the UI's DOES NOT MATCH. Not sent when null."""


class ElasticThreatGroup(TideModel):
    entries: list[ElasticThreatEntry]
    """Field mappings in this group. Every entry must match (AND)."""


class ElasticScheduling(TideModel):
    interval: Duration = "5m"
    """Runs every."""
    lookback: Duration = "1m"
    """Additional look-back time. `0m` is valid."""
    max_alerts: int | None = None
    """Max alerts per run (`max_signals`). Omitted leaves the detection engine's default of 100."""


class ElasticSeverity(TideModel):
    default: str
    """An `alert_severity` value."""
    mapping: list[ElasticSeverityMapping] | None = None
    """Severity override: alerts whose `field` equals `value` get `severity`."""


class ElasticRisk(TideModel):
    score: int | None = None
    """0–100. Omitted derives the score from the severity."""
    mapping: list[ElasticRiskScoreMapping] | None = None
    """Risk score override: the alert takes its score from `field`."""


class ElasticOverrides(TideModel):
    name: str | None = None
    """Rule name override: the alert title comes from this field."""
    timestamp: str | None = None
    """Timestamp override: the rule's time range runs on this field instead of `@timestamp`."""
    disable_fallback: bool | None = None
    """"Do not use @timestamp as a fallback timestamp field"."""


class ElasticGuide(TideModel):
    investigation: str | None = None
    """Investigation guide (Kibana `note`). Markdown."""
    setup: str | None = None
    """Setup guide (Kibana `setup`). Not the tenant `setup` table."""


class ElasticExceptionList(TideModel):
    id: str
    """Exception list id."""
    list_id: str
    """Exception list `list_id`."""
    namespace_type: Literal["single", "agnostic"]
    """`single` (one space) or `agnostic` (every space)."""
    type: Literal["detection", "rule_default"]
    """`detection` or `rule_default`."""


class ElasticExceptions(TideModel):
    endpoint: bool = False
    """Attach the Elastic Endpoint exception list."""
    lists: list[ElasticExceptionList] | None = None
    """Existing exception lists."""


class ElasticTimeline(TideModel):
    id: str | None = None
    """Timeline template id."""
    title: str | None = None
    """Timeline template title."""


class ElasticActions(TideModel):
    notify: list[dict[str, Any]] | None = None
    """Rule actions: connector `id`, `action_type_id`, `group`, `params`, and `frequency`, in
    Kibana's shape. Copied unchanged."""
    respond: list[dict[str, Any]] | None = None
    """Response actions: `{endpoint: <command>, field?, comment?}` or `{osquery: {...}}`."""
    timeline: ElasticTimeline | None = None
    """Timeline template attached to the rule: `id` and `title`, both optional strings."""


class ElasticFilter(TideModel):
    field: str | None = None
    """Phrase shorthand: field to match."""
    value: str | None = None
    """Phrase shorthand: value to match."""
    negate: bool = False
    """Phrase shorthand: exclude matches."""
    meta: dict[str, Any] | None = None
    """Raw detection-engine filter `meta`."""
    query: dict[str, Any] | None = None
    """Raw detection-engine filter query."""


class ElasticEql(TideModel):
    timestamp_field: str | None = None
    """Timestamp field for EQL sequencing."""
    event_category_override: str | None = None
    """Event category field."""
    tiebreaker_field: str | None = None
    """Tiebreaker for events with equal timestamps."""


class ElasticNewTerms(TideModel):
    fields: list[str]
    """1–3 fields whose value, or combination of values, must be new."""
    history_window_start: Duration
    """History window size. Sent as `now-<duration>`. Separate from the schedule."""


class ElasticThreatMatch(TideModel):
    index: list[str]
    """Indicator index patterns. Always a list."""
    query: str
    """Indicator query."""
    language: Literal["kuery", "lucene"] | None = None
    """`kuery` or `lucene`, for the indicator query."""
    mapping: list[ElasticThreatGroup]
    """Groups are OR. Entries in a group are AND."""
    filters: list[dict[str, Any]] | None = None
    """Indicator filters, in the same two shapes as the block `filters`."""
    indicator_path: str | None = None
    """Indicator prefix override. Kibana's default is `threat.indicator`."""


class ElasticMachineLearning(TideModel):
    job_id: str | list[str]
    """Existing anomaly detection job id or ids. Sent unchanged, in either shape. The block does not
    create jobs."""
    anomaly_threshold: int
    """Anomaly score cutoff on Kibana's 0–100 scale."""
