"""Per-platform configuration Pydantic models — schema ``platform::<name>::1.0``.

The field contract, including every optional key, is ``specs/platforms/`` in the
specifications repository. This module implements that contract. Do not document
the keys anywhere else. The docstring under each field is the editor hover
(the JSON Schema ``description``). It starts from the spec table's text but
describes what this model enforces: where the two differ (``status`` is required
here, optional in the spec), the docstring follows the code and the difference
is raised upstream. ``tests/test_models/test_spec_field_descriptions.py``
reports any other drift.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, ClassVar, Literal, cast

from pydantic import AfterValidator, model_validator

from opentide.models.base import TideField, TideModel
from opentide.models.platform_configs import (
    CrowdstrikeDetails,
    CrowdstrikeSchedule,
    DefenderAlert,
    DefenderExclusion,
    DefenderGroupScoping,
    DefenderImpactedEntities,
    DefenderResponseActions,
    ElasticActions,
    ElasticEql,
    ElasticExceptions,
    ElasticFilter,
    ElasticGuide,
    ElasticIntegration,
    ElasticMachineLearning,
    ElasticNewTerms,
    ElasticOverrides,
    ElasticRequiredField,
    ElasticRisk,
    ElasticScheduling,
    ElasticSeverity,
    ElasticSuppression,
    ElasticThreatMatch,
    ElasticThreshold,
    HarfangLabSigma,
    HarfangLabYara,
    SentinelAlert,
    SentinelEntityMapping,
    SentinelExclusion,
    SentinelGrouping,
    SentinelOneCondition,
    SentinelOneDetails,
    SentinelOneResponse,
    SentinelScheduling,
    SentinelTemplate,
    SentinelTrigger,
    SplunkActions,
    SplunkScheduling,
    SplunkTrigger,
)
from opentide.models.splunk_legacy import SPLUNK_V2_KEYS, normalize_splunk_v2
from opentide.platforms.elastic.durations import duration_seconds


def _query_not_blank(value: str) -> str:
    # Every deployer treats a falsy query as "nothing to deploy" and moves on,
    # so `query: ""` is the same silent skip as no query at all.
    if not value.strip():
        raise ValueError("query must not be empty")
    return value


QueryText = Annotated[str, AfterValidator(_query_not_blank)]


class PlatformConfigBase(TideModel):
    """Shared platform block on detection rules."""

    enabled: bool = False
    """Whether this platform block is active."""
    name: str = ""
    """Platform-specific rule name."""
    platform_schema: str | None = TideField(
        None,
        alias="schema",
        schema_extra={"tide.template.required": True},
    )
    """Platform schema identifier, for example `platform::sentinel::1.0`."""
    # Required, because the deploy planner selects on it and cannot proceed
    # without it. Leaving it optional let a rule validate cleanly and then fail
    # deployment, while the JSON Schema we publish for the same object required
    # it all along -- three surfaces disagreeing about one field.
    status: str
    """Deployment status of this platform block, from the statuses in `deployment.toml`. Required:
    the deploy planner selects on it."""
    flags: list[str] | None = None
    """Platform flags."""
    tenants: list[str] | None = None
    """Target tenant identifiers."""
    contributors: list[str] | None = None
    """Platform contributors."""

    @property
    def schema(self) -> str | None:
        """The identifier under its YAML key, which would otherwise be ``BaseModel.schema``."""
        return self.platform_schema


class SentinelConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::sentinel::1.0"
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    """KQL. Multiline. Compiled with matching `exclusions` before deploy."""
    scheduling: SentinelScheduling
    """Run cadence, or NRT."""
    alert: SentinelAlert
    """Alert and incident presentation."""
    exclusions: list[SentinelExclusion] | None = None
    """Per-tenant KQL fragments appended to `query`."""
    template: SentinelTemplate | None = None
    """Analytics-rule template this rule was built from."""
    trigger: SentinelTrigger | None = None
    """Result threshold. Ignored when `scheduling.nrt` is true."""
    grouping: SentinelGrouping | None = None
    """Event grouping and incident grouping. Required at deploy."""
    entities: list[SentinelEntityMapping] | None = None
    """Entity mappings from result columns."""


class DefenderConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::defender_for_endpoint::1.0"
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    """KQL. Multiline. Compiled with matching `exclusions` before deploy."""
    alert: DefenderAlert
    """Custom detection alert template."""
    impacted_entities: DefenderImpactedEntities
    """Columns that identify the impacted device, user, or mailbox."""
    scheduling: Literal["NRT", "1H", "3H", "12H", "24H"]
    """`NRT`, `1H`, `3H`, `12H`, or `24H`."""
    actions: DefenderResponseActions | None = None
    """Response actions run when the detection fires."""
    scope: DefenderGroupScoping | None = None
    """Device-group scope. Required by registry load. The current deployer does not send it."""
    exclusions: list[DefenderExclusion] | None = None
    """Per-tenant KQL fragments appended to `query`."""


class SplunkConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::splunk::1.0"
    __legacy_keys__: ClassVar[Mapping[str, str | None]] = SPLUNK_V2_KEYS
    # Required, like every other platform's query and like the JSON Schema
    # extras already said. Optional here meant the FieldInfo template renderer
    # emitted `#query: |` commented out for Splunk alone, and the deployer
    # silently skipped rules whose query never loaded (#233). A splunk::2.x
    # `search` is copied here by `_accept_legacy_v2_spellings` below.
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    """SPL. Multiline. Legacy `search` fills this when `query` is empty."""
    scheduling: SplunkScheduling | None = None
    """Cron or frequency, and the search time range."""
    trigger: SplunkTrigger | None = None
    """Alert threshold, severity, and throttling."""
    actions: SplunkActions | None = None
    """Notable, risk, and email actions."""
    correlation_search: bool | None = None
    """Force the Enterprise Security correlation-search action on or off. `null` follows the
    tenant."""
    advanced: dict[str, Any] | None = TideField(None, schema_extra={"tide.template.hide": True})
    """Extra `savedsearches.conf` keys, stringified at deploy. Hidden from templates. Generated
    schema marks the field deprecated in favour of the nested blocks."""
    # Legacy flat v2.x fields retained for backward-compatible loading
    search: str | None = TideField(None, schema_extra={"tide.template.hide": True})
    """Legacy v2 search string. Hidden from templates. Kept after it is copied to `query`."""
    cron_schedule: str | None = TideField(None, schema_extra={"tide.template.hide": True})
    """Legacy v2 cron. Hidden from templates. Kept after it is copied into
    `scheduling.schedule.cron`."""

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_v2_spellings(cls, data: Any) -> Any:
        """Map the splunk::2.x layout onto v3 before field validation.

        Schema validation calls ``model_validate`` on the raw YAML and never
        goes through ``load_splunk_config``, so the mapping has to live here as
        well as in the loader — and be the same function, or the two paths
        accept different rules (#233).
        """
        if not isinstance(data, dict):
            return data
        return normalize_splunk_v2(data)


class SentinelOneConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::sentinel_one::1.0"
    condition: SentinelOneCondition
    """Single-event or correlation query."""
    response: SentinelOneResponse | None = None
    """Threat verdict and network quarantine. Omitted means neither action is sent."""
    details: SentinelOneDetails | None = None
    """Overrides for name, description, severity, and expiration."""


class CrowdstrikeConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::crowdstrike::1.0"
    details: CrowdstrikeDetails
    """Correlation outcome, trigger mode, and alert metadata."""
    schedule: CrowdstrikeSchedule
    """How often the correlation search runs and how far it looks back."""
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    """Correlation filter. Multiline. Sent as the rule `filter`."""


class HarfangLabConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::harfanglab::1.0"
    maturity: str = "Experimental"
    """Rule maturity. Mapped to HarfangLab `hl_status`."""
    confidence: str = "Moderate"
    """Analyst confidence. Mapped to `rule_confidence_override`."""
    action: str = "Alert"
    """What the agent does on a match. Mapped to `global_state`."""
    tags: list[str] | None = None
    """Sigma tags, and the YARA `tags` meta line."""
    sigma: HarfangLabSigma | None = None
    """Behavioural rule. Preferred when `yara` is also set."""
    yara: HarfangLabYara | None = None
    """File or memory scan rule."""


class CarbonBlackConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::carbon_black_cloud::1.0"
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    """Lucene query. Multiline in YAML. Deploy joins lines with spaces."""
    organizations: list[str] | None = None
    """Accepted, including the loader alias `organization`. The current deployer targets the tenant
    the run selects and does not filter on this list."""
    watchlist: str | None = None
    """Watchlist name. Deploy uses the tenant watchlist when omitted. The watchlist must already
    exist."""
    report: str | None = None
    """Report title. Deploy uses the Tide rule `name` when omitted."""
    tags: list[str] | None = None
    """Extra report tags, appended after the tags opentide always writes."""


_ENDPOINT_COMMANDS = frozenset({"isolate", "kill-process", "suspend-process", "runscript"})
_ENDPOINT_KEYS = frozenset({"endpoint", "comment", "field"})
_ALERT_SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})
_EXCEPTION_TYPES = frozenset({"detection", "rule_default"})
_RULE_TYPES = frozenset(
    {"query", "eql", "esql", "threshold", "new_terms", "threat_match", "machine_learning"}
)
_REMOVED_FLAT = frozenset(
    {
        "saved_id",
        "interval",
        "from",
        "license",
        "meta",
        "alert_suppression",
        "related_integrations",
        "investigation_fields",
        "max_signals",
        "note",
        "setup",
        "endpoint_exceptions",
        "exceptions_list",
        "timeline_id",
        "timeline_title",
        "timestamp_override",
        "timestamp_override_fallback_disabled",
        "risk_score",
        "risk_score_mapping",
        "severity_mapping",
        "timestamp_field",
        "event_category_override",
        "tiebreaker_field",
        "new_terms_fields",
        "history_window_start",
        "threat_index",
        "threat_query",
        "threat_language",
        "threat_mapping",
        "threat_filters",
        "threat_indicator_path",
        "concurrent_searches",
        "items_per_search",
        "machine_learning_job_id",
        "anomaly_threshold",
        "rule_name_override",
        "response_actions",
        "timestamp",
        "timeline",
        "passthrough",
    }
)


def _pattern_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and bool(item) for item in value)
    )


def _valid_response(action: dict[str, Any]) -> bool:
    """RFC 0007 ``response_action``: the two author shapes only, never Kibana's raw form."""
    if "endpoint" in action:
        return action["endpoint"] in _ENDPOINT_COMMANDS and set(action) <= _ENDPOINT_KEYS
    if "osquery" in action:
        osquery = action["osquery"]
        return (
            set(action) == {"osquery"} and isinstance(osquery, dict) and bool(osquery.get("query"))
        )
    return False


class ElasticConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::elastic::1.0"
    # Its before-validator reports bad type blocks; it accepts no extra key.
    __legacy_keys__: ClassVar[Mapping[str, str | None]] = {}

    type: Literal[
        "query", "eql", "esql", "threshold", "new_terms", "threat_match", "machine_learning"
    ]
    """Rule type: `query`, `eql`, `esql`, `threshold`, `new_terms`, `threat_match` or
    `machine_learning`. Kibana cannot change the type of an existing rule in place."""
    query: QueryText | None = None
    """The event query, in the language the type selects. Multiline. Not sent for
    `machine_learning`."""
    language: Literal["kuery", "lucene"] | None = None
    """`kuery` (KQL) or `lucene`, for the event query of `query`, `threshold`, `new_terms`, and
    `threat_match`. Compiled as `kuery` when omitted. MUST NOT be set for `eql`, `esql`, or
    `machine_learning`."""
    index: list[str] | None = None
    """Index patterns. A single pattern is a one-item list (`[logs-*]`). Omitted uses the tenant
    `setup.index`."""
    data_view_id: str | None = None
    """One existing Kibana data view. Replaces `index`."""
    filters: list[ElasticFilter] | None = None
    """Rule query filters. Not Elastic Defend event filters."""
    scheduling: ElasticScheduling | None = None
    """Runs every, additional look-back, and max alerts per run."""
    severity: str | ElasticSeverity | None = None
    """An `alert_severity` value, or a default plus severity overrides."""
    risk: int | ElasticRisk | None = None
    """Risk score 0–100, or a score plus risk score overrides."""
    suppression: ElasticSuppression | None = None
    """Alert suppression."""
    highlighted_fields: list[str] | None = None
    """Custom highlighted fields on the alert."""
    threshold: ElasticThreshold | None = None
    """Group-by fields and count."""
    new_terms: ElasticNewTerms | None = None
    """Fields whose new values alert, and the history window."""
    eql: ElasticEql | None = None
    """EQL-only settings."""
    threat: ElasticThreatMatch | None = None
    """The indicator side of an indicator match rule. Not the ATT&CK array."""
    machine_learning: ElasticMachineLearning | None = None
    """Anomaly jobs and threshold."""
    integration: list[str | ElasticIntegration] | None = None
    """Integrations the rule expects. Recorded on the rule; Fleet is not touched."""
    required_fields: list[ElasticRequiredField] | None = None
    """Fields the rule needs, with their mapping types."""
    guide: ElasticGuide | None = None
    """Investigation guide and Setup guide."""
    false_positives: list[str] | None = None
    """Known false positives."""
    tags: list[str] | None = None
    """Rule tags, after `OpenTide` and the tenant tags."""
    exceptions: ElasticExceptions | None = None
    """Exception lists to attach."""
    building_block: bool = False
    """Building block rule: alerts are hidden from the default Alerts view."""
    overrides: ElasticOverrides | None = None
    """Rule name override and timestamp override."""
    actions: ElasticActions | None = None
    """Rule actions, response actions, and the Timeline template."""

    @model_validator(mode="before")
    @classmethod
    def _validate_raw_elastic_block(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        raw = dict(data)
        # Status is required on every platform. Leave it for Pydantic so a
        # missing value is the same "missing" error as the other platforms,
        # rather than a constraint code that hides it.
        if "status" not in raw or raw["status"] is None:
            return raw

        codes: set[str] = set()
        rule_type = raw.get("type")
        if rule_type not in _RULE_TYPES or bool(_REMOVED_FLAT & set(raw)):
            codes.add("type_block")
        if (raw.get("threshold") is not None) != (rule_type == "threshold"):
            codes.add("type_block")
        new_terms = raw.get("new_terms")
        if (new_terms is not None) != (rule_type == "new_terms") or (
            rule_type == "new_terms"
            and (
                not isinstance(new_terms, dict)
                or new_terms.get("fields") is None
                or new_terms.get("history_window_start") is None
            )
        ):
            codes.add("type_block")
        if raw.get("eql") is not None and rule_type != "eql":
            codes.add("type_block")
        threat = raw.get("threat")
        if (threat is not None) != (rule_type == "threat_match") or (
            rule_type == "threat_match"
            and (
                not isinstance(threat, dict)
                or any(threat.get(key) is None for key in ("index", "query", "mapping"))
            )
        ):
            codes.add("type_block")
        ml = raw.get("machine_learning")
        if (ml is not None) != (rule_type == "machine_learning") or (
            rule_type == "machine_learning"
            and (
                not isinstance(ml, dict)
                or ml.get("job_id") is None
                or ml.get("anomaly_threshold") is None
            )
        ):
            codes.add("type_block")
        if rule_type != "machine_learning" and not raw.get("query"):
            codes.add("type_block")
        if rule_type in ("eql", "esql", "machine_learning") and raw.get("language"):
            codes.add("language")
        if rule_type in ("esql", "machine_learning") and (
            raw.get("index") or raw.get("data_view_id") or raw.get("filters")
        ):
            codes.add("esql_source")
        if raw.get("index") and raw.get("data_view_id"):
            codes.add("index_xor_data_view")
        if raw.get("index") is not None and not _pattern_list(raw["index"]):
            codes.add("index_list")
        if (
            isinstance(threat, dict)
            and threat.get("index") is not None
            and not _pattern_list(threat["index"])
        ):
            codes.add("index_list")
        for entries in (
            raw.get("filters"),
            threat.get("filters") if isinstance(threat, dict) else None,
        ):
            if entries is None:
                continue
            if not isinstance(entries, list):
                codes.add("filter_shape")
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    codes.add("filter_shape")
                    continue
                shorthand = any(entry.get(key) is not None for key in ("field", "value", "negate"))
                raw_filter = entry.get("meta") is not None or entry.get("query") is not None
                # Exactly one shape, and that shape complete: {field, value, negate?}
                # or {meta, query}. An empty entry is neither.
                if (
                    shorthand == raw_filter
                    or (shorthand and (entry.get("field") is None or entry.get("value") is None))
                    or (raw_filter and (entry.get("meta") is None or entry.get("query") is None))
                ):
                    codes.add("filter_shape")
        for item in (raw.get("exceptions") or {}).get("lists") or []:
            if not isinstance(item, dict) or item.get("type") not in _EXCEPTION_TYPES:
                codes.add("exception_type")
        actions = raw.get("actions")
        if isinstance(actions, list):
            codes.add("type_block")
        elif isinstance(actions, dict):
            for action in actions.get("respond") or []:
                if not isinstance(action, dict) or not _valid_response(action):
                    codes.add("response_action")
        suppression = raw.get("suppression")
        if suppression is not None and not isinstance(suppression, dict):
            codes.add("suppression_shape")
            suppression = None
        if suppression is not None:
            group_by = suppression.get("group_by")
            if rule_type == "threshold":
                # A missing duration is a shape fault; an empty one is a
                # `duration` fault, reported by the duration check below.
                if suppression.get("duration") is None or group_by:
                    codes.add("suppression_shape")
            elif (
                not isinstance(group_by, list)
                or not 1 <= len(group_by) <= 3
                or len(set(group_by)) != len(group_by)
                or not all(group_by)
            ):
                codes.add("suppression_shape")
        if (
            isinstance(new_terms, dict)
            and "fields" in new_terms
            and not (isinstance(new_terms["fields"], list) and 1 <= len(new_terms["fields"]) <= 3)
        ):
            codes.add("new_terms_fields")
        threshold = raw.get("threshold")
        if isinstance(threshold, dict):
            threshold_field = threshold.get("field") or []
            threshold_value = threshold.get("value")
            if (
                not isinstance(threshold_field, list)
                or len(threshold_field) > 5
                or not isinstance(threshold_value, int)
                or threshold_value < 1
            ):
                codes.add("threshold_fields")
        severity = raw.get("severity")
        level = severity.get("default") if isinstance(severity, dict) else severity
        if level is not None and (
            not isinstance(level, str) or level.strip().lower() not in _ALERT_SEVERITIES
        ):
            # RFC 0007 §2: alert_severity vocabulary. An unknown value used to
            # compile silently to Informational (low, risk 1).
            codes.add("severity")
        risk = raw.get("risk")
        if isinstance(risk, int):
            if not 0 <= risk <= 100:
                codes.add("risk_score")
        elif isinstance(risk, dict):
            score = risk.get("score")
            if score is not None and not (isinstance(score, int) and 0 <= score <= 100):
                codes.add("risk_score")
        elif risk is not None:
            codes.add("risk_score")
        # A non-object `scheduling` is a shape fault, not a duration one: leave
        # it to the field type, which names `scheduling` and the expected shape.
        raw_scheduling = raw.get("scheduling")
        scheduling: dict[str, Any] = raw_scheduling if isinstance(raw_scheduling, dict) else {}
        if scheduling.get("lookback") is not None:
            try:
                duration_seconds(scheduling["lookback"], allow_zero=True)
            except ValueError:
                codes.add("duration")
        history = new_terms.get("history_window_start") if isinstance(new_terms, dict) else None
        # `None` is absent (#557); every other value, "" included, must parse.
        # An empty string skipped here used to pass validate and crash compile.
        for value in (
            scheduling.get("interval"),
            (suppression or {}).get("duration"),
            history,
        ):
            if value is None:
                continue
            try:
                duration_seconds(value)
            except ValueError:
                codes.add("duration")
        if codes:
            raise ValueError(
                f"ElasticConfig validation failed with code(s): {', '.join(sorted(codes))}"
            )
        return raw


PLATFORM_CONFIG_MODELS: dict[str, type[PlatformConfigBase]] = {
    "sentinel": SentinelConfig,
    "defender_for_endpoint": DefenderConfig,
    "splunk": SplunkConfig,
    "sentinel_one": SentinelOneConfig,
    "crowdstrike": CrowdstrikeConfig,
    "harfanglab": HarfangLabConfig,
    "carbon_black_cloud": CarbonBlackConfig,
    "elastic": ElasticConfig,
}


def parse_platform_config(platform: str, payload: dict[str, Any]) -> PlatformConfigBase:
    """Validate a platform configuration block from rule YAML."""
    from opentide.loading.platform_loader import load_platform_config

    return load_platform_config(platform, payload)


class RuleConfigurations(TideModel):
    """Dynamically composed rule platform configurations."""

    sentinel: SentinelConfig | None = None
    """Microsoft Sentinel analytics rule (`platform::sentinel::1.0`)."""
    defender_for_endpoint: DefenderConfig | None = None
    """Microsoft Defender for Endpoint custom detection (`platform::defender_for_endpoint::1.0`)."""
    splunk: SplunkConfig | None = None
    """Splunk saved search (`platform::splunk::1.0`)."""
    sentinel_one: SentinelOneConfig | None = None
    """SentinelOne STAR rule (`platform::sentinel_one::1.0`)."""
    crowdstrike: CrowdstrikeConfig | None = None
    """CrowdStrike Falcon correlation rule (`platform::crowdstrike::1.0`)."""
    harfanglab: HarfangLabConfig | None = None
    """HarfangLab Sigma or YARA rule (`platform::harfanglab::1.0`)."""
    carbon_black_cloud: CarbonBlackConfig | None = None
    """Carbon Black Cloud watchlist report (`platform::carbon_black_cloud::1.0`)."""
    elastic: ElasticConfig | None = None
    """Elastic Security detection rule (`platform::elastic::1.0`)."""

    @classmethod
    def from_platforms_dict(cls, platforms: dict[str, dict[str, Any]]) -> RuleConfigurations:
        kwargs: dict[str, Any] = {}
        for key, value in platforms.items():
            if key in PLATFORM_CONFIG_MODELS and value:
                kwargs[key] = parse_platform_config(key, value)
        return cast(RuleConfigurations, cls.model_validate(kwargs))
