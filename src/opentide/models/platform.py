"""Per-platform configuration Pydantic models — schema ``platform::<name>::1.0``.

The field contract, including every optional key, is ``specs/platforms/`` in the
specifications repository. This module implements that contract. Do not document
the keys anywhere else.
"""

from __future__ import annotations

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
    ElasticThreshold,
    ElasticThreatMatch,
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
from opentide.models.splunk_legacy import normalize_splunk_v2
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
    name: str = ""
    platform_schema: str | None = TideField(
        None,
        alias="schema",
        schema_extra={"tide.template.required": True},
    )
    status: str | None = None
    flags: list[str] | None = None
    tenants: list[str] | None = None
    contributors: list[str] | None = None

    @property
    def schema(self) -> str | None:
        """The identifier under its YAML key, which would otherwise be ``BaseModel.schema``."""
        return self.platform_schema


class SentinelConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::sentinel::1.0"
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    scheduling: SentinelScheduling
    alert: SentinelAlert
    exclusions: list[SentinelExclusion] | None = None
    template: SentinelTemplate | None = None
    trigger: SentinelTrigger | None = None
    grouping: SentinelGrouping | None = None
    entities: list[SentinelEntityMapping] | None = None


class DefenderConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::defender_for_endpoint::1.0"
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    alert: DefenderAlert
    impacted_entities: DefenderImpactedEntities
    scheduling: Literal["NRT", "1H", "3H", "12H", "24H"]
    rule_id: dict[str, int] | None = None
    actions: DefenderResponseActions | None = None
    scope: DefenderGroupScoping | None = None
    exclusions: list[DefenderExclusion] | None = None


class SplunkConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::splunk::1.0"
    # Required, like every other platform's query and like the JSON Schema
    # extras already said. Optional here meant the FieldInfo template renderer
    # emitted `#query: |` commented out for Splunk alone, and the deployer
    # silently skipped rules whose query never loaded (#233). A splunk::2.x
    # `search` is copied here by `_accept_legacy_v2_spellings` below.
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    scheduling: SplunkScheduling | None = None
    trigger: SplunkTrigger | None = None
    actions: SplunkActions | None = None
    correlation_search: bool | None = None
    advanced: dict[str, Any] | None = TideField(None, schema_extra={"tide.template.hide": True})
    # Legacy flat v2.x fields retained for backward-compatible loading
    search: str | None = TideField(None, schema_extra={"tide.template.hide": True})
    cron_schedule: str | None = TideField(None, schema_extra={"tide.template.hide": True})

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
    response: SentinelOneResponse | None = None
    details: SentinelOneDetails | None = None
    rule_id_bundle: dict[str, int] | None = None


class CrowdstrikeConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::crowdstrike::1.0"
    details: CrowdstrikeDetails
    schedule: CrowdstrikeSchedule
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    rule_id_bundle: dict[str, str] | None = None


class HarfangLabConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::harfanglab::1.0"
    maturity: str = "Experimental"
    confidence: str = "Moderate"
    action: str = "Alert"
    tags: list[str] | None = None
    sigma: HarfangLabSigma | None = None
    yara: HarfangLabYara | None = None
    rule_id_bundle: dict[str, str] | None = None


class CarbonBlackConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::carbon_black_cloud::1.0"
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    organizations: list[str] | None = None
    watchlist: str | None = None
    report: str | None = None
    tags: list[str] | None = None
    rule_id_bundle: dict[str, str] | None = None


_ENDPOINT_COMMANDS = frozenset({"isolate", "kill-process", "suspend-process", "runscript"})
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
    if "endpoint" in action and action["endpoint"] in _ENDPOINT_COMMANDS:
        return True
    if "osquery" in action and isinstance(action["osquery"], dict):
        return True
    kind = action.get("action_type_id")
    command = (action.get("params") or {}).get("command")
    return kind == ".osquery" or (kind == ".endpoint" and command in _ENDPOINT_COMMANDS)


class ElasticConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::elastic::1.0"

    type: Literal[
        "query", "eql", "esql", "threshold", "new_terms", "threat_match", "machine_learning"
    ] = "query"
    query: QueryText | None = None
    language: Literal["kuery", "lucene"] | None = None
    index: list[str] | None = None
    data_view_id: str | None = None
    filters: list[ElasticFilter] | None = None
    scheduling: ElasticScheduling | None = None
    severity: str | ElasticSeverity | None = None
    risk: int | ElasticRisk | None = None
    suppression: ElasticSuppression | None = None
    highlighted_fields: list[str] | None = None
    threshold: ElasticThreshold | None = None
    new_terms: ElasticNewTerms | None = None
    eql: ElasticEql | None = None
    threat: ElasticThreatMatch | None = None
    machine_learning: ElasticMachineLearning | None = None
    integration: list[str | ElasticIntegration] | None = None
    required_fields: list[ElasticRequiredField] | None = None
    guide: ElasticGuide | None = None
    false_positives: list[str] | None = None
    tags: list[str] | None = None
    exceptions: ElasticExceptions | None = None
    building_block: bool = False
    overrides: ElasticOverrides | None = None
    actions: ElasticActions | None = None

    @model_validator(mode="before")
    @classmethod
    def _validate_raw_elastic_block(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        raw = dict(data)
        if "status" not in raw or raw["status"] is None:
            raw["status"] = "STAGING"

        codes: set[str] = set()
        rule_type = raw.get("type")
        if rule_type not in _RULE_TYPES or bool(_REMOVED_FLAT & set(raw)):
            codes.add("type_block")
        if ("threshold" in raw) != (rule_type == "threshold"):
            codes.add("type_block")
        new_terms = raw.get("new_terms")
        if ("new_terms" in raw) != (rule_type == "new_terms") or (
            rule_type == "new_terms"
            and (
                not isinstance(new_terms, dict)
                or "fields" not in new_terms
                or "history_window_start" not in new_terms
            )
        ):
            codes.add("type_block")
        if "eql" in raw and rule_type != "eql":
            codes.add("type_block")
        threat = raw.get("threat")
        if ("threat" in raw) != (rule_type == "threat_match") or (
            rule_type == "threat_match"
            and (
                not isinstance(threat, dict)
                or any(key not in threat for key in ("index", "query", "mapping"))
            )
        ):
            codes.add("type_block")
        ml = raw.get("machine_learning")
        if ("machine_learning" in raw) != (rule_type == "machine_learning") or (
            rule_type == "machine_learning"
            and (
                not isinstance(ml, dict)
                or "job_id" not in ml
                or "anomaly_threshold" not in ml
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
        if "index" in raw and not _pattern_list(raw["index"]):
            codes.add("index_list")
        if isinstance(threat, dict) and "index" in threat and not _pattern_list(threat["index"]):
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
                shorthand = "field" in entry or "value" in entry or "negate" in entry
                raw_filter = "meta" in entry or "query" in entry
                if (shorthand and raw_filter) or (
                    shorthand and ("field" not in entry or "value" not in entry)
                ):
                    codes.add("filter_shape")
        for item in ((raw.get("exceptions") or {}).get("lists") or []):
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
        if suppression is not None:
            group_by = suppression.get("group_by")
            if rule_type == "threshold":
                if not suppression.get("duration") or group_by:
                    codes.add("suppression_shape")
            elif (
                not group_by
                or not 1 <= len(group_by) <= 3
                or len(set(group_by)) != len(group_by)
                or not all(group_by)
            ):
                codes.add("suppression_shape")
        if (
            isinstance(new_terms, dict)
            and "fields" in new_terms
            and not 1 <= len(new_terms["fields"]) <= 3
        ):
            codes.add("new_terms_fields")
        threshold = raw.get("threshold")
        if isinstance(threshold, dict) and (
            len(threshold.get("field") or []) > 5 or threshold.get("value", 0) < 1
        ):
            codes.add("threshold_fields")
        risk = raw.get("risk")
        if isinstance(risk, int):
            if not 0 <= risk <= 100:
                codes.add("risk_score")
        elif isinstance(risk, dict):
            score = risk.get("score")
            if "score" in risk and not (isinstance(score, int) and 0 <= score <= 100):
                codes.add("risk_score")
        elif risk is not None:
            codes.add("risk_score")
        scheduling = raw.get("scheduling") or {}
        if "scheduling" in raw and not isinstance(scheduling, dict):
            codes.add("duration")
            scheduling = {}
        if isinstance(scheduling, dict) and "lookback" in scheduling:
            try:
                duration_seconds(scheduling["lookback"], allow_zero=True)
            except ValueError:
                codes.add("duration")
        history = (
            new_terms.get("history_window_start") if isinstance(new_terms, dict) else None
        )
        for value in filter(
            None,
            (
                scheduling.get("interval"),
                (suppression or {}).get("duration"),
                history,
            ),
        ):
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
    defender_for_endpoint: DefenderConfig | None = None
    splunk: SplunkConfig | None = None
    sentinel_one: SentinelOneConfig | None = None
    crowdstrike: CrowdstrikeConfig | None = None
    harfanglab: HarfangLabConfig | None = None
    carbon_black_cloud: CarbonBlackConfig | None = None
    elastic: ElasticConfig | None = None

    @classmethod
    def from_platforms_dict(cls, platforms: dict[str, dict[str, Any]]) -> RuleConfigurations:
        kwargs: dict[str, Any] = {}
        for key, value in platforms.items():
            if key in PLATFORM_CONFIG_MODELS and value:
                kwargs[key] = parse_platform_config(key, value)
        return cast(RuleConfigurations, cls.model_validate(kwargs))
