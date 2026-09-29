"""Per-platform configuration Pydantic models — schema ``platform::<name>::1.0``."""

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
    ElasticAction,
    ElasticAlertSuppression,
    ElasticExceptionList,
    ElasticExceptionListRef,
    ElasticResponseAction,
    ElasticThreatMapping,
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
from opentide.models.splunk_legacy import normalize_splunk_v2


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


class ElasticSecurityConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::elastic_security::1.0"

    type: Literal[
        "query",
        "saved_query",
        "eql",
        "esql",
        "threshold",
        "threat_match",
        "new_terms",
        "machine_learning",
    ] = "query"
    saved_id: str | None = None
    language: str | None = None
    query: str | None = TideField(
        None,
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True},
    )
    index: list[str] | None = None
    data_view_id: str | None = None

    query_from: str | None = TideField(None, alias="from")
    interval: str | None = None
    to: str | None = None

    severity: Literal["low", "medium", "high", "critical"] | None = None
    risk_score: int | None = None
    author: list[str] | None = None
    note: str | None = None
    setup: str | None = None
    tags: list[str] | None = None
    filters: list[dict[str, Any]] | None = None
    max_signals: int | None = None
    timestamp_override: str | None = None
    timestamp_override_fallback_disabled: bool | None = None
    building_block_type: str | None = None
    rule_id: str | None = None

    # Common fields added in P1
    references: list[str] | None = None
    false_positives: list[str] | None = None
    risk_score_mapping: list[dict[str, Any]] | None = None
    severity_mapping: list[dict[str, Any]] | None = None
    rule_name_override: str | None = None
    investigation_fields: dict[str, Any] | None = None
    required_fields: list[dict[str, Any]] | None = None
    license: str | None = None
    output_index: str | None = None
    namespace: str | None = None
    version: int | None = None

    # Exception lists (shared / inline container definitions)
    exception_lists: list[ElasticExceptionList | dict[str, Any]] | None = None

    # EQL specific
    timestamp_field: str | None = None
    event_category_override: str | None = None
    tiebreaker_field: str | None = None

    # Threshold specific
    threshold: ElasticThreshold | None = None

    # Threat match specific
    threat_index: list[str] | None = None
    threat_mapping: list[ElasticThreatMapping | dict[str, Any]] | None = None
    threat_query: str | None = None
    threat_language: str | None = None
    threat_indicator_path: str | None = None
    threat_filters: list[dict[str, Any]] | None = None
    concurrent_searches: int | None = None
    items_per_search: int | None = None

    # New terms specific
    new_terms_fields: list[str] | None = None
    history_window_start: str | None = None

    # Machine learning specific
    machine_learning_job_id: str | list[str] | None = None
    anomaly_threshold: int | None = None

    # Suppression & references
    alert_suppression: ElasticAlertSuppression | None = None
    exceptions_list: list[ElasticExceptionListRef | dict[str, Any]] | None = None
    actions: list[ElasticAction | dict[str, Any]] | None = None
    response_actions: list[ElasticResponseAction | dict[str, Any]] | None = None
    threat: list[dict[str, Any]] | None = None
    meta: dict[str, Any] | None = None

    @model_validator(mode="before")
    @classmethod
    def _set_elastic_defaults(cls, data: Any) -> Any:
        if isinstance(data, dict):
            rule_type = data.get("type", "query")
            if "language" not in data or data["language"] is None:
                if rule_type in ("query", "saved_query"):
                    data["language"] = "kuery"
                elif rule_type == "eql":
                    data["language"] = "eql"
                elif rule_type == "esql":
                    data["language"] = "esql"
        return data

    @model_validator(mode="after")
    def _validate_elastic_security_fields(self) -> ElasticSecurityConfig:
        if self.index is not None and self.data_view_id is not None:
            raise ValueError("index and data_view_id are mutually exclusive")

        rule_type = self.type

        if rule_type == "machine_learning":
            if not self.machine_learning_job_id:
                raise ValueError("machine_learning rules require 'machine_learning_job_id'")
            if self.anomaly_threshold is None:
                raise ValueError("machine_learning rules require 'anomaly_threshold'")
            if self.query is not None and self.query.strip():
                raise ValueError("machine_learning rules must not specify 'query'")
            if self.index is not None or self.data_view_id is not None:
                raise ValueError(
                    "machine_learning rules must not specify 'index' or 'data_view_id'"
                )
            return self

        if rule_type == "saved_query":
            if not self.saved_id:
                raise ValueError("saved_query rules require 'saved_id'")
            if self.language is not None and self.language not in ("kuery", "lucene"):
                raise ValueError("saved_query rules must use language 'kuery' or 'lucene'")
        else:
            if not self.query or not self.query.strip():
                raise ValueError(f"query must not be empty for {rule_type} rules")

        if rule_type == "esql":
            if self.index is not None or self.data_view_id is not None:
                raise ValueError(
                    "esql rules must not specify 'index' or 'data_view_id' (index is in query)"
                )
            if self.language is not None and self.language != "esql":
                raise ValueError("esql rules must use language 'esql'")

        elif rule_type == "eql":
            if self.language is not None and self.language != "eql":
                raise ValueError("eql rules must use language 'eql'")

        elif rule_type in ("query", "threshold", "threat_match", "new_terms"):
            if self.language is not None and self.language not in ("kuery", "lucene"):
                raise ValueError(f"{rule_type} rules must use language 'kuery' or 'lucene'")

        if rule_type == "threshold":
            if self.threshold is None:
                raise ValueError("threshold rules require 'threshold' configuration (field and value)")
            if self.alert_suppression is not None and self.alert_suppression.group_by:
                raise ValueError("threshold rules with alert_suppression do not allow 'group_by'")

        elif rule_type == "threat_match":
            if not self.threat_index:
                raise ValueError("threat_match rules require 'threat_index'")
            if not self.threat_mapping:
                raise ValueError("threat_match rules require 'threat_mapping'")
            if self.threat_language is not None and self.threat_language not in (
                "kuery",
                "lucene",
            ):
                raise ValueError(
                    "threat_language for threat_match rules must be 'kuery' or 'lucene'"
                )

        elif rule_type == "new_terms":
            if not self.new_terms_fields:
                raise ValueError("new_terms rules require 'new_terms_fields'")
            if not self.history_window_start:
                raise ValueError("new_terms rules require 'history_window_start'")

        if self.alert_suppression is not None and not self.alert_suppression.duration:
            raise ValueError("alert_suppression requires 'duration'")

        return self


PLATFORM_CONFIG_MODELS: dict[str, type[PlatformConfigBase]] = {
    "sentinel": SentinelConfig,
    "defender_for_endpoint": DefenderConfig,
    "splunk": SplunkConfig,
    "sentinel_one": SentinelOneConfig,
    "crowdstrike": CrowdstrikeConfig,
    "harfanglab": HarfangLabConfig,
    "carbon_black_cloud": CarbonBlackConfig,
    "elastic_security": ElasticSecurityConfig,
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
    elastic_security: ElasticSecurityConfig | None = None

    @classmethod
    def from_platforms_dict(cls, platforms: dict[str, dict[str, Any]]) -> RuleConfigurations:
        kwargs: dict[str, Any] = {}
        for key, value in platforms.items():
            if key in PLATFORM_CONFIG_MODELS and value:
                kwargs[key] = parse_platform_config(key, value)
        return cast(RuleConfigurations, cls.model_validate(kwargs))
