//! Elastic Security detection rule, `platform::elastic::1.0` (RFC 0007;
//! `ElasticConfig` and its nested models), with the named check
//! `elastic_rule_shape` ([`block_codes`]): the constraint codes of the
//! oracle's `_validate_raw_elastic_block`, judged on the raw block before its
//! fields, in the oracle's terms (Python's truthiness and `isinstance`).

use std::collections::{BTreeMap, BTreeSet};

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::from_node::Context;
use crate::node::{Node, Value};
use crate::objects::any::Any;
use crate::objects::platform::durations::duration_seconds;
use crate::objects::platform::{
    get, is_map, literal_enum, platform_block, present, python_int, python_strip, truthy,
};
use crate::pins::Pins;

literal_enum! {
    /// `missing_fields_strategy`.
    MissingFieldsStrategy { Suppress = "suppress", DoNotSuppress = "doNotSuppress", }
}

literal_enum! {
    /// An Elasticsearch mapping type (`FieldType`).
    FieldType {
        Keyword = "keyword",
        ConstantKeyword = "constant_keyword",
        Wildcard = "wildcard",
        Text = "text",
        MatchOnlyText = "match_only_text",
        Long = "long",
        Integer = "integer",
        Short = "short",
        Byte = "byte",
        UnsignedLong = "unsigned_long",
        Double = "double",
        Float = "float",
        HalfFloat = "half_float",
        ScaledFloat = "scaled_float",
        Date = "date",
        DateNanos = "date_nanos",
        Boolean = "boolean",
        Ip = "ip",
        Version = "version",
        Binary = "binary",
        GeoPoint = "geo_point",
        GeoShape = "geo_shape",
        Object = "object",
        Flattened = "flattened",
        Nested = "nested",
    }
}

literal_enum! {
    /// `equals`, the only operator.
    EqualsOperator { Equals = "equals", }
}

literal_enum! {
    /// A Kibana severity.
    KibanaSeverity { Low = "low", Medium = "medium", High = "high", Critical = "critical", }
}

literal_enum! {
    /// `mapping`, the only threat entry type.
    MappingType { Mapping = "mapping", }
}

literal_enum! {
    /// An exception list's namespace.
    NamespaceType { Single = "single", Agnostic = "agnostic", }
}

literal_enum! {
    /// An exception list's type.
    ExceptionListType { Detection = "detection", RuleDefault = "rule_default", }
}

literal_enum! {
    /// A query language.
    QueryLanguage { Kuery = "kuery", Lucene = "lucene", }
}

literal_enum! {
    /// The rule type.
    RuleType {
        Query = "query",
        Eql = "eql",
        Esql = "esql",
        Threshold = "threshold",
        NewTerms = "new_terms",
        ThreatMatch = "threat_match",
        MachineLearning = "machine_learning",
    }
}

/// Declares an Elastic nested model with the shared derives.
macro_rules! model {
    ($(#[$meta:meta])* $name:ident = $model:tt { $($body:tt)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
        #[serde(deny_unknown_fields)]
        #[garde(context(Pins))]
        #[garde(allow_unvalidated)]
        #[schemars(rename = $model, description = "")]
        #[from_node(model = $model)]
        pub struct $name { $($body)* }
    };
}

fn suppress() -> MissingFieldsStrategy {
    MissingFieldsStrategy::Suppress
}

fn equals() -> EqualsOperator {
    EqualsOperator::Equals
}

fn mapping() -> MappingType {
    MappingType::Mapping
}

fn five_minutes() -> String {
    "5m".to_owned()
}

fn one_minute() -> String {
    "1m".to_owned()
}

fn any_version() -> String {
    "*".to_owned()
}

model! {
    /// Alert suppression (`ElasticSuppression`).
    ElasticSuppression = "ElasticSuppression" {
        /// 1–3 field names. Required for every type except `threshold`, where it is forbidden.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group_by: Option<Vec<String>>,
        /// Suppression window. Required for `threshold`. Omitted on other types suppresses for the rule
        /// execution only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub duration: Option<String>,
        /// `suppress` or `doNotSuppress`: whether alerts missing a `group_by` field are suppressed
        /// together. Not sent for `threshold`.
        #[serde(default = "suppress")]
        pub missing_fields_strategy: MissingFieldsStrategy,
    }
}

model! {
    /// Count of distinct values (`ElasticCardinality`).
    ElasticCardinality = "ElasticCardinality" {
        /// Field whose distinct values are counted.
        pub field: String,
        /// Minimum number of distinct values.
        pub value: i64,
    }
}

model! {
    /// Group-by fields and count (`ElasticThreshold`).
    ElasticThreshold = "ElasticThreshold" {
        /// Group by, 0–5 fields. `[]` counts all matches.
        #[serde(default)]
        pub field: Vec<String>,
        /// Threshold, at least 1.
        pub value: i64,
        /// Count: alert only when `field` has at least `value` distinct values.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cardinality: Option<ElasticCardinality>,
    }
}

model! {
    /// A field the rule needs (`ElasticRequiredField`).
    ElasticRequiredField = "ElasticRequiredField" {
        /// Field name.
        pub name: String,
        /// Elasticsearch mapping type: `keyword`, `constant_keyword`, `wildcard`, `text`,
        /// `match_only_text`, `long`, `integer`, `short`, `byte`, `unsigned_long`, `double`, `float`,
        /// `half_float`, `scaled_float`, `date`, `date_nanos`, `boolean`, `ip`, `version`, `binary`,
        /// `geo_point`, `geo_shape`, `object`, `flattened`, or `nested`.
        pub r#type: FieldType,
    }
}

model! {
    /// An integration the rule expects (`ElasticIntegration`).
    ElasticIntegration = "ElasticIntegration" {
        /// Integration package, for example `windows`, `endpoint`, `aws`.
        pub package: String,
        /// Policy template inside the package, for example `cloudtrail`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub integration: Option<String>,
        /// Semver range, for example `^2.0.0`.
        #[serde(default = "any_version")]
        pub version: String,
    }
}

model! {
    /// A severity override (`ElasticSeverityMapping`).
    ElasticSeverityMapping = "ElasticSeverityMapping" {
        /// Source event field.
        pub field: String,
        /// Value to match.
        pub value: String,
        /// `equals` is the only operator.
        #[serde(default = "equals")]
        pub operator: EqualsOperator,
        /// Kibana severity: `low`, `medium`, `high`, or `critical`.
        pub severity: KibanaSeverity,
    }
}

fn empty() -> String {
    String::new()
}

model! {
    /// A risk score override (`ElasticRiskScoreMapping`).
    ElasticRiskScoreMapping = "ElasticRiskScoreMapping" {
        /// Source event field holding a score.
        pub field: String,
        /// `equals` is the only operator.
        #[serde(default = "equals")]
        pub operator: EqualsOperator,
        /// Kibana sends an empty string.
        #[serde(default = "empty")]
        pub value: String,
    }
}

model! {
    /// An indicator field mapping (`ElasticThreatEntry`).
    ElasticThreatEntry = "ElasticThreatEntry" {
        /// Event field.
        pub field: String,
        /// Indicator field.
        pub value: String,
        /// `mapping` is the only type.
        #[serde(default = "mapping")]
        pub r#type: MappingType,
        /// `true` is the UI's DOES NOT MATCH. Not sent when null.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub negate: Option<bool>,
    }
}

model! {
    /// A group of indicator mappings (`ElasticThreatGroup`).
    ElasticThreatGroup = "ElasticThreatGroup" {
        /// Field mappings in this group. Every entry must match (AND).
        pub entries: Vec<ElasticThreatEntry>,
    }
}

model! {
    /// Runs every, additional look-back, and max alerts per run (`ElasticScheduling`).
    ElasticScheduling = "ElasticScheduling" {
        /// Runs every.
        #[serde(default = "five_minutes")]
        pub interval: String,
        /// Additional look-back time. `0m` is valid.
        #[serde(default = "one_minute")]
        pub lookback: String,
        /// Max alerts per run (`max_signals`). Omitted leaves the detection engine's default of 100.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_alerts: Option<i64>,
    }
}

model! {
    /// A default severity plus severity overrides (`ElasticSeverity`).
    ElasticSeverity = "ElasticSeverity" {
        /// An `alert_severity` value.
        pub default: String,
        /// Severity override: alerts whose `field` equals `value` get `severity`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mapping: Option<Vec<ElasticSeverityMapping>>,
    }
}

model! {
    /// A score plus risk score overrides (`ElasticRisk`).
    ElasticRisk = "ElasticRisk" {
        /// 0–100. Omitted derives the score from the severity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub score: Option<i64>,
        /// Risk score override: the alert takes its score from `field`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mapping: Option<Vec<ElasticRiskScoreMapping>>,
    }
}

model! {
    /// Rule name override and timestamp override (`ElasticOverrides`).
    ElasticOverrides = "ElasticOverrides" {
        /// Rule name override: the alert title comes from this field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// Timestamp override: the rule's time range runs on this field instead of `@timestamp`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timestamp: Option<String>,
        /// "Do not use @timestamp as a fallback timestamp field".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub disable_fallback: Option<bool>,
    }
}

model! {
    /// Investigation guide and Setup guide (`ElasticGuide`).
    ElasticGuide = "ElasticGuide" {
        /// Investigation guide (Kibana `note`). Markdown.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub investigation: Option<String>,
        /// Setup guide (Kibana `setup`). Not the tenant `setup` table.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setup: Option<String>,
    }
}

model! {
    /// An existing exception list (`ElasticExceptionList`).
    ElasticExceptionList = "ElasticExceptionList" {
        /// Exception list id.
        pub id: String,
        /// Exception list `list_id`.
        pub list_id: String,
        /// `single` (one space) or `agnostic` (every space).
        pub namespace_type: NamespaceType,
        /// `detection` or `rule_default`.
        pub r#type: ExceptionListType,
    }
}

model! {
    /// Exception lists to attach (`ElasticExceptions`).
    ElasticExceptions = "ElasticExceptions" {
        /// Attach the Elastic Endpoint exception list.
        #[serde(default)]
        pub endpoint: bool,
        /// Existing exception lists.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lists: Option<Vec<ElasticExceptionList>>,
    }
}

model! {
    /// The Timeline template (`ElasticTimeline`).
    ElasticTimeline = "ElasticTimeline" {
        /// Timeline template id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        /// Timeline template title.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }
}

model! {
    /// Rule actions, response actions, and the Timeline template (`ElasticActions`).
    ElasticActions = "ElasticActions" {
        /// Rule actions: connector `id`, `action_type_id`, `group`, `params`, and `frequency`, in
        /// Kibana's shape. Copied unchanged.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notify: Option<Vec<BTreeMap<String, Any>>>,
        /// Response actions: `{endpoint: <command>, field?, comment?}` or `{osquery: {...}}`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub respond: Option<Vec<BTreeMap<String, Any>>>,
        /// Timeline template attached to the rule: `id` and `title`, both optional strings.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeline: Option<ElasticTimeline>,
    }
}

model! {
    /// A rule query filter (`ElasticFilter`).
    ElasticFilter = "ElasticFilter" {
        /// Phrase shorthand: field to match.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub field: Option<String>,
        /// Phrase shorthand: value to match.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        /// Phrase shorthand: exclude matches.
        #[serde(default)]
        pub negate: bool,
        /// Raw detection-engine filter `meta`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub meta: Option<BTreeMap<String, Any>>,
        /// Raw detection-engine filter query.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub query: Option<BTreeMap<String, Any>>,
    }
}

model! {
    /// EQL-only settings (`ElasticEql`).
    ElasticEql = "ElasticEql" {
        /// Timestamp field for EQL sequencing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timestamp_field: Option<String>,
        /// Event category field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub event_category_override: Option<String>,
        /// Tiebreaker for events with equal timestamps.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tiebreaker_field: Option<String>,
    }
}

model! {
    /// Fields whose new values alert, and the history window (`ElasticNewTerms`).
    ElasticNewTerms = "ElasticNewTerms" {
        /// 1–3 fields whose value, or combination of values, must be new.
        pub fields: Vec<String>,
        /// History window size. Sent as `now-<duration>`. Separate from the schedule.
        pub history_window_start: String,
    }
}

model! {
    /// The indicator side of an indicator match rule (`ElasticThreatMatch`).
    ElasticThreatMatch = "ElasticThreatMatch" {
        /// Indicator index patterns. Always a list.
        pub index: Vec<String>,
        /// Indicator query.
        pub query: String,
        /// `kuery` or `lucene`, for the indicator query.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::objects::platform::optional_literal::<QueryLanguage>")]
        pub language: Option<QueryLanguage>,
        /// Groups are OR. Entries in a group are AND.
        pub mapping: Vec<ElasticThreatGroup>,
        /// Indicator filters, in the same two shapes as the block `filters`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filters: Option<Vec<BTreeMap<String, Any>>>,
        /// Indicator prefix override. Kibana's default is `threat.indicator`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub indicator_path: Option<String>,
    }
}

/// `job_id: str | list[str]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, FromNode)]
#[serde(untagged)]
#[from_node(union)]
pub enum JobId {
    /// One job.
    #[from_node(tag = "str")]
    #[schemars(description = "")]
    One(String),
    /// Several jobs.
    #[from_node(tag = "list[str]")]
    #[schemars(description = "")]
    Many(Vec<String>),
}

model! {
    /// Anomaly jobs and threshold (`ElasticMachineLearning`).
    ElasticMachineLearning = "ElasticMachineLearning" {
        /// Existing anomaly detection job id or ids. Sent unchanged, in either shape. The block does not
        /// create jobs.
        pub job_id: JobId,
        /// Anomaly score cutoff on Kibana's 0–100 scale.
        pub anomaly_threshold: i64,
    }
}

/// `severity: str | ElasticSeverity`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, FromNode)]
#[serde(untagged)]
#[from_node(union)]
pub enum SeverityChoice {
    /// An `alert_severity` value.
    #[from_node(tag = "str")]
    #[schemars(description = "")]
    Level(String),
    /// A default plus severity overrides.
    #[from_node(tag = "ElasticSeverity")]
    #[schemars(description = "")]
    Mapped(ElasticSeverity),
}

/// `risk: int | ElasticRisk`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, FromNode)]
#[serde(untagged)]
#[from_node(union)]
pub enum RiskChoice {
    /// A score 0–100.
    #[from_node(tag = "int")]
    #[schemars(description = "")]
    Score(i64),
    /// A score plus risk score overrides.
    #[from_node(tag = "ElasticRisk")]
    #[schemars(description = "")]
    Mapped(ElasticRisk),
}

/// An `integration` item: `str | ElasticIntegration`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, FromNode)]
#[schemars(description = "")]
#[serde(untagged)]
#[from_node(union)]
pub enum IntegrationChoice {
    /// A package name.
    #[from_node(tag = "str")]
    #[schemars(description = "")]
    Package(String),
    /// A package, policy template and version range.
    #[from_node(tag = "ElasticIntegration")]
    #[schemars(description = "")]
    Detailed(ElasticIntegration),
}

fn garde_block(block: &ElasticConfig, _pins: &Pins) -> garde::Result {
    crate::objects::platform::garde_named("ElasticConfig", block)
}

fn raw_block(node: &Node, cx: &mut Context) -> bool {
    crate::objects::platform::before("ElasticConfig", node, cx)
}

platform_block! {
    /// Elastic Security detection rule (`ElasticConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[garde(custom(garde_block))]
    #[schemars(rename = "ElasticConfig", description = "")]
    #[from_node(model = "ElasticConfig", before = "raw_block")]
    pub struct ElasticConfig ["platform::elastic::1.0"] {
        /// Rule type: `query`, `eql`, `esql`, `threshold`, `new_terms`, `threat_match` or
        /// `machine_learning`. Kibana cannot change the type of an existing rule in place.
        pub r#type: RuleType,
        /// The event query, in the language the type selects. Multiline. Not sent for
        /// `machine_learning`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[from_node(with = "crate::objects::platform::optional_query_text")]
        #[garde(custom(crate::objects::platform::garde_optional_query_text))]
        pub query: Option<String>,
        /// `kuery` (KQL) or `lucene`, for the event query of `query`, `threshold`, `new_terms`, and
        /// `threat_match`. Compiled as `kuery` when omitted. MUST NOT be set for `eql`, `esql`, or
        /// `machine_learning`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::objects::platform::optional_literal::<QueryLanguage>")]
        pub language: Option<QueryLanguage>,
        /// Index patterns. A single pattern is a one-item list (`[logs-*]`). Omitted uses the tenant
        /// `setup.index`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub index: Option<Vec<String>>,
        /// One existing Kibana data view. Replaces `index`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub data_view_id: Option<String>,
        /// Rule query filters. Not Elastic Defend event filters.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filters: Option<Vec<ElasticFilter>>,
        /// Runs every, additional look-back, and max alerts per run.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scheduling: Option<ElasticScheduling>,
        /// An `alert_severity` value, or a default plus severity overrides.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub severity: Option<SeverityChoice>,
        /// Risk score 0–100, or a score plus risk score overrides.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub risk: Option<RiskChoice>,
        /// Alert suppression.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suppression: Option<ElasticSuppression>,
        /// Custom highlighted fields on the alert.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub highlighted_fields: Option<Vec<String>>,
        /// Group-by fields and count.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub threshold: Option<ElasticThreshold>,
        /// Fields whose new values alert, and the history window.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub new_terms: Option<ElasticNewTerms>,
        /// EQL-only settings.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub eql: Option<ElasticEql>,
        /// The indicator side of an indicator match rule. Not the ATT&CK array.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub threat: Option<ElasticThreatMatch>,
        /// Anomaly jobs and threshold.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub machine_learning: Option<ElasticMachineLearning>,
        /// Integrations the rule expects. Recorded on the rule; Fleet is not touched.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub integration: Option<Vec<IntegrationChoice>>,
        /// Fields the rule needs, with their mapping types.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required_fields: Option<Vec<ElasticRequiredField>>,
        /// Investigation guide and Setup guide.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub guide: Option<ElasticGuide>,
        /// Known false positives.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub false_positives: Option<Vec<String>>,
        /// Rule tags, after `OpenTide` and the tenant tags.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tags: Option<Vec<String>>,
        /// Exception lists to attach.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exceptions: Option<ElasticExceptions>,
        /// Building block rule: alerts are hidden from the default Alerts view.
        #[serde(default)]
        pub building_block: bool,
        /// Rule name override and timestamp override.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub overrides: Option<ElasticOverrides>,
        /// Rule actions, response actions, and the Timeline template.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<ElasticActions>,
    }
}

// ---------------------------------------------------------------------------
// The named check `elastic_rule_shape`.
// ---------------------------------------------------------------------------

const ENDPOINT_COMMANDS: [&str; 4] = ["isolate", "kill-process", "suspend-process", "runscript"];
const ENDPOINT_KEYS: [&str; 3] = ["endpoint", "comment", "field"];
const ALERT_SEVERITIES: [&str; 5] = ["informational", "low", "medium", "high", "critical"];
const EXCEPTION_TYPES: [&str; 2] = ["detection", "rule_default"];
const RULE_TYPES: [&str; 7] = [
    "query",
    "eql",
    "esql",
    "threshold",
    "new_terms",
    "threat_match",
    "machine_learning",
];
/// The flat keys of the pre-RFC 0007 block, removed (`type_block`).
pub const REMOVED_FLAT: [&str; 40] = [
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
];

/// `_pattern_list`: a non-empty list of non-empty strings.
fn pattern_list(node: &Node) -> bool {
    match &node.value {
        Value::Seq(items) => {
            !items.is_empty()
                && items
                    .iter()
                    .all(|item| item.value.as_str().is_some_and(|text| !text.is_empty()))
        }
        _ => false,
    }
}

/// The keys of a mapping, as strings.
fn keys(node: &Node) -> Vec<&str> {
    match &node.value {
        Value::Map(entries) => entries
            .iter()
            .filter_map(|entry| entry.key.value.as_str())
            .collect(),
        _ => Vec::new(),
    }
}

/// `_valid_response`: RFC 0007 `response_action`, the two author shapes only,
/// never Kibana's raw form.
fn valid_response(action: &Node) -> bool {
    let Value::Map(entries) = &action.value else {
        return false;
    };
    let all_strings = entries
        .iter()
        .all(|entry| entry.key.value.as_str().is_some());
    if let Some(endpoint) = action.get("endpoint") {
        return endpoint
            .value
            .as_str()
            .is_some_and(|command| ENDPOINT_COMMANDS.contains(&command))
            && all_strings
            && keys(action).iter().all(|key| ENDPOINT_KEYS.contains(key));
    }
    if let Some(osquery) = action.get("osquery") {
        return entries.len() == 1 && is_map(Some(osquery)) && truthy(get(Some(osquery), "query"));
    }
    false
}

/// The items a Python `for item in value` visits, for a value that is a
/// list, a string (its characters) or a mapping (its keys): each is judged
/// as an item. `None`: a value Python cannot iterate (the oracle crashed).
fn iterated(node: &Node) -> Option<Vec<Option<&Node>>> {
    match &node.value {
        Value::Seq(items) => Some(items.iter().map(|item| Some(item.as_ref())).collect()),
        Value::Str(text) => Some(text.chars().map(|_| None).collect()),
        Value::Map(entries) => Some(entries.iter().map(|_| None).collect()),
        _ => None,
    }
}

/// Every constraint code of the oracle's `_validate_raw_elastic_block` on a
/// raw block, sorted; empty when the block passes, is not a mapping, or has
/// no `status` (left to the field: a missing status is "Field required", as
/// on every platform).
#[expect(
    clippy::too_many_lines,
    reason = "one check per constraint, in the oracle's order"
)]
pub fn block_codes(raw: &Node) -> BTreeSet<&'static str> {
    let mut codes = BTreeSet::new();
    if !is_map(Some(raw)) || !present(get(Some(raw), "status")) || !super::within_budget(raw) {
        return codes;
    }
    let field = |key: &str| get(Some(raw), key);
    let rule_type = field("type").and_then(|node| node.value.as_str());
    let is_type = |wanted: &str| rule_type == Some(wanted);

    if !rule_type.is_some_and(|value| RULE_TYPES.contains(&value))
        || keys(raw).iter().any(|key| REMOVED_FLAT.contains(key))
    {
        codes.insert("type_block");
    }
    if present(field("threshold")) != is_type("threshold") {
        codes.insert("type_block");
    }
    let new_terms = field("new_terms");
    if present(new_terms) != is_type("new_terms")
        || (is_type("new_terms")
            && (!is_map(new_terms)
                || !present(get(new_terms, "fields"))
                || !present(get(new_terms, "history_window_start"))))
    {
        codes.insert("type_block");
    }
    if present(field("eql")) && !is_type("eql") {
        codes.insert("type_block");
    }
    let threat = field("threat");
    if present(threat) != is_type("threat_match")
        || (is_type("threat_match")
            && (!is_map(threat)
                || ["index", "query", "mapping"]
                    .iter()
                    .any(|key| !present(get(threat, key)))))
    {
        codes.insert("type_block");
    }
    let ml = field("machine_learning");
    if present(ml) != is_type("machine_learning")
        || (is_type("machine_learning")
            && (!is_map(ml)
                || !present(get(ml, "job_id"))
                || !present(get(ml, "anomaly_threshold"))))
    {
        codes.insert("type_block");
    }
    if !is_type("machine_learning") && !truthy(field("query")) {
        codes.insert("type_block");
    }
    if ["eql", "esql", "machine_learning"]
        .iter()
        .any(|kind| is_type(kind))
        && truthy(field("language"))
    {
        codes.insert("language");
    }
    if ["esql", "machine_learning"]
        .iter()
        .any(|kind| is_type(kind))
        && (truthy(field("index")) || truthy(field("data_view_id")) || truthy(field("filters")))
    {
        codes.insert("esql_source");
    }
    if truthy(field("index")) && truthy(field("data_view_id")) {
        codes.insert("index_xor_data_view");
    }
    if let Some(index) = field("index").filter(|node| present(Some(node)))
        && !pattern_list(index)
    {
        codes.insert("index_list");
    }
    if is_map(threat)
        && let Some(index) = get(threat, "index").filter(|node| present(Some(node)))
        && !pattern_list(index)
    {
        codes.insert("index_list");
    }
    let threat_filters = if is_map(threat) {
        get(threat, "filters")
    } else {
        None
    };
    for entries in [field("filters"), threat_filters] {
        let Some(entries) = entries.filter(|node| present(Some(node))) else {
            continue;
        };
        let Value::Seq(items) = &entries.value else {
            codes.insert("filter_shape");
            continue;
        };
        for entry in items {
            let entry = Some(entry.as_ref());
            if !is_map(entry) {
                codes.insert("filter_shape");
                continue;
            }
            let shorthand = ["field", "value", "negate"]
                .iter()
                .any(|key| present(get(entry, key)));
            let raw_filter = present(get(entry, "meta")) || present(get(entry, "query"));
            // Exactly one shape, and that shape complete: {field, value,
            // negate?} or {meta, query}. An empty entry is neither.
            if shorthand == raw_filter
                || (shorthand && (!present(get(entry, "field")) || !present(get(entry, "value"))))
                || (raw_filter && (!present(get(entry, "meta")) || !present(get(entry, "query"))))
            {
                codes.insert("filter_shape");
            }
        }
    }
    // `(raw.get("exceptions") or {}).get("lists") or []`.
    let exceptions = field("exceptions").filter(|node| truthy(Some(node)));
    if let Some(lists) = get(exceptions, "lists").filter(|node| truthy(Some(node)))
        && let Some(items) = iterated(lists)
    {
        for item in items {
            let ok = item.is_some_and(|item| {
                is_map(Some(item))
                    && get(Some(item), "type")
                        .and_then(|kind| kind.value.as_str())
                        .is_some_and(|kind| EXCEPTION_TYPES.contains(&kind))
            });
            if !ok {
                codes.insert("exception_type");
            }
        }
    }
    let actions = field("actions");
    match actions.map(|node| &node.value) {
        Some(Value::Seq(_)) => {
            codes.insert("type_block");
        }
        Some(Value::Map(_)) => {
            if let Some(respond) = get(actions, "respond").filter(|node| truthy(Some(node)))
                && let Some(items) = iterated(respond)
            {
                for action in items {
                    if !action.is_some_and(valid_response) {
                        codes.insert("response_action");
                    }
                }
            }
        }
        _ => {}
    }
    let mut suppression = field("suppression").filter(|node| present(Some(node)));
    if suppression.is_some() && !is_map(suppression) {
        codes.insert("suppression_shape");
        suppression = None;
    }
    if suppression.is_some() {
        let group_by = get(suppression, "group_by");
        if is_type("threshold") {
            // A missing duration is a shape fault; an empty one is a
            // `duration` fault, reported by the duration check below.
            if !present(get(suppression, "duration")) || truthy(group_by) {
                codes.insert("suppression_shape");
            }
        } else {
            let ok = match group_by.map(|node| &node.value) {
                Some(Value::Seq(items)) => {
                    (1..=3).contains(&items.len())
                        && items.iter().all(|item| truthy(Some(item)))
                        && items.iter().enumerate().all(|(index, item)| {
                            items[..index]
                                .iter()
                                .all(|other| !crate::objects::any::same(other, item))
                        })
                }
                _ => false,
            };
            if !ok {
                codes.insert("suppression_shape");
            }
        }
    }
    if is_map(new_terms)
        && let Some(fields) = get(new_terms, "fields")
        && !matches!(&fields.value, Value::Seq(items) if (1..=3).contains(&items.len()))
    {
        codes.insert("new_terms_fields");
    }
    let threshold = field("threshold");
    if is_map(threshold) {
        let threshold_field = get(threshold, "field").filter(|node| truthy(Some(node)));
        let field_ok = match threshold_field.map(|node| &node.value) {
            None => true,
            Some(Value::Seq(items)) => items.len() <= 5,
            Some(_) => false,
        };
        let value_ok = python_int(get(threshold, "value")).is_some_and(|value| value >= 1);
        if !field_ok || !value_ok {
            codes.insert("threshold_fields");
        }
    }
    let severity = field("severity");
    let level = if is_map(severity) {
        get(severity, "default")
    } else {
        severity
    };
    if present(level) {
        let known = level
            .and_then(|node| node.value.as_str())
            .is_some_and(|text| {
                ALERT_SEVERITIES.contains(&python_strip(text).to_lowercase().as_str())
            });
        if !known {
            // RFC 0007 §2: alert_severity vocabulary. An unknown value used
            // to compile silently to Informational (low, risk 1).
            codes.insert("severity");
        }
    }
    let risk = field("risk");
    if let Some(score) = python_int(risk) {
        if !(0..=100).contains(&score) {
            codes.insert("risk_score");
        }
    } else if is_map(risk) {
        let score = get(risk, "score");
        if present(score) && !python_int(score).is_some_and(|score| (0..=100).contains(&score)) {
            codes.insert("risk_score");
        }
    } else if present(risk) {
        codes.insert("risk_score");
    }
    // A non-object `scheduling` is a shape fault, not a duration one: left to
    // the field type, which names `scheduling` and the expected shape.
    let scheduling = field("scheduling").filter(|node| is_map(Some(node)));
    let duration_ok = |node: &Node, allow_zero: bool| {
        node.value
            .as_str()
            .is_some_and(|text| duration_seconds(text, allow_zero).is_ok())
    };
    if let Some(lookback) = get(scheduling, "lookback").filter(|node| present(Some(node)))
        && !duration_ok(lookback, true)
    {
        codes.insert("duration");
    }
    let history = if is_map(new_terms) {
        get(new_terms, "history_window_start")
    } else {
        None
    };
    // `None` is absent (#557); every other value, "" included, must parse.
    for value in [
        get(scheduling, "interval"),
        get(suppression, "duration"),
        history,
    ] {
        if let Some(value) = value.filter(|node| present(Some(node)))
            && !duration_ok(value, false)
        {
            codes.insert("duration");
        }
    }
    codes
}
