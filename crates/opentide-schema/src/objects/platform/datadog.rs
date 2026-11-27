//! Datadog Cloud SIEM detection rule, `platform::datadog::1.0`
//! (`DatadogConfig` and its nested models, RFC
//! `docs/internal/rfc-datadog-cloud-siem.md` §5), with the block's
//! constraints ([`block_findings`]): every code of the RFC's §5.9 but
//! `datadog_notification_alias`, which needs a tenant and is the compiler's,
//! each reported by its own code ([`ErrorKind::Constraint`]) at its field
//! path, relative to the block. `datadog_condition_mixed`, a warning, is an
//! advisory ([`advisories`]).
//!
//! The block groups the API's properties by meaning (§5.3): `queries` (what
//! to look at), `detection` (how the queries become a match), `cases` (when
//! a match becomes a signal) and `signal` (what happens to the signal). The
//! queries themselves are the analysis engine's (the Datadog search syntax,
//! profile `rule`); a case's condition is parsed here ([`condition`]).
//!
//! Facts the RFC marks unverified stay as it marks them: the anomaly
//! defaults are sent only when the block sets them, `detect_ip_transitions`
//! is sent only when `true`, and the upper bound of `queries` (10) is left to
//! Datadog's own validation (open question 5).

pub mod condition;

use std::collections::BTreeSet;

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::configuration::repr;
use crate::error::{ErrorKind, PathSegment};
use crate::from_node::Context;
use crate::node::{Node, Value};
use crate::objects::checks::check_at_least_one;
use crate::objects::platform::{literal_enum, platform_block};
use crate::pins::Pins;

/// The schema identifier.
pub const SCHEMA: &str = "platform::datadog::1.0";

/// `detection.window`'s values and their seconds (`options.evaluationWindow`);
/// `signal.keep_alive` and `signal.max_duration` take the same.
pub const WINDOWS: [(&str, i64); 12] = [
    ("0", 0),
    ("1m", 60),
    ("5m", 300),
    ("10m", 600),
    ("15m", 900),
    ("30m", 1800),
    ("1h", 3600),
    ("2h", 7200),
    ("3h", 10_800),
    ("6h", 21_600),
    ("12h", 43_200),
    ("1d", 86_400),
];
/// `detection.bucket`'s values and their seconds
/// (`anomalyDetectionOptions.bucketDuration`).
pub const BUCKETS: [(&str, i64); 6] = [
    ("5m", 300),
    ("10m", 600),
    ("15m", 900),
    ("30m", 1800),
    ("1h", 3600),
    ("3h", 10_800),
];
/// `detection.learning`'s values under `anomaly` and their hours
/// (`anomalyDetectionOptions.learningDuration`).
pub const ANOMALY_LEARNING: [(&str, i64); 7] = [
    ("1h", 1),
    ("6h", 6),
    ("12h", 12),
    ("1d", 24),
    ("2d", 48),
    ("7d", 168),
    ("14d", 336),
];
/// The most days `learning` (`new_value`, `impossible_travel`) and
/// `forget_after` take.
pub const MAX_DAYS: i64 = 30;
/// `detection.tolerance`'s range (`anomalyDetectionOptions.detectionTolerance`).
pub const TOLERANCE: (i64, i64) = (1, 5);
/// The most fields a `new_value` lists.
pub const NEW_VALUE_FIELDS: usize = 5;
/// The most characters a Datadog tag has.
pub const TAG_LIMIT: usize = 200;

/// The detection methods of 1.0, as written.
pub const METHODS: [&str; 4] = ["threshold", "new_value", "anomaly", "impossible_travel"];
/// A case's severities: Datadog's five statuses.
pub const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];
/// `queries[].from`'s values.
pub const SOURCES: [&str; 4] = ["logs", "audit", "events", "signals"];
/// The measure keys of a query; at most one is set.
pub const MEASURES: [&str; 4] = ["count_distinct", "sum", "max", "new_value"];
/// The `detection` keys each method takes (`method` and `window` are
/// everyone's).
pub const METHOD_KEYS: [(&str, &[&str]); 4] = [
    ("threshold", &[]),
    ("new_value", &["learning", "forget_after"]),
    ("anomaly", &["learning", "bucket", "tolerance"]),
    ("impossible_travel", &["learning", "detect_ip_transitions"]),
];
/// Every method-specific `detection` key.
const METHOD_OPTIONS: [&str; 5] = [
    "learning",
    "forget_after",
    "bucket",
    "tolerance",
    "detect_ip_transitions",
];

/// The default `detection.method`.
pub const DEFAULT_METHOD: &str = "threshold";
/// The default `detection.window`.
pub const DEFAULT_WINDOW: &str = "5m";
/// The default `signal.keep_alive`.
pub const DEFAULT_KEEP_ALIVE: &str = "1h";
/// The default `signal.max_duration`.
pub const DEFAULT_MAX_DURATION: &str = "1d";
/// The default `detection.learning` under `new_value`.
pub const DEFAULT_NEW_VALUE_LEARNING: &str = "1d";

/// What each constraint code says (RFC §5.9).
pub const CODE_MESSAGES: [(&str, &str); 10] = [
    (
        "datadog_method_unsupported",
        "detection.method is threshold, new_value, anomaly or impossible_travel",
    ),
    ("datadog_duration", "not a duration this key accepts"),
    (
        "datadog_window_order",
        "detection.window is not longer than signal.keep_alive or signal.max_duration",
    ),
    (
        "datadog_query_name",
        "a query name is [a-z][a-z0-9_]*, unique in the block, and not set on a new_value query",
    ),
    (
        "datadog_measure",
        "a query sets at most one of count_distinct, sum, max and new_value; new_value goes \
         with method: new_value, one to five fields",
    ),
    (
        "datadog_detection_option",
        "a detection key the method does not take, or new_value without forget_after",
    ),
    (
        "datadog_signal_group_by",
        "every signal.group_by field is in some query's group_by",
    ),
    (
        "datadog_condition",
        "the condition does not parse, names an unknown query, or does not suit the method",
    ),
    (
        "datadog_severity",
        "a case severity is info, low, medium, high or critical",
    ),
    (
        "datadog_tag",
        "a tag is lower case, starts with a letter, holds only a-z 0-9 _ - : . /, and is at \
         most 200 characters",
    ),
];

/// The deploy-time code a notification alias the tenant does not define
/// gives (RFC §5.9; the compiler's, with a tenant).
pub const NOTIFICATION_ALIAS: &str = "datadog_notification_alias";

/// Every code [`block_findings`] reports.
pub fn constraint_codes() -> impl Iterator<Item = &'static str> {
    CODE_MESSAGES.iter().map(|(code, _)| *code)
}

/// What constraint `code` says, or nothing for a code it does not know.
pub fn code_message(code: &str) -> &'static str {
    CODE_MESSAGES
        .iter()
        .find(|(known, _)| *known == code)
        .map_or("", |(_, message)| *message)
}

// ---------------------------------------------------------------------------
// The model.
// ---------------------------------------------------------------------------

literal_enum! {
    /// `detection.method`.
    DatadogMethod {
        Threshold = "threshold",
        NewValue = "new_value",
        Anomaly = "anomaly",
        ImpossibleTravel = "impossible_travel",
    }
}

literal_enum! {
    /// `cases[].severity`.
    DatadogSeverity {
        Info = "info",
        Low = "low",
        Medium = "medium",
        High = "high",
        Critical = "critical",
    }
}

literal_enum! {
    /// `queries[].from`.
    DatadogSource {
        Logs = "logs",
        Audit = "audit",
        Events = "events",
        Signals = "signals",
    }
}

/// Declares a nested Datadog model (closed, Tide's shape).
macro_rules! model {
    ($(#[$meta:meta])* $name:ident = $model:tt { $($body:tt)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
        #[serde(deny_unknown_fields)]
        #[garde(context(Pins))]
        #[garde(allow_unvalidated)]
        #[schemars(rename = $model, description = "")]
        #[from_node(model = $model)]
        #[cfg_attr(
            feature = "python",
            pyo3::pyclass(frozen, get_all, eq, name = $model, module = "opentide._native.models")
        )]
        #[cfg_attr(
            feature = "python",
            expect(
                clippy::unsafe_derive_deserialize,
                reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
            )
        )]
        pub struct $name { $($body)* }
    };
}

/// The schema of a window-valued key: one of [`WINDOWS`], its default
/// first (the value a template offers), `0` also as a number, or null.
fn window_schema_with(default: &str) -> schemars::Schema {
    let mut values: Vec<&str> = vec![default];
    values.extend(
        WINDOWS
            .iter()
            .map(|(text, _)| *text)
            .filter(|text| *text != default),
    );
    schemars::json_schema!({"anyOf": [
        {"type": "string", "enum": values},
        {"type": "integer", "const": 0},
        {"type": "null"}
    ]})
}

/// `detection.window`'s schema.
fn window_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    window_schema_with(DEFAULT_WINDOW)
}

/// `signal.keep_alive`'s schema.
fn keep_alive_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    window_schema_with(DEFAULT_KEEP_ALIVE)
}

/// `signal.max_duration`'s schema.
fn max_duration_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    window_schema_with(DEFAULT_MAX_DURATION)
}

/// A duration in the conversion: a string, or the number `0` read as `"0"`
/// (`window: 0`), or null.
#[expect(
    clippy::option_option,
    reason = "a FromNode `with` function's signature: the outer Option is the conversion's \
              success, the inner the optional field's own value (as `optional_query_text`)"
)]
fn duration_text(node: &Node, cx: &mut Context) -> Option<Option<String>> {
    match node.value {
        Value::Null => Some(None),
        Value::Int(0) => Some(Some("0".to_owned())),
        _ => String::from_node(node, cx).map(Some),
    }
}

model! {
    /// One search over a data source (`DatadogQuery`).
    DatadogQuery = "DatadogQuery" {
        /// The Datadog search syntax, profile `rule`. Multiline in YAML.
        #[schemars(extend(
            "tide.template.multiline" = true,
            "tide.template.required" = true
        ))]
        #[from_node(with = "crate::objects::platform::query_text")]
        pub query: String,
        /// What conditions call the query: `[a-z][a-z0-9_]*`, unique in the block. Default: `a`, `b`, …
        /// by position. Not allowed on a `new_value` query.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// `logs`, `audit`, `events`, or `signals` (security signals). Default: `logs`.
        #[serde(default, rename = "from", skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::objects::platform::optional_literal::<DatadogSource>")]
        pub from_: Option<DatadogSource>,
        /// Matches are counted per distinct combination of these fields' values.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group_by: Option<Vec<String>>,
        /// Keep an event that lacks a `group_by` value, grouped as `N/A`, instead of dropping it.
        /// Default: `false`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keep_missing_groups: Option<bool>,
        /// The cases compare the number of distinct values of this field instead of events.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count_distinct: Option<String>,
        /// The cases compare this numeric field's sum.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sum: Option<String>,
        /// The cases compare this numeric field's maximum.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<String>,
        /// `method: new_value` only: one to five fields whose unseen values trigger.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub new_value: Option<Vec<String>>,
    }
}

model! {
    /// How the queries become a match (`DatadogDetection`).
    DatadogDetection = "DatadogDetection" {
        /// `threshold`, `new_value`, `anomaly`, or `impossible_travel`. Default: `threshold`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::objects::platform::optional_literal::<DatadogMethod>")]
        pub method: Option<DatadogMethod>,
        /// The sliding window the cases are tested over: `0`, `1m`, `5m`, `10m`, `15m`, `30m`, `1h`,
        /// `2h`, `3h`, `6h`, `12h`, or `1d`. Default: `5m`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "window_schema")]
        #[from_node(with = "duration_text")]
        pub window: Option<String>,
        /// How long Datadog learns what is normal. `new_value`: `0d` to `30d` (default `1d`).
        /// `anomaly`: `1h`, `6h`, `12h`, `1d`, `2d`, `7d`, or `14d`. `impossible_travel`: `1d` to `30d`,
        /// a baseline of each user's locations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub learning: Option<String>,
        /// `new_value` only, required: a learned value unseen for this long is new again, `1d` to `30d`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forget_after: Option<String>,
        /// `anomaly` only: the time bucket the baseline is computed on: `5m`, `10m`, `15m`, `30m`, `1h`,
        /// or `3h`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bucket: Option<String>,
        /// `anomaly` only: how far above the baseline counts as anomalous, 1 to 5.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tolerance: Option<i64>,
        /// `impossible_travel` only: detect transitions between IP addresses of the same user.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detect_ip_transitions: Option<bool>,
    }
}

model! {
    /// When a match becomes a signal (`DatadogCase`).
    DatadogCase = "DatadogCase" {
        /// Comparisons of query names with numbers, joined by `&&` or `||`: `failed > 10 && success > 0`.
        /// Required with `threshold` and `anomaly`; under `anomaly`, the number is a percentile between 0
        /// and 1.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(extend("tide.template.required" = true))]
        pub condition: Option<String>,
        /// The case's name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// `info`, `low`, `medium`, `high`, or `critical`. Default: from `response.alert_severity`, else
        /// `info`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::objects::platform::optional_literal::<DatadogSeverity>")]
        pub severity: Option<DatadogSeverity>,
        /// Tenant notification aliases or raw `@handles`. Left out in a `PREVIEW` deploy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notify: Option<Vec<String>>,
    }
}

model! {
    /// What happens to a signal once it exists (`DatadogSignal`).
    DatadogSignal = "DatadogSignal" {
        /// Matches with the same values of these fields update one signal. Each is in some query's
        /// `group_by`. Default: no signal grouping.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group_by: Option<Vec<String>>,
        /// The signal stays open while a case matches again within this time: a `detection.window` value,
        /// at least the window. Default: `1h`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "keep_alive_schema")]
        #[from_node(with = "duration_text")]
        pub keep_alive: Option<String>,
        /// The signal closes this long after its first match: a `detection.window` value, at least the
        /// window. Default: `1d`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "max_duration_schema")]
        #[from_node(with = "duration_text")]
        pub max_duration: Option<String>,
        /// One severity level lower when the `env` tag starts with `staging`, `test`, or `dev`. Default:
        /// `false`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub downgrade_non_production: Option<bool>,
        /// Notifications put the group-by values in their title. Default: `false`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group_in_notification_title: Option<bool>,
    }
}

/// A list with `min_length=1` (`too_short`), its items converted first.
fn at_least_one<T: FromNode>(node: &Node, cx: &mut Context) -> Option<Vec<T>> {
    let items = Vec::<T>::from_node(node, cx)?;
    match check_at_least_one(items.len()) {
        Ok(()) => Some(items),
        Err(violation) => {
            violation.report(node, cx);
            None
        }
    }
}

fn raw_block(node: &Node, cx: &mut Context) -> bool {
    if !super::is_map(Some(node))
        || !super::present(super::get(Some(node), "status"))
        || !super::within_budget(node)
    {
        return true;
    }
    let findings = block_findings(node);
    for finding in &findings {
        let path = finding.path.clone();
        report_at(cx, &path, finding, node);
    }
    findings.is_empty()
}

fn report_at(cx: &mut Context, path: &[PathSegment], finding: &Finding, input: &Node) {
    match path.split_first() {
        None => cx.error(ErrorKind::Constraint(finding.code), &finding.message, input),
        Some((head, rest)) => cx.at(head.clone(), |cx| report_at(cx, rest, finding, input)),
    }
}

fn garde_block(block: &DatadogConfig, _pins: &Pins) -> garde::Result {
    let value = serde_json::to_value(block)
        .map_err(|error| garde::Error::new(format!("DatadogConfig does not serialise: {error}")))?;
    let findings = block_findings(&super::json_node(&value));
    match findings.first() {
        None => Ok(()),
        Some(first) => Err(garde::Error::new(format!(
            "{}: {}",
            first.code, first.message
        ))),
    }
}

platform_block! {
    /// Datadog Cloud SIEM detection rule (`DatadogConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[garde(custom(garde_block))]
    #[schemars(rename = "DatadogConfig", description = "")]
    #[from_node(model = "DatadogConfig", before = "raw_block")]
    #[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all, eq, name = "DatadogConfig", module = "opentide._native.models"))]
    #[cfg_attr(feature = "python", expect(clippy::unsafe_derive_deserialize, reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"))]
    pub struct DatadogConfig ["platform::datadog::1.0"] {
        /// One or more searches, each with the name conditions call it by.
        #[schemars(extend("tide.template.required" = true))]
        #[from_node(with = "at_least_one")]
        #[garde(length(min = 1))]
        pub queries: Vec<DatadogQuery>,
        /// How the queries become a match. Default: `method: threshold`, `window: 5m`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detection: Option<DatadogDetection>,
        /// One or more cases, tested in order: the first that matches creates or updates the signal.
        #[schemars(extend("tide.template.required" = true))]
        #[from_node(with = "at_least_one")]
        #[garde(length(min = 1))]
        pub cases: Vec<DatadogCase>,
        /// What happens to the signal: grouping, how long it stays open, how it reads.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signal: Option<DatadogSignal>,
        /// The signal's message: Markdown with Datadog template variables. Default: derived from the
        /// rule's description and response.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(extend("tide.template.multiline" = true))]
        pub message: Option<String>,
        /// Datadog tags, added to the derived ones: lower case, such as `team:identity`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tags: Option<Vec<String>>,
    }
}

// ---------------------------------------------------------------------------
// The constraints (`block_findings`).
// ---------------------------------------------------------------------------

/// A code, its path relative to `configurations.datadog`, and its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The constraint code (`datadog_duration`).
    pub code: &'static str,
    /// Where, relative to the block.
    pub path: Vec<PathSegment>,
    /// What is wrong.
    pub message: String,
}

impl Finding {
    fn new(code: &'static str, path: Vec<PathSegment>, message: impl Into<String>) -> Self {
        Self {
            code,
            path,
            message: message.into(),
        }
    }

    /// The path as the CLI's `field_path` tuple: keys and indexes as strings.
    pub fn field_path(&self) -> Vec<String> {
        self.path.iter().map(ToString::to_string).collect()
    }
}

fn key(name: &str) -> PathSegment {
    PathSegment::Key(name.to_owned())
}

fn path(parts: &[PathSegment], last: &str) -> Vec<PathSegment> {
    let mut out = parts.to_vec();
    out.push(key(last));
    out
}

/// A mapping's value at `name`, a null left out (a key whose value is null
/// is the key not written).
fn field<'n>(node: &'n Node, name: &str) -> Option<&'n Node> {
    node.get(name)
        .map(AsRef::as_ref)
        .filter(|value| !matches!(value.value, Value::Null))
}

/// A table's value at `name`, when `node` is a table.
fn table_field<'n>(node: Option<&'n Node>, name: &str) -> Option<&'n Node> {
    node.filter(|node| matches!(node.value, Value::Map(_)))
        .and_then(|node| field(node, name))
}

/// The mapping's keys whose values are set.
fn keys(node: &Node) -> Vec<&str> {
    match &node.value {
        Value::Map(entries) => entries
            .iter()
            .filter(|entry| !matches!(entry.value.value, Value::Null))
            .filter_map(|entry| entry.key.value.as_str())
            .collect(),
        _ => Vec::new(),
    }
}

fn text(node: Option<&Node>) -> Option<&str> {
    match node.map(|node| &node.value) {
        Some(Value::Str(text)) => Some(text),
        _ => None,
    }
}

/// A window-valued key's text: a string, or the number `0`.
fn window_text(node: Option<&Node>) -> Option<&str> {
    match node.map(|node| &node.value) {
        Some(Value::Str(text)) => Some(text),
        Some(Value::Int(0)) => Some("0"),
        _ => None,
    }
}

/// The strings of a list (other items left out).
fn strings(node: Option<&Node>) -> Vec<&str> {
    match node.map(|node| &node.value) {
        Some(Value::Seq(items)) => items.iter().filter_map(|item| text(Some(item))).collect(),
        _ => Vec::new(),
    }
}

fn items(node: Option<&Node>) -> &[std::sync::Arc<Node>] {
    match node.map(|node| &node.value) {
        Some(Value::Seq(items)) => items,
        _ => &[],
    }
}

/// The seconds a window-valued text stands for ([`WINDOWS`]).
pub fn window_seconds(value: &str) -> Option<i64> {
    WINDOWS
        .iter()
        .find(|(text, _)| *text == value)
        .map(|(_, seconds)| *seconds)
}

/// The seconds a bucket stands for ([`BUCKETS`]).
pub fn bucket_seconds(value: &str) -> Option<i64> {
    BUCKETS
        .iter()
        .find(|(text, _)| *text == value)
        .map(|(_, seconds)| *seconds)
}

/// The hours an anomaly `learning` stands for ([`ANOMALY_LEARNING`]).
pub fn anomaly_learning_hours(value: &str) -> Option<i64> {
    ANOMALY_LEARNING
        .iter()
        .find(|(text, _)| *text == value)
        .map(|(_, hours)| *hours)
}

/// Whole days, `<n>d` with `low <= n <= 30`: no sign, no leading zero but
/// `0d` itself.
pub fn days(value: &str, low: i64) -> Option<i64> {
    let digits = value.strip_suffix('d')?;
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return None;
    }
    let number: i64 = digits.parse().ok()?;
    (low..=MAX_DAYS).contains(&number).then_some(number)
}

/// The method a block's `detection` names, as written, defaulting to
/// `threshold` when it is not set; `None` when it is not a 1.0 method.
pub fn method_of(block: &Node) -> Option<&str> {
    let detection = field(block, "detection");
    match table_field(detection, "method") {
        None => Some(DEFAULT_METHOD),
        Some(method) => text(Some(method)).filter(|method| METHODS.contains(method)),
    }
}

/// The name a query goes by: its own, else `a`, `b`, … by position.
pub fn default_query_name(index: usize) -> String {
    u8::try_from(index)
        .ok()
        .filter(|index| *index < 26)
        .map_or_else(
            || format!("q{index}"),
            |index| char::from(b'a' + index).to_string(),
        )
}

/// Each query's name, as conditions call it: its `name` when it is a
/// string, else its default ([`default_query_name`]).
pub fn query_names(block: &Node) -> Vec<String> {
    items(field(block, "queries"))
        .iter()
        .enumerate()
        .map(|(index, query)| {
            table_field(Some(query), "name")
                .and_then(|name| text(Some(name)))
                .map_or_else(|| default_query_name(index), str::to_owned)
        })
        .collect()
}

/// Why a tag would be refused or rewritten by Datadog, if it would.
pub fn tag_problem(tag: &str) -> Option<String> {
    let count = tag.chars().count();
    if count > TAG_LIMIT {
        return Some(format!(
            "{} is {count} characters, more than {TAG_LIMIT}",
            repr::quote(&tag.chars().take(24).collect::<String>())
        ));
    }
    if !tag.starts_with(|ch: char| ch.is_ascii_lowercase()) {
        return Some(format!(
            "{} does not start with a lower-case letter",
            repr::quote(tag)
        ));
    }
    if tag.chars().any(|ch| ch.is_uppercase()) {
        return Some(format!(
            "{} has upper case, which Datadog lowers: write it in lower case",
            repr::quote(tag)
        ));
    }
    if let Some(bad) = tag
        .chars()
        .find(|ch| !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || "_-:./".contains(*ch)))
    {
        return Some(format!(
            "{} holds {}, which Datadog rewrites: use a-z, 0-9, _, -, :, . or /",
            repr::quote(tag),
            repr::quote(&bad.to_string())
        ));
    }
    None
}

fn query_findings(block: &Node, method: Option<&str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let queries = items(field(block, "queries"));
    let names = query_names(block);
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (index, query) in queries.iter().enumerate() {
        let at = vec![key("queries"), PathSegment::Index(index)];
        if !matches!(query.value, Value::Map(_)) {
            continue;
        }
        let new_value = field(query, "new_value");
        if let Some(name) = field(query, "name") {
            let name_path = path(&at, "name");
            match text(Some(name)) {
                Some(written) if !condition::query_name(written) => {
                    findings.push(Finding::new(
                        "datadog_query_name",
                        name_path.clone(),
                        format!(
                            "{} is not a query name: [a-z][a-z0-9_]*, such as failed_logins",
                            repr::quote(written)
                        ),
                    ));
                }
                Some(_) if new_value.is_some() => findings.push(Finding::new(
                    "datadog_query_name",
                    name_path.clone(),
                    "a new_value query takes no name: remove it",
                )),
                _ => {}
            }
        }
        let name = names.get(index).map_or("", String::as_str);
        if !seen.insert(name) {
            findings.push(Finding::new(
                "datadog_query_name",
                if field(query, "name").is_some() {
                    path(&at, "name")
                } else {
                    at.clone()
                },
                format!(
                    "two queries go by the name {}: every query's name is unique (an unnamed \
                     query is called a, b, … by its position)",
                    repr::quote(name)
                ),
            ));
        }
        let measures: Vec<&str> = MEASURES
            .iter()
            .copied()
            .filter(|measure| field(query, measure).is_some())
            .collect();
        if measures.len() > 1 {
            findings.push(Finding::new(
                "datadog_measure",
                path(&at, measures[1]),
                format!(
                    "a query sets at most one measure; this one sets {}",
                    measures.join(" and ")
                ),
            ));
        }
        match (method, new_value) {
            (Some("new_value"), None) => findings.push(Finding::new(
                "datadog_measure",
                at.clone(),
                "method: new_value: every query lists the fields whose new values trigger in \
                 new_value",
            )),
            (Some(method), Some(_)) if method != "new_value" => findings.push(Finding::new(
                "datadog_measure",
                path(&at, "new_value"),
                format!("new_value goes with method: new_value, not {method}"),
            )),
            (_, Some(fields)) => {
                let count = items(Some(fields)).len();
                if !matches!(fields.value, Value::Seq(_)) || count == 0 || count > NEW_VALUE_FIELDS
                {
                    findings.push(Finding::new(
                        "datadog_measure",
                        path(&at, "new_value"),
                        format!("new_value lists one to {NEW_VALUE_FIELDS} fields"),
                    ));
                }
            }
            _ => {}
        }
        if method == Some("impossible_travel")
            && let Some(measure) = measures.first()
        {
            findings.push(Finding::new(
                "datadog_measure",
                path(&at, measure),
                "impossible_travel measures the distance between logins itself \
                 (@network.client.geoip): remove the measure",
            ));
        }
    }
    findings
}

/// A finding for a duration that is not one its key accepts.
fn duration_finding(at: Vec<PathSegment>, message: String) -> Finding {
    Finding::new("datadog_duration", at, message)
}

fn window_choices() -> String {
    WINDOWS
        .iter()
        .map(|(text, _)| *text)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The window-valued key at `name` of `table`: its seconds, a finding when
/// it is not one, and `None` when it is not set.
fn window_key(
    table: &Node,
    at: &[PathSegment],
    name: &str,
    findings: &mut Vec<Finding>,
) -> Option<i64> {
    let node = field(table, name)?;
    let seconds = window_text(Some(node)).and_then(window_seconds);
    if seconds.is_none() {
        findings.push(duration_finding(
            path(at, name),
            format!("{name} is {}, not {}", window_choices(), repr::node(node)),
        ));
    }
    seconds
}

/// The findings of the method's own `detection` settings: `learning` in the
/// unit its method takes, `forget_after` (required with `new_value`), and
/// anomaly's `bucket` and `tolerance`.
fn method_option_findings(
    detection: &Node,
    at: &[PathSegment],
    method: &str,
    takes: &[&str],
    findings: &mut Vec<Finding>,
) {
    if let Some(learning) = field(detection, "learning")
        && takes.contains(&"learning")
    {
        let value = text(Some(learning));
        let (ok, says) = match method {
            "new_value" => (
                value.and_then(|value| days(value, 0)).is_some(),
                "0d to 30d, in whole days",
            ),
            "anomaly" => (
                value.and_then(anomaly_learning_hours).is_some(),
                "1h, 6h, 12h, 1d, 2d, 7d or 14d",
            ),
            _ => (
                value.and_then(|value| days(value, 1)).is_some(),
                "1d to 30d, in whole days",
            ),
        };
        if !ok {
            findings.push(duration_finding(
                path(at, "learning"),
                format!(
                    "learning under {method} is {says}, not {}",
                    repr::node(learning)
                ),
            ));
        }
    }
    if method == "new_value" {
        match field(detection, "forget_after") {
            None => findings.push(Finding::new(
                "datadog_detection_option",
                at.to_vec(),
                "method: new_value needs forget_after: how long a learned value stays known, 1d \
                 to 30d",
            )),
            Some(forget) => {
                if text(Some(forget))
                    .and_then(|value| days(value, 1))
                    .is_none()
                {
                    findings.push(duration_finding(
                        path(at, "forget_after"),
                        format!(
                            "forget_after is 1d to 30d, in whole days, not {}",
                            repr::node(forget)
                        ),
                    ));
                }
            }
        }
    }
    if method == "anomaly" {
        if let Some(bucket) = field(detection, "bucket")
            && text(Some(bucket)).and_then(bucket_seconds).is_none()
        {
            findings.push(duration_finding(
                path(at, "bucket"),
                format!(
                    "bucket is 5m, 10m, 15m, 30m, 1h or 3h, not {}",
                    repr::node(bucket)
                ),
            ));
        }
        if let Some(tolerance) = field(detection, "tolerance")
            && !matches!(tolerance.value, Value::Int(value) if (TOLERANCE.0..=TOLERANCE.1).contains(&value))
        {
            findings.push(Finding::new(
                "datadog_detection_option",
                path(at, "tolerance"),
                format!(
                    "tolerance is a whole number, {} to {}, not {}",
                    TOLERANCE.0,
                    TOLERANCE.1,
                    repr::node(tolerance)
                ),
            ));
        }
    }
}

fn detection_findings(block: &Node, method: Option<&str>) -> (Vec<Finding>, Option<i64>) {
    let at = vec![key("detection")];
    let mut findings = Vec::new();
    let Some(detection) =
        field(block, "detection").filter(|node| matches!(node.value, Value::Map(_)))
    else {
        return (findings, window_seconds(DEFAULT_WINDOW));
    };
    if let Some(written) = field(detection, "method")
        && method.is_none()
    {
        findings.push(Finding::new(
            "datadog_method_unsupported",
            path(&at, "method"),
            format!(
                "{} is not a detection method of platform::datadog::1.0: {} (sequence rules wait \
                 for 1.x)",
                repr::node(written),
                METHODS.join(", ")
            ),
        ));
    }
    let window = if field(detection, "window").is_some() {
        window_key(detection, &at, "window", &mut findings)
    } else {
        window_seconds(DEFAULT_WINDOW)
    };
    let Some(method) = method else {
        return (findings, window);
    };
    let takes: &[&str] = METHOD_KEYS
        .iter()
        .find(|(name, _)| *name == method)
        .map_or(&[], |(_, keys)| *keys);
    for name in keys(detection) {
        if METHOD_OPTIONS.contains(&name) && !takes.contains(&name) {
            findings.push(Finding::new(
                "datadog_detection_option",
                path(&at, name),
                format!(
                    "method: {method} does not take {name}{}",
                    if takes.is_empty() {
                        String::new()
                    } else {
                        format!(" (it takes {})", takes.join(", "))
                    }
                ),
            ));
        }
    }
    method_option_findings(detection, &at, method, takes, &mut findings);
    (findings, window)
}

fn signal_findings(block: &Node, window: Option<i64>) -> Vec<Finding> {
    let at = vec![key("signal")];
    let mut findings = Vec::new();
    let signal = field(block, "signal").filter(|node| matches!(node.value, Value::Map(_)));
    let keep_alive = match signal {
        Some(signal) if field(signal, "keep_alive").is_some() => {
            window_key(signal, &at, "keep_alive", &mut findings)
        }
        _ => window_seconds(DEFAULT_KEEP_ALIVE),
    };
    let max_duration = match signal {
        Some(signal) if field(signal, "max_duration").is_some() => {
            window_key(signal, &at, "max_duration", &mut findings)
        }
        _ => window_seconds(DEFAULT_MAX_DURATION),
    };
    if let Some(window) = window {
        for (name, seconds) in [("keep_alive", keep_alive), ("max_duration", max_duration)] {
            if let Some(seconds) = seconds
                && seconds < window
            {
                let written = signal.and_then(|signal| window_text(field(signal, name)));
                let shown = written.map_or_else(
                    || {
                        if name == "keep_alive" {
                            format!("{DEFAULT_KEEP_ALIVE} (the default)")
                        } else {
                            format!("{DEFAULT_MAX_DURATION} (the default)")
                        }
                    },
                    str::to_owned,
                );
                findings.push(Finding::new(
                    "datadog_window_order",
                    if written.is_some() {
                        path(&at, name)
                    } else {
                        vec![key("detection"), key("window")]
                    },
                    format!(
                        "detection.window is longer than signal.{name}, {shown}: a signal \
                         would close before its window ends"
                    ),
                ));
            }
        }
    }
    if let Some(signal) = signal
        && let Some(group_by) = field(signal, "group_by")
    {
        let grouped: BTreeSet<&str> = items(field(block, "queries"))
            .iter()
            .flat_map(|query| strings(table_field(Some(query), "group_by")))
            .collect();
        for (index, item) in items(Some(group_by)).iter().enumerate() {
            if let Some(name) = text(Some(item))
                && !grouped.contains(name)
            {
                findings.push(Finding::new(
                    "datadog_signal_group_by",
                    vec![key("signal"), key("group_by"), PathSegment::Index(index)],
                    format!(
                        "{} is in no query's group_by: signals can only be grouped by a field \
                         the queries group by",
                        repr::quote(name)
                    ),
                ));
            }
        }
    }
    findings
}

fn case_findings(block: &Node, method: Option<&str>) -> Vec<Finding> {
    let names = query_names(block);
    let mut findings = Vec::new();
    for (index, case) in items(field(block, "cases")).iter().enumerate() {
        let at = vec![key("cases"), PathSegment::Index(index)];
        if !matches!(case.value, Value::Map(_)) {
            continue;
        }
        if let Some(severity) = field(case, "severity")
            && !text(Some(severity)).is_some_and(|severity| SEVERITIES.contains(&severity))
        {
            findings.push(Finding::new(
                "datadog_severity",
                path(&at, "severity"),
                format!(
                    "{} is not a Datadog severity: {} (lower case)",
                    repr::node(severity),
                    SEVERITIES.join(", ")
                ),
            ));
        }
        let condition_path = path(&at, "condition");
        let Some(written) = field(case, "condition") else {
            if let Some(method @ ("threshold" | "anomaly")) = method {
                findings.push(Finding::new(
                    "datadog_condition",
                    at.clone(),
                    format!("method: {method} needs a condition on every case, such as a > 5"),
                ));
            }
            continue;
        };
        let Some(source) = text(Some(written)) else {
            findings.push(Finding::new(
                "datadog_condition",
                condition_path,
                "a condition is a string, such as failed > 10 && success > 0",
            ));
            continue;
        };
        let parsed = match condition::parse(source) {
            Ok(parsed) => parsed,
            Err(error) => {
                findings.push(Finding::new(
                    "datadog_condition",
                    condition_path,
                    format!("the condition does not parse: {}", error.message),
                ));
                continue;
            }
        };
        for comparison in &parsed.comparisons {
            if !names.contains(&comparison.query) {
                findings.push(Finding::new(
                    "datadog_condition",
                    condition_path.clone(),
                    format!(
                        "{} names no query: the queries are {}",
                        repr::quote(&comparison.query),
                        names.join(", ")
                    ),
                ));
            }
            if method == Some("anomaly") {
                if matches!(comparison.op, "<" | "<=") {
                    findings.push(Finding::new(
                        "datadog_condition",
                        condition_path.clone(),
                        format!(
                            "{} is documented for threshold rules only: an anomaly condition \
                             takes > or >=",
                            comparison.op
                        ),
                    ));
                }
                if !(comparison.value > 0.0 && comparison.value < 1.0) {
                    findings.push(Finding::new(
                        "datadog_condition",
                        condition_path.clone(),
                        format!(
                            "under anomaly, {} is a percentile between 0 and 1 (such as 0.995), \
                             not {}",
                            comparison.query, comparison.number
                        ),
                    ));
                }
            }
        }
    }
    findings
}

fn tag_findings(block: &Node) -> Vec<Finding> {
    items(field(block, "tags"))
        .iter()
        .enumerate()
        .filter_map(|(index, tag)| {
            let problem = match text(Some(tag)) {
                Some(tag) => tag_problem(tag),
                None => Some(format!("{} is not a tag", repr::node(tag))),
            };
            problem.map(|problem| {
                Finding::new(
                    "datadog_tag",
                    vec![key("tags"), PathSegment::Index(index)],
                    problem,
                )
            })
        })
        .collect()
}

/// Every constraint finding of a block, as authored, at its path
/// (`block_findings`). A null is the key left out, at the root and inside
/// every table. A block that is not a mapping has none: its type is the
/// model's error.
pub fn block_findings(block: &Node) -> Vec<Finding> {
    if !matches!(block.value, Value::Map(_)) {
        return Vec::new();
    }
    let method = method_of(block);
    let (mut findings, window) = detection_findings(block, method);
    findings.extend(query_findings(block, method));
    findings.extend(case_findings(block, method));
    findings.extend(signal_findings(block, window));
    findings.extend(tag_findings(block));
    findings
}

/// Every constraint code a block breaks, sorted (`block_codes`).
pub fn block_codes(block: &Node) -> BTreeSet<&'static str> {
    block_findings(block)
        .into_iter()
        .map(|finding| finding.code)
        .collect()
}

// ---------------------------------------------------------------------------
// Advisories: warnings that never reject a rule.
// ---------------------------------------------------------------------------

/// `&&` and `||` in one condition.
pub const CONDITION_MIXED: &str = "datadog_condition_mixed";

/// Every advisory code.
pub const ADVISORY_CODES: [&str; 1] = [CONDITION_MIXED];

/// A rule's `configurations.datadog` block, when it is a table.
fn rule_block(rule: &Node) -> Option<&Node> {
    let block = rule.get("configurations")?.get("datadog")?;
    matches!(block.value, Value::Map(_)).then_some(block.as_ref())
}

/// Every advisory a rule's `datadog` block, as authored, earns, each one of
/// [`ADVISORY_CODES`].
pub fn advisories(rule: &Node) -> Vec<super::Advisory> {
    let Some(block) = rule_block(rule) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (index, case) in items(field(block, "cases")).iter().enumerate() {
        let Some(source) = table_field(Some(case), "condition").and_then(|node| text(Some(node)))
        else {
            continue;
        };
        if condition::parse(source).is_ok_and(|parsed| parsed.mixed()) {
            found.push(super::Advisory {
                code: CONDITION_MIXED,
                field_path: vec![
                    "configurations".to_owned(),
                    "datadog".to_owned(),
                    "cases".to_owned(),
                    index.to_string(),
                    "condition".to_owned(),
                ],
                message: "the condition mixes && and ||, whose precedence Datadog does not \
                          document: split it into two cases, or keep to one operator"
                    .to_owned(),
            });
        }
    }
    found
}

#[cfg(test)]
mod tests;
