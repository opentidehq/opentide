//! Exabeam New-Scale SIEM correlation rule, `platform::exabeam::1.0`
//! (`ExabeamConfig` and its nested models, RFC 0018), with the block's
//! constraints ([`block_findings`]): every code of exabeam-1.0's
//! Constraints but the workspace check `exabeam_name_duplicate`
//! (`opentide-workspace`), each reported by its own code
//! ([`ErrorKind::Constraint`]) at the path the specification fixes for it,
//! relative to the block.
//!
//! The sequence queries themselves are the analysis engine's (the Exabeam
//! Query Language, profile `rule`). The one query check made here is
//! `exabeam_context_table_trigger`, a rule about the condition a
//! context-table lookup may take ([`uses_context_table`]).
//!
//! A port of 0.28.0's `platforms/exabeam/constraints.py`; the language
//! server's `opentide-tide` checks the block through this module, never a
//! second copy.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use garde::Validate;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::configuration::repr;
use crate::error::{ErrorKind, PathSegment};
use crate::from_node::Context;
use crate::node::{Node, Value};
use crate::objects::checks::check_at_least_one;
use crate::objects::platform::{literal_enum, platform_block, python_strip};
use crate::pins::Pins;

/// The schema identifier.
pub const SCHEMA: &str = "platform::exabeam::1.0";

/// The most characters an Exabeam rule name has.
pub const NAME_LIMIT: usize = 128;
/// The most fields a `group_by` lists.
pub const GROUP_BY_LIMIT: usize = 3;
/// `delay` in minutes, the least and the most (exabeam-1.0, Durations).
pub const DELAY_MINUTES: (u64, u64) = (7, 180);

/// `threshold.function`'s values.
pub const FUNCTIONS: [&str; 7] = [
    "count",
    "unique_count",
    "value",
    "max",
    "min",
    "sum",
    "average",
];
/// The operators of every function but `value`.
pub const NUMERIC_OPERATORS: [&str; 2] = ["more_than", "less_than"];
/// The operators of `value`.
pub const VALUE_OPERATORS: [&str; 2] = ["in", "not_in"];
/// The functions that compare with a non-negative integer.
pub const INTEGRAL_FUNCTIONS: [&str; 2] = ["count", "unique_count"];
/// `severity`'s values.
pub const SEVERITIES: [&str; 5] = ["none", "low", "medium", "high", "critical"];
/// `outcome`'s values.
pub const OUTCOMES: [&str; 3] = ["alert", "case", "none"];
/// The weekday names, Monday first.
pub const WEEKDAYS: [&str; 7] = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
];
/// The day keys each `every` takes (exabeam-1.0, `schedule[]`).
pub const RECURRENCE_DAY_KEYS: [(&str, &[&str]); 4] = [
    ("day", &[]),
    ("week", &["days"]),
    ("month", &["days", "last_day"]),
    ("days", &["first", "last"]),
];
/// Every day key of a recurrence.
const ALL_DAY_KEYS: [&str; 4] = ["days", "last_day", "first", "last"];

/// A duration's unit letter and how Exabeam spells it (`UNITS`).
pub const UNITS: [(char, &str); 4] = [
    ('m', "minutes"),
    ('h', "hours"),
    ('d', "days"),
    ('w', "weeks"),
];

/// What each constraint code says (`CODE_MESSAGES`, exabeam-1.0, Constraints).
pub const CODE_MESSAGES: [(&str, &str); 13] = [
    (
        "exabeam_sequences",
        "sequences is a non-empty list, and every sequence has a non-blank query",
    ),
    (
        "exabeam_correlation",
        "correlation is set with two or more sequences and left out with one",
    ),
    (
        "exabeam_threshold_function",
        "threshold.function is count, unique_count, value, max, min, sum or average, and field \
         is set unless the function is count",
    ),
    (
        "exabeam_threshold_operator",
        "threshold.operator is not one the function takes",
    ),
    (
        "exabeam_threshold_value",
        "threshold.value does not have the shape its operator takes",
    ),
    (
        "exabeam_group_by",
        "group_by is a list of one to three distinct non-blank field names",
    ),
    ("exabeam_duration", "not a duration this field takes"),
    (
        "exabeam_severity",
        "severity is none, low, medium, high or critical",
    ),
    ("exabeam_outcome", "outcome is alert, case or none"),
    (
        "exabeam_email",
        "email.recipients is a non-empty list of distinct addresses, and subject is non-blank \
         when set",
    ),
    ("exabeam_schedule", "not a valid recurrence"),
    (
        "exabeam_name_length",
        "the Exabeam rule name is at most 128 characters",
    ),
    (
        "exabeam_context_table_trigger",
        "a sequence whose query looks up a context table (IN \"…\") triggers on any match: \
         remove its threshold",
    ),
];

/// Every code [`block_findings`] reports (`CONSTRAINT_CODES`).
pub fn constraint_codes() -> impl Iterator<Item = &'static str> {
    CODE_MESSAGES.iter().map(|(code, _)| *code)
}

/// What constraint `code` says, or the code itself for one it does not know.
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
    /// `threshold.function`.
    ExabeamFunction {
        Count = "count",
        UniqueCount = "unique_count",
        Value = "value",
        Max = "max",
        Min = "min",
        Sum = "sum",
        Average = "average",
    }
}

literal_enum! {
    /// `threshold.operator`.
    ExabeamOperator {
        MoreThan = "more_than",
        LessThan = "less_than",
        In = "in",
        NotIn = "not_in",
    }
}

literal_enum! {
    /// `severity`.
    ExabeamSeverity {
        NoSeverity = "none",
        Low = "low",
        Medium = "medium",
        High = "high",
        Critical = "critical",
    }
}

literal_enum! {
    /// `outcome`.
    ExabeamOutcome {
        Alert = "alert",
        Case = "case",
        NoOutcome = "none",
    }
}

literal_enum! {
    /// `schedule[].every`.
    ExabeamEvery {
        Day = "day",
        Week = "week",
        Month = "month",
        Days = "days",
    }
}

impl ExabeamFunction {
    /// The value as written.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::UniqueCount => "unique_count",
            Self::Value => "value",
            Self::Max => "max",
            Self::Min => "min",
            Self::Sum => "sum",
            Self::Average => "average",
        }
    }
}

impl ExabeamOperator {
    /// The value as written.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MoreThan => "more_than",
            Self::LessThan => "less_than",
            Self::In => "in",
            Self::NotIn => "not_in",
        }
    }
}

impl ExabeamSeverity {
    /// The value as written.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoSeverity => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl ExabeamOutcome {
    /// The value as written.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Case => "case",
            Self::NoOutcome => "none",
        }
    }
}

impl ExabeamEvery {
    /// The value as written.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
            Self::Days => "days",
        }
    }
}

/// An item of a threshold's list value: `str | int | float`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, FromNode)]
#[schemars(description = "")]
#[serde(untagged)]
#[from_node(union)]
pub enum ExabeamValueItem {
    /// A string.
    #[from_node(tag = "str")]
    #[schemars(description = "")]
    Text(String),
    /// An integer.
    #[from_node(tag = "int")]
    #[schemars(description = "")]
    Int(i64),
    /// A number.
    #[from_node(tag = "float")]
    #[schemars(
        description = "",
        schema_with = "crate::objects::platform::number_schema"
    )]
    Float(f64),
}

/// `threshold.value`: `int | float | list[str | int | float]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, FromNode)]
#[schemars(description = "")]
#[serde(untagged)]
#[from_node(union)]
pub enum ExabeamValue {
    /// An integer.
    #[from_node(tag = "int")]
    #[schemars(description = "")]
    Int(i64),
    /// A number.
    #[from_node(tag = "float")]
    #[schemars(
        description = "",
        schema_with = "crate::objects::platform::number_schema"
    )]
    Float(f64),
    /// A list of strings or numbers.
    #[from_node(tag = "list[union[str,int,float]]")]
    #[schemars(description = "")]
    List(Vec<ExabeamValueItem>),
}

/// `schedule[].days`: `list[str] | list[int]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, FromNode)]
#[schemars(description = "")]
#[serde(untagged)]
#[from_node(union)]
pub enum ExabeamDays {
    /// Weekday names.
    #[from_node(tag = "list[str]")]
    #[schemars(description = "")]
    Names(Vec<String>),
    /// Day numbers.
    #[from_node(tag = "list[int]")]
    #[schemars(description = "")]
    Numbers(Vec<i64>),
}

/// Declares a nested Exabeam model (closed, Tide's shape).
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

model! {
    /// A sequence's condition (`ExabeamThreshold`).
    ExabeamThreshold = "ExabeamThreshold" {
        /// `count`, `unique_count`, `value`, `max`, `min`, `sum`, or `average`
        pub function: ExabeamFunction,
        /// The field the function reads. Required except for `count`. `count` without a field counts
        /// events.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub field: Option<String>,
        /// `more_than`, `less_than`, `in`, or `not_in`
        pub operator: ExabeamOperator,
        /// `more_than` and `less_than`: a number (`count` and `unique_count`: a non-negative
        /// integer). `in` and `not_in`: a non-empty list of strings or numbers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<ExabeamValue>,
        /// The window: whole `m`, `h`, or `d`
        pub within: String,
    }
}

model! {
    /// One sequence: a filter and a condition (`ExabeamSequence`).
    ExabeamSequence = "ExabeamSequence" {
        /// A filter in the Exabeam Query Language, profile `rule`. Multiline in YAML.
        #[schemars(extend(
            "tide.template.multiline" = true,
            "tide.template.required" = true
        ))]
        pub query: String,
        /// Sequence name, shown in the console
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// The condition. Without it, the sequence triggers on any matching event.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub threshold: Option<ExabeamThreshold>,
        /// One to three fields. A threshold is evaluated per value. With any match, the rule still
        /// triggers on every matching event; to trigger once per value, also set `suppression.group_by`
        /// to these fields (Exabeam's granular suppression).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group_by: Option<Vec<String>>,
    }
}

model! {
    /// The window two or more sequences correlate in (`ExabeamCorrelation`).
    ExabeamCorrelation = "ExabeamCorrelation" {
        /// The window every sequence's condition must be met in: whole `m`, `h`, or `d`
        pub within: String,
        /// Up to three fields every sequence shares (the API's limit; the console allows more)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group_by: Option<Vec<String>>,
    }
}

model! {
    /// Repeated triggers suppressed (`ExabeamSuppression`). The YAML key is
    /// `for`, a Python keyword: `for_` is an unknown key.
    ExabeamSuppression = "ExabeamSuppression" {
        /// Suppress repeated triggers for this long: whole `m`, `h`, `d`, or `w`
        #[serde(rename = "for")]
        pub for_: String,
        /// One to three fields. Suppress per value instead of for the whole rule.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group_by: Option<Vec<String>>,
    }
}

model! {
    /// An email when the rule triggers (`ExabeamEmail`).
    ExabeamEmail = "ExabeamEmail" {
        /// One or more email addresses
        #[from_node(with = "at_least_one")]
        #[garde(length(min = 1))]
        pub recipients: Vec<String>,
        /// Email subject
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        /// Attach the matching events as CSV
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attach_csv: Option<bool>,
    }
}

model! {
    /// When the rule is active (`ExabeamRecurrence`). The YAML key is `from`,
    /// a Python keyword: `from_` is an unknown key.
    ExabeamRecurrence = "ExabeamRecurrence" {
        /// `day`, `week`, `month`, or `days` (a range of weekdays)
        pub every: ExabeamEvery,
        /// Start time, UTC, `H:MMZ` or `HH:MMZ` (`8:00Z`, `08:00Z`)
        #[serde(rename = "from")]
        pub from_: String,
        /// End time, UTC, `H:MMZ` or `HH:MMZ`
        pub to: String,
        /// `week`: one or more weekday names (`monday` … `sunday`). `month`: day numbers 1–31. Not
        /// allowed otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub days: Option<ExabeamDays>,
        /// `month` only: also the last day of the month. A `month` recurrence has `days`,
        /// `last_day: true`, or both.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_day: Option<bool>,
        /// `days` only: the first weekday of the range
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub first: Option<String>,
        /// `days` only: the last weekday of the range
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last: Option<String>,
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

fn garde_block(block: &ExabeamConfig, _pins: &Pins) -> garde::Result {
    let value = serde_json::to_value(block)
        .map_err(|error| garde::Error::new(format!("ExabeamConfig does not serialise: {error}")))?;
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
    /// Exabeam New-Scale SIEM correlation rule (`ExabeamConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[garde(custom(garde_block))]
    #[schemars(rename = "ExabeamConfig", description = "")]
    #[from_node(model = "ExabeamConfig", before = "raw_block")]
    #[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all, eq, name = "ExabeamConfig", module = "opentide._native.models"))]
    #[cfg_attr(feature = "python", expect(clippy::unsafe_derive_deserialize, reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"))]
    pub struct ExabeamConfig ["platform::exabeam::1.0"] {
        /// One or more sequences, in the order the events happen. Each is a filter and a condition:
        /// any match, or a threshold.
        #[schemars(extend("tide.template.required" = true))]
        #[from_node(with = "at_least_one")]
        #[garde(length(min = 1))]
        pub sequences: Vec<ExabeamSequence>,
        /// Required with two or more sequences; not allowed with one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub correlation: Option<ExabeamCorrelation>,
        /// `none`, `low`, `medium`, `high`, or `critical`. Derived from `response.alert_severity`
        /// when omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::objects::platform::optional_literal::<ExabeamSeverity>")]
        pub severity: Option<ExabeamSeverity>,
        /// `alert` (an alert in Threat Center), `case`, or `none`. Default: `alert`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::objects::platform::optional_literal::<ExabeamOutcome>")]
        pub outcome: Option<ExabeamOutcome>,
        /// Also send an email when the rule triggers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub email: Option<ExabeamEmail>,
        /// Suppress repeated triggers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suppression: Option<ExabeamSuppression>,
        /// Evaluation delay, `7m` to `180m` (`3h`). Omitted: Exabeam's default of 7 minutes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delay: Option<String>,
        /// When the rule is active. Omitted: always.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schedule: Option<Vec<ExabeamRecurrence>>,
        /// Run the rule in test mode: it triggers and writes a `rule-trigger-test` event, with no
        /// outcome. Default: the tenant `test_mode`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub test_mode: Option<bool>,
    }
}

// ---------------------------------------------------------------------------
// The constraints (`block_findings`).
// ---------------------------------------------------------------------------

/// A code, its path relative to `configurations.exabeam`, and its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The constraint code (`exabeam_duration`).
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

/// A mapping's value at `name`, a null left out (`as_authored`: a key whose
/// value is null is the key not written).
fn field<'n>(node: &'n Node, name: &str) -> Option<&'n Node> {
    node.get(name)
        .map(AsRef::as_ref)
        .filter(|value| !matches!(value.value, Value::Null))
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

/// A string with something besides whitespace.
fn non_blank(node: Option<&Node>) -> bool {
    text(node).is_some_and(|text| !python_strip(text).is_empty())
}

/// `_number`: an integer or a float, not a boolean.
fn number(node: &Node) -> bool {
    matches!(node.value, Value::Int(_) | Value::Float(_))
}

/// Python's `repr` of a value, `None` when absent.
fn py_repr(node: Option<&Node>) -> String {
    node.map_or_else(|| "None".to_owned(), repr::node)
}

/// Whether `value` is one of `allowed` (Python's `value in allowed`).
fn one_of(node: Option<&Node>, allowed: &[&str]) -> bool {
    text(node).is_some_and(|value| allowed.contains(&value))
}

#[expect(
    clippy::expect_used,
    reason = "regex literals, exercised by every duration and schedule case"
)]
fn patterns() -> &'static (Regex, Regex, Regex) {
    static PATTERNS: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        (
            Regex::new(r"^([1-9][0-9]*)([mhdw])$").expect("a valid pattern"),
            Regex::new(r"^(?:[01]?[0-9]|2[0-3]):[0-5][0-9]Z$").expect("a valid pattern"),
            Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").expect("a valid pattern"),
        )
    })
}

/// `(number, unit letter)` of a duration whose unit is in `units`
/// (`duration`): a positive whole number and one unit, no space (`30m`,
/// `4h`, `1d`, `2w`). A number too large for 64 bits is `u64::MAX`.
pub fn duration(value: &str, units: &str) -> Option<(u64, char)> {
    let captures = patterns().0.captures(value)?;
    let unit = captures.get(2)?.as_str().chars().next()?;
    if !units.contains(unit) {
        return None;
    }
    let digits = captures.get(1)?.as_str();
    Some((digits.parse().unwrap_or(u64::MAX), unit))
}

/// A node's duration ([`duration`]), when it is a string.
fn node_duration(node: Option<&Node>, units: &str) -> Option<(u64, char)> {
    text(node).and_then(|value| duration(value, units))
}

/// How Exabeam spells a duration's unit (`UNITS`).
pub fn unit_name(unit: char) -> &'static str {
    UNITS
        .iter()
        .find(|(letter, _)| *letter == unit)
        .map_or("minutes", |(_, name)| *name)
}

/// `delay` in minutes, or `None` when it is not a duration in `m` or `h`
/// (`delay_minutes`).
pub fn delay_minutes(value: &str) -> Option<u64> {
    let (number, unit) = duration(value, "mh")?;
    Some(if unit == 'h' {
        number.saturating_mul(60)
    } else {
        number
    })
}

/// Whether the text the scan kept so far ends in the keyword `IN`, alone:
/// `(?i)(?<![A-Za-z0-9_.-])IN\s*$`.
fn ends_in_keyword(code: &[char]) -> bool {
    let mut end = code.len();
    while end > 0 && code[end - 1].is_whitespace() {
        end -= 1;
    }
    if end < 2
        || !code[end - 2].eq_ignore_ascii_case(&'i')
        || !code[end - 1].eq_ignore_ascii_case(&'n')
    {
        return false;
    }
    end == 2 || {
        let before = code[end - 3];
        !(before.is_ascii_alphanumeric() || matches!(before, '_' | '.' | '-'))
    }
}

/// Whether `query` looks a value up in a context table: `field IN "Table"`
/// (`uses_context_table`). Text inside a double- or single-quoted string is
/// not read, so a phrase that holds `IN "` is not a lookup.
pub fn uses_context_table(query: &str) -> bool {
    let chars: Vec<char> = query.chars().collect();
    let mut code: Vec<char> = Vec::with_capacity(chars.len());
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        if character == '"' || character == '\'' {
            if ends_in_keyword(&code) {
                return true;
            }
            let mut end = index + 1;
            while end < chars.len() && chars[end] != character {
                end += if chars[end] == '\\' { 2 } else { 1 };
            }
            code.push(' ');
            index = end + 1;
            continue;
        }
        code.push(character);
        index += 1;
    }
    false
}

/// `_group_by_ok`: a list of up to three distinct non-blank strings, empty
/// only when `allow_empty`.
fn group_by_ok(node: &Node, allow_empty: bool) -> bool {
    let Value::Seq(items) = &node.value else {
        return false;
    };
    if items.len() > GROUP_BY_LIMIT || (items.is_empty() && !allow_empty) {
        return false;
    }
    if !items.iter().all(|item| non_blank(Some(item))) {
        return false;
    }
    let distinct: BTreeSet<&str> = items
        .iter()
        .filter_map(|item| item.value.as_str())
        .collect();
    distinct.len() == items.len()
}

fn threshold_findings(threshold: &Node, at: &[PathSegment]) -> Vec<Finding> {
    let found = |code: &'static str, message: String| Finding::new(code, at.to_vec(), message);
    if !matches!(threshold.value, Value::Map(_)) {
        return vec![found(
            "exabeam_threshold_function",
            "threshold is a table".to_owned(),
        )];
    }
    let function_node = field(threshold, "function");
    let Some(function) = text(function_node).filter(|name| FUNCTIONS.contains(name)) else {
        return vec![found(
            "exabeam_threshold_function",
            format!(
                "{} is not an Exabeam function: {}",
                py_repr(function_node),
                FUNCTIONS.join(", ")
            ),
        )];
    };
    let mut findings = Vec::new();
    match field(threshold, "field") {
        Some(name) if !non_blank(Some(name)) => findings.push(found(
            "exabeam_threshold_function",
            "field is a non-blank string".to_owned(),
        )),
        None if function != "count" => findings.push(found(
            "exabeam_threshold_function",
            format!("{function} reads a field: set field"),
        )),
        _ => {}
    }
    let operator_node = field(threshold, "operator");
    let allowed: &[&str] = if function == "value" {
        &VALUE_OPERATORS
    } else {
        &NUMERIC_OPERATORS
    };
    match text(operator_node).filter(|operator| allowed.contains(operator)) {
        None => findings.push(found(
            "exabeam_threshold_operator",
            format!(
                "{function} takes the operator {}, not {}",
                allowed.join(" or "),
                py_repr(operator_node)
            ),
        )),
        Some(operator) => {
            let value = field(threshold, "value");
            let (ok, shape) = if NUMERIC_OPERATORS.contains(&operator) {
                let integral = INTEGRAL_FUNCTIONS.contains(&function);
                let ok = value.is_some_and(|value| match value.value {
                    Value::Int(integer) => !integral || integer >= 0,
                    Value::Float(_) => !integral,
                    _ => false,
                });
                let shape = if integral {
                    "a non-negative integer"
                } else {
                    "a number"
                };
                (ok, shape)
            } else {
                let ok = matches!(value.map(|value| &value.value), Some(Value::Seq(items))
                if !items.is_empty() && items.iter().all(|item| {
                    number(item)
                        || text(Some(item)).is_some_and(|text| {
                            !python_strip(text).is_empty() && !text.contains(',')
                        })
                }));
                (
                    ok,
                    "a non-empty list of strings (without commas) or numbers",
                )
            };
            if !ok {
                findings.push(found(
                    "exabeam_threshold_value",
                    format!("{function} {operator} compares with {shape}"),
                ));
            }
        }
    }
    if node_duration(field(threshold, "within"), "mhd").is_none() {
        findings.push(Finding::new(
            "exabeam_duration",
            path(at, "within"),
            "within is a whole number of minutes, hours or days: 30m, 4h, 1d",
        ));
    }
    findings
}

fn sequence_findings(sequences: Option<&Node>) -> Vec<Finding> {
    let items = match sequences.map(|node| &node.value) {
        Some(Value::Seq(items)) if !items.is_empty() => items,
        _ => {
            return vec![Finding::new(
                "exabeam_sequences",
                vec![key("sequences")],
                "sequences is a non-empty list of sequences",
            )];
        }
    };
    let mut findings = Vec::new();
    for (index, sequence) in items.iter().enumerate() {
        let at = vec![key("sequences"), PathSegment::Index(index)];
        if !matches!(sequence.value, Value::Map(_)) {
            findings.push(Finding::new(
                "exabeam_sequences",
                at,
                "a sequence is a table with a query",
            ));
            continue;
        }
        let query = field(sequence, "query");
        if !non_blank(query) {
            findings.push(Finding::new(
                "exabeam_sequences",
                path(&at, "query"),
                "query is a non-blank string",
            ));
        }
        if let Some(group_by) = field(sequence, "group_by")
            && !group_by_ok(group_by, false)
        {
            findings.push(Finding::new(
                "exabeam_group_by",
                path(&at, "group_by"),
                code_message("exabeam_group_by"),
            ));
        }
        if let Some(threshold) = field(sequence, "threshold") {
            let threshold_path = path(&at, "threshold");
            findings.extend(threshold_findings(threshold, &threshold_path));
            if text(query).is_some_and(uses_context_table) {
                findings.push(Finding::new(
                    "exabeam_context_table_trigger",
                    threshold_path,
                    code_message("exabeam_context_table_trigger"),
                ));
            }
        }
    }
    findings
}

fn correlation_findings(correlation: Option<&Node>, count: usize) -> Vec<Finding> {
    let at = vec![key("correlation")];
    let Some(correlation) = correlation else {
        if count >= 2 {
            return vec![Finding::new(
                "exabeam_correlation",
                at,
                format!("{count} sequences correlate within a window: set correlation.within"),
            )];
        }
        return Vec::new();
    };
    if count == 1 {
        return vec![Finding::new(
            "exabeam_correlation",
            at,
            "one sequence has nothing to correlate with: remove correlation",
        )];
    }
    if !matches!(correlation.value, Value::Map(_)) {
        return vec![Finding::new(
            "exabeam_correlation",
            at,
            "correlation is a table with within",
        )];
    }
    let mut findings = Vec::new();
    if node_duration(field(correlation, "within"), "mhd").is_none() {
        findings.push(Finding::new(
            "exabeam_duration",
            path(&at, "within"),
            "within is a whole number of minutes, hours or days: 15m, 1h, 1d",
        ));
    }
    if let Some(group_by) = field(correlation, "group_by")
        && !group_by_ok(group_by, true)
    {
        findings.push(Finding::new(
            "exabeam_group_by",
            path(&at, "group_by"),
            "correlation.group_by is a list of up to three distinct non-blank field names",
        ));
    }
    findings
}

/// `_email_ok`.
fn email_ok(email: &Node) -> bool {
    if !matches!(email.value, Value::Map(_)) {
        return false;
    }
    let Some(Value::Seq(recipients)) = field(email, "recipients").map(|node| &node.value) else {
        return false;
    };
    if recipients.is_empty()
        || !recipients
            .iter()
            .all(|item| text(Some(item)).is_some_and(|address| patterns().2.is_match(address)))
    {
        return false;
    }
    let distinct: BTreeSet<&str> = recipients
        .iter()
        .filter_map(|item| item.value.as_str())
        .collect();
    if distinct.len() != recipients.len() {
        return false;
    }
    if let Some(subject) = field(email, "subject")
        && !non_blank(Some(subject))
    {
        return false;
    }
    field(email, "attach_csv").is_none_or(|flag| matches!(flag.value, Value::Bool(_)))
}

fn suppression_findings(suppression: &Node) -> Vec<Finding> {
    let at = vec![key("suppression")];
    if !matches!(suppression.value, Value::Map(_)) {
        return vec![Finding::new(
            "exabeam_duration",
            path(&at, "for"),
            "suppression is a table with for",
        )];
    }
    let mut findings = Vec::new();
    if node_duration(field(suppression, "for"), "mhdw").is_none() {
        findings.push(Finding::new(
            "exabeam_duration",
            path(&at, "for"),
            "for is a whole number of minutes, hours, days or weeks: 30m, 1h, 1d, 2w",
        ));
    }
    if let Some(group_by) = field(suppression, "group_by")
        && !group_by_ok(group_by, false)
    {
        findings.push(Finding::new(
            "exabeam_group_by",
            path(&at, "group_by"),
            code_message("exabeam_group_by"),
        ));
    }
    findings
}

/// `_distinct`: no two items with the same `repr`.
fn distinct(items: &[std::sync::Arc<Node>]) -> bool {
    let seen: BTreeSet<String> = items.iter().map(|item| repr::node(item)).collect();
    seen.len() == items.len()
}

/// Why `recurrence` is not a valid `schedule[]` entry (`_recurrence_problem`).
fn recurrence_problem(recurrence: &Node) -> Option<String> {
    let every = if matches!(recurrence.value, Value::Map(_)) {
        text(field(recurrence, "every"))
    } else {
        None
    };
    let Some((every, day_keys)) = every.and_then(|every| {
        RECURRENCE_DAY_KEYS
            .iter()
            .find(|(name, _)| *name == every)
            .copied()
    }) else {
        return Some("every is day, week, month or days".to_owned());
    };
    for name in ["from", "to"] {
        if !text(field(recurrence, name)).is_some_and(|time| patterns().1.is_match(time)) {
            return Some(format!(
                "{name} is a UTC time written H:MMZ or HH:MMZ, such as 08:00Z"
            ));
        }
    }
    // A day key the recurrence does not take; a key that is no day key at
    // all is the model's unknown key, at its own path.
    let extra: BTreeSet<&str> = keys(recurrence)
        .into_iter()
        .filter(|name| ALL_DAY_KEYS.contains(name) && !day_keys.contains(name))
        .collect();
    if !extra.is_empty() {
        return Some(format!(
            "a {every} recurrence does not take {}",
            extra.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    match every {
        "week" => {
            let ok = matches!(field(recurrence, "days").map(|node| &node.value), Some(Value::Seq(days))
                if !days.is_empty()
                    && distinct(days)
                    && days.iter().all(|day| one_of(Some(day), &WEEKDAYS)));
            if !ok {
                return Some(
                    "a week recurrence has days: distinct weekday names, monday to sunday"
                        .to_owned(),
                );
            }
        }
        "month" => {
            let last_day = match field(recurrence, "last_day").map(|node| &node.value) {
                None => false,
                Some(Value::Bool(flag)) => *flag,
                Some(_) => return Some("last_day is true or false".to_owned()),
            };
            let days = field(recurrence, "days");
            if days.is_none() && !last_day {
                return Some("a month recurrence has days, last_day: true, or both".to_owned());
            }
            if let Some(days) = days {
                let ok = matches!(&days.value, Value::Seq(days)
                    if !days.is_empty()
                        && distinct(days)
                        && days.iter().all(|day| matches!(day.value, Value::Int(1..=31))));
                if !ok {
                    return Some(
                        "a month recurrence's days are distinct day numbers, 1 to 31".to_owned(),
                    );
                }
            }
        }
        "days"
            if !one_of(field(recurrence, "first"), &WEEKDAYS)
                || !one_of(field(recurrence, "last"), &WEEKDAYS) =>
        {
            return Some(
                "a days recurrence has first and last: weekday names, monday to sunday".to_owned(),
            );
        }
        _ => {}
    }
    None
}

fn schedule_findings(schedule: &Node) -> Vec<Finding> {
    let items = match &schedule.value {
        Value::Seq(items) if !items.is_empty() => items,
        _ => {
            return vec![Finding::new(
                "exabeam_schedule",
                vec![key("schedule")],
                "schedule is a non-empty list",
            )];
        }
    };
    items
        .iter()
        .enumerate()
        .filter_map(|(index, recurrence)| {
            recurrence_problem(recurrence).map(|problem| {
                Finding::new(
                    "exabeam_schedule",
                    vec![key("schedule"), PathSegment::Index(index)],
                    problem,
                )
            })
        })
        .collect()
}

/// `exabeam_name_length` for an Exabeam rule name longer than 128
/// characters (`name_length_finding`).
pub fn name_length_finding(name: &str) -> Finding {
    Finding::new(
        "exabeam_name_length",
        vec![key("name")],
        format!(
            "the Exabeam rule name is {} characters, more than {NAME_LIMIT}: set a shorter \
             configurations.exabeam.name",
            name.chars().count()
        ),
    )
}

/// Every exabeam-1.0 constraint finding of a block, as authored, at its
/// path (`block_findings`). A null is the key left out, at the root and
/// inside every table. A block that is not a mapping has none: its type is
/// the model's error.
pub fn block_findings(block: &Node) -> Vec<Finding> {
    if !matches!(block.value, Value::Map(_)) {
        return Vec::new();
    }
    let sequences = field(block, "sequences");
    let mut findings = sequence_findings(sequences);
    let count = match sequences.map(|node| &node.value) {
        Some(Value::Seq(items)) => items.len(),
        _ => 0,
    };
    findings.extend(correlation_findings(field(block, "correlation"), count));
    let severity = field(block, "severity");
    if severity.is_some() && !one_of(severity, &SEVERITIES) {
        findings.push(Finding::new(
            "exabeam_severity",
            vec![key("severity")],
            format!(
                "{} is not an Exabeam severity: {} (lower case)",
                py_repr(severity),
                SEVERITIES.join(", ")
            ),
        ));
    }
    let outcome = field(block, "outcome");
    if outcome.is_some() && !one_of(outcome, &OUTCOMES) {
        findings.push(Finding::new(
            "exabeam_outcome",
            vec![key("outcome")],
            format!("{} is not alert, case or none", py_repr(outcome)),
        ));
    }
    if let Some(email) = field(block, "email")
        && !email_ok(email)
    {
        findings.push(Finding::new(
            "exabeam_email",
            vec![key("email")],
            code_message("exabeam_email"),
        ));
    }
    if let Some(suppression) = field(block, "suppression") {
        findings.extend(suppression_findings(suppression));
    }
    if let Some(delay) = field(block, "delay") {
        let (low, high) = DELAY_MINUTES;
        let minutes = text(Some(delay)).and_then(delay_minutes);
        if !minutes.is_some_and(|minutes| (low..=high).contains(&minutes)) {
            findings.push(Finding::new(
                "exabeam_duration",
                vec![key("delay")],
                format!(
                    "delay is {low} to {high} minutes, written in m or h: 7m to 180m, 1h to 3h"
                ),
            ));
        }
    }
    if let Some(schedule) = field(block, "schedule") {
        findings.extend(schedule_findings(schedule));
    }
    if let Some(name) = text(field(block, "name"))
        && name.chars().count() > NAME_LIMIT
    {
        findings.push(name_length_finding(name));
    }
    findings
}

/// Every exabeam-1.0 constraint code a block breaks, sorted (`block_codes`).
pub fn block_codes(block: &Node) -> BTreeSet<&'static str> {
    block_findings(block)
        .into_iter()
        .map(|finding| finding.code)
        .collect()
}

// ---------------------------------------------------------------------------
// Across the workspace: rule names (`validation/exabeam_names.py`).
// ---------------------------------------------------------------------------

/// The workspace check's code.
pub const NAME_DUPLICATE: &str = "exabeam_name_duplicate";

/// A rule's `configurations.exabeam` block, when it is a table.
fn rule_block(rule: &Node) -> Option<&Node> {
    let block = rule.get("configurations")?.get("exabeam")?;
    matches!(block.value, Value::Map(_)).then_some(block.as_ref())
}

/// The Exabeam rule name a rule resolves to: the block's `name`, else the
/// rule's; `None` without a block, or, when `enabled_only`, for a block
/// that is not `enabled: true` (`_exabeam_name`).
pub fn rule_exabeam_name(rule: &Node, enabled_only: bool) -> Option<String> {
    let block = rule_block(rule)?;
    if enabled_only
        && !matches!(
            field(block, "enabled").map(|node| &node.value),
            Some(Value::Bool(true))
        )
    {
        return None;
    }
    if let Some(name) = text(field(block, "name")).filter(|name| !name.is_empty()) {
        return Some(name.to_owned());
    }
    text(field(rule, "name"))
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

/// A workspace finding on one rule, at `configurations.exabeam.name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameFinding {
    /// The rule's UUID.
    pub uuid: String,
    /// `exabeam_name_duplicate` or `exabeam_name_length`.
    pub code: &'static str,
    /// What is wrong.
    pub message: String,
    /// What to do.
    pub suggestion: &'static str,
    /// The name, for a duplicate (`context.value`).
    pub value: Option<String>,
}

/// `exabeam_name_duplicate` and `exabeam_name_length` for each rule of
/// `in_scope`, among `rules` (UUID and document): two enabled blocks that
/// resolve to one name, compared case-insensitively; a block with no `name`
/// whose rule name is longer than 128 characters (`exabeam_name_issues`).
pub fn name_findings<'r>(
    rules: &[(&'r str, &'r Node)],
    in_scope: impl IntoIterator<Item = &'r str>,
) -> Vec<NameFinding> {
    let mut by_name: std::collections::BTreeMap<String, Vec<&str>> =
        std::collections::BTreeMap::new();
    for (uuid, rule) in rules {
        if let Some(name) = rule_exabeam_name(rule, true) {
            by_name.entry(casefold(&name)).or_default().push(uuid);
        }
    }
    let mut findings = Vec::new();
    for uuid in in_scope {
        let Some((_, rule)) = rules.iter().find(|(known, _)| *known == uuid) else {
            continue;
        };
        if let Some(block) = rule_block(rule)
            && !field(block, "name").is_some_and(|name| super::truthy(Some(name)))
            && let Some(resolved) = rule_exabeam_name(rule, false)
            && resolved.chars().count() > NAME_LIMIT
        {
            findings.push(NameFinding {
                uuid: uuid.to_owned(),
                code: "exabeam_name_length",
                message: format!(
                    "the Exabeam rule name (the rule name) is {} characters, more than {NAME_LIMIT}",
                    resolved.chars().count()
                ),
                suggestion: "Set a shorter configurations.exabeam.name",
                value: None,
            });
        }
        let Some(name) = rule_exabeam_name(rule, true) else {
            continue;
        };
        let mut others: Vec<&str> = by_name
            .get(&casefold(&name))
            .map(|uuids| {
                uuids
                    .iter()
                    .copied()
                    .filter(|other| *other != uuid)
                    .collect()
            })
            .unwrap_or_default();
        if others.is_empty() {
            continue;
        }
        others.sort_unstable();
        findings.push(NameFinding {
            uuid: uuid.to_owned(),
            code: NAME_DUPLICATE,
            message: format!(
                "Exabeam rule name {} is also the name of rule(s) {}, compared \
                 case-insensitively; Exabeam rule names are unique",
                repr::quote(&name),
                others.join(", ")
            ),
            suggestion: "Set a distinct configurations.exabeam.name on one of the rules",
            value: Some(name),
        });
    }
    findings
}

/// `str.casefold()` for the names Exabeam compares.
fn casefold(text: &str) -> String {
    text.chars()
        .flat_map(char::to_lowercase)
        .collect::<String>()
        .replace('ß', "ss")
}

// ---------------------------------------------------------------------------
// Advisories (`platforms/exabeam/advisories.py`): warnings that never
// reject a rule.
// ---------------------------------------------------------------------------

/// `outcome: none` and no email.
pub const OUTCOME_SILENT: &str = "exabeam_outcome_silent";
/// A correlation window the ordered sequences cannot fit in.
pub const CORRELATION_WINDOW: &str = "exabeam_correlation_window";

/// Exabeam waits a minute before it evaluates the next ordered sequence, and
/// an any-match sequence evaluates events for one minute.
const STEP_MINUTES: u64 = 1;

/// Every advisory code (`ADVISORY_CODES`).
pub const ADVISORY_CODES: [&str; 2] = [OUTCOME_SILENT, CORRELATION_WINDOW];

fn minutes(node: Option<&Node>) -> Option<u64> {
    let (number, unit) = node_duration(node, "mhd")?;
    let factor = match unit {
        'h' => 60,
        'd' => 1440,
        _ => 1,
    };
    Some(number.saturating_mul(factor))
}

/// The minutes ordered `sequences` need: each window (`threshold.within`,
/// one minute for an any-match sequence) and one minute between sequences;
/// `None` when a window does not parse, which is a constraint error already
/// (`ordered_minutes`).
pub fn ordered_minutes(sequences: &[std::sync::Arc<Node>]) -> Option<u64> {
    let mut needed = STEP_MINUTES * (sequences.len() as u64).saturating_sub(1);
    for sequence in sequences {
        let threshold = if matches!(sequence.value, Value::Map(_)) {
            field(sequence, "threshold")
        } else {
            None
        };
        let Some(threshold) = threshold else {
            needed += STEP_MINUTES;
            continue;
        };
        let within = if matches!(threshold.value, Value::Map(_)) {
            field(threshold, "within")
        } else {
            None
        };
        needed = needed.saturating_add(minutes(within)?);
    }
    Some(needed)
}

/// Every advisory a rule's `exabeam` block, as authored, earns
/// (`exabeam_advisories`), each one of [`ADVISORY_CODES`].
pub fn advisories(rule: &Node) -> Vec<super::Advisory> {
    let Some(block) = rule_block(rule) else {
        return Vec::new();
    };
    let at = |last: &[&str]| {
        ["configurations", "exabeam"]
            .iter()
            .chain(last)
            .map(|part| (*part).to_owned())
            .collect::<Vec<_>>()
    };
    let mut found = Vec::new();
    if text(field(block, "outcome")) == Some("none") && field(block, "email").is_none() {
        found.push(super::Advisory {
            code: OUTCOME_SILENT,
            field_path: at(&["outcome"]),
            message: "outcome: none and no email: the rule only writes a rule-trigger event, \
                      which nobody is told about"
                .to_owned(),
        });
    }
    if let Some(correlation) =
        field(block, "correlation").filter(|node| matches!(node.value, Value::Map(_)))
        && let Some(Value::Seq(sequences)) = field(block, "sequences").map(|node| &node.value)
        && sequences.len() >= 2
        && let Some(window) = minutes(field(correlation, "within"))
        && let Some(needed) = ordered_minutes(sequences)
        && window <= needed
    {
        let within = field(correlation, "within")
            .map(|node| repr::node(node).trim_matches('\'').to_owned())
            .unwrap_or_default();
        found.push(super::Advisory {
            code: CORRELATION_WINDOW,
            field_path: at(&["correlation", "within"]),
            message: format!(
                "correlation.within {within} is not more than the {needed} minutes the ordered \
                 sequences need (their windows, one minute for each any-match sequence, and one \
                 minute between sequences): make it more than {needed}m"
            ),
        });
    }
    found
}

#[cfg(test)]
#[path = "exabeam_tests.rs"]
mod tests;
