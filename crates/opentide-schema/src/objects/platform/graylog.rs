//! Graylog event definition, `platform::graylog::1.0` (`GraylogConfig` and
//! its nested models), with the named check `graylog_constraints`
//! ([`block_findings`]): every constraint code of graylog-1.0, each at the
//! `field_path` the specification fixes for it, as
//! `platforms/graylog/constraints.py` (0.26.0) reports them.
//!
//! Unlike the Elastic and Sysdig checks, which report their codes as one
//! `value_error` on the block, each finding is its own error, typed by its
//! code ([`crate::error::ErrorKind::Constraint`]), so `validate` and the editor
//! name the same finding at the same key.
//!
//! The condition grammar is [`condition`] (the language server's parser,
//! moved here: deploy compiles the condition with it), the Quartz reader and
//! the time zone names [`cron`].

pub mod condition;
pub mod cron;

use std::collections::BTreeSet;

use garde::Validate;
use indexmap::IndexMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::configuration::repr;
use crate::from_node::Context;
use crate::node::{Node, Value};
use crate::objects::checks::Violation;
use crate::objects::platform::durations::duration_seconds;
use crate::objects::platform::{Finding, platform_block, python_strip};
use crate::pins::Pins;

pub use condition::{FUNCTIONS, field_name, parse_condition};
pub use cron::{cron_ok, timezone_ok};

/// Block fields that take one string or a list of strings (graylog-1.0,
/// "List fields").
pub const LIST_FIELDS: [&str; 5] = [
    "tags",
    "streams",
    "stream_categories",
    "event_key",
    "notifications",
];

/// The priorities, in Graylog's order (0 to 4).
pub const PRIORITIES: [&str; 5] = ["Informational", "Low", "Medium", "High", "Critical"];

/// The most events one run of a filter creates.
pub const EVENT_LIMIT_MAX: i64 = 1000;

/// The constraint codes and the message each gives when the finding names
/// nothing more (`CODE_MESSAGES`).
pub const CODE_MESSAGES: [(&str, &str); 9] = [
    (
        "graylog_query_blank",
        "query must not be empty: it is the Graylog search query",
    ),
    (
        "graylog_list_shape",
        "a string or a list of distinct, non-blank strings",
    ),
    ("graylog_schedule", "schedule is invalid"),
    (
        "graylog_event_limit",
        "event_limit is an integer from 1 to 1,000, on a filter only",
    ),
    (
        "graylog_aggregation",
        "aggregation needs a condition in the condition grammar",
    ),
    (
        "graylog_event_field",
        "an event field value is a field name, a string containing ${...}, {template}, or {lookup}",
    ),
    (
        "graylog_event_key",
        "each event_key item is an event_fields name",
    ),
    (
        "graylog_priority",
        "priority is Informational, Low, Medium, High, or Critical",
    ),
    (
        "graylog_field_name",
        "each aggregation.group_by item is a field name",
    ),
];

/// The block's constraint codes (`CONSTRAINT_CODES`).
pub fn constraint_codes() -> impl Iterator<Item = &'static str> {
    CODE_MESSAGES.iter().map(|(code, _)| *code)
}

fn default_message(code: &str) -> &'static str {
    CODE_MESSAGES
        .iter()
        .find(|(known, _)| *known == code)
        .map_or("", |(_, message)| message)
}

/// `str | list[str]`: one value or several.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, FromNode)]
#[serde(untagged)]
#[from_node(union)]
pub enum StringOrList {
    /// One.
    #[from_node(tag = "str")]
    #[schemars(description = "")]
    One(String),
    /// Several.
    #[from_node(tag = "list[str]")]
    #[schemars(description = "")]
    Many(Vec<String>),
}

impl StringOrList {
    /// The values: a string is a one-item list (`as_list`).
    pub fn items(&self) -> Vec<&str> {
        match self {
            Self::One(one) => vec![one.as_str()],
            Self::Many(many) => many.iter().map(String::as_str).collect(),
        }
    }
}

/// `as_list`: a string-or-list field as a list, absent as empty.
pub fn as_list(value: Option<&StringOrList>) -> Vec<&str> {
    value.map(StringOrList::items).unwrap_or_default()
}

/// Declares a nested model of the block.
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
    /// When the definition runs and the time range it searches
    /// (`GraylogSchedule`).
    GraylogSchedule = "GraylogSchedule" {
        /// How often the definition runs (`execute_every_ms`). Exclusive with `cron`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub every: Option<String>,
        /// The time range each run searches (`search_within_ms`)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub window: Option<String>,
        /// A Quartz cron expression of 6 or 7 fields (`0 */5 * * * ?`). Exclusive with `every`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cron: Option<String>,
        /// The IANA time zone `cron` runs in
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timezone: Option<String>,
    }
}

model! {
    /// Turns the filter into an aggregation (`GraylogAggregation`).
    GraylogAggregation = "GraylogAggregation" {
        /// Message fields the events are grouped by
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group_by: Option<StringOrList>,
        /// A boolean expression over series, in the condition grammar
        pub condition: String,
    }
}

model! {
    /// A constant or template event field value (`GraylogEventTemplate`).
    GraylogEventTemplate = "GraylogEventTemplate" {
        /// A Graylog template (`${source.<field>}`) or constant text, sent as written.
        pub template: String,
    }
}

model! {
    /// A lookup table and the message field keying it (`GraylogLookupTable`).
    GraylogLookupTable = "GraylogLookupTable" {
        /// The Graylog lookup table name.
        pub table: String,
        /// The message field whose value is the lookup key.
        pub key_field: String,
    }
}

model! {
    /// A lookup-table event field value (`GraylogEventLookup`).
    GraylogEventLookup = "GraylogEventLookup" {
        /// A lookup-table value keyed by a message field.
        pub lookup: GraylogLookupTable,
    }
}

/// An `event_fields` value: a bare field name or a `${...}` template string,
/// `{template: ...}`, or `{lookup: {table, key_field}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, FromNode)]
#[serde(untagged)]
#[from_node(union)]
pub enum GraylogEventField {
    /// A field name, or a string with a `${...}` template.
    #[from_node(tag = "str")]
    #[schemars(description = "")]
    Text(String),
    /// `{template: ...}`.
    #[from_node(tag = "GraylogEventTemplate")]
    #[schemars(description = "")]
    Template(GraylogEventTemplate),
    /// `{lookup: {table, key_field}}`.
    #[from_node(tag = "GraylogEventLookup")]
    #[schemars(description = "")]
    Lookup(GraylogEventLookup),
}

/// `grace_period`: a duration, zero allowed (`_grace_period_duration`).
pub fn check_grace_period(value: &str) -> Result<(), Violation> {
    duration_seconds(value, true).map(|_| ()).map_err(|_| {
        Violation::value_error(format!("Invalid duration format: {}", repr::quote(value)))
    })
}

/// `grace_period` in the conversion: a duration, zero allowed, or null.
pub fn grace_period(node: &Node, cx: &mut Context) -> Option<Option<String>> {
    if matches!(node.value, Value::Null) {
        return Some(None);
    }
    let value = String::from_node(node, cx)?;
    match check_grace_period(&value) {
        Ok(()) => Some(Some(value)),
        Err(violation) => {
            violation.report(node, cx);
            None
        }
    }
}

/// garde: [`check_grace_period`] on a present value.
pub fn garde_grace_period(value: &Option<String>, _pins: &Pins) -> garde::Result {
    value.as_deref().map_or(Ok(()), |value| {
        check_grace_period(value).map_err(Violation::into_garde)
    })
}

fn garde_block(block: &GraylogConfig, _pins: &Pins) -> garde::Result {
    crate::objects::platform::garde_named("GraylogConfig", block)
}

fn raw_block(node: &Node, cx: &mut Context) -> bool {
    crate::objects::platform::before("GraylogConfig", node, cx)
}

fn yes() -> bool {
    true
}

platform_block! {
    /// Graylog event definition, Filter & Aggregation (`GraylogConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[garde(custom(garde_block))]
    #[schemars(rename = "GraylogConfig", description = "")]
    #[from_node(model = "GraylogConfig", before = "raw_block")]
    #[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all, eq, name = "GraylogConfig", module = "opentide._native.models"))]
    #[cfg_attr(feature = "python", expect(clippy::unsafe_derive_deserialize, reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"))]
    pub struct GraylogConfig ["platform::graylog::1.0"] {
        /// A Graylog search query, in the Graylog dialect
        #[schemars(extend(
            "tide.template.multiline" = true,
            "tide.template.spacer" = true,
            "tide.template.required" = true
        ))]
        pub query: String,
        /// `Informational`, `Low`, `Medium`, `High`, or `Critical`
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub priority: Option<String>,
        /// `false` makes fired events plain events, not alerts
        #[serde(default = "yes")]
        pub alert: bool,
        /// Extra Graylog tags (Graylog 7.2+). Deploy adds the derived tags.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tags: Option<StringOrList>,
        /// Aliases from the tenant's `stream_ids` table
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub streams: Option<StringOrList>,
        /// Graylog stream categories, as written
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stream_categories: Option<StringOrList>,
        /// When the definition runs and the time range it searches
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schedule: Option<GraylogSchedule>,
        /// Filters only: the most events one run creates, 1–1,000
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub event_limit: Option<i64>,
        /// Turns the filter into an aggregation
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aggregation: Option<GraylogAggregation>,
        /// Event field name → a value
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub event_fields: Option<IndexMap<String, GraylogEventField>>,
        /// Event fields that make up the event key
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub event_key: Option<StringOrList>,
        /// Aliases from the tenant's `notification_ids` table
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notifications: Option<StringOrList>,
        /// No second notification for the same event key within this time
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[from_node(with = "grace_period")]
        #[garde(custom(garde_grace_period))]
        pub grace_period: Option<String>,
        /// Messages attached to a notification, 0 or more
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(range(min = 0))]
        #[from_node(with = "super::sysdig::minimum_engine_version")]
        #[garde(custom(super::sysdig::garde_minimum_engine_version))]
        pub backlog: Option<i64>,
        /// Event summary template (Graylog 7.1+)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub summary: Option<String>,
        /// Remediation steps shown with the event
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remediation: Option<String>,
    }
}

// ---------------------------------------------------------------------------
// The named check `graylog_constraints`.
// ---------------------------------------------------------------------------

/// A value as Python's `str()` writes it: a string as itself.
fn py_str(node: &Node) -> String {
    match &node.value {
        Value::Str(text) => text.clone(),
        _ => repr::node(node),
    }
}

/// `raw.get(key)` on a mapping, a null as the key left out.
fn get<'n>(node: &'n Node, key: &str) -> Option<&'n Node> {
    node.get(key)
        .map(AsRef::as_ref)
        .filter(|value| !matches!(value.value, Value::Null))
}

fn non_blank(text: &str) -> bool {
    !python_strip(text).is_empty()
}

/// `list_ok`: absent, a non-blank string, or a list of distinct non-blank
/// strings.
pub fn list_ok(value: Option<&Node>) -> bool {
    match value.map(|node| &node.value) {
        None | Some(Value::Null) => true,
        Some(Value::Str(text)) => non_blank(text),
        Some(Value::Seq(items)) => {
            let mut seen: Vec<&str> = Vec::with_capacity(items.len());
            for item in items {
                match item.value.as_str() {
                    Some(text) if non_blank(text) && !seen.contains(&text) => seen.push(text),
                    _ => return false,
                }
            }
            true
        }
        Some(_) => false,
    }
}

/// The strings of a string-or-list node.
fn list_items(value: Option<&Node>) -> Vec<&str> {
    match value.map(|node| &node.value) {
        Some(Value::Str(text)) => vec![text.as_str()],
        Some(Value::Seq(items)) => items
            .iter()
            .filter_map(|item| item.value.as_str())
            .collect(),
        _ => Vec::new(),
    }
}

/// `_positive_duration`: a duration string greater than zero.
fn positive_duration(node: &Node) -> bool {
    node.value
        .as_str()
        .is_some_and(|text| duration_seconds(text, false).is_ok())
}

/// `event_field_kind`: `field`, `template` or `lookup` for a valid event
/// field value.
pub fn event_field_kind(value: &Node) -> Option<&'static str> {
    let non_blank_text = |node: Option<&Node>| {
        node.and_then(|node| node.value.as_str())
            .is_some_and(non_blank)
    };
    let only = |node: &Node, key: &str| {
        matches!(&node.value, Value::Map(entries)
            if entries.len() == 1 && entries[0].key.value.as_str() == Some(key))
    };
    match &value.value {
        Value::Str(text) if text.contains("${") => Some("template"),
        Value::Str(text) => field_name(text).then_some("field"),
        Value::Map(_) if only(value, "template") => {
            non_blank_text(value.get("template").map(AsRef::as_ref)).then_some("template")
        }
        Value::Map(_) if only(value, "lookup") => {
            let lookup = value.get("lookup")?;
            let Value::Map(entries) = &lookup.value else {
                return None;
            };
            let keys: BTreeSet<Option<&str>> = entries
                .iter()
                .map(|entry| entry.key.value.as_str())
                .collect();
            (entries.len() == 2
                && keys == BTreeSet::from([Some("table"), Some("key_field")])
                && entries
                    .iter()
                    .all(|entry| non_blank_text(Some(&entry.value))))
            .then_some("lookup")
        }
        _ => None,
    }
}

fn finding(code: &'static str, path: &[&str], message: Option<String>) -> Finding {
    Finding {
        code,
        path: path.iter().map(|part| (*part).to_owned()).collect(),
        message: message.unwrap_or_else(|| default_message(code).to_owned()),
    }
}

fn schedule_findings(schedule: &Node, found: &mut Vec<Finding>) {
    const S: &str = "schedule";
    if !matches!(schedule.value, Value::Map(_)) {
        found.push(finding(
            "graylog_schedule",
            &[S],
            Some("schedule is a map".into()),
        ));
        return;
    }
    let every = get(schedule, "every");
    let cron = get(schedule, "cron");
    if every.is_some() && cron.is_some() {
        found.push(finding(
            "graylog_schedule",
            &[S],
            Some("every and cron are exclusive".into()),
        ));
    }
    for key in ["every", "window"] {
        if let Some(value) = get(schedule, key)
            && !positive_duration(value)
        {
            found.push(finding(
                "graylog_schedule",
                &[S, key],
                Some(format!(
                    "{key} is a duration greater than zero (5m, 1h10m, PT15M)"
                )),
            ));
        }
    }
    if let Some(cron) = cron {
        if !cron.value.as_str().is_some_and(cron_ok) {
            found.push(finding(
                "graylog_schedule",
                &[S, "cron"],
                Some(
                    "cron is a Quartz expression of 6 or 7 fields, with ? in day of month or \
                     day of week (0 */5 * * * ?)"
                        .into(),
                ),
            ));
        }
        if get(schedule, "window").is_none() {
            found.push(finding(
                "graylog_schedule",
                &[S, "window"],
                Some("window is required with cron".into()),
            ));
        }
    }
    if let Some(timezone) = get(schedule, "timezone")
        && !timezone.value.as_str().is_some_and(timezone_ok)
    {
        found.push(finding(
            "graylog_schedule",
            &[S, "timezone"],
            Some(format!(
                "{} is not an IANA time zone (UTC, Europe/Paris)",
                repr::node(timezone)
            )),
        ));
    }
}

fn aggregation_findings(aggregation: &Node, found: &mut Vec<Finding>) {
    const A: &str = "aggregation";
    let condition = match aggregation.value {
        Value::Map(_) => aggregation
            .get("condition")
            .and_then(|node| node.value.as_str()),
        _ => None,
    };
    let Some(condition) = condition else {
        found.push(finding(
            "graylog_aggregation",
            &[A],
            Some("aggregation needs a condition".into()),
        ));
        return;
    };
    let group_by = get(aggregation, "group_by");
    if list_ok(group_by) {
        let bad: Vec<&str> = list_items(group_by)
            .into_iter()
            .filter(|item| !field_name(item))
            .collect();
        if !bad.is_empty() {
            found.push(finding(
                "graylog_field_name",
                &[A, "group_by"],
                Some(format!(
                    "not field names ([A-Za-z0-9_.@-]+): {}",
                    bad.join(", ")
                )),
            ));
        }
    } else {
        found.push(finding(
            "graylog_list_shape",
            &[A, "group_by"],
            Some("group_by is a string or a list of distinct, non-blank strings".into()),
        ));
    }
    if let Err(error) = parse_condition(condition) {
        found.push(finding(
            "graylog_aggregation",
            &[A, "condition"],
            Some(error.message),
        ));
    }
}

fn event_findings(raw: &Node, found: &mut Vec<Finding>) {
    let mut names: Vec<&str> = Vec::new();
    match get(raw, "event_fields").map(|node| &node.value) {
        None => {}
        Some(Value::Map(entries)) => {
            for entry in entries {
                let label = py_str(&entry.key);
                let path = ["event_fields", label.as_str()];
                match entry.key.value.as_str() {
                    Some(name) if field_name(name) => {
                        if event_field_kind(&entry.value).is_some() {
                            names.push(name);
                        } else {
                            found.push(finding("graylog_event_field", &path, None));
                        }
                    }
                    _ => found.push(finding(
                        "graylog_event_field",
                        &path,
                        Some(format!(
                            "{} is not a field name ([A-Za-z0-9_.@-]+)",
                            repr::node(&entry.key)
                        )),
                    )),
                }
            }
        }
        Some(_) => found.push(finding(
            "graylog_event_field",
            &["event_fields"],
            Some("event_fields is a map".into()),
        )),
    }
    let key = get(raw, "event_key");
    if key.is_some() && list_ok(key) {
        let missing: Vec<&str> = list_items(key)
            .into_iter()
            .filter(|item| !names.contains(item))
            .collect();
        if !missing.is_empty() {
            found.push(finding(
                "graylog_event_key",
                &["event_key"],
                Some(format!("not event_fields names: {}", missing.join(", "))),
            ));
        }
    }
}

/// Every graylog-1.0 constraint finding of a block, as authored, at its path
/// relative to the block (`block_findings`). At the block's root a null is
/// the key left out, as for every optional key.
pub fn block_findings(raw: &Node) -> Vec<Finding> {
    let mut found = Vec::new();
    if !matches!(raw.value, Value::Map(_)) {
        return found;
    }
    if !get(raw, "query")
        .and_then(|node| node.value.as_str())
        .is_some_and(non_blank)
    {
        found.push(finding("graylog_query_blank", &["query"], None));
    }
    for key in LIST_FIELDS {
        if !list_ok(get(raw, key)) {
            found.push(finding(
                "graylog_list_shape",
                &[key],
                Some(format!(
                    "{key} is a string or a list of distinct, non-blank strings"
                )),
            ));
        }
    }
    if let Some(schedule) = get(raw, "schedule") {
        schedule_findings(schedule, &mut found);
    }
    let aggregation = get(raw, "aggregation");
    if let Some(limit) = get(raw, "event_limit") {
        // A boolean is a Python `int` but not an event limit.
        let integer = match limit.value {
            Value::Int(integer) => Some(integer),
            _ => None,
        };
        if !integer.is_some_and(|limit| (1..=EVENT_LIMIT_MAX).contains(&limit))
            || aggregation.is_some()
        {
            let is_int = matches!(limit.value, Value::Int(_) | Value::Bool(_));
            let message = (aggregation.is_some() && is_int).then(|| {
                "event_limit is for filters: an aggregation creates one event per group".to_owned()
            });
            found.push(finding("graylog_event_limit", &["event_limit"], message));
        }
    }
    if let Some(aggregation) = aggregation {
        aggregation_findings(aggregation, &mut found);
    }
    event_findings(raw, &mut found);
    if let Some(priority) = get(raw, "priority")
        && !priority
            .value
            .as_str()
            .is_some_and(|text| PRIORITIES.contains(&text))
    {
        found.push(finding(
            "graylog_priority",
            &["priority"],
            Some(format!(
                "{} is not one of {}",
                repr::node(priority),
                PRIORITIES.join(", ")
            )),
        ));
    }
    found
}

/// The codes of [`block_findings`], sorted: what the named check
/// `graylog_constraints` finds on a block with a `status` (the oracle's
/// before-validator leaves a block without one to the field).
pub fn block_codes(raw: &Node) -> BTreeSet<&'static str> {
    findings(raw)
        .into_iter()
        .map(|finding| finding.code)
        .collect()
}

/// [`block_findings`] on a block with a `status`, within the conversion's
/// budget; none otherwise.
pub fn findings(raw: &Node) -> Vec<Finding> {
    if get(raw, "status").is_none() || !super::within_budget(raw) {
        return Vec::new();
    }
    block_findings(raw)
}

impl GraylogConfig {
    /// The block's `streams`, as a list.
    pub fn stream_aliases(&self) -> Vec<&str> {
        as_list(self.streams.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Advisories (graylog-1.0, "Advisories"): warnings that never reject a rule
// (`platforms/graylog/advisories.py`). `graylog_title_duplicate` is a
// workspace check.
// ---------------------------------------------------------------------------

/// The interval of a filter that sets none.
pub const DEFAULT_EVERY: &str = "5m";

/// One advisory: its code, its path from the rule's root, and its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    /// `graylog_overlapping_window` or `graylog_all_streams`.
    pub code: &'static str,
    /// The keys from the rule to the value it is about.
    pub field_path: Vec<String>,
    /// The message.
    pub message: String,
}

/// What an advisory reads of a tenant: its name, whether its `streams` name
/// any stream, and its `allow_leading_wildcard`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantView<'a> {
    /// The tenant's name.
    pub name: &'a str,
    /// Whether the tenant's `streams` is not empty.
    pub has_streams: bool,
    /// The tenant's `allow_leading_wildcard`.
    pub allow_leading_wildcard: bool,
}

fn block_path(rest: &[&str]) -> Vec<String> {
    ["configurations", "graylog"]
        .iter()
        .chain(rest)
        .map(|part| (*part).to_owned())
        .collect()
}

fn seconds(node: Option<&Node>) -> Option<u128> {
    node.and_then(|node| node.value.as_str())
        .and_then(|text| duration_seconds(text, false).ok())
}

/// How long a filter searches and how often it runs, in seconds, when the
/// window is the longer: runs overlap, and each message the runs share alerts
/// once per run. A block with an aggregation, a cron schedule, or a window or
/// interval that is not a duration has none.
///
/// [`overlapping_window`] (validate's advisory) and the engine's block check
/// in `opentide lint` (`opentide_tide::block_diagnostics`) both read it.
pub fn overlapping_runs(block: &Node) -> Option<(u128, u128)> {
    let schedule = get(block, "schedule")?;
    if get(block, "aggregation").is_some() || !matches!(schedule.value, Value::Map(_)) {
        return None;
    }
    if get(schedule, "cron").is_some() {
        return None;
    }
    let window = seconds(Some(get(schedule, "window")?))?;
    let every = match every_node(schedule) {
        Some(node) => seconds(Some(node))?,
        None => 300,
    };
    (window > every).then_some((window, every))
}

/// `schedule.every`, unless it is falsy (`schedule.get("every") or "5m"`:
/// a falsy interval is the default).
fn every_node(schedule: &Node) -> Option<&Node> {
    schedule
        .get("every")
        .map(AsRef::as_ref)
        .filter(|node| super::truthy(Some(node)))
}

/// `graylog_overlapping_window`: a filter that searches a longer window than
/// its interval alerts once per run on each message the runs share.
pub fn overlapping_window(block: &Node) -> Option<Advisory> {
    overlapping_runs(block)?;
    let schedule = get(block, "schedule")?;
    let window_node = get(schedule, "window")?;
    let every_text = every_node(schedule).map_or_else(|| DEFAULT_EVERY.to_owned(), py_str);
    Some(Advisory {
        code: "graylog_overlapping_window",
        field_path: block_path(&["schedule"]),
        message: format!(
            "the window ({}) is longer than the interval ({every_text}): on a filter, each \
             message alerts once per overlapping run",
            py_str(window_node)
        ),
    })
}

/// The tenants among `tenants` a block reaches: those its `tenants` names,
/// else all (`targeted_tenants`).
pub fn targeted<'t, 'a>(block: &Node, tenants: &'t [TenantView<'a>]) -> Vec<&'t TenantView<'a>> {
    match get(block, "tenants").map(|node| &node.value) {
        Some(Value::Seq(names)) if !names.is_empty() => tenants
            .iter()
            .filter(|tenant| {
                names
                    .iter()
                    .any(|name| name.value.as_str() == Some(tenant.name))
            })
            .collect(),
        _ => tenants.iter().collect(),
    }
}

/// `graylog_all_streams`: a block that names no streams, on a tenant that
/// names none either, searches every stream the token's user can read.
/// Without a tenant there is nothing to judge: the tenant may name streams.
pub fn all_streams(block: &Node, tenants: &[TenantView<'_>]) -> Option<Advisory> {
    let streams = get(block, "streams");
    let categories = get(block, "stream_categories");
    if !list_ok(streams) || !list_ok(categories) {
        return None; // graylog_list_shape is the finding
    }
    if !list_items(streams).is_empty() || !list_items(categories).is_empty() {
        return None;
    }
    let bare: Vec<&str> = targeted(block, tenants)
        .into_iter()
        .filter(|tenant| !tenant.has_streams)
        .map(|tenant| tenant.name)
        .collect();
    if bare.is_empty() {
        return None;
    }
    Some(Advisory {
        code: "graylog_all_streams",
        field_path: block_path(&[]),
        message: format!(
            "the block sets no streams or stream_categories, and tenant(s) {} set no streams \
             either: the definition searches every stream the token's user can read",
            bare.join(", ")
        ),
    })
}

/// Every advisory a rule's Graylog block, as authored, earns
/// (`graylog_advisories`); `rule` is the rule's root.
pub fn advisories(rule: &Node, tenants: &[TenantView<'_>]) -> Vec<Advisory> {
    let Some(block) = rule
        .get("configurations")
        .and_then(|configurations| configurations.get("graylog"))
        .filter(|block| matches!(block.value, Value::Map(_)))
    else {
        return Vec::new();
    };
    [overlapping_window(block), all_streams(block, tenants)]
        .into_iter()
        .flatten()
        .collect()
}

/// Whether every tenant the block reaches sets `allow_leading_wildcard`
/// (`leading_wildcard_allowed`): `validate` then drops the engine's
/// `graylog_leading_wildcard`. Offline, with no tenant, it stays.
pub fn leading_wildcard_allowed(block: &Node, tenants: &[TenantView<'_>]) -> bool {
    let reached = targeted(block, tenants);
    !reached.is_empty() && reached.iter().all(|tenant| tenant.allow_leading_wildcard)
}

/// A Graylog tenant of the workspace's configuration, as the advisories and
/// the leading-wildcard filter read it (`configured_tenants`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredTenant {
    /// The tenant's name.
    pub name: String,
    /// Whether its `streams` names any stream.
    pub has_streams: bool,
    /// Its `allow_leading_wildcard`.
    pub allow_leading_wildcard: bool,
}

impl ConfiguredTenant {
    /// The tenant as [`advisories`] and [`leading_wildcard_allowed`] read it.
    pub fn view(&self) -> TenantView<'_> {
        TenantView {
            name: &self.name,
            has_streams: self.has_streams,
            allow_leading_wildcard: self.allow_leading_wildcard,
        }
    }
}

/// The `[[tenants]]` of the resolved `platforms/graylog.toml`, in order
/// (`configured_tenants`); `platforms` is the resolved configuration's
/// `platforms` table.
pub fn configured_tenants(platforms: Option<&Node>) -> Vec<ConfiguredTenant> {
    tenants_of(
        platforms
            .and_then(|platforms| platforms.get("graylog"))
            .map(AsRef::as_ref),
    )
}

/// The `[[tenants]]` of a Graylog configuration (`platforms/graylog.toml`'s
/// table), in order. A tenant without a name is not one.
pub fn tenants_of(graylog: Option<&Node>) -> Vec<ConfiguredTenant> {
    let Some(Value::Seq(tenants)) = graylog
        .and_then(|graylog| graylog.get("tenants"))
        .map(|tenants| &tenants.value)
    else {
        return Vec::new();
    };
    tenants
        .iter()
        .filter_map(|tenant| {
            let name = tenant.get("name")?.value.as_str()?.to_owned();
            let setup = tenant.get("setup");
            Some(ConfiguredTenant {
                name,
                has_streams: !list_items(
                    setup
                        .and_then(|setup| setup.get("streams"))
                        .map(AsRef::as_ref),
                )
                .is_empty(),
                allow_leading_wildcard: matches!(
                    setup
                        .and_then(|setup| setup.get("allow_leading_wildcard"))
                        .map(|flag| &flag.value),
                    Some(Value::Bool(true))
                ),
            })
        })
        .collect()
}

/// The event definition title of a rule's enabled Graylog block (the block's
/// `name`, else the rule's), or `None` when the rule has no enabled block
/// (`graylog_titles._title`).
pub fn definition_title(rule: &Node) -> Option<&str> {
    let block = rule
        .get("configurations")
        .and_then(|configurations| configurations.get("graylog"))
        .filter(|block| matches!(block.value, Value::Map(_)))?;
    if !matches!(
        block.get("enabled").map(|node| &node.value),
        Some(Value::Bool(true))
    ) {
        return None;
    }
    block
        .get("name")
        .and_then(|name| name.value.as_str())
        .filter(|name| !name.is_empty())
        .or_else(|| {
            rule.get("name")
                .and_then(|name| name.value.as_str())
                .filter(|name| !name.is_empty())
        })
}

/// `graylog_title_duplicate`: the other rules whose enabled Graylog block
/// resolves to the same event definition title, sorted
/// (`graylog_title_issues`). Graylog allows two definitions with one title,
/// and its alert list cannot tell them apart.
pub fn title_duplicates<'r>(uuid: &str, title: &str, rules: &[(&'r str, &Node)]) -> Vec<&'r str> {
    let mut others: Vec<&str> = rules
        .iter()
        .filter(|(other, rule)| *other != uuid && definition_title(rule) == Some(title))
        .map(|(other, _)| *other)
        .collect();
    others.sort_unstable();
    others
}

/// What `graylog_title_duplicate` says, and what to do.
pub fn title_duplicate_message(title: &str, others: &[&str]) -> (String, String) {
    (
        format!(
            "Graylog event definition title {} is also the title of rule(s) {}; Graylog's alert \
             list cannot tell them apart",
            repr::quote(title),
            others.join(", ")
        ),
        "Set a distinct configurations.graylog.name on one of the rules".to_owned(),
    )
}
