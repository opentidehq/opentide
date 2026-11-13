//! Google Security Operations YARA-L 2.0 detection rule,
//! `platform::google_secops::1.0` (`GoogleSecopsConfig` and its nested
//! models), ported from 0.28.0 (platform-google-secops rev 1.2).
//!
//! | Oracle (0.28.0) | Here |
//! |-----------------|------|
//! | `models/platform.py` `GoogleSecopsConfig`, `platform_configs.py` | [`GoogleSecopsConfig`], [`GoogleSecopsMatch`], [`GoogleSecopsOptions`], [`GoogleSecopsSchedule`] |
//! | `platforms/google_secops/checks.py` `block_findings` | [`block_findings`], [`block_codes`] (the named check `google_secops_rule_shape`) |
//! | `platforms/google_secops/yaral.py` | [`yaral`] |
//! | `platforms/google_secops/compile.py` `assemble`, `AssembledRule`, `SectionPlace`, `Location` | [`assemble`] |
//!
//! Unlike the older platforms' before-validators, which report one
//! `value_error` naming every code, this block's reports one error per
//! finding, typed by its code and placed at the path the spec fixes for it,
//! so `validate` and the editor name the same finding.

pub mod advisories;
pub mod assemble;
pub mod yaral;

use std::collections::BTreeSet;

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::configuration::repr;
use crate::error::ErrorKind;
use crate::from_node::Context;
use crate::node::{Node, Value};
use crate::objects::platform::{literal_enum, optional_literal, platform_block};
use crate::pins::Pins;

pub use yaral::Finding;

/// Severity and priority values (google-secops-1.0, Constraints).
pub const SEVERITIES: [&str; 5] = ["Info", "Low", "Medium", "High", "Critical"];

/// Run frequencies opentide accepts. Deploy sends one only when the block
/// names it.
pub const RUN_FREQUENCIES: [&str; 4] =
    ["LIVE", "LIVE_CUSTOMIZABLE", "HOURLY_CUSTOMIZABLE", "DAILY"];

/// The run frequencies that take schedule customizations.
pub const CUSTOMIZABLE: [&str; 2] = ["LIVE_CUSTOMIZABLE", "HOURLY_CUSTOMIZABLE"];

/// The meta keys deploy writes, in order (google-secops-1.0, Meta).
pub const DERIVED_META: [&str; 7] = [
    "author",
    "description",
    "severity",
    "priority",
    "technique",
    "opentide_uuid",
    "opentide_version",
];

/// Every code [`block_findings`] reports.
pub const CONSTRAINT_CODES: [&str; 12] = [
    "google_secops_rule_name",
    "google_secops_severity",
    "google_secops_run_frequency",
    "google_secops_schedule",
    "google_secops_meta_key",
    "yaral_section_missing",
    "yaral_section_empty",
    "yaral_section_header",
    "yaral_match_shape",
    "yaral_match_window",
    "yaral_option",
    "extra_forbidden",
];

literal_enum! {
    /// `match.type`: `hop`, `tumbling` or `sliding`.
    MatchType { Hop = "hop", Tumbling = "tumbling", Sliding = "sliding", }
}

literal_enum! {
    /// `match.direction`: `before` or `after`.
    MatchDirection { Before = "before", After = "after", }
}

literal_enum! {
    /// `severity` and `priority`.
    Severity { Info = "Info", Low = "Low", Medium = "Medium", High = "High", Critical = "Critical", }
}

literal_enum! {
    /// `run_frequency`.
    RunFrequency {
        Live = "LIVE",
        LiveCustomizable = "LIVE_CUSTOMIZABLE",
        HourlyCustomizable = "HOURLY_CUSTOMIZABLE",
        Daily = "DAILY",
    }
}

impl Severity {
    /// The value as written.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

impl RunFrequency {
    /// The value as written, and as Google's API takes it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "LIVE",
            Self::LiveCustomizable => "LIVE_CUSTOMIZABLE",
            Self::HourlyCustomizable => "HOURLY_CUSTOMIZABLE",
            Self::Daily => "DAILY",
        }
    }
}

/// `match.group_by`: a list of at least one item (`min_length=1`).
fn group_by(node: &Node, cx: &mut Context) -> Option<Vec<String>> {
    let names = Vec::<String>::from_node(node, cx)?;
    match crate::objects::checks::check_at_least_one(names.len()) {
        Ok(()) => Some(names),
        Err(violation) => {
            violation.report(node, cx);
            None
        }
    }
}

/// garde: `group_by` has an item.
fn garde_group_by(names: &[String], _pins: &Pins) -> garde::Result {
    crate::objects::checks::check_at_least_one(names.len())
        .map_err(crate::objects::checks::Violation::into_garde)
}

/// The rule's match window (`GoogleSecopsMatch`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "GoogleSecopsMatch", description = "")]
#[from_node(model = "GoogleSecopsMatch")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "GoogleSecopsMatch",
        module = "opentide._native.models"
    )
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct GoogleSecopsMatch {
    /// The placeholders the rule groups by, each `$name`, non-empty, no repeats. Rendered joined
    /// with `, `.
    #[schemars(length(min = 1))]
    #[from_node(with = "group_by")]
    #[garde(custom(garde_group_by))]
    pub group_by: Vec<String>,
    /// The match window: `<n>m`, `<n>h`, or `<n>d`. A hop or sliding window is at most `14d`, a
    /// tumbling window at most `72h`.
    pub window: String,
    /// `hop` (the default) renders `over`, `tumbling` renders `by`, `sliding` renders
    /// `over … before|after $pivot`.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "optional_literal::<MatchType>")]
    pub r#type: Option<MatchType>,
    /// With `sliding`: the event variable the window is anchored on, `$name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pivot: Option<String>,
    /// With `sliding`: `before` or `after`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "optional_literal::<MatchDirection>")]
    pub direction: Option<MatchDirection>,
}

/// The rule's options (`GoogleSecopsOptions`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "GoogleSecopsOptions", description = "")]
#[from_node(model = "GoogleSecopsOptions")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "GoogleSecopsOptions",
        module = "opentide._native.models"
    )
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct GoogleSecopsOptions {
    /// Keep zero values of match placeholders (`false` by default). Rendered
    /// `allow_zero_values = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_zero_values: Option<bool>,
    /// Suppress repeated detections for this duration (`m`, `h`, `d`). Rendered
    /// `suppression_window = 1h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppression_window: Option<String>,
}

/// Schedule customizations (`GoogleSecopsSchedule`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "GoogleSecopsSchedule", description = "")]
#[from_node(model = "GoogleSecopsSchedule")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "GoogleSecopsSchedule",
        module = "opentide._native.models"
    )
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct GoogleSecopsSchedule {
    /// Sent as `scheduleCustomizations.ensureEnrichmentCompleteness`. Google's default when
    /// omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ensure_enrichment_completeness: Option<bool>,
    /// A duration (`30m`, `2h`), sent as `scheduleCustomizations.lateArrivingDataAdjustment` in
    /// seconds (`"1800s"`). Google's default when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_arriving_data_adjustment: Option<String>,
}

fn garde_block(block: &GoogleSecopsConfig, _pins: &Pins) -> garde::Result {
    let value = serde_json::to_value(block).map_err(|error| {
        garde::Error::new(format!("GoogleSecopsConfig does not serialise: {error}"))
    })?;
    let findings = block_findings(&crate::objects::platform::json_node(&value));
    if findings.is_empty() {
        return Ok(());
    }
    let joined: Vec<String> = findings
        .iter()
        .map(|finding| format!("{}: {}", finding.code, finding.message))
        .collect();
    Err(garde::Error::new(joined.join("; ")))
}

/// The before-validator: a block with a `status` is judged as authored, and
/// each finding is one error at its own path, typed by its code. With any
/// finding, the block's fields are not converted.
fn raw_block(node: &Node, cx: &mut Context) -> bool {
    if !matches!(node.value, Value::Map(_))
        || node
            .get("status")
            .is_none_or(|status| matches!(status.value, Value::Null))
    {
        return true;
    }
    if !crate::objects::platform::within_budget(node) {
        return true;
    }
    let findings = block_findings(&authored(node));
    if findings.is_empty() {
        return true;
    }
    for finding in &findings {
        report_at(cx, &finding.path, |cx| {
            let kind = if finding.code == "extra_forbidden" {
                ErrorKind::UnknownKey
            } else {
                ErrorKind::Constraint(finding.code)
            };
            cx.error(kind, finding.message.clone(), node);
        });
    }
    false
}

fn report_at(cx: &mut Context, path: &[String], f: impl FnOnce(&mut Context)) {
    match path.split_first() {
        None => f(cx),
        Some((first, rest)) => cx.at_key(first, |cx| report_at(cx, rest, f)),
    }
}

/// The block's fields, in declaration order (`model_fields`).
const FIELDS: [&str; 20] = [
    "enabled",
    "name",
    "schema",
    "status",
    "flags",
    "tenants",
    "contributors",
    "setup",
    "events",
    "match",
    "outcome",
    "condition",
    "options",
    "export",
    "severity",
    "priority",
    "alerting",
    "run_frequency",
    "schedule",
    "meta",
];

/// A block dumped and loaded again (deploy's modifiers, a model dumped with
/// every field) carries unset fields as `null`: only an authored `null` is a
/// section with no text, so a block with every field has its nulls dropped.
fn authored(node: &Node) -> Node {
    let Value::Map(entries) = &node.value else {
        return node.clone();
    };
    let has = |key: &str| {
        node.get(key).is_some() || (key == "schema" && node.get("platform_schema").is_some())
    };
    if !FIELDS.iter().all(|key| has(key)) {
        return node.clone();
    }
    Node {
        value: Value::Map(
            entries
                .iter()
                .filter(|entry| !matches!(entry.value.value, Value::Null))
                .cloned()
                .collect(),
        ),
        start: node.start,
        end: node.end,
    }
}

platform_block! {
    /// Google Security Operations YARA-L 2.0 detection rule (`GoogleSecopsConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[garde(custom(garde_block))]
    #[schemars(rename = "GoogleSecopsConfig", description = "")]
    #[from_node(model = "GoogleSecopsConfig", before = "raw_block")]
    #[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all, eq, name = "GoogleSecopsConfig", module = "opentide._native.models"))]
    #[cfg_attr(feature = "python", expect(clippy::unsafe_derive_deserialize, reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"))]
    pub struct GoogleSecopsConfig ["platform::google_secops::1.0"] {
        /// YARA-L `setup` section text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(extend("tide.template.multiline" = true))]
        pub setup: Option<String>,
        /// YARA-L `events` section text.
        #[schemars(extend("tide.template.multiline" = true, "tide.template.required" = true))]
        pub events: String,
        /// `group_by`, `window`, and `type` (`hop`, `tumbling`, `sliding` with `pivot` and
        /// `direction`). Required with two or more event variables.
        #[serde(rename = "match", default, skip_serializing_if = "Option::is_none")]
        pub r#match: Option<GoogleSecopsMatch>,
        /// YARA-L `outcome` section text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(extend("tide.template.multiline" = true))]
        pub outcome: Option<String>,
        /// YARA-L `condition` section text.
        #[schemars(extend("tide.template.multiline" = true, "tide.template.required" = true))]
        pub condition: String,
        /// `allow_zero_values`, `suppression_window`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub options: Option<GoogleSecopsOptions>,
        /// YARA-L `export` section text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(extend("tide.template.multiline" = true))]
        pub export: Option<String>,
        /// `Info`, `Low`, `Medium`, `High`, or `Critical`. Written as meta `severity`. Derived from
        /// `response.alert_severity` when omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "optional_literal::<Severity>")]
        pub severity: Option<Severity>,
        /// Same values. Written as meta `priority`. Default: the severity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "optional_literal::<Severity>")]
        pub priority: Option<Severity>,
        /// Whether detections become alerts (`RuleDeployment.alerting`). Default: `false` under
        /// `PREVIEW`, `true` under `RELEASE` and `UNIVERSAL`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alerting: Option<bool>,
        /// `LIVE`, `LIVE_CUSTOMIZABLE`, `HOURLY_CUSTOMIZABLE`, or `DAILY`. Not sent when omitted: a new
        /// rule gets Google's default, and an existing rule keeps its own.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "optional_literal::<RunFrequency>")]
        pub run_frequency: Option<RunFrequency>,
        /// Schedule customizations, for `LIVE_CUSTOMIZABLE` and `HOURLY_CUSTOMIZABLE` only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schedule: Option<GoogleSecopsSchedule>,
        /// Extra meta keys, written after the derived meta in the order given.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub meta: Option<indexmap::IndexMap<String, String>>,
    }
}

// ---------------------------------------------------------------------------
// The named check `google_secops_rule_shape` (`checks.py` `block_findings`).
// ---------------------------------------------------------------------------

/// A positive `<n>s`, `<n>m`, `<n>h` or `<n>d` duration in seconds, or
/// `None`.
pub fn duration_seconds(value: &str) -> Option<u64> {
    let unit = value.chars().last()?;
    let factor: u64 = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        _ => return None,
    };
    yaral::positive_number(&value[..value.len() - 1]).map(|count| count.saturating_mul(factor))
}

fn schedule_findings(block: &Node) -> Vec<Finding> {
    let Some(schedule) = block
        .get("schedule")
        .filter(|node| !matches!(node.value, Value::Null))
    else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let frequency = block
        .get("run_frequency")
        .and_then(|node| node.value.as_str());
    if !frequency.is_some_and(|frequency| CUSTOMIZABLE.contains(&frequency)) {
        found.push(Finding::new(
            "google_secops_schedule",
            &["schedule"],
            "schedule customizes LIVE_CUSTOMIZABLE and HOURLY_CUSTOMIZABLE rules only: set \
             run_frequency to one of them, or remove schedule",
        ));
    }
    if let Some(adjustment) = schedule
        .get("late_arriving_data_adjustment")
        .filter(|node| !matches!(node.value, Value::Null))
        && adjustment
            .value
            .as_str()
            .and_then(duration_seconds)
            .is_none()
    {
        found.push(Finding::new(
            "google_secops_schedule",
            &["schedule", "late_arriving_data_adjustment"],
            format!(
                "late_arriving_data_adjustment {} is not a positive duration in s, m, h or d \
                 (30m, 2h)",
                repr::node(adjustment)
            ),
        ));
    }
    found
}

fn meta_findings(meta: Option<&Node>) -> Vec<Finding> {
    let Some(Value::Map(entries)) = meta.map(|node| &node.value) else {
        return Vec::new(); // the field type reports it
    };
    let mut found = Vec::new();
    for entry in entries {
        let key = entry.key.value.as_str();
        let reason = if !key.is_some_and(yaral::is_identifier) {
            if key.is_some_and(yaral::is_keyword) {
                "a YARA-L keyword".to_owned()
            } else {
                "not an identifier ([A-Za-z_][A-Za-z0-9_]*)".to_owned()
            }
        } else if key.is_some_and(|key| DERIVED_META.contains(&key)) {
            "a key deploy writes itself".to_owned()
        } else if !matches!(entry.value.value, Value::Str(_)) {
            format!(
                "set to a {}: a meta value is a string (quote it)",
                yaral::python_type(&entry.value)
            )
        } else {
            continue;
        };
        found.push(Finding::new(
            "google_secops_meta_key",
            &["meta", &yaral::key_text(&entry.key)],
            format!("meta key {} is {reason}", repr::node(&entry.key)),
        ));
    }
    found
}

/// Every constraint and structural YARA-L finding of a block, as authored,
/// each at its path relative to the block.
pub fn block_findings(block: &Node) -> Vec<Finding> {
    let mut found = Vec::new();
    if let Some(name) = block.get("name").and_then(|node| node.value.as_str())
        && !name.is_empty()
        && !yaral::is_identifier(name)
    {
        found.push(Finding::new(
            "google_secops_rule_name",
            &["name"],
            format!(
                "name {} is not a YARA-L rule name: an identifier ([A-Za-z_][A-Za-z0-9_]*) that \
                 is not a keyword",
                repr::quote(name)
            ),
        ));
    }
    for key in ["severity", "priority"] {
        if let Some(value) = block
            .get(key)
            .filter(|node| !matches!(node.value, Value::Null))
            && !value
                .value
                .as_str()
                .is_some_and(|text| SEVERITIES.contains(&text))
        {
            found.push(Finding::new(
                "google_secops_severity",
                &[key],
                format!(
                    "{key} {} is not Info, Low, Medium, High or Critical",
                    repr::node(value)
                ),
            ));
        }
    }
    if let Some(frequency) = block
        .get("run_frequency")
        .filter(|node| !matches!(node.value, Value::Null))
        && !frequency
            .value
            .as_str()
            .is_some_and(|text| RUN_FREQUENCIES.contains(&text))
    {
        let legacy = if frequency.value.as_str() == Some("HOURLY") {
            " (Google's legacy HOURLY is refused)"
        } else {
            ""
        };
        found.push(Finding::new(
            "google_secops_run_frequency",
            &["run_frequency"],
            format!(
                "run_frequency {} is not LIVE, LIVE_CUSTOMIZABLE, HOURLY_CUSTOMIZABLE or \
                 DAILY{legacy}",
                repr::node(frequency)
            ),
        ));
    }
    found.extend(schedule_findings(block));
    found.extend(meta_findings(block.get("meta").map(AsRef::as_ref)));
    if block.get("query").is_some() {
        found.push(Finding::new(
            "extra_forbidden",
            &["query"],
            "query is not a google_secops key: write the rule as its sections (events, match, \
             outcome, condition, options)",
        ));
    }
    found.extend(yaral::section_findings(block));
    found
}

/// The codes of [`block_findings`] (the named check
/// `google_secops_rule_shape`).
pub fn block_codes(block: &Node) -> BTreeSet<&'static str> {
    if !crate::objects::platform::within_budget(block) {
        return BTreeSet::new();
    }
    block_findings(block)
        .into_iter()
        .map(|finding| finding.code)
        .collect()
}
