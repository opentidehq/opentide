//! Microsoft Sentinel analytics rule, `platform::sentinel::1.0`
//! (`SentinelConfig` and its nested models).

use std::borrow::Cow;

use garde::Validate;
use indexmap::IndexMap;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::configuration::repr;
use crate::from_node::Context;
use crate::node::Node;
use crate::objects::any::Any;
use crate::objects::checks::Violation;
use crate::objects::platform::platform_block;
use crate::pins::Pins;
use crate::vocab::sentinel::{SentinelAttack, VERSION};

/// Analytics-rule template (`SentinelTemplate`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelTemplate", description = "")]
#[from_node(model = "SentinelTemplate")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SentinelTemplate",
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
pub struct SentinelTemplate {
    /// Sentinel alert-rule template name.
    pub uuid: String,
    /// Template version.
    pub version: String,
}

/// Result threshold (`SentinelTrigger`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelTrigger", description = "")]
#[from_node(model = "SentinelTrigger")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SentinelTrigger",
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
pub struct SentinelTrigger {
    /// Sentinel trigger operator.
    pub operator: String,
    /// Sentinel trigger threshold.
    pub threshold: i64,
}

/// A Sentinel duration (`frequency`, `lookback`, `grouping_lookback`, a
/// string `suppression`): what deploy converts to ISO 8601
/// (`iso_duration_timedelta`). ISO 8601 with weeks, days and a time part, any
/// case (`PT1H`, `P1D`, `p1w`), or the shorthand `<n>d<n>h<n>m<n>s` (`30m`,
/// `1h10m`), around blanks; empty is left to deploy, which asks for the
/// value where it needs one. Validation refuses what deploy cannot convert:
/// a value of neither shape (`frequency: hourly`), and one longer than
/// deploy's `timedelta` holds ([`MAX_DURATION_SECONDS`]: `1000000000d`,
/// `P99999999999D`), both of which the oracle accepted and deploy refused.
pub fn check_duration(value: &str) -> Result<(), Violation> {
    let text = crate::objects::platform::python_strip(value);
    if text.is_empty() {
        return Ok(());
    }
    match duration_seconds(text) {
        Length::Seconds(_) => Ok(()),
        Length::TooLong => Err(Violation::value_error(format!(
            "Duration {} is longer than a rule can be deployed with (at most {MAX_DURATION_DAYS} \
             days, 23 hours, 59 minutes and 59 seconds)",
            repr::quote(value)
        ))),
        Length::NotADuration => Err(Violation::value_error(format!(
            "Duration {} is not an ISO 8601 duration (PT1H, PT30M, P1D) or a shorthand duration \
             (30m, 1h, 1d, 1h10m)",
            repr::quote(value)
        ))),
    }
}

/// The most days deploy's duration holds (Python's `timedelta.max.days`).
pub const MAX_DURATION_DAYS: u64 = 999_999_999;

/// The longest duration deploy converts, in seconds: [`MAX_DURATION_DAYS`]
/// and a day less one second (`timedelta.max`, whole seconds).
pub const MAX_DURATION_SECONDS: u64 = MAX_DURATION_DAYS * 86_400 + 86_399;

/// What a Sentinel duration's text spells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Length {
    /// Neither shape.
    NotADuration,
    /// Longer than [`MAX_DURATION_SECONDS`] (a part too long for a `u64`
    /// included: the sum is checked, so no digit string can overflow it).
    TooLong,
    /// The duration, in seconds.
    Seconds(u64),
}

/// The duration `text` (stripped) spells.
#[expect(
    clippy::expect_used,
    reason = "regex literals, tested by `sentinel_durations`"
)]
fn duration_seconds(text: &str) -> Length {
    use std::sync::OnceLock;
    static PATTERNS: OnceLock<(regex::Regex, regex::Regex)> = OnceLock::new();
    let (short, iso) = PATTERNS.get_or_init(|| {
        (
            regex::Regex::new(r"^(?:([0-9]+)d)?(?:([0-9]+)h)?(?:([0-9]+)m)?(?:([0-9]+)s)?$")
                .expect("a valid pattern"),
            regex::Regex::new(
                r"(?i)^P(?:([0-9]+)W)?(?:([0-9]+)D)?(?:T(?:([0-9]+)H)?(?:([0-9]+)M)?(?:([0-9]+)S)?)?$",
            )
            .expect("a valid pattern"),
        )
    });
    // Each group's length in seconds, in the pattern's order.
    let total = |captures: &regex::Captures<'_>, units: &[u64]| -> Option<Length> {
        if !captures.iter().skip(1).any(|part| part.is_some()) {
            return None;
        }
        let mut sum: Option<u64> = Some(0);
        for (part, unit) in captures.iter().skip(1).zip(units) {
            if let Some(part) = part {
                let seconds = part
                    .as_str()
                    .parse::<u64>()
                    .ok()
                    .and_then(|count| count.checked_mul(*unit));
                sum = sum
                    .zip(seconds)
                    .and_then(|(sum, seconds)| sum.checked_add(seconds));
            }
        }
        Some(
            sum.filter(|seconds| *seconds <= MAX_DURATION_SECONDS)
                .map_or(Length::TooLong, Length::Seconds),
        )
    };
    if let Some(captures) = short.captures(text)
        && let Some(length) = total(&captures, &[86_400, 3_600, 60, 1])
    {
        return length;
    }
    if text.to_uppercase().ends_with('T') {
        return Length::NotADuration;
    }
    iso.captures(text)
        .and_then(|captures| total(&captures, &[604_800, 86_400, 3_600, 60, 1]))
        .unwrap_or(Length::NotADuration)
}

/// A duration field in the conversion: `null`, or a string [`check_duration`]
/// accepts.
pub fn duration(node: &Node, cx: &mut Context) -> Option<Option<String>> {
    if matches!(node.value, crate::node::Value::Null) {
        return Some(None);
    }
    let value = String::from_node(node, cx)?;
    match check_duration(&value) {
        Ok(()) => Some(Some(value)),
        Err(violation) => {
            violation.report(node, cx);
            None
        }
    }
}

/// garde: [`check_duration`] on a present value.
pub fn garde_duration(value: &Option<String>, _pins: &Pins) -> garde::Result {
    value.as_deref().map_or(Ok(()), |value| {
        check_duration(value).map_err(Violation::into_garde)
    })
}

/// `alert.suppression`: the union, then [`check_duration`] on a string.
fn suppression(node: &Node, cx: &mut Context) -> Option<Suppression> {
    let value = Suppression::from_node(node, cx)?;
    if let Suppression::Duration(text) = &value
        && let Err(violation) = check_duration(text)
    {
        violation.report(node, cx);
        return None;
    }
    Some(value)
}

fn garde_suppression(value: &Suppression, _pins: &Pins) -> garde::Result {
    match value {
        Suppression::Duration(text) => check_duration(text).map_err(Violation::into_garde),
        Suppression::Flag(_) => Ok(()),
    }
}

/// Run cadence, or NRT (`SentinelScheduling`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelScheduling", description = "")]
#[from_node(model = "SentinelScheduling")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SentinelScheduling",
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
pub struct SentinelScheduling {
    /// `true` deploys `kind: NRT` and skips frequency, lookback, and trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nrt: Option<bool>,
    /// Duration: ISO 8601, or shorthand converted to ISO 8601. How often a scheduled rule runs
    /// (`PT1H`). Required at deploy unless `nrt` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[from_node(with = "duration")]
    #[garde(custom(garde_duration))]
    pub frequency: Option<String>,
    /// Duration: ISO 8601, or shorthand converted to ISO 8601. Query window (`PT2H`). Required at
    /// deploy unless `nrt` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[from_node(with = "duration")]
    #[garde(custom(garde_duration))]
    pub lookback: Option<String>,
}

/// An extra alert property (`SentinelCustomDetails`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelCustomDetails", description = "")]
#[from_node(model = "SentinelCustomDetails")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SentinelCustomDetails",
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
pub struct SentinelCustomDetails {
    /// Alert property name.
    pub key: String,
    /// Result column.
    pub column: String,
}

/// A column-driven alert property (`SentinelDynamicProperties`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelDynamicProperties", description = "")]
#[from_node(model = "SentinelDynamicProperties")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SentinelDynamicProperties",
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
pub struct SentinelDynamicProperties {
    /// Sentinel alert property. `Tactics` and `Severity` are sent as the tactics and severity column
    /// overrides. Any other value is an alert dynamic property.
    pub property: String,
    /// Result column.
    pub column: String,
}

/// `alert.suppression`: a duration, or a boolean.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, FromNode)]
#[serde(untagged)]
#[from_node(union)]
pub enum Suppression {
    /// A duration, ISO 8601 or shorthand.
    #[schemars(description = "")]
    #[from_node(tag = "str")]
    Duration(String),
    /// `false` disables suppression.
    #[schemars(description = "")]
    #[from_node(tag = "bool")]
    Flag(bool),
}

impl Default for Suppression {
    fn default() -> Self {
        Self::Flag(false)
    }
}

/// One `alert.techniques` entry: an ATT&CK v18 technique or sub-technique id
/// (`SentinelTechnique`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SentinelTechnique(pub String);

/// The id when Sentinel accepts it; else `sentinel_attack_technique`, with
/// what to write instead when the list knows
/// ([`SentinelAttack::hint`], `opentide_core::suggest` for a typo).
pub fn check_technique(value: &str) -> Result<(), Violation> {
    let list = SentinelAttack::bundled();
    if list.techniques.contains_key(value) {
        return Ok(());
    }
    let quoted = repr::quote(value);
    let hint = list.hint(value);
    Err(Violation {
        kind: "sentinel_attack_technique",
        message: format!(
            "{quoted} is not an ATT&CK v{VERSION} technique or sub-technique id, which is what \
             Sentinel is aligned to{hint}"
        ),
        context: vec![
            ("value", quoted),
            ("version", VERSION.to_owned()),
            ("hint", hint),
        ],
    })
}

impl FromNode for SentinelTechnique {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        let value = String::from_node(node, cx)?;
        match check_technique(&value) {
            Ok(()) => Some(Self(value)),
            Err(violation) => {
                violation.report(node, cx);
                None
            }
        }
    }
}

impl JsonSchema for SentinelTechnique {
    fn schema_name() -> Cow<'static, str> {
        "SentinelTechnique".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let techniques = &SentinelAttack::bundled().techniques;
        let ids: Vec<&String> = techniques.keys().collect();
        let descriptions: Vec<String> = techniques
            .iter()
            .map(|(id, name)| format!("**{id}** {name}"))
            .collect();
        json_schema!({
            "type": "string",
            "enum": ids,
            "markdownEnumDescriptions": descriptions,
        })
    }
}

/// garde: [`check_technique`] on each id.
pub fn garde_techniques(value: &Option<Vec<SentinelTechnique>>, _pins: &Pins) -> garde::Result {
    for technique in value.iter().flatten() {
        check_technique(&technique.0).map_err(Violation::into_garde)?;
    }
    Ok(())
}

/// Alert and incident presentation (`SentinelAlert`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelAlert", description = "")]
#[from_node(model = "SentinelAlert")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SentinelAlert",
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
pub struct SentinelAlert {
    /// Alert display-name format. Empty leaves the Sentinel default. The rule `name` is still the
    /// analytics-rule display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Alert description format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Sentinel severity. When omitted, deploy uses `response.alert_severity`. `Critical` is sent as
    /// `High`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// `false` disables suppression and sends a one-hour duration. A duration, ISO 8601 or
    /// shorthand, enables suppression for that long. Boolean `true` fails deploy.
    #[serde(default)]
    #[from_node(with = "suppression")]
    #[garde(custom(garde_suppression))]
    pub suppression: Suppression,
    /// Whether a firing alert opens an incident.
    #[serde(default = "yes")]
    pub create_incident: bool,
    /// Sentinel tactic names (the ARM `AttackTactic` enum). Replaced when the rule's ATT&CK
    /// techniques resolve to tactics: each `att&ck` stage maps to the tactic of the same name.
    /// Stealth, Defense Impairment, and the ICS Evasion tactic map to `DefenseEvasion`. A stage with
    /// no Sentinel tactic is dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tactics: Option<Vec<String>>,
    /// ATT&CK v18 technique and sub-technique ids, the ATT&CK version Sentinel is aligned to. A
    /// sub-technique is sent in `subTechniques` and its parent in `techniques`. Replaced by the
    /// rule's resolved techniques when those exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(custom(garde_techniques))]
    pub techniques: Option<Vec<SentinelTechnique>>,
    /// Extra alert properties.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_details: Option<Vec<SentinelCustomDetails>>,
    /// Column-driven alert properties.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_properties: Option<Vec<SentinelDynamicProperties>>,
}

fn yes() -> bool {
    true
}

/// Incident grouping (`SentinelAlertGrouping`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelAlertGrouping", description = "")]
#[from_node(model = "SentinelAlertGrouping")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SentinelAlertGrouping",
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
pub struct SentinelAlertGrouping {
    /// Group alerts into one incident.
    pub enabled: bool,
    /// Reopen a matching closed incident. Deploy sends `false` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reopen_closed_incidents: Option<bool>,
    /// Duration: ISO 8601, or shorthand converted to ISO 8601. Required at deploy when `enabled` is
    /// true. When `enabled` is false and this is omitted, deploy sends `PT1H`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[from_node(with = "duration")]
    #[garde(custom(garde_duration))]
    pub grouping_lookback: Option<String>,
    /// Sentinel matching method. Deploy sends `AllEntities` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching: Option<String>,
    /// Entity types used when matching is selective.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_by_entities: Option<Vec<String>>,
    /// Alert-detail fields used when matching is selective.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_by_alert_details: Option<Vec<String>>,
    /// Custom-detail keys used when matching is selective.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_by_custom_details: Option<Vec<String>>,
}

/// Event grouping and incident grouping (`SentinelGrouping`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelGrouping", description = "")]
#[from_node(model = "SentinelGrouping")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SentinelGrouping",
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
pub struct SentinelGrouping {
    /// Sentinel `aggregationKind`. `SingleAlert` groups events into one alert. `AlertPerResult`
    /// emits one alert per row.
    pub event: String,
    /// Incident grouping. Required at deploy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert: Option<SentinelAlertGrouping>,
}

/// A column binding (`SentinelMappingEntry`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelMappingEntry", description = "")]
#[from_node(model = "SentinelMappingEntry")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SentinelMappingEntry",
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
pub struct SentinelMappingEntry {
    /// Entity identifier (`Name`, `Address`, …).
    pub identifier: String,
    /// Result column.
    pub column: String,
}

/// An entity mapping (`SentinelEntityMapping`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelEntityMapping", description = "")]
#[from_node(model = "SentinelEntityMapping")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SentinelEntityMapping",
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
pub struct SentinelEntityMapping {
    /// Sentinel entity type (`Account`, `Host`, `IP`, `URL`, …).
    pub entity: String,
    /// Column bindings for that entity.
    pub mappings: Vec<SentinelMappingEntry>,
}

/// A per-tenant KQL fragment (`SentinelExclusion`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelExclusion", description = "")]
#[from_node(model = "SentinelExclusion")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SentinelExclusion",
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
pub struct SentinelExclusion {
    /// KQL fragment appended after the base query. The key is required. An empty string is accepted
    /// (this field is not the non-blank rule `query`).
    #[schemars(extend("tide.template.multiline" = true))]
    pub query: String,
    /// Why the exclusion exists. Not sent to Sentinel.
    pub reason: String,
    /// Limit the exclusion to one tenant name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// KQL `let` bindings prepended to the query. Values may be string, number, or boolean. Other
    /// types are skipped. The last definition of a name wins.
    #[serde(rename = "let", default, skip_serializing_if = "Option::is_none")]
    pub r#let: Option<IndexMap<String, Any>>,
}

platform_block! {
    /// Microsoft Sentinel analytics rule (`SentinelConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[schemars(rename = "SentinelConfig", description = "")]
    #[from_node(model = "SentinelConfig")]
    #[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all, eq, name = "SentinelConfig", module = "opentide._native.models"))]
    #[cfg_attr(feature = "python", expect(clippy::unsafe_derive_deserialize, reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"))]
    pub struct SentinelConfig ["platform::sentinel::1.0"] {
        /// KQL. Multiline. Compiled with matching `exclusions` before deploy.
        #[schemars(extend("tide.template.multiline" = true, "tide.template.spacer" = true))]
        #[from_node(with = "crate::objects::platform::query_text")]
        #[garde(custom(crate::objects::platform::garde_query_text))]
        pub query: String,
        /// Run cadence, or NRT.
        #[garde(dive)]
        pub scheduling: SentinelScheduling,
        /// Alert and incident presentation.
        #[garde(dive)]
        pub alert: SentinelAlert,
        /// Per-tenant KQL fragments appended to `query`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exclusions: Option<Vec<SentinelExclusion>>,
        /// Analytics-rule template this rule was built from.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub template: Option<SentinelTemplate>,
        /// Result threshold. Ignored when `scheduling.nrt` is true.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trigger: Option<SentinelTrigger>,
        /// Event grouping and incident grouping. Required at deploy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grouping: Option<SentinelGrouping>,
        /// Entity mappings from result columns.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entities: Option<Vec<SentinelEntityMapping>>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_durations() {
        for text in [
            "PT1H", "PT30M", "P1D", "p1w", "P1DT2H", "pt5m", "30m", "1h10m", "1d", "45s", " PT1H ",
            "",
        ] {
            assert_eq!(check_duration(text), Ok(()), "{text:?}");
        }
        for text in [
            "hourly", "1H", "P", "PT", "P1DT", "1x", "5", "-1h", "1h 10m",
        ] {
            let violation = check_duration(text).unwrap_err();
            assert_eq!(violation.kind, "value_error");
        }
        assert_eq!(
            check_duration("hourly").unwrap_err().message,
            "Value error, Duration 'hourly' is not an ISO 8601 duration (PT1H, PT30M, P1D) or a \
             shorthand duration (30m, 1h, 1d, 1h10m)"
        );
    }

    /// What deploy's `timedelta` holds passes; one second more, or a part
    /// too long for any integer, is refused (the oracle's deploy raised
    /// `OverflowError` on each, after validation accepted it).
    #[test]
    fn sentinel_durations_are_bounded_by_what_deploy_converts() {
        for text in [
            "P999999999DT23H59M59S",
            "86399999999999s",
            "999999999d23h59m59s",
            "P142857142W",
            "0d",
            "PT0S",
        ] {
            assert_eq!(check_duration(text), Ok(()), "{text:?}");
        }
        for text in [
            "1000000000d",
            "P99999999999D",
            "P142857143W",
            "86400000000000s",
            "P142857142WT1000000M",
            "P999999999DT24H",
            "99999999999999999999999999999999999999999d",
            "PT99999999999999999999999999999999999999999S",
        ] {
            let violation = check_duration(text).unwrap_err();
            assert_eq!(violation.kind, "value_error", "{text:?}");
            assert!(violation.message.contains("longer than"), "{text:?}");
        }
        assert_eq!(
            check_duration("1000000000d").unwrap_err().message,
            "Value error, Duration '1000000000d' is longer than a rule can be deployed with (at \
             most 999999999 days, 23 hours, 59 minutes and 59 seconds)"
        );
    }
}
