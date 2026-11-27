//! Microsoft Sentinel analytics rule, `platform::sentinel::1.0`
//! (`SentinelConfig` and its nested models).

use std::borrow::Cow;

use garde::Validate;
use indexmap::IndexMap;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::configuration::repr;
use crate::from_node::{Context, Shape};
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
    let text = value.trim();
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

/// The most days deploy's duration holds: 999,999,999.
pub const MAX_DURATION_DAYS: u64 = 999_999_999;

/// The longest duration deploy converts, in seconds: [`MAX_DURATION_DAYS`]
/// and a day less one second, in whole seconds.
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

/// `scheduling.frequency` is 5 minutes to 14 days.
pub const FREQUENCY: &str = opentide_core::codes::SENTINEL_FREQUENCY;
/// `scheduling.lookback` is 5 minutes to 14 days, and at least `frequency`.
pub const LOOKBACK: &str = opentide_core::codes::SENTINEL_LOOKBACK;

/// Every code [`schedule_findings`] reports.
pub const CONSTRAINT_CODES: [&str; 2] = [FREQUENCY, LOOKBACK];

/// The shortest frequency and lookback Sentinel takes, in seconds: 5 minutes.
pub const SCHEDULE_MIN_SECONDS: u64 = 5 * 60;

/// The longest frequency and lookback Sentinel takes, in seconds: 14 days.
pub const SCHEDULE_MAX_SECONDS: u64 = 14 * 86_400;

/// One broken bound of a scheduled rule: its code, the key under
/// `scheduling` it is about, and what is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleFinding {
    /// [`FREQUENCY`] or [`LOOKBACK`].
    pub code: &'static str,
    /// `frequency` or `lookback`.
    pub key: &'static str,
    /// The message.
    pub message: String,
}

/// The bounds Microsoft documents for a scheduled rule's "Run query every"
/// and "Lookup data from the last" (learn.microsoft.com/en-us/azure/sentinel/
/// scheduled-rules-overview, read 2026-11-27): "The allowed range for both of
/// these parameters is from 5 minutes to 14 days", and "The query interval
/// must be shorter than or equal to the lookback period". Sentinel refuses a
/// rule outside them at deploy.
///
/// A near-real-time rule (`nrt: true`) is not judged: deploy sends neither
/// field. Neither is a value that is empty or not a duration
/// ([`check_duration`] reports the latter, deploy asks for the former).
pub fn schedule_findings(
    nrt: Option<bool>,
    frequency: Option<&str>,
    lookback: Option<&str>,
) -> Vec<ScheduleFinding> {
    let mut found = Vec::new();
    if nrt == Some(true) {
        return found;
    }
    let seconds = |value: Option<&str>| match value.map(str::trim) {
        Some(text) if !text.is_empty() => match duration_seconds(text) {
            Length::Seconds(seconds) => Some(seconds),
            Length::NotADuration | Length::TooLong => None,
        },
        _ => None,
    };
    let every = seconds(frequency);
    let window = seconds(lookback);
    for (code, key, value, length) in [
        (FREQUENCY, "frequency", frequency, every),
        (LOOKBACK, "lookback", lookback, window),
    ] {
        let Some(length) = length else {
            continue;
        };
        let bound = if length < SCHEDULE_MIN_SECONDS {
            "shorter than 5 minutes"
        } else if length > SCHEDULE_MAX_SECONDS {
            "longer than 14 days"
        } else {
            continue;
        };
        found.push(ScheduleFinding {
            code,
            key,
            message: format!(
                "scheduling.{key} {} is {bound}: Sentinel takes a scheduled rule's {key} from 5 \
                 minutes to 14 days",
                repr::quote(value.unwrap_or_default())
            ),
        });
    }
    if let (Some(every), Some(window)) = (every, window)
        && window < every
        && !found.iter().any(|finding| finding.code == LOOKBACK)
    {
        found.push(ScheduleFinding {
            code: LOOKBACK,
            key: "lookback",
            message: format!(
                "scheduling.lookback {} is shorter than frequency {}: Sentinel requires the \
                 lookback to be at least the frequency, or the rule's runs leave gaps",
                repr::quote(lookback.unwrap_or_default()),
                repr::quote(frequency.unwrap_or_default())
            ),
        });
    }
    found
}

/// [`schedule_findings`] as a `mode="after"` validator: each finding an error
/// typed by its code, at its key.
fn schedule_bounds(value: &SentinelScheduling, node: &Node, cx: &mut Context) -> bool {
    let found = schedule_findings(
        value.nrt,
        value.frequency.as_deref(),
        value.lookback.as_deref(),
    );
    for finding in &found {
        let input = match &node.value {
            crate::node::Value::Map(entries) => entries
                .iter()
                .find(|entry| entry.key.value.as_str() == Some(finding.key))
                .map_or(node, |entry| entry.value.as_ref()),
            _ => node,
        };
        cx.at_key(finding.key, |cx| {
            cx.error(
                crate::error::ErrorKind::Constraint(finding.code),
                finding.message.clone(),
                input,
            );
        });
    }
    found.is_empty()
}

/// garde: [`schedule_findings`] on a value built in memory.
fn garde_schedule(value: &SentinelScheduling, _pins: &Pins) -> garde::Result {
    match schedule_findings(
        value.nrt,
        value.frequency.as_deref(),
        value.lookback.as_deref(),
    )
    .first()
    {
        None => Ok(()),
        Some(first) => Err(garde::Error::new(format!(
            "{}: scheduling.{}: {}",
            first.code, first.key, first.message
        ))),
    }
}

/// Run cadence, or NRT (`SentinelScheduling`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[garde(custom(garde_schedule))]
#[schemars(rename = "SentinelScheduling", description = "")]
#[from_node(model = "SentinelScheduling", after = "schedule_bounds")]
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
    Duration(String),
    /// `false` disables suppression.
    #[schemars(description = "")]
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

    fn shape() -> Shape {
        Shape::String
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
    /// Sentinel tactic names (the ARM `AttackTactic` enum), sent when set; an empty list counts
    /// as unset. Left out, the tactics are those of the techniques that are sent: each `att&ck`
    /// stage maps to the tactic of the same name. Stealth, Defense Impairment, and the ICS Evasion
    /// tactic map to `DefenseEvasion`. A stage with no Sentinel tactic is dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tactics: Option<Vec<String>>,
    /// ATT&CK v18 technique and sub-technique ids, the ATT&CK version Sentinel is aligned to. A
    /// sub-technique is sent in `subTechniques` and its parent in `techniques`. Sent when set; an
    /// empty list counts as unset. Left out, the techniques of the rule's objective are sent.
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

    /// Microsoft's bounds (#1916): 5 minutes to 14 days each, the lookback
    /// at least the frequency, compared in seconds whatever the spelling.
    #[test]
    fn schedule_bounds() {
        let codes = |nrt: Option<bool>, frequency: Option<&str>, lookback: Option<&str>| {
            schedule_findings(nrt, frequency, lookback)
                .into_iter()
                .map(|finding| (finding.code, finding.key))
                .collect::<Vec<_>>()
        };
        // Inside the bounds, at both ends and across spellings.
        assert!(codes(None, Some("5m"), Some("PT5M")).is_empty());
        assert!(codes(None, Some("PT1H"), Some("60m")).is_empty());
        assert!(codes(None, Some("14d"), Some("P2W")).is_empty());
        assert!(codes(Some(false), Some("300s"), Some("1209600s")).is_empty());
        // Below 5 minutes, above 14 days.
        assert_eq!(
            codes(None, Some("4m59s"), Some("1h")),
            [(FREQUENCY, "frequency")]
        );
        assert_eq!(
            codes(None, Some("1h"), Some("14d1s")),
            [(LOOKBACK, "lookback")]
        );
        assert_eq!(
            codes(None, Some("P15D"), Some("P15D")),
            [(FREQUENCY, "frequency"), (LOOKBACK, "lookback")]
        );
        assert_eq!(codes(None, Some("0m"), None), [(FREQUENCY, "frequency")]);
        // The lookback shorter than the frequency, once.
        assert_eq!(
            codes(None, Some("2h"), Some("PT1H")),
            [(LOOKBACK, "lookback")]
        );
        assert_eq!(
            codes(None, Some("1h"), Some("1m")),
            [(LOOKBACK, "lookback")]
        );
        // Not judged: NRT, absent, empty, or not a duration.
        assert!(codes(Some(true), Some("1m"), Some("30d")).is_empty());
        assert!(codes(None, None, None).is_empty());
        assert!(codes(None, Some("  "), Some("hourly")).is_empty());
        // The message names the value and the bounds.
        let [finding] = schedule_findings(None, Some("1m"), None)
            .try_into()
            .unwrap();
        assert_eq!(
            finding.message,
            "scheduling.frequency \"1m\" is shorter than 5 minutes: Sentinel takes a scheduled \
             rule's frequency from 5 minutes to 14 days"
        );
    }

    /// The conversion reports each finding typed by its code, at its key;
    /// garde reports the first on a value built in memory.
    #[test]
    fn schedule_bounds_in_the_conversion_and_garde() {
        let document = crate::node::load("frequency: 2h\nlookback: 1m\n").unwrap();
        let root = document.root().unwrap();
        let mut cx = Context::new();
        assert!(SentinelScheduling::from_node(root, &mut cx).is_none());
        let errors = cx.into_errors();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(
            errors[0].kind,
            crate::error::ErrorKind::Constraint(LOOKBACK)
        );
        assert_eq!(
            errors[0].path,
            [crate::error::PathSegment::Key("lookback".into())]
        );
        let built = SentinelScheduling {
            nrt: None,
            frequency: Some("1m".into()),
            lookback: Some("1h".into()),
        };
        let error = built.validate_with(&Pins::default()).unwrap_err();
        assert!(error.to_string().contains("sentinel_frequency"), "{error}");
    }

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
            "Duration \"hourly\" is not an ISO 8601 duration (PT1H, PT30M, P1D) or a \
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
            "Duration \"1000000000d\" is longer than a rule can be deployed with (at \
             most 999999999 days, 23 hours, 59 minutes and 59 seconds)"
        );
    }
}
