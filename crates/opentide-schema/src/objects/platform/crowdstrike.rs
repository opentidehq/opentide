//! CrowdStrike Falcon correlation rule, `platform::crowdstrike::1.0`
//! (`CrowdstrikeConfig` and its nested models).

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::from_node::Context;
use crate::node::Node;
use crate::objects::checks::Violation;
use crate::objects::platform::platform_block;
use crate::pins::Pins;

/// The values `details.trigger` takes, in any case.
const TRIGGERS: [&str; 2] = ["verbose", "summary"];
/// The values `details.outcome` takes, in any case.
const OUTCOMES: [&str; 2] = ["detection", "incident"];

/// `details.<field>` is one of `choices` in any case, as deploy lowercases
/// it and then refuses anything else (B2: `trigger: sometimes` passed
/// `validate` and the dry run, and failed the deploy).
fn check_one_of(field: &str, value: &str, choices: &[&str]) -> Result<(), Violation> {
    if choices.contains(&value.to_lowercase().as_str()) {
        return Ok(());
    }
    Err(Violation::value_error(format!(
        "details.{field} is {}, not {value:?}",
        choices.join(" or ")
    )))
}

fn one_of(field: &str, choices: &[&str], node: &Node, cx: &mut Context) -> Option<String> {
    let value = String::from_node(node, cx)?;
    match check_one_of(field, &value, choices) {
        Ok(()) => Some(value),
        Err(violation) => {
            violation.report(node, cx);
            None
        }
    }
}

fn trigger(node: &Node, cx: &mut Context) -> Option<String> {
    one_of("trigger", &TRIGGERS, node, cx)
}

fn outcome(node: &Node, cx: &mut Context) -> Option<String> {
    one_of("outcome", &OUTCOMES, node, cx)
}

fn garde_trigger(value: &str, _pins: &Pins) -> garde::Result {
    check_one_of("trigger", value, &TRIGGERS).map_err(Violation::into_garde)
}

fn garde_outcome(value: &str, _pins: &Pins) -> garde::Result {
    check_one_of("outcome", value, &OUTCOMES).map_err(Violation::into_garde)
}

/// Correlation outcome, trigger mode, and alert metadata (`CrowdstrikeDetails`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "CrowdstrikeDetails", description = "")]
#[from_node(model = "CrowdstrikeDetails")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "CrowdstrikeDetails",
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
pub struct CrowdstrikeDetails {
    /// `verbose` or `summary`, any case. Deploy lowercases the value.
    #[from_node(with = "trigger")]
    #[garde(custom(garde_trigger))]
    pub trigger: String,
    /// `detection` or `incident`, any case. Deploy lowercases the value.
    #[from_node(with = "outcome")]
    #[garde(custom(garde_outcome))]
    pub outcome: String,
    /// Falcon rule name. Deploy uses the Tide rule `name` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Falcon description. Deploy uses the Tide rule `description` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `Informational`, `Low`, `Medium`, `High`, or `Critical`. Deploy uses
    /// `response.alert_severity` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Falcon tactic. Sent as given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tactic: Option<String>,
    /// Falcon technique. Sent as given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub technique: Option<String>,
}

/// How often the search runs and how far it looks back (`CrowdstrikeSchedule`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "CrowdstrikeSchedule", description = "")]
#[from_node(model = "CrowdstrikeSchedule")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "CrowdstrikeSchedule",
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
pub struct CrowdstrikeSchedule {
    /// Run interval. Deploy sends it as `@every <frequency>` (`@every 1h`).
    pub frequency: String,
    /// How far back each run searches. Sent as the search lookback.
    pub lookback: String,
    /// Do not run before this UTC time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    /// Stop running at this UTC time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
}

platform_block! {
    /// CrowdStrike Falcon correlation rule (`CrowdstrikeConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[schemars(rename = "CrowdstrikeConfig", description = "")]
    #[from_node(model = "CrowdstrikeConfig")]
    #[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all, eq, name = "CrowdstrikeConfig", module = "opentide._native.models"))]
    #[cfg_attr(feature = "python", expect(clippy::unsafe_derive_deserialize, reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"))]
    pub struct CrowdstrikeConfig ["platform::crowdstrike::1.0"] {
        /// Correlation outcome, trigger mode, and alert metadata.
        pub details: CrowdstrikeDetails,
        /// How often the correlation search runs and how far it looks back.
        pub schedule: CrowdstrikeSchedule,
        /// Correlation filter. Multiline. Sent as the rule `filter`.
        #[schemars(extend("tide.template.multiline" = true, "tide.template.spacer" = true))]
        #[from_node(with = "crate::objects::platform::query_text")]
        #[garde(custom(crate::objects::platform::garde_query_text))]
        pub query: String,
    }
}
