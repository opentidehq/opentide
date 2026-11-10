//! SentinelOne STAR rule, `platform::sentinel_one::1.0` (`SentinelOneConfig`
//! and its nested models).

use std::borrow::Cow;

use garde::Validate;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::FromNode;
use crate::error::ErrorKind;
use crate::from_node::Context;
use crate::node::{Node, Value};
use crate::objects::platform::{literal_enum, platform_block};
use crate::pins::Pins;

/// Overrides for name, description, severity, and expiration (`SentinelOneDetails`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelOneDetails", description = "")]
#[from_node(model = "SentinelOneDetails")]
pub struct SentinelOneDetails {
    /// STAR rule name. Deploy uses the Tide rule `name` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// STAR description. Deploy uses the Tide rule `description` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Sent as the STAR severity string. When omitted, deploy maps `response.alert_severity`:
    /// `Informational` and `Low` become `Low`; `Medium`, `High`, and `Critical` keep those names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// When set, the rule is `Temporary` and this value is the expiration. When omitted, the rule is
    /// `Permanent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
}

/// A single-event query (`SentinelOneSingleEvent`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelOneSingleEvent", description = "")]
#[from_node(model = "SentinelOneSingleEvent")]
pub struct SentinelOneSingleEvent {
    /// S1QL. Multiline. Sent as `queryType: events`.
    #[schemars(extend("tide.template.multiline" = true))]
    pub query: String,
}

/// A correlation sub-query (`SentinelOneSubQuery`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelOneSubQuery", description = "")]
#[from_node(model = "SentinelOneSubQuery")]
pub struct SentinelOneSubQuery {
    /// S1QL sub-query. Multiline.
    #[schemars(extend("tide.template.multiline" = true))]
    pub query: String,
    /// Number of matches this sub-query needs within the correlation window.
    pub matches_required: i64,
}

/// A correlation query (`SentinelOneCorrelation`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelOneCorrelation", description = "")]
#[from_node(model = "SentinelOneCorrelation")]
pub struct SentinelOneCorrelation {
    /// Entity the sub-queries correlate on (`host`, `user`, …).
    pub entity: String,
    /// Whether sub-queries must match in list order.
    pub match_in_order: bool,
    /// Correlation window (`1h`, `30m`).
    pub time_window: String,
    /// Each item has `query` (S1QL) and `matches_required` (int).
    pub sub_queries: Vec<SentinelOneSubQuery>,
}

literal_enum! {
    /// `Single Event` or `Correlation`.
    ConditionType { SingleEvent = "Single Event", Correlation = "Correlation", }
}

/// Single-event or correlation query (`SentinelOneCondition`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelOneCondition", description = "")]
#[from_node(model = "SentinelOneCondition")]
pub struct SentinelOneCondition {
    /// `Single Event` or `Correlation`.
    pub r#type: ConditionType,
    /// Required at deploy when `type` is `Single Event`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_event: Option<SentinelOneSingleEvent>,
    /// Required at deploy when `type` is `Correlation`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<SentinelOneCorrelation>,
    /// Renotify window (`30m`, `1h`). Intended to become `renotifyMinutes`. The current deployer
    /// does not convert it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cool_off: Option<String>,
}

/// `treat_as_threat`: `Literal[False, "Malicious", "Suspicious"]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreatAsThreat {
    /// `false`, sent as `UNDEFINED`.
    No,
    /// `Malicious`.
    Malicious,
    /// `Suspicious`.
    Suspicious,
}

/// Pydantic's `expected` for the literal.
const TREAT_AS_THREAT_EXPECTED: &str = "False, 'Malicious' or 'Suspicious'";

impl FromNode for TreatAsThreat {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        match &node.value {
            Value::Bool(false) => return Some(Self::No),
            Value::Str(text) if text == "Malicious" => return Some(Self::Malicious),
            Value::Str(text) if text == "Suspicious" => return Some(Self::Suspicious),
            _ => {}
        }
        cx.error_with(
            ErrorKind::InvalidValue("literal_error"),
            format!("Input should be {TREAT_AS_THREAT_EXPECTED}"),
            node,
            &[("expected", TREAT_AS_THREAT_EXPECTED.to_owned())],
        );
        None
    }
}

impl Serialize for TreatAsThreat {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::No => serializer.serialize_bool(false),
            Self::Malicious => serializer.serialize_str("Malicious"),
            Self::Suspicious => serializer.serialize_str("Suspicious"),
        }
    }
}

impl<'de> Deserialize<'de> for TreatAsThreat {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Flag(bool),
            Text(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Flag(false) => Ok(Self::No),
            Raw::Text(text) if text == "Malicious" => Ok(Self::Malicious),
            Raw::Text(text) if text == "Suspicious" => Ok(Self::Suspicious),
            _ => Err(serde::de::Error::custom(format!(
                "expected {TREAT_AS_THREAT_EXPECTED}"
            ))),
        }
    }
}

impl JsonSchema for TreatAsThreat {
    fn schema_name() -> Cow<'static, str> {
        "TreatAsThreat".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"enum": [false, "Malicious", "Suspicious"]})
    }
}

/// Threat verdict and network quarantine (`SentinelOneResponse`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SentinelOneResponse", description = "")]
#[from_node(model = "SentinelOneResponse")]
pub struct SentinelOneResponse {
    /// `false` is sent as `UNDEFINED`.
    pub treat_as_threat: TreatAsThreat,
    /// Quarantine the endpoint from the network.
    pub network_quarantine: bool,
}

platform_block! {
    /// SentinelOne STAR rule (`SentinelOneConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[schemars(rename = "SentinelOneConfig", description = "")]
    #[from_node(model = "SentinelOneConfig")]
    pub struct SentinelOneConfig ["platform::sentinel_one::1.0"] {
        /// Single-event or correlation query.
        pub condition: SentinelOneCondition,
        /// Threat verdict and network quarantine. Omitted means neither action is sent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub response: Option<SentinelOneResponse>,
        /// Overrides for name, description, severity, and expiration.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub details: Option<SentinelOneDetails>,
    }
}
