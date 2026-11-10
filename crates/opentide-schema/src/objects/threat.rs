//! Threat vector (TVM) models, schema `threat::1.0` (`models/threat.py`).

use std::collections::BTreeMap;

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::objects::checks;
use crate::objects::metadata::{ObjectMetadata, ObjectReferences};
use crate::pins::Pins;

/// One attributed actor on a threat vector (the ``actors`` vocabulary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "ThreatActor")]
#[from_node(model = "ThreatActor")]
pub struct ThreatActor {
    /// Scoped `actors::1.0` value: `att&ck::<id>` or `misp::<id>`.
    #[schemars(extend("tide.vocab" = "actors", "tide.vocab.scoped" = true))]
    #[garde(skip)]
    pub name: String,
    /// Optional sighting note or date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("tide.template.multiline" = true))]
    #[garde(skip)]
    pub sighting: Option<String>,
    /// Optional actor reference URLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub references: Option<Vec<String>>,
}

/// `killchain: str | list[str]`: one kill chain stage or several.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, FromNode)]
#[serde(untagged)]
#[from_node(union)]
pub enum Killchain {
    /// One stage.
    #[from_node(tag = "str")]
    #[schemars(description = "")]
    One(String),
    /// Several stages.
    #[from_node(tag = "list[str]")]
    #[schemars(description = "")]
    Many(Vec<String>),
}

/// The threat assessment body (`ThreatBody`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "ThreatBody", description = "")]
#[from_node(model = "ThreatBody")]
pub struct ThreatBody {
    /// Narrative description.
    #[schemars(extend("tide.template.multiline" = true))]
    #[garde(skip)]
    pub description: String,
    /// Threat severity vocabulary (`severity::1.0`).
    #[schemars(extend("tide.vocab" = true))]
    #[garde(skip)]
    pub severity: String,
    /// Impact vocabulary names (`impact::1.0`); non-empty.
    #[schemars(extend("tide.vocab" = true))]
    #[from_node(
        before = "crate::from_node::require_vocab_list",
        with = "checks::vocab_names"
    )]
    #[garde(length(min = 1), inner(custom(checks::garde_single_vocab_name)))]
    pub impact: Vec<String>,
    /// Leverage vocabulary names (`leverage::1.0`); non-empty.
    #[schemars(extend("tide.vocab" = true))]
    #[from_node(
        before = "crate::from_node::require_vocab_list",
        with = "checks::vocab_names"
    )]
    #[garde(length(min = 1), inner(custom(checks::garde_single_vocab_name)))]
    pub leverage: Vec<String>,
    /// Viability vocabulary (`viability::1.0`).
    #[schemars(extend("tide.vocab" = true))]
    #[garde(skip)]
    pub viability: String,
    /// Explanatory narrative about where/how the threat operates.
    #[garde(skip)]
    pub terrain: String,
    // `surface` keys are grouped by stage and the same key name appears under
    // two stages (VPN, Wireless and Industrial are each both Infrastructure
    // and Protocol): scoped, so every value is reachable.
    /// Threat surface vocabulary values (`surface::1.0`).
    #[schemars(extend("tide.vocab" = true, "tide.vocab.scoped" = true))]
    #[garde(skip)]
    pub surface: Vec<String>,
    /// MITRE ATT&CK technique ids (`att&ck::1.2`).
    #[schemars(extend("tide.vocab" = true, "tide.field.role" = "techniques"))]
    #[garde(skip)]
    pub mitre_attack: Vec<String>,
    /// Threat actors attributed to this vector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("tide.field.role" = "actors"))]
    #[garde(dive)]
    pub actors: Option<Vec<ThreatActor>>,
    /// Kill chain stage(s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("tide.vocab" = true))]
    #[garde(skip)]
    pub killchain: Option<Killchain>,
    /// Vector chaining relationships.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub chaining: Option<Vec<BTreeMap<String, String>>>,
    /// CVE identifiers the threat exploits (`CVE-2024-3400`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(title = "CVE")]
    #[garde(skip)]
    pub cve: Option<Vec<String>>,
}

/// Code-first threat vector model (replaces raw TVM dict entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "ThreatVector")]
#[from_node(model = "ThreatVector")]
pub struct ThreatVectorV1_0 {
    /// Threat vector display name.
    #[garde(skip)]
    pub name: String,
    /// Criticality vocabulary value.
    #[schemars(extend("tide.vocab" = true))]
    #[garde(skip)]
    pub criticality: String,
    /// Object metadata: identifier, schema, version, dates and TLP.
    #[schemars(extend("tide.template.spacer" = true))]
    #[garde(dive)]
    pub metadata: ObjectMetadata,
    /// Threat assessment body.
    #[garde(dive)]
    pub threat: ThreatBody,
    /// External and internal references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub references: Option<ObjectReferences>,
}

/// The newest threat vector revision.
pub type ThreatVector = ThreatVectorV1_0;

impl ThreatVectorV1_0 {
    /// The revision's schema identifier.
    pub const SCHEMA_IDENTIFIER: &'static str = "threat::1.0";
}
