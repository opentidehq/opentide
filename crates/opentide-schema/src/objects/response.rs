//! Detection rule response block models (`models/response.py`).

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::pins::Pins;

/// One supplemental hunt search (`ResponseSearch`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "ResponseSearch", description = "")]
#[from_node(model = "ResponseSearch")]
pub struct ResponseSearch {
    /// Why this search is run.
    #[garde(skip)]
    pub purpose: String,
    /// Target platform or system.
    #[garde(skip)]
    pub system: String,
    /// Query text.
    #[schemars(extend("tide.template.multiline" = true))]
    #[garde(skip)]
    pub query: String,
}

/// The analysis and containment procedure (`ResponseProcedure`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "ResponseProcedure", description = "")]
#[from_node(model = "ResponseProcedure")]
pub struct ResponseProcedure {
    /// Analysis steps narrative.
    #[schemars(extend("tide.template.multiline" = true))]
    #[garde(skip)]
    pub analysis: String,
    /// Supplemental hunt searches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub searches: Option<Vec<ResponseSearch>>,
    /// Containment guidance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub containment: Option<String>,
}

/// A rule's alert and response configuration (`RuleResponse`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "RuleResponse", description = "")]
#[from_node(model = "RuleResponse")]
pub struct RuleResponse {
    /// Alert severity vocabulary.
    #[serde(default = "default_alert_severity")]
    #[garde(skip)]
    pub alert_severity: String,
    /// Playbook identifier or URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub playbook: Option<String>,
    // `responders` is a configuration enum, not a vocabulary: the alert
    // handling team is per organisation, so the allowed values come from
    // `[[responders]]` in deployment.toml (#507).
    /// Alert-handling team. Free text, not a vocabulary: teams are configured per organisation in
    /// `deployment.toml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("tide.config.responders" = true))]
    #[garde(skip)]
    pub responders: Option<String>,
    /// Analysis and containment procedure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub procedure: Option<ResponseProcedure>,
}

/// `alert_severity`'s default.
pub const DEFAULT_ALERT_SEVERITY: &str = "Informational";

fn default_alert_severity() -> String {
    DEFAULT_ALERT_SEVERITY.to_owned()
}

impl Default for RuleResponse {
    fn default() -> Self {
        Self {
            alert_severity: default_alert_severity(),
            playbook: None,
            responders: None,
            procedure: None,
        }
    }
}
