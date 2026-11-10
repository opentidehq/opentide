//! Microsoft Defender for Endpoint custom detection,
//! `platform::defender_for_endpoint::1.0` (`DefenderConfig` and its nested
//! models).

use std::collections::BTreeMap;

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::objects::any::Any;
use crate::objects::platform::{literal_enum, platform_block};
use crate::pins::Pins;

/// Custom detection alert template (`DefenderAlert`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderAlert", description = "")]
#[from_node(model = "DefenderAlert")]
pub struct DefenderAlert {
    /// Defender alert category. Deploy removes spaces (`Suspicious Activity` is sent as
    /// `SuspiciousActivity`).
    pub category: String,
    /// Alert title. Deploy uses the rule `name` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Alert description. Deploy uses the rule `description` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `Informational`, `Low`, `Medium`, `High`, or `Critical`. Deploy uses
    /// `response.alert_severity` when omitted. `Critical` is sent as `high`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Recommended actions text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    /// Accepted on the block. The current deployer sends an empty technique list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub techniques: Option<Vec<String>>,
}

/// Columns that identify the impacted entity (`DefenderImpactedEntities`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderImpactedEntities", description = "")]
#[from_node(model = "DefenderImpactedEntities")]
pub struct DefenderImpactedEntities {
    /// Device column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Mailbox column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox: Option<String>,
    /// User column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

literal_enum! {
    /// `All` or `Specific`.
    Selection { All = "All", Specific = "Specific", }
}

/// Device-group scope (`DefenderGroupScoping`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderGroupScoping", description = "")]
#[from_node(model = "DefenderGroupScoping")]
pub struct DefenderGroupScoping {
    /// `All` or `Specific`.
    pub selection: Selection,
    /// Group names. Used when `selection` is `Specific`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_groups: Option<Vec<String>>,
}

/// Device groups an allow or block applies to (`DefenderAllowBlockGroupScoping`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderAllowBlockGroupScoping", description = "")]
#[from_node(model = "DefenderAllowBlockGroupScoping")]
pub struct DefenderAllowBlockGroupScoping {
    /// `All` or `Specific`.
    pub selection: Selection,
    /// Group names. Used when `selection` is `Specific`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_groups: Option<Vec<String>>,
}

literal_enum! {
    /// `Allow` or `Block`.
    AllowBlock { Allow = "Allow", Block = "Block", }
}

/// Allow or block a file identifier (`DefenderAllowBlockAction`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderAllowBlockAction", description = "")]
#[from_node(model = "DefenderAllowBlockAction")]
pub struct DefenderAllowBlockAction {
    /// `Allow` or `Block`.
    pub action: AllowBlock,
    /// Column identifying the file. Deploy lowercases the first character.
    pub identifier: String,
    /// Device groups the allow or block applies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<DefenderAllowBlockGroupScoping>,
}

/// File actions (`DefenderFileActions`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderFileActions", description = "")]
#[from_node(model = "DefenderFileActions")]
pub struct DefenderFileActions {
    /// Allow or block a file identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_block: Option<DefenderAllowBlockAction>,
    /// Column identifying the file to quarantine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine_file: Option<String>,
}

/// Device actions (`DefenderDeviceActions`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderDeviceActions", description = "")]
#[from_node(model = "DefenderDeviceActions")]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the model's fields, as the oracle declares them"
)]
pub struct DefenderDeviceActions {
    /// Isolation type. Deploy lowercases the first character (`Full` is sent as `full`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolate_device: Option<String>,
    /// Collect an investigation package.
    #[serde(default)]
    pub collect_investigation_package: bool,
    /// Run an antivirus scan.
    #[serde(default)]
    pub run_antivirus_scan: bool,
    /// Start an automated investigation.
    #[serde(default)]
    pub initiate_investigation: bool,
    /// Restrict app execution.
    #[serde(default)]
    pub restrict_app_execution: bool,
}

/// User actions (`DefenderUserActions`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderUserActions", description = "")]
#[from_node(model = "DefenderUserActions")]
pub struct DefenderUserActions {
    /// User column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark_as_compromised: Option<String>,
    /// User column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_user: Option<String>,
    /// User column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_password_reset: Option<String>,
}

/// Response actions (`DefenderResponseActions`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderResponseActions", description = "")]
#[from_node(model = "DefenderResponseActions")]
pub struct DefenderResponseActions {
    /// Device actions: isolate, collect an investigation package, scan, investigate or restrict app
    /// execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<DefenderDeviceActions>,
    /// File actions: allow or block, and quarantine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<DefenderFileActions>,
    /// User actions: mark as compromised, disable, or force a password reset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<DefenderUserActions>,
}

/// A per-tenant KQL fragment (`DefenderExclusion`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderExclusion", description = "")]
#[from_node(model = "DefenderExclusion")]
pub struct DefenderExclusion {
    /// KQL fragment appended after the base query. The key is required. An empty string is
    /// accepted.
    #[schemars(extend("tide.template.multiline" = true))]
    pub query: String,
    /// Why the exclusion exists. Not sent to Defender.
    pub reason: String,
    /// Limit the exclusion to one tenant name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// KQL `let` bindings. String, number, or boolean.
    #[serde(rename = "let", default, skip_serializing_if = "Option::is_none")]
    pub r#let: Option<BTreeMap<String, Any>>,
}

literal_enum! {
    /// `scheduling`: `NRT`, `1H`, `3H`, `12H`, or `24H`.
    DefenderSchedule { Nrt = "NRT", Hour1 = "1H", Hour3 = "3H", Hour12 = "12H", Hour24 = "24H", }
}

platform_block! {
    /// Microsoft Defender for Endpoint custom detection (`DefenderConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[schemars(rename = "DefenderConfig", description = "")]
    #[from_node(model = "DefenderConfig")]
    pub struct DefenderConfig ["platform::defender_for_endpoint::1.0"] {
        /// KQL. Multiline. Compiled with matching `exclusions` before deploy.
        #[schemars(extend("tide.template.multiline" = true, "tide.template.spacer" = true))]
        #[from_node(with = "crate::objects::platform::query_text")]
        #[garde(custom(crate::objects::platform::garde_query_text))]
        pub query: String,
        /// Custom detection alert template.
        pub alert: DefenderAlert,
        /// Columns that identify the impacted device, user, or mailbox.
        pub impacted_entities: DefenderImpactedEntities,
        /// `NRT`, `1H`, `3H`, `12H`, or `24H`.
        pub scheduling: DefenderSchedule,
        /// Response actions run when the detection fires.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<DefenderResponseActions>,
        /// Device-group scope. Required by registry load. The current deployer does not send it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<DefenderGroupScoping>,
        /// Per-tenant KQL fragments appended to `query`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exclusions: Option<Vec<DefenderExclusion>>,
    }
}
