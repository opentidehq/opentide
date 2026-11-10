//! Detection rule (MDR) models, schemas `rule::1.0` and `rule::1.1`
//! (`models/rule.py`), with the `configurations` container
//! (`models/platform.py` `RuleConfigurations`).
//!
//! The platform blocks are UC-1.4's (#810). Until they arrive each block is an
//! [`UncheckedBlock`]: the node the file holds, unchecked. Reading one is
//! behind the `unchecked-platform-blocks` feature, which only the oracle
//! comparisons (xtask) turn on, and the crate's own unit tests (`cfg(test)`),
//! so nothing ships that accepts a rule with unchecked blocks: without it,
//! the rule models and the container serialise and give their schema, and do
//! not read.

use std::collections::BTreeMap;

use garde::Validate;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::Serialize;

#[cfg(any(test, feature = "unchecked-platform-blocks"))]
use serde::Deserialize;

#[cfg(any(test, feature = "unchecked-platform-blocks"))]
use crate::FromNode;
use crate::objects::any::Any;
use crate::objects::metadata::{ObjectMetadata, ObjectReferences, RuleMetadata};
use crate::objects::response::RuleResponse;
use crate::pins::Pins;
use crate::revision::revisions;

/// A platform block, unchecked until its model arrives (UC-1.4, #810).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(any(test, feature = "unchecked-platform-blocks"), derive(Deserialize))]
#[serde(transparent)]
pub struct UncheckedBlock(pub Any);

#[cfg(any(test, feature = "unchecked-platform-blocks"))]
impl FromNode for UncheckedBlock {
    fn from_node(node: &crate::node::Node, cx: &mut crate::from_node::Context) -> Option<Self> {
        Any::from_node(node, cx).map(Self)
    }
}

impl JsonSchema for UncheckedBlock {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "UncheckedBlock".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "object"})
    }
}

/// Dynamically composed rule platform configurations.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema, Validate)]
#[cfg_attr(
    any(test, feature = "unchecked-platform-blocks"),
    derive(Deserialize, FromNode),
    from_node(model = "RuleConfigurations")
)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "RuleConfigurations")]
pub struct RuleConfigurations {
    /// Microsoft Sentinel analytics rule (`platform::sentinel::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub sentinel: Option<UncheckedBlock>,
    /// Microsoft Defender for Endpoint custom detection (`platform::defender_for_endpoint::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub defender_for_endpoint: Option<UncheckedBlock>,
    /// Splunk saved search (`platform::splunk::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub splunk: Option<UncheckedBlock>,
    /// SentinelOne STAR rule (`platform::sentinel_one::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub sentinel_one: Option<UncheckedBlock>,
    /// CrowdStrike Falcon correlation rule (`platform::crowdstrike::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub crowdstrike: Option<UncheckedBlock>,
    /// HarfangLab Sigma or YARA rule (`platform::harfanglab::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub harfanglab: Option<UncheckedBlock>,
    /// Carbon Black Cloud watchlist report (`platform::carbon_black_cloud::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub carbon_black_cloud: Option<UncheckedBlock>,
    /// Elastic Security detection rule (`platform::elastic::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub elastic: Option<UncheckedBlock>,
    /// Sysdig Secure or Falco rule (`platform::sysdig::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub sysdig: Option<UncheckedBlock>,
}

impl RuleConfigurations {
    /// The platforms, in the container's order.
    pub const PLATFORMS: [&'static str; 9] = [
        "sentinel",
        "defender_for_endpoint",
        "splunk",
        "sentinel_one",
        "crowdstrike",
        "harfanglab",
        "carbon_black_cloud",
        "elastic",
        "sysdig",
    ];

    /// Each block the rule has, with its platform, in the container's order.
    pub fn blocks(&self) -> Vec<(&'static str, &UncheckedBlock)> {
        let blocks = [
            &self.sentinel,
            &self.defender_for_endpoint,
            &self.splunk,
            &self.sentinel_one,
            &self.crowdstrike,
            &self.harfanglab,
            &self.carbon_black_cloud,
            &self.elastic,
            &self.sysdig,
        ];
        Self::PLATFORMS
            .into_iter()
            .zip(blocks)
            .filter_map(|(platform, block)| Some((platform, block.as_ref()?)))
            .collect()
    }
}

/// `file`'s schema: a path, as Pydantic writes a `Path` field.
fn file_schema(_: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "anyOf": [{"type": "string", "format": "path"}, {"type": "null"}]
    })
}

revisions! {
    shared [
        {
            /// Rule display name.
            #[garde(skip)]
            pub name: String,
        }
        {
            /// Rule narrative (multiline YAML encouraged).
            #[schemars(extend("tide.template.multiline" = true, "tide.template.spacer" = true))]
            #[garde(skip)]
            pub description: String,
            /// Read by no command: a rule deploys by each platform block's `status`
            /// (`platform_statuses`), the value promotion moves. Left out, it stays unset.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[garde(skip)]
            pub status: Option<String>,
            /// `alert_severity::1.0`. Deploy sends `response.alert_severity`
            /// (`alert_severity`); this is shown only when the rule has no `response`.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[garde(skip)]
            pub severity: Option<String>,
            /// MITRE ATT&CK technique ids (`att&ck::1.2`).
            #[serde(default)]
            #[schemars(extend("tide.field.role" = "techniques"))]
            #[garde(skip)]
            pub techniques: Vec<String>,
            /// Legacy flat platform dict (prefer `configurations`).
            #[serde(default)]
            #[schemars(extend("tide.template.hide" = true, "tide.field.role" = "configurations"))]
            #[garde(skip)]
            pub platforms: BTreeMap<String, BTreeMap<String, Any>>,
            /// External and internal references.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[garde(dive)]
            pub references: Option<ObjectReferences>,
            /// UUID of the objective, or of a signal defined under an objective, that this rule implements
            /// (`objective::1.0` or `objective::1.1`).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[garde(skip)]
            pub detection_model: Option<String>,
            /// Alert and response configuration.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[schemars(extend("tide.template.required" = true))]
            #[garde(dive)]
            pub response: Option<RuleResponse>,
            /// Typed per-platform configuration blocks.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[schemars(extend("tide.template.required" = true, "tide.field.role" = "configurations"))]
            #[garde(dive)]
            pub configurations: Option<RuleConfigurations>,
            /// Path of the file the rule was loaded from. Set by the loader, not written by authors.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[schemars(schema_with = "file_schema", extend("tide.template.hide" = true))]
            #[garde(skip)]
            pub file: Option<String>,
        }
    ]

    /// Code-first detection rule with registry-backed delegation helpers.
    #[derive(Debug, Clone, PartialEq, Serialize, JsonSchema, Validate)]
    #[cfg_attr(
        any(test, feature = "unchecked-platform-blocks"),
        derive(Deserialize, FromNode),
        from_node(model = "DetectionRule")
    )]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[schemars(rename = "DetectionRule")]
    pub struct RuleV1_0 {
        @0,
        /// Object metadata: identifier, schema, version, dates and TLP.
        #[schemars(extend("tide.template.spacer" = true))]
        #[garde(dive)]
        pub metadata: ObjectMetadata,
        @1,
    }

    /// Detection rule schema ``rule::1.1`` with optional ``metadata.reviewed``.
    #[derive(Debug, Clone, PartialEq, Serialize, JsonSchema, Validate)]
    #[cfg_attr(
        any(test, feature = "unchecked-platform-blocks"),
        derive(Deserialize, FromNode),
        from_node(model = "DetectionRule_v1_1")
    )]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[schemars(rename = "DetectionRule_v1_1")]
    pub struct RuleV1_1 {
        @0,
        /// Object metadata: identifier, schema, version, dates and TLP. This revision adds optional
        /// `reviewed`.
        #[schemars(extend("tide.template.spacer" = true))]
        #[garde(dive)]
        pub metadata: RuleMetadata,
        @1,
    }
}

/// The newest rule revision.
pub type Rule = RuleV1_1;

impl RuleV1_0 {
    /// The revision's schema identifier.
    pub const SCHEMA_IDENTIFIER: &'static str = "rule::1.0";
}

impl RuleV1_1 {
    /// The revision's schema identifier.
    pub const SCHEMA_IDENTIFIER: &'static str = "rule::1.1";
}

macro_rules! rule_helpers {
    ($($rule:ty),+) => {$(
        impl $rule {
            /// The severity a page shows: `response.alert_severity` when the
            /// rule has a `response` (what deploy sends), else an authored
            /// `severity`, else `None` (`displayed_severity`).
            pub fn displayed_severity(&self) -> Option<&str> {
                match &self.response {
                    Some(response) => Some(&response.alert_severity),
                    None => self.severity.as_deref(),
                }
            }

            /// `response.alert_severity`, or its default without a response
            /// (`alert_severity`).
            pub fn alert_severity(&self) -> &str {
                self.response.as_ref().map_or(
                    crate::objects::response::DEFAULT_ALERT_SEVERITY,
                    |response| &response.alert_severity,
                )
            }
        }
    )+};
}

rule_helpers!(RuleV1_0, RuleV1_1);
