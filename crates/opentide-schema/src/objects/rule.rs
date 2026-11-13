//! Detection rule (MDR) models, schemas `rule::1.0` and `rule::1.1`
//! (`models/rule.py`), with the `configurations` container
//! (`models/platform.py` `RuleConfigurations`).
//!
//! The platform blocks are [`crate::objects::platform`]'s (UC-1.4, #810).

use garde::Validate;
use indexmap::IndexMap;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::objects::any::Any;
use crate::objects::metadata::{ObjectMetadata, ObjectReferences, RuleMetadata};
use crate::objects::platform::{
    CarbonBlackConfig, CrowdstrikeConfig, DefenderConfig, ElasticConfig, ExabeamConfig,
    GoogleSecopsConfig, HarfangLabConfig, PlatformBlock, SentinelConfig, SentinelOneConfig,
    SplunkConfig, SysdigConfig,
};
use crate::objects::response::RuleResponse;
use crate::pins::Pins;
use crate::revision::revisions;

/// Dynamically composed rule platform configurations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[from_node(model = "RuleConfigurations")]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "RuleConfigurations")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "RuleConfigurations",
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
pub struct RuleConfigurations {
    /// Microsoft Sentinel analytics rule (`platform::sentinel::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub sentinel: Option<SentinelConfig>,
    /// Microsoft Defender for Endpoint custom detection (`platform::defender_for_endpoint::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub defender_for_endpoint: Option<DefenderConfig>,
    /// Splunk saved search (`platform::splunk::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub splunk: Option<SplunkConfig>,
    /// SentinelOne STAR rule (`platform::sentinel_one::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub sentinel_one: Option<SentinelOneConfig>,
    /// CrowdStrike Falcon correlation rule (`platform::crowdstrike::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub crowdstrike: Option<CrowdstrikeConfig>,
    /// HarfangLab Sigma or YARA rule (`platform::harfanglab::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub harfanglab: Option<HarfangLabConfig>,
    /// Carbon Black Cloud watchlist report (`platform::carbon_black_cloud::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub carbon_black_cloud: Option<CarbonBlackConfig>,
    /// Elastic Security detection rule (`platform::elastic::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub elastic: Option<ElasticConfig>,
    /// Sysdig Secure or Falco rule (`platform::sysdig::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub sysdig: Option<SysdigConfig>,
    /// Exabeam New-Scale SIEM correlation rule (`platform::exabeam::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub exabeam: Option<ExabeamConfig>,
    /// Google Security Operations YARA-L 2.0 detection rule (`platform::google_secops::1.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub google_secops: Option<GoogleSecopsConfig>,
}

impl RuleConfigurations {
    /// The platforms, in the container's order ([`crate::platforms`]).
    pub const PLATFORMS: [&'static str; crate::platforms::COUNT] =
        crate::platforms::ordered(crate::platforms::Order::Container);

    /// Each block's `status`, keyed by platform, in the container's order,
    /// for the blocks that are set and have one: what deploy and promotion
    /// use (`platform_statuses`).
    pub fn platform_statuses(&self) -> Vec<(&'static str, &str)> {
        let statuses = [
            self.sentinel.as_ref().map(PlatformBlock::status),
            self.defender_for_endpoint
                .as_ref()
                .map(PlatformBlock::status),
            self.splunk.as_ref().map(PlatformBlock::status),
            self.sentinel_one.as_ref().map(PlatformBlock::status),
            self.crowdstrike.as_ref().map(PlatformBlock::status),
            self.harfanglab.as_ref().map(PlatformBlock::status),
            self.carbon_black_cloud.as_ref().map(PlatformBlock::status),
            self.elastic.as_ref().map(PlatformBlock::status),
            self.sysdig.as_ref().map(PlatformBlock::status),
            self.exabeam.as_ref().map(PlatformBlock::status),
            self.google_secops.as_ref().map(PlatformBlock::status),
        ];
        Self::PLATFORMS
            .into_iter()
            .zip(statuses)
            .filter_map(|(platform, status)| Some((platform, status.filter(|s| !s.is_empty())?)))
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
            pub platforms: IndexMap<String, IndexMap<String, Any>>,
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
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[from_node(model = "DetectionRule")]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[schemars(rename = "DetectionRule")]
    #[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all, eq, name = "DetectionRule", module = "opentide._native.models"))]
    #[cfg_attr(feature = "python", expect(clippy::unsafe_derive_deserialize, reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"))]
    pub struct RuleV1_0 {
        @0,
        /// Object metadata: identifier, schema, version, dates and TLP.
        #[schemars(extend("tide.template.spacer" = true))]
        #[garde(dive)]
        pub metadata: ObjectMetadata,
        @1,
    }

    /// Detection rule schema ``rule::1.1`` with optional ``metadata.reviewed``.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[from_node(model = "DetectionRule_v1_1")]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[schemars(rename = "DetectionRule_v1_1")]
    #[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all, eq, name = "DetectionRule_v1_1", module = "opentide._native.models"))]
    #[cfg_attr(feature = "python", expect(clippy::unsafe_derive_deserialize, reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"))]
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
