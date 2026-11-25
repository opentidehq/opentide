//! Detection objective (DOM) models, schema `objective::1.0`
//! (`models/objective.py`).

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::objects::metadata::{ObjectMetadata, ObjectReferences};
use crate::pins::Pins;

/// A signal's data availability and requirements (`SignalData`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "SignalData", description = "")]
#[from_node(model = "SignalData")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SignalData",
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
pub struct SignalData {
    /// Data availability level.
    #[garde(skip)]
    pub availability: String,
    /// Data source requirements.
    #[garde(skip)]
    pub requirements: String,
    /// Log source names from the workspace `visibility.toml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("tide.config.visibility.logsource-names" = true))]
    #[garde(skip)]
    pub logsources: Option<Vec<String>>,
}

/// An external detector reference (`ExternalDetector`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "ExternalDetector", description = "")]
#[from_node(model = "ExternalDetector")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "ExternalDetector",
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
pub struct ExternalDetector {
    /// Detector name.
    #[garde(skip)]
    pub name: String,
    /// Technology identifier.
    #[garde(skip)]
    pub technology: String,
    /// Detector description.
    #[schemars(extend("tide.template.multiline" = true))]
    #[garde(skip)]
    pub description: String,
    /// Reference URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "uri"))]
    #[garde(skip)]
    pub link: Option<String>,
}

/// An example query (`DetectionExample`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "DetectionExample", description = "")]
#[from_node(model = "DetectionExample")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "DetectionExample",
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
pub struct DetectionExample {
    /// Example description.
    #[schemars(extend("tide.template.multiline" = true))]
    #[garde(skip)]
    pub description: String,
    /// Example URL.
    #[schemars(extend("format" = "uri"))]
    #[garde(skip)]
    pub link: String,
    /// Query language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub language: Option<String>,
    /// Example query text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("tide.template.multiline" = true))]
    #[garde(skip)]
    pub query: Option<String>,
}

/// Nested detection signal within a detection objective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "DetectionSignal")]
#[from_node(model = "DetectionSignal")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "DetectionSignal",
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
pub struct DetectionSignal {
    /// Signal name.
    #[garde(skip)]
    pub name: String,
    /// Signal UUID.
    #[garde(skip)]
    pub uuid: String,
    /// Signal description.
    #[schemars(extend("tide.template.multiline" = true))]
    #[garde(skip)]
    pub description: String,
    /// Alert severity vocabulary (`alert_severity::1.0`).
    #[schemars(extend("tide.vocab" = "alert_severity"))]
    #[garde(skip)]
    pub severity: String,
    /// Data availability and requirements.
    #[garde(dive)]
    pub data: SignalData,
    /// Detection methodology vocabulary.
    #[schemars(extend("tide.vocab" = true))]
    #[garde(skip)]
    pub methodology: String,
    // Scoped: the same entity name appears under two stages (Account, User,
    // Email, Token, Authentication, Permissions and API Call), so a host
    // account and a cloud account stay apart.
    /// Signal entity vocabulary values, stage-scoped (`signal.entities::1.0`; e.g. `Host::Process`,
    /// `Cloud::Account`).
    #[schemars(extend("tide.vocab" = true, "tide.vocab.scoped" = true))]
    #[garde(skip)]
    pub entities: Vec<String>,
    // Strict (`StrictInt`), so validation and the editor schema (`type:
    // integer`) refuse the same values: no quoted numbers or booleans.
    /// Implementation effort of the signal, a score from `1` (lowest) to `10` (highest). Values
    /// SHOULD be within that range. Not a vocabulary term.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub effort: Option<i64>,
    /// External detector references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub detectors: Option<Vec<ExternalDetector>>,
    /// Example queries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub examples: Option<Vec<DetectionExample>>,
    /// Parent signal UUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub parent: Option<String>,
}

/// How an objective's signals compose (`ObjectiveComposition`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "ObjectiveComposition", description = "")]
#[from_node(model = "ObjectiveComposition")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "ObjectiveComposition",
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
pub struct ObjectiveComposition {
    /// Detection composition strategy vocabulary.
    #[garde(skip)]
    pub strategy: String,
    /// How signals compose.
    #[schemars(extend("tide.template.multiline" = true))]
    #[garde(skip)]
    pub description: String,
}

/// The detection objective body (`ObjectiveBody`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "ObjectiveBody", description = "")]
#[from_node(model = "ObjectiveBody")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "ObjectiveBody",
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
pub struct ObjectiveBody {
    /// Priority level.
    #[garde(skip)]
    pub priority: String,
    /// Detection type vocabulary.
    #[garde(skip)]
    pub r#type: String,
    /// Objective narrative.
    #[schemars(extend("tide.template.multiline" = true))]
    #[garde(skip)]
    pub description: String,
    /// Detection signals. At least one.
    #[garde(dive)]
    pub signals: Vec<DetectionSignal>,
    /// Nested composition (same semantics as top-level).
    #[garde(dive)]
    pub composition: ObjectiveComposition,
    /// Investment level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub investment: Option<String>,
    /// Threat vector UUIDs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub threats: Option<Vec<String>>,
    /// ATT&CK technique ids (`att&ck::1.2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("tide.vocab" = true, "tide.field.role" = "techniques"))]
    #[garde(skip)]
    pub mitre_attack: Option<Vec<String>>,
}

/// Code-first detection objective model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "DetectionObjective")]
#[from_node(model = "DetectionObjective")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "DetectionObjective",
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
pub struct ObjectiveV1_0 {
    /// Objective display name.
    #[garde(skip)]
    pub name: String,
    /// Object metadata: identifier, schema, version, dates and TLP.
    #[schemars(extend("tide.template.spacer" = true))]
    #[garde(dive)]
    pub metadata: ObjectMetadata,
    /// Detection objective body.
    #[garde(dive)]
    pub objective: ObjectiveBody,
    /// External and internal references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(dive)]
    pub references: Option<ObjectReferences>,
}

/// The newest objective revision.
pub type Objective = ObjectiveV1_0;

impl ObjectiveV1_0 {
    /// The revision's schema identifier.
    pub const SCHEMA_IDENTIFIER: &'static str = "objective::1.0";
}
