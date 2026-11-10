//! HarfangLab Sigma or YARA rule, `platform::harfanglab::1.0`
//! (`HarfangLabConfig` and its nested models).

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::objects::platform::platform_block;
use crate::pins::Pins;

/// Sigma logsource (`HarfangLabSigmaLogSource`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "HarfangLabSigmaLogSource", description = "")]
#[from_node(model = "HarfangLabSigmaLogSource")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "HarfangLabSigmaLogSource",
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
pub struct HarfangLabSigmaLogSource {
    /// Sigma logsource category (`process_creation`).
    pub category: String,
    /// Sigma logsource product (`windows`).
    pub product: String,
}

/// A selection's match value: `str | list[str] | bool | int | float`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, FromNode)]
#[serde(untagged)]
#[from_node(union)]
pub enum SelectionValue {
    /// A string.
    #[from_node(tag = "str")]
    #[schemars(description = "")]
    Text(String),
    /// A Sigma list.
    #[from_node(tag = "list[str]")]
    #[schemars(description = "")]
    List(Vec<String>),
    /// A boolean.
    #[from_node(tag = "bool")]
    #[schemars(description = "")]
    Bool(bool),
    /// An integer.
    #[from_node(tag = "int")]
    #[schemars(description = "")]
    Int(i64),
    /// A number.
    #[from_node(tag = "float")]
    #[schemars(
        description = "",
        schema_with = "crate::objects::platform::number_schema"
    )]
    Float(f64),
}

/// A named selection (`HarfangLabSigmaSelection`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "HarfangLabSigmaSelection", description = "")]
#[from_node(model = "HarfangLabSigmaSelection")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "HarfangLabSigmaSelection",
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
pub struct HarfangLabSigmaSelection {
    /// Selection name used by `condition`.
    pub name: String,
    /// Event field (`Image`, `CommandLine`).
    pub field: String,
    /// Match value. A list is a Sigma list.
    pub value: SelectionValue,
    /// Sigma modifiers (`contains`, `endswith`). Empty when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modifiers: Option<Vec<String>>,
}

/// Behavioural rule (`HarfangLabSigma`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "HarfangLabSigma", description = "")]
#[from_node(model = "HarfangLabSigma")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "HarfangLabSigma",
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
pub struct HarfangLabSigma {
    /// Sigma logsource: `category` and `product`.
    pub logsource: HarfangLabSigmaLogSource,
    /// Named selections.
    pub selections: Vec<HarfangLabSigmaSelection>,
    /// Sigma condition expression (`selection`, `selection1 and selection2`).
    pub condition: String,
    /// Sigma false-positive notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub false_positives: Option<Vec<String>>,
}

/// Scan context, OS, and optional score override (`HarfangLabYaraMeta`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "HarfangLabYaraMeta", description = "")]
#[from_node(model = "HarfangLabYaraMeta")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "HarfangLabYaraMeta",
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
pub struct HarfangLabYaraMeta {
    /// Scan contexts. The value `file` is rewritten from `os`: `Windows` → `file.pe`, `MacOS` →
    /// `file.macho`, `Linux` → `file.elf`. Other context values are kept.
    pub context: Vec<String>,
    /// `Windows`, `MacOS`, or `Linux`. Also written to meta `os`.
    pub os: String,
    /// Architectures, joined with commas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<Vec<String>>,
    /// `Informational`, `Low`, `Medium`, `High`, or `Critical`. A known value overrides the score
    /// taken from `response.alert_severity`. An unknown value falls back to that severity, then to
    /// 50.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<String>,
    /// Free-form classification written to meta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
}

/// File or memory scan rule (`HarfangLabYara`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "HarfangLabYara", description = "")]
#[from_node(model = "HarfangLabYara")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "HarfangLabYara",
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
pub struct HarfangLabYara {
    /// Scan context, OS, and optional score override.
    pub meta: HarfangLabYaraMeta,
    /// YARA string section body, one definition per line, without the `strings:` header.
    pub strings: String,
    /// YARA condition body, without the `condition:` header.
    pub condition: String,
    /// YARA modules (`pe`, `elf`). Each becomes `import "<module>"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imports: Option<Vec<String>>,
}

fn experimental() -> String {
    "Experimental".to_owned()
}

fn moderate() -> String {
    "Moderate".to_owned()
}

fn alert() -> String {
    "Alert".to_owned()
}

platform_block! {
    /// HarfangLab Sigma or YARA rule (`HarfangLabConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[schemars(rename = "HarfangLabConfig", description = "")]
    #[from_node(model = "HarfangLabConfig")]
    #[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all, eq, name = "HarfangLabConfig", module = "opentide._native.models"))]
    #[cfg_attr(feature = "python", expect(clippy::unsafe_derive_deserialize, reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"))]
    pub struct HarfangLabConfig ["platform::harfanglab::1.0"] {
        /// Rule maturity. Mapped to HarfangLab `hl_status`.
        #[serde(default = "experimental")]
        pub maturity: String,
        /// Analyst confidence. Mapped to `rule_confidence_override`.
        #[serde(default = "moderate")]
        pub confidence: String,
        /// What the agent does on a match. Mapped to `global_state`.
        #[serde(default = "alert")]
        pub action: String,
        /// Sigma tags, and the YARA `tags` meta line.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tags: Option<Vec<String>>,
        /// Behavioural rule. Preferred when `yara` is also set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sigma: Option<HarfangLabSigma>,
        /// File or memory scan rule.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub yara: Option<HarfangLabYara>,
    }
}
