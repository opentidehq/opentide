//! HarfangLab Sigma or YARA rule, `platform::harfanglab::1.0`
//! (`HarfangLabConfig` and its nested models), harfanglab-1.0 1.2 and 1.3:
//! one kind per block, and a YARA rule as a whole `signature` or the
//! decomposed form ([`yara`]).
//!
//! | Oracle | Here |
//! |--------|------|
//! | `HarfangLabConfig._validate_raw_harfanglab_block` (before) | [`yara::block_codes`], the named check `harfanglab_rule_shape` |
//! | `HarfangLabYara._decomposed_form_is_complete` (after) | `decomposed_form`, the model's `after` |
//! | `DetectionRule._harfanglab_yara_rule_name` (after) | [`rule_name`], the rule model's `after` |

pub mod yara;

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::from_node::Context;
use crate::node::Node;
use crate::objects::checks::Violation;
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

/// One form: `signature`, or the decomposed `meta`, `strings`, `condition`, and `imports`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[garde(custom(garde_decomposed_form))]
#[schemars(rename = "HarfangLabYara")]
#[from_node(model = "HarfangLabYara", after = "decomposed_form")]
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
    /// A whole YARA text: imports, then one or more YARA rules, written out in the block. Deploy
    /// sends it as the YaraFile `content`, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("tide.template.multiline" = true))]
    pub signature: Option<String>,
    /// Decomposed form: scan context, OS, and optional score override. Required without
    /// `signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<HarfangLabYaraMeta>,
    /// Decomposed form: YARA string section body, one definition per line, without the
    /// `strings:` header. Required without `signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strings: Option<String>,
    /// Decomposed form: YARA condition body, without the `condition:` header. Required without
    /// `signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// Decomposed form: YARA modules (`pe`, `elf`). Each becomes `import "<module>"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imports: Option<Vec<String>>,
}

/// The message of `_decomposed_form_is_complete`.
fn decomposed_form_message(missing: &[&str]) -> String {
    format!(
        "a yara object sets signature, or the decomposed meta, strings and condition; missing {}",
        missing.join(", ")
    )
}

/// The decomposed form's keys a `yara` object without `signature` leaves
/// out (`_decomposed_form_is_complete`).
fn missing_keys(value: &HarfangLabYara) -> Vec<&'static str> {
    if value.signature.is_some() {
        return Vec::new();
    }
    [
        ("meta", value.meta.is_none()),
        ("strings", value.strings.is_none()),
        ("condition", value.condition.is_none()),
    ]
    .into_iter()
    .filter_map(|(key, absent)| absent.then_some(key))
    .collect()
}

/// `_decomposed_form_is_complete` (after): a `yara` object without
/// `signature` sets `meta`, `strings` and `condition`. As in Pydantic, it
/// runs only once the fields validated.
fn decomposed_form(value: &HarfangLabYara, node: &Node, cx: &mut Context) -> bool {
    let missing = missing_keys(value);
    if missing.is_empty() {
        return true;
    }
    Violation::value_error(decomposed_form_message(&missing)).report(node, cx);
    false
}

/// garde: `_decomposed_form_is_complete` on a value built in memory.
fn garde_decomposed_form(value: &HarfangLabYara, _pins: &Pins) -> garde::Result {
    let missing = missing_keys(value);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(garde::Error::new(format!(
            "Value error, {}",
            decomposed_form_message(&missing)
        )))
    }
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
    #[garde(custom(garde_block))]
    #[schemars(rename = "HarfangLabConfig", description = "")]
    #[from_node(model = "HarfangLabConfig", before = "raw_block")]
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
        /// Sigma tags, and the YARA `tags` meta line of the decomposed form.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tags: Option<Vec<String>>,
        /// Behavioural rule. Not with `yara`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sigma: Option<HarfangLabSigma>,
        /// File or memory scan rule. Not with `sigma`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub yara: Option<HarfangLabYara>,
    }
}

fn raw_block(node: &Node, cx: &mut Context) -> bool {
    crate::objects::platform::before("HarfangLabConfig", node, cx)
}

fn garde_block(block: &HarfangLabConfig, _pins: &Pins) -> garde::Result {
    crate::objects::platform::garde_named("HarfangLabConfig", block)
}

/// `DetectionRule._harfanglab_yara_rule_name` (after): the decomposed
/// HarfangLab YARA form names its YARA rule after the Tide rule `name`, and
/// libyara refuses a keyword, a non-ASCII letter or more than 128 characters.
/// `None` when the rule has no decomposed HarfangLab YARA block.
#[must_use]
pub fn rule_name(name: &str, block: Option<&HarfangLabConfig>) -> Option<String> {
    let yara = block?.yara.as_ref()?;
    if yara.signature.is_some() {
        return None;
    }
    let problem = yara::rule_name_problem(name)?;
    Some(format!(
        "DetectionRule validation failed with code(s): {} (rule {}: {problem})",
        yara::codes::RULE_NAME,
        yara::python_repr(name)
    ))
}
