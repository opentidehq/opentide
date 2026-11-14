//! Bitdefender GravityZone custom detection rule, `platform::bitdefender::1.0`
//! (`BitdefenderConfig` and its nested models), with the named check
//! `bitdefender_rule_shape` ([`checks::block_findings`]): the constraint codes
//! of bitdefender-1.0 (`bitdefender_*`), judged on the raw block before its
//! fields, each reported at the path the spec fixes for it, so `validate`
//! and the editor name the same finding (0.28.0's
//! `platforms/bitdefender/catalog.py`).
//!
//! | 0.28.0 | Here |
//! |--------|------|
//! | `platforms/bitdefender/criteria.py` | [`criteria`]: `data/catalogs/bitdefender/criteria.toml` |
//! | `platforms/bitdefender/catalog.py` (`block_findings`) | [`checks`] |
//! | `platforms/bitdefender/advisories.py` | [`advisories`] |
//! | `platforms/bitdefender/compile.py` (`normalise`, `gravityzone_name`) | [`normalise`], [`gravityzone_name`] |

pub mod advisories;
pub mod checks;
pub mod criteria;

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::error::ErrorKind;
use crate::from_node::Context;
use crate::node::{Node, Value};
use crate::objects::platform::{literal_enum, platform_block};
use crate::pins::Pins;

pub use checks::{Finding, block_codes, block_findings};

/// `is: str | int`: an exact-match value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, FromNode)]
#[serde(untagged)]
#[from_node(union)]
pub enum CriterionValue {
    /// A string.
    #[from_node(tag = "str")]
    #[schemars(description = "")]
    Text(String),
    /// An integer.
    #[from_node(tag = "int")]
    #[schemars(description = "")]
    Int(i64),
}

impl CriterionValue {
    /// The value as JSON.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Text(text) => serde_json::Value::String(text.clone()),
            Self::Int(integer) => serde_json::Value::from(*integer),
        }
    }
}

/// One criterion (`BitdefenderCriterion`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "BitdefenderCriterion", description = "")]
#[from_node(model = "BitdefenderCriterion")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "BitdefenderCriterion",
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
pub struct BitdefenderCriterion {
    /// API field name (`Process.CommandLine`) from the criteria catalogue for the `target`.
    pub field: String,
    /// Exact match. Sent as `relation: "is"`.
    #[serde(rename = "is", default, skip_serializing_if = "Option::is_none")]
    pub is_: Option<CriterionValue>,
    /// Substring, with `*` and `?` wildcards. Sent as `relation: "contains"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    /// Any of the values. Sent as `relation: "any"`.
    #[serde(rename = "any", default, skip_serializing_if = "Option::is_none")]
    pub any_: Option<Vec<CriterionValue>>,
}

impl BitdefenderCriterion {
    /// The relation the criterion uses and its value, as the API takes them
    /// (`{"relation": ..., "value": ...}`): the first of `is`, `contains` and
    /// `any` it sets.
    pub fn relation(&self) -> Option<(&'static str, serde_json::Value)> {
        if let Some(value) = &self.is_ {
            return Some(("is", value.to_json()));
        }
        if let Some(text) = &self.contains {
            return Some(("contains", serde_json::Value::String(text.clone())));
        }
        self.any_.as_ref().map(|values| {
            (
                "any",
                serde_json::Value::Array(values.iter().map(CriterionValue::to_json).collect()),
            )
        })
    }
}

/// `criteria`: at least one (`Field(min_length=1)`).
fn criteria_list(node: &Node, cx: &mut Context) -> Option<Vec<BitdefenderCriterion>> {
    let list = Vec::<BitdefenderCriterion>::from_node(node, cx)?;
    if list.is_empty() {
        cx.error_with(
            ErrorKind::InvalidValue("too_short"),
            "List should have at least 1 item after validation, not 0",
            node,
            &[
                ("field_type", "List".to_owned()),
                ("min_length", "1".to_owned()),
                ("actual_length", "0".to_owned()),
            ],
        );
        return None;
    }
    Some(list)
}

/// garde: `criteria` has at least one criterion.
fn garde_criteria(value: &[BitdefenderCriterion], _pins: &Pins) -> garde::Result {
    if value.is_empty() {
        Err(garde::Error::new(
            "List should have at least 1 item after validation, not 0",
        ))
    } else {
        Ok(())
    }
}

/// A Basic detection rule's criteria (`BitdefenderDetection`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "BitdefenderDetection", description = "")]
#[from_node(model = "BitdefenderDetection")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "BitdefenderDetection",
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
pub struct BitdefenderDetection {
    /// A GravityZone detection target, as the API spells it: `process`, `file`, `connection`,
    /// `registry`, `user connection`, `email`, `application`, `key vault`, `role`, `policy`,
    /// `sharing link`, `url`, `ssh key`, `launch template`, `service principal`, `user group`,
    /// `automation account`, `automation account hook`, `certificate authority`, `api`, `bucket`,
    /// `jira project`, or `confluence page`.
    pub target: String,
    /// At least one. All criteria must match (AND).
    #[schemars(length(min = 1))]
    #[from_node(with = "criteria_list")]
    #[garde(custom(garde_criteria))]
    pub criteria: Vec<BitdefenderCriterion>,
    /// A GravityZone alert (detection) name. Sent as
    /// `filters: [{"field": "detection", "value": <alert>}]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert: Option<String>,
}

fn on_access() -> bool {
    true
}

/// A YARA detection rule (`BitdefenderYara`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "BitdefenderYara", description = "")]
#[from_node(model = "BitdefenderYara")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "BitdefenderYara",
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
pub struct BitdefenderYara {
    /// The YARA signature: imports, then one or more YARA rules, written out in the block. Sent as
    /// `settings.yaraQuery`, verbatim.
    #[schemars(extend("tide.template.multiline" = true, "tide.template.required" = true))]
    pub signature: String,
    /// On-access scanning with this rule (`settings.status`). With `false`, the rule serves
    /// on-demand scans only.
    #[serde(default = "on_access")]
    pub on_access: bool,
}

/// Endpoint tags or companies a rule applies to (`BitdefenderTargets`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "BitdefenderTargets", description = "")]
#[from_node(model = "BitdefenderTargets")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "BitdefenderTargets",
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
pub struct BitdefenderTargets {
    /// Aliases from the tenant's `endpoint_tags` table. Each resolves to `{tagId, companyId}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_tags: Option<Vec<String>>,
    /// Partner tenants: aliases from the tenant's `companies` table. Each resolves to a company
    /// id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub companies: Option<Vec<String>>,
}

/// `{include_parent, include_children}` of a process action
/// (`BitdefenderProcessScope`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "BitdefenderProcessScope", description = "")]
#[from_node(model = "BitdefenderProcessScope")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "BitdefenderProcessScope",
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
pub struct BitdefenderProcessScope {
    /// Also act on the parent process.
    #[serde(default)]
    pub include_parent: bool,
    /// Also act on the child processes.
    #[serde(default)]
    pub include_children: bool,
}

/// A process or file action: `true`, or its scope
/// (`Literal[True] | BitdefenderProcessScope`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProcessAction {
    /// `true`.
    On(bool),
    /// `{include_parent, include_children}`.
    Scoped(BitdefenderProcessScope),
}

impl ProcessAction {
    /// The scope the action acts with: `true` is neither parent nor children.
    pub fn scope(&self) -> BitdefenderProcessScope {
        match self {
            Self::On(_) => BitdefenderProcessScope {
                include_parent: false,
                include_children: false,
            },
            Self::Scoped(scope) => scope.clone(),
        }
    }
}

impl JsonSchema for ProcessAction {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ProcessAction".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let scope = generator.subschema_for::<BitdefenderProcessScope>();
        schemars::json_schema!({"anyOf": [{"const": true, "type": "boolean"}, scope]})
    }
}

/// `Literal[True]`'s error, at the node.
fn not_true(node: &Node, cx: &mut Context) {
    cx.error_with(
        ErrorKind::InvalidValue("literal_error"),
        "Input should be True",
        node,
        &[("expected", "True".to_owned())],
    );
}

/// `Literal[True] | None`.
pub fn literal_true(node: &Node, cx: &mut Context) -> Option<Option<bool>> {
    match node.value {
        Value::Null => Some(None),
        Value::Bool(true) => Some(Some(true)),
        _ => {
            not_true(node, cx);
            None
        }
    }
}

/// garde: a `Literal[True]` built in memory is `true`.
pub fn garde_true(value: &Option<bool>, _pins: &Pins) -> garde::Result {
    match value {
        Some(false) => Err(garde::Error::new("Input should be True")),
        _ => Ok(()),
    }
}

/// `Literal[True] | BitdefenderProcessScope | None`: Pydantic's smart union,
/// each member's error under its tag when neither takes the value.
pub fn process_action(node: &Node, cx: &mut Context) -> Option<Option<ProcessAction>> {
    match &node.value {
        Value::Null => Some(None),
        Value::Bool(true) => Some(Some(ProcessAction::On(true))),
        Value::Map(_) => BitdefenderProcessScope::from_node(node, cx)
            .map(|scope| Some(ProcessAction::Scoped(scope))),
        _ => {
            cx.at_key("literal[True]", |cx| not_true(node, cx));
            cx.at_key("BitdefenderProcessScope", |cx| {
                cx.error_with(
                    ErrorKind::InvalidType("model_type"),
                    crate::from_node::messages::model_type("BitdefenderProcessScope"),
                    node,
                    &[("class_name", "BitdefenderProcessScope".to_owned())],
                );
            });
            None
        }
    }
}

/// garde: a process action built in memory is `true` or a scope.
pub fn garde_process_action(value: &Option<ProcessAction>, _pins: &Pins) -> garde::Result {
    match value {
        Some(ProcessAction::On(false)) => Err(garde::Error::new("Input should be True")),
        _ => Ok(()),
    }
}

/// Pydantic's schema of `Literal[True] | None`.
fn optional_true(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"anyOf": [{"const": true, "type": "boolean"}, {"type": "null"}]})
}

/// Pydantic's schema of `Literal[True] | BitdefenderProcessScope | None`.
fn optional_process_action(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let scope = generator.subschema_for::<BitdefenderProcessScope>();
    schemars::json_schema!({
        "anyOf": [{"const": true, "type": "boolean"}, scope, {"type": "null"}]
    })
}

literal_enum! {
    /// `quick` or `full`.
    ScanType { Quick = "quick", Full = "full", }
}

literal_enum! {
    /// `Low`, `Medium`, or `High`.
    Severity { Low = "Low", Medium = "Medium", High = "High", }
}

impl Severity {
    /// GravityZone's `settings.severity`: 1, 2 or 3 (`SEVERITIES`).
    pub const fn level(self) -> i64 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
        }
    }
}

/// Automatic actions (`BitdefenderActions`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "BitdefenderActions", description = "")]
#[from_node(model = "BitdefenderActions")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "BitdefenderActions",
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
pub struct BitdefenderActions {
    /// Isolate the endpoint (type 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "optional_true")]
    #[from_node(with = "literal_true")]
    #[garde(custom(garde_true))]
    pub isolate: Option<bool>,
    /// Collect an investigation package (type 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "optional_true")]
    #[from_node(with = "literal_true")]
    #[garde(custom(garde_true))]
    pub collect_investigation_package: Option<bool>,
    /// Submit to the Sandbox Analyzer (type 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "optional_true")]
    #[from_node(with = "literal_true")]
    #[garde(custom(garde_true))]
    pub sandbox: Option<bool>,
    /// Kill the process (type 4): `true`, or `{include_parent, include_children}`. Basic rules
    /// only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "optional_process_action")]
    #[from_node(with = "process_action")]
    #[garde(custom(garde_process_action))]
    pub kill_process: Option<ProcessAction>,
    /// Run an antimalware scan (type 5): `quick` or `full`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::objects::platform::optional_literal::<ScanType>")]
    pub antimalware_scan: Option<ScanType>,
    /// Quarantine the file (type 6): `true`, or `{include_parent, include_children}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "optional_process_action")]
    #[from_node(with = "process_action")]
    #[garde(custom(garde_process_action))]
    pub quarantine: Option<ProcessAction>,
    /// Run a risk scan (type 7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "optional_true")]
    #[from_node(with = "literal_true")]
    #[garde(custom(garde_true))]
    pub risk_scan: Option<bool>,
}

/// GravityZone's automatic action `type` of each action key, in type order
/// (bitdefender-1.0, `actions`).
pub const ACTION_TYPES: [(&str, i64); 7] = [
    ("isolate", 1),
    ("collect_investigation_package", 2),
    ("sandbox", 3),
    ("kill_process", 4),
    ("antimalware_scan", 5),
    ("quarantine", 6),
    ("risk_scan", 7),
];

/// Actions that act on a process or a file: a `process` or `file` target or a
/// `*.CreatedBy.*` criterion, on a Basic rule.
pub const PROCESS_ACTIONS: [&str; 3] = ["sandbox", "kill_process", "quarantine"];

/// Actions a YARA rule cannot take.
pub const NOT_ON_YARA: [&str; 1] = ["kill_process"];

/// What a block deploys: a Basic rule or a YARA rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `detection`: `type: 1`, `subtype: 0`.
    Detection,
    /// `yara`: `type: 1`, `subtype: 1`.
    Yara,
}

impl Kind {
    /// `detection` or `yara`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Detection => "detection",
            Self::Yara => "yara",
        }
    }

    /// GravityZone's `subtype`.
    pub const fn subtype(self) -> i64 {
        match self {
            Self::Detection => 0,
            Self::Yara => 1,
        }
    }
}

fn garde_block(block: &BitdefenderConfig, _pins: &Pins) -> garde::Result {
    let value = serde_json::to_value(block).map_err(|error| {
        garde::Error::new(format!("BitdefenderConfig does not serialise: {error}"))
    })?;
    let findings = block_findings(&crate::objects::platform::json_node(&value));
    match findings.first() {
        None => Ok(()),
        Some(finding) => Err(garde::Error::new(format!(
            "{}: {}",
            finding.code,
            finding.text()
        ))),
    }
}

/// `_validate_raw_bitdefender_block` (before): with a `status`, every
/// finding of [`block_findings`] is one error typed by its code, at its path
/// under the block; the block's fields are then not converted.
fn raw_block(node: &Node, cx: &mut Context) -> bool {
    if matches!(
        node.get("status").map(|status| &status.value),
        None | Some(Value::Null)
    ) {
        return true;
    }
    let findings = block_findings(node);
    for finding in &findings {
        finding.report(node, cx);
    }
    findings.is_empty()
}

platform_block! {
    /// Bitdefender GravityZone custom detection rule (`BitdefenderConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[garde(custom(garde_block))]
    #[schemars(rename = "BitdefenderConfig", description = "")]
    #[from_node(model = "BitdefenderConfig", before = "raw_block")]
    #[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all, eq, name = "BitdefenderConfig", module = "opentide._native.models"))]
    #[cfg_attr(feature = "python", expect(clippy::unsafe_derive_deserialize, reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"))]
    pub struct BitdefenderConfig ["platform::bitdefender::1.0"] {
        /// `Low`, `Medium`, or `High`. Derived from `response.alert_severity` when omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::objects::platform::optional_literal::<Severity>")]
        pub severity: Option<Severity>,
        /// Extra GravityZone tags. Deploy adds the derived tags.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tags: Option<Vec<String>>,
        /// Endpoint tags, or companies on a partner tenant, the rule applies to. Neither means the
        /// whole company. Default: the tenant `targets`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub targets: Option<BitdefenderTargets>,
        /// Automatic actions.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<BitdefenderActions>,
        /// A Basic detection rule (`type: 1`, `subtype: 0`). Exactly one of `detection` and `yara`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detection: Option<BitdefenderDetection>,
        /// A YARA detection rule (`type: 1`, `subtype: 1`). Exactly one of `detection` and `yara`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub yara: Option<BitdefenderYara>,
    }
}

impl BitdefenderConfig {
    /// The rule kind the block deploys (`kind`).
    pub fn kind(&self) -> Kind {
        if self.yara.is_some() {
            Kind::Yara
        } else {
            Kind::Detection
        }
    }
}

// ---------------------------------------------------------------------------
// GravityZone names (`compile.py`): what deploy sends and what the workspace
// check `bitdefender_name_duplicate` compares.
// ---------------------------------------------------------------------------

/// The longest GravityZone rule name.
pub const NAME_LIMIT: usize = 128;

/// What GravityZone refuses in names, descriptions and tags, and what deploy
/// sends instead: `<` `>` `'` `"` as `‹` `›` `’` `”`.
const REPLACEMENTS: [(char, char); 4] = [
    ('<', '\u{2039}'),
    ('>', '\u{203A}'),
    ('\'', '\u{2019}'),
    ('"', '\u{201D}'),
];

/// GravityZone refuses `< > ' "` and leading whitespace: replace and strip
/// them (`normalise`).
pub fn normalise(text: &str) -> String {
    let replaced: String = text
        .chars()
        .map(|character| {
            REPLACEMENTS
                .iter()
                .find(|(before, _)| *before == character)
                .map_or(character, |(_, after)| *after)
        })
        .collect();
    replaced
        .trim_start_matches(crate::objects::platform::is_python_space)
        .to_owned()
}

/// The first `limit` characters of `text` (Python's `text[:limit]`).
pub fn cut(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// The block's `name`, else the rule's, normalised, cut at 128 characters
/// (`gravityzone_name`).
pub fn gravityzone_name(rule_name: &str, block_name: Option<&str>) -> String {
    let name = block_name
        .filter(|name| !name.is_empty())
        .unwrap_or(rule_name);
    cut(&normalise(name), NAME_LIMIT)
}

#[cfg(test)]
mod tests;
