//! Sysdig Secure or Falco rule, `platform::sysdig::1.0` (`SysdigConfig` and
//! its nested models), with the named check `sysdig_rule_shape`
//! ([`block_codes`]): the constraint codes of the oracle's
//! `_validate_raw_sysdig_block` and `platforms/sysdig/expansion.py`
//! (`check_definitions`), judged on the raw block before its fields.
//!
//! Which names a macro uses, and where a list name stands in a value, are
//! read on the text as Falco's loader reads it ([`super::falco_text`]).

use std::collections::BTreeSet;

use garde::Validate;
use opentide_core::falco::{
    EXPANSION_LIMIT, LIST_OPERATORS, TUNING_FORBIDDEN, definition_name_ok, flatten_lists, is_blank,
    is_exception_operator, is_list_comparison, is_modified_operator, list_inside, normalize_comp,
    priority_ok, source_ok, upsert, value_passes,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::error::ErrorKind;
use crate::from_node::Context;
use crate::node::{Node, Value};
use crate::objects::platform::{get, is_map, platform_block, present, python_strip};
use crate::pins::Pins;

use super::falco_text::join_lines;

/// `str | list[str]`: one Falco field, or a tuple of fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, FromNode)]
#[serde(untagged)]
#[from_node(union)]
pub enum OneOrMany {
    /// One.
    #[from_node(tag = "str")]
    #[schemars(description = "")]
    One(String),
    /// Several.
    #[from_node(tag = "list[str]")]
    #[schemars(description = "")]
    Many(Vec<String>),
}

/// A list item: `str | int | float`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, FromNode)]
#[schemars(description = "")]
#[serde(untagged)]
#[from_node(union)]
pub enum ListItem {
    /// A string.
    #[from_node(tag = "str")]
    #[schemars(description = "")]
    Text(String),
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

/// A Falco exception (`SysdigException`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SysdigException", description = "")]
#[from_node(model = "SysdigException")]
pub struct SysdigException {
    /// Exception name. Names SHOULD be unique in the block: Falco warns on a repeated name
    /// (`LOAD_EXCEPTION_NAME_NOT_UNIQUE`) and the engine reports it as a warning.
    pub name: String,
    /// One Falco field (the single-field form) or a list of fields (the tuple form).
    pub fields: OneOrMany,
    /// Comparison operators, leading and trailing blanks ignored. Tuple form: a list aligned with
    /// `fields`, each a Falco operator or a modified operator; default `=` for each field.
    /// Single-field form: `in`, `pmatch`, `intersects`, or a modified operator (`startswith oneof`);
    /// default `in`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comps: Option<OneOrMany>,
    /// Tuple form: a list of rows, each a list aligned with `fields`. An item is a value or a list
    /// of values; a single value under a list comparison (`in`, `pmatch`, `intersects`, or a modified
    /// operator) is one value list, or the name of a list. Single-field form: a flat list of values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::objects::platform::optional_any_list")]
    pub values: Option<Vec<crate::objects::any::Any>>,
}

/// A block macro (`SysdigMacro`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SysdigMacro", description = "")]
#[from_node(model = "SysdigMacro")]
pub struct SysdigMacro {
    /// Macro name, matching `^[A-Za-z_][A-Za-z0-9_]*$`.
    pub name: String,
    /// Falco condition. It may reference other macros and lists of this block.
    #[schemars(extend("tide.template.multiline" = true))]
    pub condition: String,
}

/// A block list (`SysdigList`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SysdigList", description = "")]
#[from_node(model = "SysdigList")]
pub struct SysdigList {
    /// List name, matching `^[A-Za-z_][A-Za-z0-9_]*$`.
    pub name: String,
    /// List items. An item may name another list of this block.
    pub items: Vec<ListItem>,
}

/// `minimum_engine_version`: `Annotated[int, Field(ge=0, strict=True)] | None`.
pub fn minimum_engine_version(node: &Node, cx: &mut Context) -> Option<Option<i64>> {
    match node.value {
        Value::Null => Some(None),
        Value::Int(value) if value >= 0 => Some(Some(value)),
        Value::Int(_) => {
            cx.error_with(
                ErrorKind::InvalidValue("greater_than_equal"),
                "Input should be greater than or equal to 0",
                node,
                &[("ge", "0".to_owned())],
            );
            None
        }
        _ => {
            cx.error(
                ErrorKind::InvalidType("int_type"),
                crate::from_node::messages::INT_TYPE,
                node,
            );
            None
        }
    }
}

/// garde: `minimum_engine_version` is at least 0.
pub fn garde_minimum_engine_version(value: &Option<i64>, _pins: &Pins) -> garde::Result {
    match value {
        Some(value) if *value < 0 => Err(garde::Error::new(
            "Input should be greater than or equal to 0",
        )),
        _ => Ok(()),
    }
}

fn garde_block(block: &SysdigConfig, _pins: &Pins) -> garde::Result {
    crate::objects::platform::garde_named("SysdigConfig", block)
}

fn raw_block(node: &Node, cx: &mut Context) -> bool {
    crate::objects::platform::before("SysdigConfig", node, cx)
}

impl SysdigConfig {
    /// Whether the block tunes an existing rule (`append_to_rule`).
    pub fn is_tuning(&self) -> bool {
        self.append_to_rule
            .as_deref()
            .is_some_and(|name| !name.is_empty())
    }
}

platform_block! {
    /// Sysdig Secure or Falco rule (`SysdigConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[garde(custom(garde_block))]
    #[schemars(rename = "SysdigConfig", description = "")]
    #[from_node(model = "SysdigConfig", before = "raw_block")]
    pub struct SysdigConfig ["platform::sysdig::1.0"] {
        /// Falco condition. Required for a new rule. With `append_to_rule`, the text appended to the
        /// tuned rule's condition, usually starting with `and not`. Multiline; deploy joins lines with
        /// single spaces.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(extend(
            "tide.template.multiline" = true,
            "tide.template.spacer" = true,
            "tide.template.required" = true
        ))]
        pub condition: Option<String>,
        /// Name of an existing Falco or Sysdig rule this block tunes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub append_to_rule: Option<String>,
        /// Falco event source: `syscall` (the default), `k8s_audit`, `aws_cloudtrail`,
        /// `gcp_auditlog`, `azure_platformlogs`, `okta`, `github`, or another plugin's source.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        /// Falco output template, with `%field` references. Derived from the event source when
        /// omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub output: Option<String>,
        /// Falco priority: `EMERGENCY`, `ALERT`, `CRITICAL`, `ERROR`, `WARNING`, `NOTICE`,
        /// `INFORMATIONAL`, or `DEBUG`. Derived from `response.alert_severity` when omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub priority: Option<String>,
        /// Extra Falco tags. Deploy adds the derived ATT&CK, maturity, and tenant tags.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tags: Option<Vec<String>>,
        /// Falco exceptions.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exceptions: Option<Vec<SysdigException>>,
        /// Macros only this rule uses, expanded into the condition at deploy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub macros: Option<Vec<SysdigMacro>>,
        /// Lists only this rule uses, expanded into the condition at deploy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lists: Option<Vec<SysdigList>>,
        /// Names of Sysdig runtime policies the rule joins. Default: the tenant
        /// `policies`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policies: Option<Vec<String>>,
        /// Minimum Falco engine version the rule needs, as Sysdig's integer
        /// `minimumEngineVersion`. Omitted when unset.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(range(min = 0))]
        #[from_node(with = "minimum_engine_version")]
        #[garde(custom(garde_minimum_engine_version))]
        pub minimum_engine_version: Option<i64>,
    }
}

// ---------------------------------------------------------------------------
// The named check `sysdig_rule_shape`.
//
// Falco's terms (operators, modifiers, priorities, keywords, names) are
// `opentide_core::falco`'s, the one copy the language server's Sysdig
// findings (`opentide-tide`'s `sysdig` module) use too; `opentide-tide`'s
// `the_editor_and_the_model_agree_on_the_sysdig_cases` runs both on
// `tests/oracle/platform_cases.toml`.
// ---------------------------------------------------------------------------

/// `_non_blank`: a string with something besides whitespace.
fn non_blank(node: Option<&Node>) -> bool {
    node.and_then(|node| node.value.as_str())
        .is_some_and(|text| !is_blank(text))
}

/// `_sysdig_scalar`: neither a list nor a mapping.
fn scalar(node: &Node) -> bool {
    !matches!(node.value, Value::Seq(_) | Value::Map(_))
}

/// `item_text`: a list or exception item as YAML gives it to Falco.
fn item_text(node: &Node) -> String {
    match &node.value {
        Value::Null => "None".to_owned(),
        Value::Bool(flag) => flag.to_string(),
        Value::Int(integer) => integer.to_string(),
        Value::Float(float) => python_float(*float),
        Value::Str(text) | Value::Datetime(text) => text.clone(),
        Value::Seq(_) | Value::Map(_) => crate::configuration::repr::node(node),
    }
}

/// A float as Python's `str()` writes it, for the values YAML gives
/// (`1.5`, `2.0`, `inf`, `nan`).
fn python_float(float: f64) -> String {
    if float.is_nan() {
        "nan".to_owned()
    } else if float.is_infinite() {
        if float > 0.0 { "inf" } else { "-inf" }.to_owned()
    } else if float.fract() == 0.0 && float.abs() < 1e16 {
        format!("{float:.1}")
    } else {
        format!("{float}")
    }
}

/// `_sysdig_exception_ok`: one exception, by the checks of Falco's
/// `validate_exception_info` and `build_rule_exception_infos`.
fn exception_ok(entry: &Node) -> bool {
    if !is_map(Some(entry)) || !non_blank(get(Some(entry), "name")) {
        return false;
    }
    let fields = get(Some(entry), "fields");
    let comps = get(Some(entry), "comps").filter(|node| present(Some(node)));
    let values = get(Some(entry), "values").filter(|node| present(Some(node)));
    let rows: &[std::sync::Arc<Node>] = match values.map(|node| &node.value) {
        None => &[],
        Some(Value::Seq(rows)) => rows,
        Some(_) => return false,
    };
    if let Some(field) = fields.and_then(|node| node.value.as_str()) {
        if python_strip(field).is_empty() {
            return false;
        }
        if let Some(comps) = comps {
            // "Fields and comps must both be strings".
            let Some(comp) = comps.value.as_str() else {
                return false;
            };
            let comp = normalize_comp(comp);
            if !LIST_OPERATORS.contains(&comp) && !is_modified_operator(comp) {
                return false;
            }
        }
        return rows.iter().all(|value| scalar(value));
    }
    let Some(Value::Seq(fields)) = fields.map(|node| &node.value) else {
        return false;
    };
    if fields.is_empty() || !fields.iter().all(|field| non_blank(Some(field))) {
        return false;
    }
    if let Some(comps) = comps {
        // "Fields and comps lists must have equal length".
        let Value::Seq(comps) = &comps.value else {
            return false;
        };
        if comps.len() != fields.len()
            || !comps.iter().all(|comp| {
                comp.value
                    .as_str()
                    .is_some_and(|comp| is_exception_operator(normalize_comp(comp)))
            })
        {
            return false;
        }
    }
    for row in rows {
        // "Fields and values lists must have equal length".
        let Value::Seq(items) = &row.value else {
            return false;
        };
        if items.len() != fields.len() {
            return false;
        }
        for item in items {
            match &item.value {
                Value::Map(_) => return false,
                Value::Seq(values) if !values.iter().all(|value| scalar(value)) => return false,
                _ => {}
            }
        }
    }
    true
}

/// The block's macros and lists, in block order, each name once (a later
/// definition replaces an earlier one, as the oracle's dictionaries do).
struct Definitions {
    macros: Vec<(String, String)>,
    lists: Vec<(String, Vec<String>)>,
}

/// `_sysdig_definitions`: the block's macros and lists by name;
/// `sysdig_definition_name` and `sysdig_definition_duplicate` into `codes`.
fn definitions(raw: &Node, codes: &mut BTreeSet<&'static str>) -> Definitions {
    let mut out = Definitions {
        macros: Vec::new(),
        lists: Vec::new(),
    };
    let mut seen: Vec<String> = Vec::new();
    for key in ["macros", "lists"] {
        let Some(Value::Seq(entries)) = get(Some(raw), key).map(|node| &node.value) else {
            continue;
        };
        for entry in entries {
            if !is_map(Some(entry)) {
                continue; // the field type reports it
            }
            let Some(name) = get(Some(entry), "name").and_then(|node| node.value.as_str()) else {
                continue;
            };
            if !definition_name_ok(name) {
                codes.insert("sysdig_definition_name");
            }
            if seen.iter().any(|known| known == name) {
                codes.insert("sysdig_definition_duplicate");
            }
            seen.push(name.to_owned());
            if key == "macros" {
                if let Some(condition) =
                    get(Some(entry), "condition").and_then(|node| node.value.as_str())
                {
                    upsert(&mut out.macros, name, condition.to_owned());
                }
            } else if let Some(Value::Seq(items)) =
                get(Some(entry), "items").map(|node| &node.value)
            {
                upsert(
                    &mut out.lists,
                    name,
                    items.iter().map(|item| item_text(item)).collect(),
                );
            }
        }
    }
    out
}

/// The block's expansion (`Expander`): the lists flattened in block order.
struct Expander {
    macro_order: Vec<String>,
    lists: Vec<(String, Vec<String>)>,
}

impl Expander {
    fn new(definitions: &Definitions) -> Self {
        Self {
            macro_order: definitions
                .macros
                .iter()
                .map(|(name, _)| name.clone())
                .collect(),
            // `compile_list_infos`: an item naming an earlier block list is its items.
            lists: flatten_lists(&definitions.lists),
        }
    }

    /// `sysdig_definition_order`: a macro uses a block macro that is itself
    /// or defined after it (Falco refuses it as an undefined macro).
    fn macro_order_ok(&self, definitions: &Definitions) -> bool {
        for (index, (_, condition)) in definitions.macros.iter().enumerate() {
            let visible = &self.macro_order[..index];
            // Falco's `parse_condition`: every block list resolved, in block order.
            let mut text = join_lines(condition);
            for (name, items) in &self.lists {
                if text.len() > EXPANSION_LIMIT * 16 {
                    break;
                }
                text = super::falco_text::resolve_list(&text, name, items);
            }
            if super::falco_text::check_position_names(&text)
                .iter()
                .any(|name| self.macro_order.contains(name) && !visible.contains(name))
            {
                return false;
            }
        }
        true
    }

    /// `_list_in`: a block list whose name occurs inside a value (not as all
    /// of it).
    fn list_in(&self, text: &str) -> bool {
        list_inside(&self.lists, text).is_some()
    }

    /// `_passes`: each member as its text, or `None` for a list or mapping,
    /// through `opentide_core::falco::value_passes`.
    fn passes(&self, values: &[&Node]) -> Vec<Option<String>> {
        value_passes(
            &self.lists,
            values
                .iter()
                .map(|value| scalar(value).then(|| item_text(value)))
                .collect(),
        )
    }

    /// `_members`: false when a member names a block list inside it.
    fn members_ok(&self, values: &[&Node]) -> bool {
        self.passes(values)
            .iter()
            .all(|value| value.as_deref().is_none_or(|text| !self.list_in(text)))
    }

    /// `exception`: false when a block list name appears in a value where
    /// Falco's expansion would not produce a value list
    /// (`sysdig_list_in_value`).
    fn exception_ok(&self, entry: &Node) -> bool {
        let fields = get(Some(entry), "fields");
        let comps = get(Some(entry), "comps").filter(|node| present(Some(node)));
        let values = get(Some(entry), "values").filter(|node| present(Some(node)));
        if fields.is_some_and(|node| node.value.as_str().is_some()) {
            return values.is_none() || self.members_ok(&as_list(values));
        }
        let width = as_list(fields).len();
        let comp_list: Vec<String> = match comps.map(|node| &node.value) {
            Some(Value::Seq(items)) => items
                .iter()
                .map(|comp| normalize_comp(&item_text(comp)).to_owned())
                .collect(),
            _ => vec!["=".to_owned(); width],
        };
        for row in as_list(values) {
            let Value::Seq(items) = &row.value else {
                continue;
            };
            for (comp, item) in comp_list.iter().zip(items) {
                if let Value::Seq(members) = &item.value {
                    let members: Vec<&Node> = members.iter().map(AsRef::as_ref).collect();
                    if !self.members_ok(&members) {
                        return false;
                    }
                    continue;
                }
                let text = item_text(item);
                if self.list_in(&text) {
                    return false;
                }
                if self.lists.iter().any(|(name, _)| *name == text) {
                    if !is_list_comparison(comp) {
                        return false;
                    }
                    // Falco wraps it in parentheses: one value list, then the passes.
                    if !self.members_ok(&[item.as_ref()]) {
                        return false;
                    }
                }
            }
        }
        true
    }
}

/// The items of a list node, or none.
fn as_list(node: Option<&Node>) -> Vec<&Node> {
    match node.map(|node| &node.value) {
        Some(Value::Seq(items)) => items.iter().map(AsRef::as_ref).collect(),
        _ => Vec::new(),
    }
}

/// Every constraint code of the oracle's `_validate_raw_sysdig_block` on a
/// raw block, sorted; empty when the block passes, is not a mapping, or has
/// no `status`.
pub fn block_codes(raw: &Node) -> BTreeSet<&'static str> {
    let mut codes = BTreeSet::new();
    if !is_map(Some(raw)) || !present(get(Some(raw), "status")) || !super::within_budget(raw) {
        return codes;
    }
    let field = |key: &str| get(Some(raw), key);
    let tuning = field("append_to_rule").filter(|node| present(Some(node)));
    let condition = field("condition");
    match tuning {
        None => {
            if !non_blank(condition) {
                codes.insert("sysdig_rule_shape");
            }
        }
        Some(tuning) => {
            let has_condition = non_blank(condition);
            let exceptions = field("exceptions");
            let has_exceptions = matches!(exceptions.map(|node| &node.value), Some(Value::Seq(items)) if !items.is_empty());
            if !non_blank(Some(tuning))
                || (present(condition) && !has_condition)
                || !(has_condition || has_exceptions)
            {
                codes.insert("sysdig_rule_shape");
            }
            if TUNING_FORBIDDEN.iter().any(|key| {
                !matches!(field(key).map(|node| &node.value), None | Some(Value::Null))
                    && field(key).and_then(|node| node.value.as_str()) != Some("")
            }) {
                codes.insert("sysdig_tuning_keys");
            }
        }
    }
    if let Some(priority) = field("priority").filter(|node| present(Some(node)))
        && !priority.value.as_str().is_some_and(priority_ok)
    {
        codes.insert("sysdig_priority");
    }
    if let Some(source) = field("source").filter(|node| present(Some(node)))
        && !source.value.as_str().is_some_and(source_ok)
    {
        codes.insert("sysdig_source");
    }
    let exceptions = field("exceptions").filter(|node| present(Some(node)));
    if let Some(exceptions) = exceptions {
        let ok = match &exceptions.value {
            Value::Seq(entries) => entries.iter().all(|entry| exception_ok(entry)),
            _ => false,
        };
        if !ok {
            codes.insert("sysdig_exception_shape");
        }
    }
    let definitions = definitions(raw, &mut codes);
    if !codes.contains("sysdig_definition_duplicate") && !codes.contains("sysdig_definition_name") {
        let expander = Expander::new(&definitions);
        if !expander.macro_order_ok(&definitions) {
            codes.insert("sysdig_definition_order");
        } else if !codes.contains("sysdig_exception_shape")
            && let Some(Value::Seq(entries)) = exceptions.map(|node| &node.value)
            && !entries.iter().all(|entry| expander.exception_ok(entry))
        {
            codes.insert("sysdig_list_in_value");
        }
    }
    codes
}
