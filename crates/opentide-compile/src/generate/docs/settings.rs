//! Every setting a platform block carries (`documentation/facts/settings.py`).
//!
//! The block is walked as the model holds it ([`Json::from_serialize`]: the
//! fields in declaration order, the model's defaults filled in), beside the
//! JSON Schema of the rule's `configurations`, which gives each field's
//! description (the doc comment editors show on hover) and marks the fields
//! that hold multiline text. Every value becomes a row keyed by its YAML path
//! (`scheduling.frequency`); code (queries, YARA, investigation guides) is
//! lifted into fenced blocks, and a list of small objects becomes a table of
//! its own. A field the model gains, or a platform, is documented with no
//! change here.
//!
//! A value the author did not write is the model's default, which deploy
//! still uses: the row says so. What the author wrote is the block's YAML,
//! read beside the model.

use std::sync::OnceLock;

use serde_json::Value as Schema;

use super::platforms::{self, CodeLanguage};
use super::text::{first_sentence, inline_code};
use crate::json::Json;

/// A description is cut to its first sentence, at most this long.
const DESCRIPTION_LENGTH: usize = 160;

/// One scalar, or list of scalars, and where it sits in the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// The YAML path.
    pub path: String,
    /// The value as a cell shows it.
    pub value: String,
    /// The field's description.
    pub description: String,
    /// The model's default: the author did not write it.
    pub default: bool,
}

/// A setting whose value is code, shown as a fenced block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSetting {
    /// The YAML path.
    pub path: String,
    /// The code.
    pub code: String,
    /// Its language, when the platform names one.
    pub language: Option<CodeLanguage>,
    /// The field's description.
    pub description: String,
}

/// A list of flat objects (exclusions, mappings, criteria), a row per item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingTable {
    /// The YAML path.
    pub path: String,
    /// The keys any item sets, in field order.
    pub columns: Vec<String>,
    /// A row per item.
    pub rows: Vec<Vec<String>>,
    /// The field's description.
    pub description: String,
}

/// Everything a block sets, split by how a page shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// Scalars.
    pub rows: Vec<Setting>,
    /// Code.
    pub code: Vec<CodeSetting>,
    /// Lists of flat objects.
    pub tables: Vec<SettingTable>,
}

impl Settings {
    /// Whether the block sets nothing.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.code.is_empty() && self.tables.is_empty()
    }
}

/// The JSON Schema of a rule's `configurations`, every block's model under
/// `$defs`.
fn configurations_schema() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        schemars::schema_for!(opentide_schema::objects::RuleConfigurations).to_value()
    })
}

/// The schema of `platform`'s block model, when the rule model has it.
fn block_schema(platform: &str) -> Option<&'static Schema> {
    let root = configurations_schema();
    let property = root.get("properties")?.get(platform)?;
    Some(resolve(root, property))
}

/// `node` with its `$ref` followed, and an `Option`'s `anyOf` reduced to
/// the branch that is not `null`.
fn resolve<'s>(root: &'s Schema, node: &'s Schema) -> &'s Schema {
    let mut node = node;
    for _ in 0..16 {
        if let Some(reference) = node.get("$ref").and_then(Schema::as_str) {
            let Some(found) = reference
                .strip_prefix("#/$defs/")
                .and_then(|name| root.get("$defs")?.get(name))
            else {
                return node;
            };
            node = found;
            continue;
        }
        let branches = node
            .get("anyOf")
            .or_else(|| node.get("oneOf"))
            .or_else(|| node.get("allOf"))
            .and_then(Schema::as_array);
        if let Some(branches) = branches {
            let kept: Vec<&Schema> = branches
                .iter()
                .filter(|branch| branch.get("type").and_then(Schema::as_str) != Some("null"))
                .collect();
            if let [only] = kept.as_slice() {
                node = only;
                continue;
            }
            // Several shapes: the one a model reads, else the first.
            if let Some(model) = kept
                .iter()
                .find(|branch| resolve(root, branch).get("properties").is_some())
            {
                node = model;
                continue;
            }
        }
        return node;
    }
    node
}

/// A property's own schema: its description and `tide.*` keys, before any
/// `$ref` is followed.
#[derive(Clone, Copy)]
struct Field<'s> {
    schema: &'s Schema,
}

impl Field<'_> {
    /// The first sentence of the description; a cut that leaves a code span
    /// open loses its backticks.
    fn description(self) -> String {
        let text = self
            .schema
            .get("description")
            .and_then(Schema::as_str)
            .unwrap_or_default();
        if text.is_empty() {
            return String::new();
        }
        let sentence = first_sentence(text, DESCRIPTION_LENGTH);
        if sentence.matches('`').count() % 2 == 1 {
            sentence.replace('`', "")
        } else {
            sentence
        }
    }

    /// Whether the model marks the field multiline.
    fn multiline(self) -> bool {
        matches!(
            self.schema.get("tide.template.multiline"),
            Some(Schema::Bool(true))
        )
    }
}

/// Every value `block` holds, in declaration order. `exclude` names
/// top-level keys documented elsewhere on the page; `written` is the block
/// as the author wrote it (a value it does not hold is a default).
pub fn flatten(platform: &str, block: &Json, written: Option<&Json>, exclude: &[&str]) -> Settings {
    let mut walker = Walker {
        out: Settings::default(),
        platform,
        block,
        root: configurations_schema(),
    };
    let schema = block_schema(platform);
    walker.model(block, schema, written, "", exclude);
    walker.out
}

struct Walker<'w> {
    out: Settings,
    platform: &'w str,
    block: &'w Json,
    root: &'static Schema,
}

impl Walker<'_> {
    fn language(&self, path: &str) -> Option<CodeLanguage> {
        platforms::code_language(self.platform, &pattern(path), self.block)
    }

    /// The property `key` of the model `schema`, and the model or mapping
    /// its value reads into.
    fn property(&self, schema: Option<&'static Schema>, key: &str) -> Option<&'static Schema> {
        schema?.get("properties")?.get(key)
    }

    fn model(
        &mut self,
        value: &Json,
        schema: Option<&'static Schema>,
        written: Option<&Json>,
        prefix: &str,
        exclude: &[&str],
    ) {
        let Some(fields) = value.as_object() else {
            return;
        };
        for (key, item) in fields {
            if prefix.is_empty() && exclude.contains(&key.as_str()) {
                continue;
            }
            let field = self.property(schema, key);
            let given = written.and_then(|written| written.get(key));
            self.value(
                item,
                &format!("{prefix}{key}"),
                field,
                given,
                given.is_none(),
            );
        }
    }

    fn value(
        &mut self,
        value: &Json,
        path: &str,
        field: Option<&'static Schema>,
        written: Option<&Json>,
        default: bool,
    ) {
        if is_blank(value) {
            return;
        }
        let info = field.map(|schema| Field { schema });
        let description = info.map(Field::description).unwrap_or_default();
        let resolved = field.map(|schema| resolve(self.root, schema));
        match value {
            Json::Object(entries) => {
                if resolved.is_some_and(|schema| schema.get("properties").is_some()) {
                    self.model(value, resolved, written, &format!("{path}."), &[]);
                } else {
                    // A mapping: its keys are the author's, not fields.
                    for (key, item) in entries {
                        let given = written.and_then(|written| written.get(key));
                        self.value(item, &format!("{path}.{key}"), None, given, default);
                    }
                }
            }
            Json::Array(items) => self.sequence(items, path, field, written, default),
            Json::Str(text) => {
                let language = self.language(path);
                if language.is_some()
                    || text.trim().contains('\n')
                    || info.is_some_and(Field::multiline)
                {
                    self.out.code.push(CodeSetting {
                        path: path.to_owned(),
                        code: text.trim_end_matches('\n').to_owned(),
                        language,
                        description,
                    });
                } else {
                    self.out.rows.push(Setting {
                        path: path.to_owned(),
                        value: scalar(value, true),
                        description,
                        default,
                    });
                }
            }
            _ => self.out.rows.push(Setting {
                path: path.to_owned(),
                value: scalar(value, true),
                description,
                default,
            }),
        }
    }

    fn sequence(
        &mut self,
        items: &[Json],
        path: &str,
        field: Option<&'static Schema>,
        written: Option<&Json>,
        default: bool,
    ) {
        let description = field
            .map(|schema| Field { schema }.description())
            .unwrap_or_default();
        if items.iter().all(is_scalar) {
            let text: Vec<String> = items
                .iter()
                .filter(|item| !is_blank(item))
                .map(|item| scalar(item, false))
                .collect();
            self.out.rows.push(Setting {
                path: path.to_owned(),
                value: text.join(", "),
                description,
                default,
            });
            return;
        }
        let item_schema = field
            .map(|schema| resolve(self.root, schema))
            .and_then(|schema| schema.get("items"))
            .map(|items| resolve(self.root, items))
            .filter(|schema| schema.get("properties").is_some());
        let models = item_schema.is_some() && items.iter().all(|item| item.as_object().is_some());
        if models
            && items.iter().all(is_flat)
            && !items
                .iter()
                .any(|item| self.holds_code(item, item_schema, path))
        {
            self.out.tables.push(table(items, path, description));
            return;
        }
        let item_field = field.and_then(|schema| resolve(self.root, schema).get("items"));
        for (index, item) in items.iter().enumerate() {
            let given = match written {
                Some(Json::Array(list)) => list.get(index),
                _ => None,
            };
            // A model item reads its fields from the item schema; any other
            // item is described by the list's field.
            let schema = if item.as_object().is_some() {
                item_field.or(field)
            } else {
                field
            };
            self.value(item, &format!("{path}[{index}]"), schema, given, default);
        }
    }

    /// Whether a field of `item` is code: a query belongs in a fenced block,
    /// not a cell.
    fn holds_code(&self, item: &Json, schema: Option<&'static Schema>, path: &str) -> bool {
        let base = pattern(path);
        let Some(fields) = item.as_object() else {
            return false;
        };
        fields.iter().any(|(key, value)| {
            let Json::Str(text) = value else {
                return false;
            };
            if text.trim().is_empty() {
                return false;
            }
            let multiline = self
                .property(schema, key)
                .is_some_and(|schema| Field { schema }.multiline());
            multiline
                || platforms::code_language(self.platform, &format!("{base}.{key}"), self.block)
                    .is_some()
        })
    }
}

/// A list of flat objects as a table: the keys any item sets, in field
/// order, a row per item.
fn table(items: &[Json], path: &str, description: String) -> SettingTable {
    let mut columns: Vec<String> = Vec::new();
    for item in items {
        for (key, value) in item.as_object().into_iter().flatten() {
            if !columns.contains(key) && !is_blank(value) {
                columns.push(key.clone());
            }
        }
    }
    let rows = items
        .iter()
        .map(|item| {
            columns
                .iter()
                .map(|key| match item.get(key) {
                    None => "-".to_owned(),
                    Some(value) if is_blank(value) => "-".to_owned(),
                    Some(Json::Array(list)) => list
                        .iter()
                        .map(|value| scalar(value, false))
                        .collect::<Vec<_>>()
                        .join(", "),
                    Some(value) => scalar(value, true),
                })
                .collect()
        })
        .collect();
    SettingTable {
        path: path.to_owned(),
        columns,
        rows,
        description,
    }
}

/// A value as text, as the author spells it in YAML (`true`, not `True`).
fn stringify(value: &Json) -> String {
    match value {
        Json::Null => String::new(),
        Json::Bool(flag) => if *flag { "true" } else { "false" }.to_owned(),
        Json::Int(number) => number.to_string(),
        Json::Str(text) => text.clone(),
        Json::Array(items) => items
            .iter()
            .map(stringify)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join(", "),
        Json::Float(_) | Json::Object(_) => value.to_compact(),
    }
}

/// A scalar as a cell: plain language as text when `prose` allows, anything
/// else (identifiers, numbers, cron, templates) as code.
fn scalar(value: &Json, prose: bool) -> String {
    let text = super::text::collapse(&stringify(value));
    if prose && matches!(value, Json::Str(_)) && is_prose(&text) {
        return text;
    }
    inline_code(&text)
}

/// A rule name or a reason reads as text: blanks, at least two words, and
/// only letters, digits and sentence punctuation, nothing Markdown or a
/// query language reads specially. `0 * * * *` or `{{Account}} on {{Host}}`
/// is code.
fn is_prose(text: &str) -> bool {
    if !text.contains(' ') {
        return false;
    }
    let plain = text.chars().all(|c| {
        c.is_alphanumeric()
            || c == '_'
            || c.is_whitespace()
            || matches!(
                c,
                '.' | ',' | ';' | ':' | '\'' | '(' | ')' | '&' | '/' | '-'
            )
    });
    if !plain {
        return false;
    }
    let mut words = 0;
    let mut run = 0;
    for c in text.chars().chain(std::iter::once(' ')) {
        if c.is_alphabetic() {
            run += 1;
        } else {
            if run >= 2 {
                words += 1;
            }
            run = 0;
        }
    }
    words >= 2
}

fn is_scalar(value: &Json) -> bool {
    !matches!(value, Json::Object(_) | Json::Array(_))
}

/// Only scalars and lists of scalars, no multiline text: one table row holds
/// it.
fn is_flat(item: &Json) -> bool {
    item.as_object()
        .into_iter()
        .flatten()
        .all(|(_, value)| match value {
            Json::Array(list) => list.iter().all(is_scalar),
            Json::Str(text) => !text.trim().contains('\n'),
            other => is_scalar(other),
        })
}

fn is_blank(value: &Json) -> bool {
    match value {
        Json::Null => true,
        Json::Str(text) => text.trim().is_empty(),
        Json::Array(items) => items.is_empty(),
        Json::Object(entries) => entries.is_empty(),
        _ => false,
    }
}

/// `exclusions[0].query` as `exclusions.query`.
fn pattern(path: &str) -> String {
    path.split('.')
        .map(|part| part.split('[').next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> Json {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn prose_and_code() {
        assert!(is_prose("Sentinel KQL Rule"));
        assert!(!is_prose("PT1H"));
        assert!(!is_prose("0 * * * *"));
        assert!(!is_prose("{{Account}} on {{Host}}"));
        assert!(!is_prose("a b"));
        assert_eq!(scalar(&json("true"), true), "`true`");
        assert_eq!(scalar(&json("3"), true), "`3`");
        assert_eq!(scalar(&json("\"Rule name\""), true), "Rule name");
        assert_eq!(scalar(&json("\"Rule name\""), false), "`Rule name`");
        assert_eq!(pattern("exclusions[0].query"), "exclusions.query");
    }

    #[test]
    fn a_sentinel_block_reads_in_declaration_order_with_its_defaults() {
        let block = json(
            r#"{"enabled": true, "name": "Sentinel KQL Rule", "status": "STAGING",
                "query": "SecurityEvent\n| take 1\n",
                "scheduling": {"frequency": "PT1H", "lookback": "PT2H"},
                "alert": {"title": "Sentinel KQL Rule", "create_incident": true},
                "exclusions": [{"tenant": "a", "query": "| where x"}],
                "entities": [{"entity": "Account", "mappings": [{"identifier": "Name", "column": "User"}]}]}"#,
        );
        let written = json(
            r#"{"name": "Sentinel KQL Rule", "query": "q", "scheduling": {"frequency": "PT1H", "lookback": "PT2H"},
                "alert": {"title": "Sentinel KQL Rule"}}"#,
        );
        let settings = flatten("sentinel", &block, Some(&written), &["enabled", "status"]);
        let paths: Vec<&str> = settings.rows.iter().map(|row| row.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "name",
                "scheduling.frequency",
                "scheduling.lookback",
                "alert.title",
                "alert.create_incident",
                "exclusions[0].tenant",
                "entities[0].entity",
            ]
        );
        assert_eq!(settings.rows[0].value, "Sentinel KQL Rule");
        assert_eq!(settings.rows[0].description, "Platform-specific rule name.");
        assert!(!settings.rows[0].default);
        assert!(settings.rows[4].default, "{:?}", settings.rows[4]);
        assert_eq!(settings.rows[4].value, "`true`");
        // The query, and the exclusion's, are KQL: fenced, not cells.
        assert_eq!(settings.code[0].path, "query");
        assert_eq!(settings.code[0].code, "SecurityEvent\n| take 1");
        assert_eq!(settings.code[0].language, Some(platforms::KQL));
        assert_eq!(settings.code[1].path, "exclusions[0].query");
        // An entity's mappings are a list of flat objects: a table.
        assert_eq!(settings.tables[0].path, "entities[0].mappings");
        assert_eq!(settings.tables[0].columns, ["identifier", "column"]);
        assert_eq!(settings.tables[0].rows, [["`Name`", "`User`"]]);
    }

    #[test]
    fn blank_values_and_unknown_platforms() {
        let block = json(r#"{"a": "", "b": [], "c": null, "d": ["x", "y"], "e": {"k": 1}}"#);
        let settings = flatten("my_plugin", &block, None, &[]);
        let rows: Vec<(&str, &str, bool)> = settings
            .rows
            .iter()
            .map(|row| (row.path.as_str(), row.value.as_str(), row.default))
            .collect();
        assert_eq!(rows, [("d", "`x`, `y`", true), ("e.k", "`1`", true)]);
        assert!(!settings.is_empty());
        assert!(flatten("my_plugin", &json("{}"), None, &[]).is_empty());
    }

    #[test]
    fn descriptions_never_leave_a_code_span_open() {
        let schema = json(r#"{"description": "Uses `a. B` here."}"#);
        let schema: Schema = serde_json::to_value(&schema).unwrap();
        assert_eq!(Field { schema: &schema }.description(), "Uses a.");
    }
}
