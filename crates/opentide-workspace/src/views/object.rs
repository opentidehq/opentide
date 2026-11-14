//! An object as `opentide tui` shows it by default: a page, not a file
//! (`cli/services/object_view.py`, #776).
//!
//! Each value is placed under the field its schema revision defines, with
//! the field's title and description, a vocabulary value's meaning, and the
//! name of the object or signal a UUID names. The fields the revision allows
//! but the object does not set are listed too, so an author sees what they
//! could add.
//!
//! The fields come from the language server's field catalog
//! (`opentide_schema::generate::catalog::fields_catalog`, the `fields.json`
//! document), read with [`FieldNodes::from_catalog`]: the same fields,
//! descriptions and vocabularies validation and the editor use, for the
//! revision in `metadata.schema`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use indexmap::IndexMap;
use opentide_schema::node::{Node, Value};
use regex::Regex;

use crate::index::Index;

/// The `metadata` keys the header shows; the others are rows of the
/// Metadata section.
const HEADER_KEYS: [&str; 6] = ["uuid", "schema", "version", "created", "modified", "tlp"];

/// Fields a severity badge colours, by their path without list indexes.
pub const SEVERITY_FIELDS: [&str; 4] = [
    "severity",
    "response.alert_severity",
    "threat.severity",
    "objective.signals.severity",
];

/// One field of a revision, as the field catalog describes it.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the catalog row's flags, one field each, as fields.json has them"
)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldNode {
    /// `title`.
    pub title: String,
    /// `description`.
    pub description: String,
    /// The values its vocabulary allows, as text.
    pub choices: Vec<String>,
    /// What each value means, in the order of `choices`.
    pub choice_docs: Vec<String>,
    /// Whether validation requires it.
    pub required: bool,
    /// Whether the editor hides it.
    pub hidden: bool,
    /// Whether it is kept only for older objects.
    pub legacy: bool,
    /// Whether the templates ask for it.
    pub recommended: bool,
}

/// Each revision's fields by path (`rule::1.0` → `metadata.tlp` → its node).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldNodes(pub BTreeMap<String, BTreeMap<String, FieldNode>>);

fn text_of(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(serde_json::Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn flag(value: Option<&serde_json::Value>) -> bool {
    value.and_then(serde_json::Value::as_bool).unwrap_or(false)
}

fn texts(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|items| items.iter().map(|item| text_of(Some(item))).collect())
        .unwrap_or_default()
}

impl FieldNodes {
    /// The fields of a `fields.json` document (its `fields` rows).
    pub fn from_catalog(document: &serde_json::Value) -> Self {
        let mut nodes: BTreeMap<String, BTreeMap<String, FieldNode>> = BTreeMap::new();
        let rows = document
            .get("fields")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for row in rows {
            let schema = text_of(row.get("schema"));
            let path = text_of(row.get("path"));
            nodes.entry(schema).or_default().insert(
                path,
                FieldNode {
                    title: text_of(row.get("title")),
                    description: text_of(row.get("description")),
                    choices: texts(row.get("enum")),
                    choice_docs: texts(row.get("enum_docs")),
                    required: flag(row.get("required")),
                    hidden: flag(row.get("hidden")),
                    legacy: flag(row.get("legacy")),
                    recommended: flag(row.get("recommended")),
                },
            );
        }
        Self(nodes)
    }

    /// The revision whose fields apply: `schema` itself, else a bare
    /// family's newest.
    fn resolve(&self, schema: &str) -> Option<&BTreeMap<String, FieldNode>> {
        if let Some(fields) = self.0.get(schema) {
            return Some(fields);
        }
        if schema.contains("::") {
            return None;
        }
        self.0
            .iter()
            .rev()
            .find(|(key, _)| key.split("::").next() == Some(schema))
            .map(|(_, fields)| fields)
    }
}

/// What a UUID value names: an object of the catalogue, or a signal of one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkTarget {
    /// The UUID.
    pub uuid: String,
    /// The object's or signal's name.
    pub name: String,
    /// `threat`, `objective`, `rule` or `signal`.
    pub kind: String,
    /// The object to open: the signal's objective for a signal.
    pub opens: String,
}

/// A scalar of a value row.
#[derive(Debug, Clone, PartialEq)]
pub enum Scalar {
    /// A boolean, shown as `yes` or `no`.
    Bool(bool),
    /// Anything else, as YAML 1.2 writes it.
    Text(String),
}

impl Scalar {
    /// Its text: `true`/`false` for a boolean.
    pub fn text(&self) -> String {
        match self {
            Self::Bool(flag) => flag.to_string(),
            Self::Text(text) => text.clone(),
        }
    }
}

/// What a row of a section is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowKind {
    /// A mapping, or a list of mappings: a heading.
    Group,
    /// One entry of such a list: a heading.
    Item,
    /// A scalar, or a list of scalars.
    Value,
}

/// One line of a section: a group heading, a list item heading or a value.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldRow {
    /// The field's path with list indexes (`objective.signals.0.severity`),
    /// as findings name it.
    pub path: String,
    /// The path the schema defines it under, without list indexes.
    pub schema_path: String,
    /// The field's title (a list with its length).
    pub title: String,
    /// How deep it is nested in its section.
    pub depth: usize,
    /// What it is.
    pub kind: RowKind,
    /// The field's description.
    pub description: String,
    /// The value: one scalar, or each of a list's.
    pub values: Vec<Scalar>,
    /// What each vocabulary value means, in the order of `values`.
    pub meanings: Vec<String>,
    /// The objects and signals the values' UUIDs name, in the order of `values`.
    pub links: Vec<Option<LinkTarget>>,
    /// Whether the field holds a severity (a badge).
    pub severity: bool,
}

/// A top-level field of the object, and what it holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    /// Its title.
    pub title: String,
    /// Its path (`objective`), empty for the overview.
    pub path: String,
    /// The field's description.
    pub description: String,
    /// Its rows.
    pub rows: Vec<FieldRow>,
}

/// A field the object's revision allows that the object does not set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsetField {
    /// Its path, without list indexes.
    pub path: String,
    /// Its title.
    pub title: String,
    /// Its description.
    pub description: String,
    /// The values its vocabulary allows, when it has one.
    pub choices: Vec<String>,
    /// Whether the schema recommends it.
    pub recommended: bool,
}

/// What the object view shows for one object.
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectView {
    /// `name`.
    pub name: String,
    /// Its family.
    pub kind: String,
    /// `metadata.schema` as written.
    pub schema: String,
    /// `uuid`, `schema`, `version`, `created`, `modified`, `tlp` as written.
    pub header: IndexMap<String, String>,
    /// What the object's TLP means, from the vocabulary.
    pub tlp_meaning: String,
    /// The overview, then the metadata, then a section per block.
    pub sections: Vec<Section>,
    /// The optional fields it could add.
    pub unset: Vec<UnsetField>,
    /// Every reference the object makes, each once, in order (`f`).
    pub links: Vec<LinkTarget>,
    /// Why the schema's fields are not known, when they are not.
    pub unknown_schema: Option<String>,
}

#[expect(clippy::expect_used, reason = "a regex literal")]
fn uuid_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
            .expect("a valid pattern")
    })
}

/// `key` read as a title: `detection_model` → `Detection model`.
fn capitalised(key: &str) -> String {
    let spaced = key.replace('_', " ");
    let mut chars = spaced.chars();
    chars.next().map_or_else(String::new, |first| {
        first
            .to_uppercase()
            .chain(chars.flat_map(char::to_lowercase))
            .collect()
    })
}

/// The field's title, unless it only respells its key.
fn title(node: Option<&FieldNode>, key: &str) -> String {
    let title = node.map(|node| node.title.as_str()).unwrap_or_default();
    if title.is_empty()
        || title.replace(' ', "").to_lowercase() == key.replace('_', "").to_lowercase()
    {
        return capitalised(key);
    }
    title.to_owned()
}

fn description(node: Option<&FieldNode>) -> String {
    node.map(|node| {
        node.description
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    })
    .unwrap_or_default()
}

fn meaning(node: Option<&FieldNode>, value: Option<&str>) -> String {
    let (Some(node), Some(value)) = (node, value) else {
        return String::new();
    };
    node.choices
        .iter()
        .position(|choice| choice == value)
        .and_then(|index| node.choice_docs.get(index))
        .cloned()
        .unwrap_or_default()
}

fn strip_indexes(path: &str) -> String {
    path.split('.')
        .filter(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        .collect::<Vec<_>>()
        .join(".")
}

fn is_scalar(node: &Node) -> bool {
    !matches!(node.value, Value::Map(_) | Value::Seq(_))
}

fn scalar(node: &Node) -> Option<Scalar> {
    match &node.value {
        Value::Null => None,
        Value::Bool(flag) => Some(Scalar::Bool(*flag)),
        other => Some(Scalar::Text(other.to_string())),
    }
}

fn key_text(node: &Node) -> String {
    node.value.to_string()
}

fn item_label(item: &Node, index: usize) -> String {
    for key in ["name", "title", "relation", "vector", "link"] {
        if let Some(text) = item.get(key).and_then(|value| value.value.as_str())
            && !text.is_empty()
        {
            return format!("{}. {text}", index + 1);
        }
    }
    format!("{}.", index + 1)
}

fn link(value: &Scalar, links: &BTreeMap<String, LinkTarget>) -> Option<LinkTarget> {
    let Scalar::Text(text) = value else {
        return None;
    };
    let trimmed = text.trim();
    if !uuid_pattern().is_match(trimmed) {
        return None;
    }
    links
        .get(trimmed)
        .or_else(|| links.get(&trimmed.to_lowercase()))
        .cloned()
}

struct Builder<'a> {
    fields: Option<&'a BTreeMap<String, FieldNode>>,
    links: &'a BTreeMap<String, LinkTarget>,
    found: Vec<LinkTarget>,
}

impl Builder<'_> {
    fn node(&self, path: &str) -> Option<&FieldNode> {
        self.fields.and_then(|fields| fields.get(path))
    }

    fn rows(&mut self, path: &str, key: &str, value: &Node, depth: usize) -> Vec<FieldRow> {
        let schema_path = strip_indexes(path);
        let node = self.node(&schema_path).cloned();
        let node = node.as_ref();
        let heading = |title: String, kind: RowKind| FieldRow {
            path: path.to_owned(),
            schema_path: schema_path.clone(),
            title,
            depth,
            kind,
            description: description(node),
            values: Vec::new(),
            meanings: Vec::new(),
            links: Vec::new(),
            severity: false,
        };
        match &value.value {
            Value::Map(entries) => {
                let mut rows = vec![heading(title(node, key), RowKind::Group)];
                for entry in entries {
                    let child = key_text(&entry.key);
                    rows.extend(self.rows(
                        &format!("{path}.{child}"),
                        &child,
                        &entry.value,
                        depth + 1,
                    ));
                }
                rows
            }
            Value::Seq(items) if !items.iter().all(|item| is_scalar(item)) => {
                let mut rows = vec![heading(
                    format!("{} ({})", title(node, key), items.len()),
                    RowKind::Group,
                )];
                for (index, item) in items.iter().enumerate() {
                    rows.push(FieldRow {
                        path: format!("{path}.{index}"),
                        schema_path: schema_path.clone(),
                        title: item_label(item, index),
                        depth: depth + 1,
                        kind: RowKind::Item,
                        description: String::new(),
                        values: Vec::new(),
                        meanings: Vec::new(),
                        links: Vec::new(),
                        severity: false,
                    });
                    if let Value::Map(entries) = &item.value {
                        for entry in entries {
                            let child = key_text(&entry.key);
                            rows.extend(self.rows(
                                &format!("{path}.{index}.{child}"),
                                &child,
                                &entry.value,
                                depth + 2,
                            ));
                        }
                    } else {
                        rows.extend(self.rows(&format!("{path}.{index}"), key, item, depth + 2));
                    }
                }
                rows
            }
            other => {
                let values: Vec<Scalar> = match other {
                    Value::Seq(items) => items.iter().filter_map(|item| scalar(item)).collect(),
                    _ => scalar(value).into_iter().collect(),
                };
                let targets: Vec<Option<LinkTarget>> =
                    values.iter().map(|item| link(item, self.links)).collect();
                for target in targets.iter().flatten() {
                    if !self.found.contains(target) {
                        self.found.push(target.clone());
                    }
                }
                let meanings = values
                    .iter()
                    .map(|item| match item {
                        Scalar::Text(text) => meaning(node, Some(text)),
                        Scalar::Bool(_) => String::new(),
                    })
                    .collect();
                vec![FieldRow {
                    severity: SEVERITY_FIELDS.contains(&schema_path.as_str()),
                    title: title(node, key),
                    description: description(node),
                    path: path.to_owned(),
                    schema_path,
                    depth,
                    kind: RowKind::Value,
                    values,
                    meanings,
                    links: targets,
                }]
            }
        }
    }
}

/// Every path `node` sets, without list indexes; a `null` value sets none.
fn present(node: &Node, prefix: &str, found: &mut BTreeSet<String>) {
    match &node.value {
        Value::Map(entries) => {
            for entry in entries {
                if matches!(entry.value.value, Value::Null) {
                    continue;
                }
                let key = key_text(&entry.key);
                let path = if prefix.is_empty() {
                    key
                } else {
                    format!("{prefix}.{key}")
                };
                found.insert(path.clone());
                present(&entry.value, &path, found);
            }
        }
        Value::Seq(items) => {
            for item in items {
                present(item, prefix, found);
            }
        }
        _ => {}
    }
}

/// The optional fields the revision defines where `root` could add them.
///
/// A field counts when its parent is set (or it is top-level), so a block
/// the object leaves out is one entry, not one per field inside it.
/// Required fields are not listed: leaving one out is a validation error,
/// not an option.
fn unset(root: &Node, fields: &BTreeMap<String, FieldNode>) -> Vec<UnsetField> {
    let mut set = BTreeSet::new();
    present(root, "", &mut set);
    fields
        .iter()
        .filter(|(path, node)| {
            if set.contains(*path) || node.required || node.hidden || node.legacy {
                return false;
            }
            path.rsplit_once('.')
                .is_none_or(|(parent, _)| set.contains(parent))
        })
        .map(|(path, node)| UnsetField {
            path: path.clone(),
            title: title(Some(node), path.rsplit('.').next().unwrap_or(path)),
            description: description(Some(node)),
            choices: node.choices.clone(),
            recommended: node.recommended,
        })
        .collect()
}

/// The [`ObjectView`] of `root`, an object of `kind`. `links` maps each
/// UUID of the catalogue (objects and signals) to what it names.
pub fn build_object_view(
    root: &Node,
    kind: &str,
    links: &BTreeMap<String, LinkTarget>,
    nodes: &FieldNodes,
) -> ObjectView {
    let metadata = root
        .get("metadata")
        .filter(|node| matches!(node.value, Value::Map(_)));
    let schema = metadata
        .and_then(|metadata| metadata.get("schema"))
        .and_then(|node| scalar(node))
        .map(|value| value.text())
        .unwrap_or_default();
    let fields = nodes.resolve(if schema.is_empty() { kind } else { &schema });
    let mut header = IndexMap::new();
    for key in HEADER_KEYS {
        if let Some(value) = metadata
            .and_then(|metadata| metadata.get(key))
            .and_then(|node| scalar(node))
        {
            header.insert(key.to_owned(), value.text());
        }
    }
    let mut builder = Builder {
        fields,
        links,
        found: Vec::new(),
    };
    let mut sections = Vec::new();
    if let Some(Value::Map(entries)) = metadata.map(|metadata| &metadata.value) {
        let rows: Vec<FieldRow> = entries
            .iter()
            .filter(|entry| !HEADER_KEYS.contains(&key_text(&entry.key).as_str()))
            .flat_map(|entry| {
                let key = key_text(&entry.key);
                builder.rows(&format!("metadata.{key}"), &key, &entry.value, 0)
            })
            .collect();
        if !rows.is_empty() {
            let node = builder.node("metadata");
            sections.push(Section {
                title: title(node, "metadata"),
                path: "metadata".into(),
                description: description(node),
                rows,
            });
        }
    }
    // Top-level values (description, status, severity, …) read as one
    // section; each block (objective, threat, response, configurations) is
    // its own.
    let mut overview = Vec::new();
    let mut blocks = Vec::new();
    if let Value::Map(entries) = &root.value {
        for entry in entries {
            let key = key_text(&entry.key);
            if key == "name" || key == "metadata" {
                continue;
            }
            if let Value::Map(children) = &entry.value.value {
                let rows: Vec<FieldRow> = children
                    .iter()
                    .flat_map(|child| {
                        let name = key_text(&child.key);
                        builder.rows(&format!("{key}.{name}"), &name, &child.value, 0)
                    })
                    .collect();
                let node = builder.node(&key);
                blocks.push(Section {
                    title: title(node, &key),
                    description: description(node),
                    path: key,
                    rows,
                });
            } else {
                overview.extend(builder.rows(&key, &key, &entry.value, 0));
            }
        }
    }
    if !overview.is_empty() {
        sections.insert(
            0,
            Section {
                title: "Overview".into(),
                path: String::new(),
                description: String::new(),
                rows: overview,
            },
        );
    }
    sections.extend(blocks);
    let tlp = header.get("tlp").map(String::as_str);
    let tlp_meaning = meaning(builder.node("metadata.tlp"), tlp);
    let shown = if schema.is_empty() { kind } else { &schema };
    ObjectView {
        name: root
            .get("name")
            .and_then(|node| scalar(node))
            .map(|value| value.text())
            .unwrap_or_default(),
        kind: kind.to_owned(),
        unset: fields.map(|fields| unset(root, fields)).unwrap_or_default(),
        unknown_schema: fields.is_none().then(|| {
            format!("opentide does not know the fields of {shown:?}: they are shown as written")
        }),
        schema,
        header,
        tlp_meaning,
        sections,
        links: builder.found,
    }
}

/// Every UUID a reference can name: each object's, and each signal's
/// (the signal opens its objective).
pub fn catalogue_links(
    index: &Index,
    names: &BTreeMap<String, (String, String)>,
) -> BTreeMap<String, LinkTarget> {
    let mut links: BTreeMap<String, LinkTarget> = names
        .iter()
        .map(|(uuid, (name, kind))| {
            (
                uuid.clone(),
                LinkTarget {
                    uuid: uuid.clone(),
                    name: name.clone(),
                    kind: kind.clone(),
                    opens: uuid.clone(),
                },
            )
        })
        .collect();
    for (owner, objective) in index.objects.get("objective").into_iter().flatten() {
        let Some(root) = objective.root() else {
            continue;
        };
        let signals = root
            .get("objective")
            .and_then(|section| section.get("signals"))
            .map(Arc::as_ref);
        let Some(Value::Seq(signals)) = signals.map(|node| &node.value) else {
            continue;
        };
        for signal in signals {
            let Some(uuid) = signal.get("uuid").and_then(|node| node.value.as_str()) else {
                continue;
            };
            let name = signal
                .get("name")
                .and_then(|node| scalar(node))
                .map_or_else(|| uuid.to_owned(), |value| value.text());
            links.entry(uuid.to_owned()).or_insert_with(|| LinkTarget {
                uuid: uuid.to_owned(),
                name,
                kind: "signal".into(),
                opens: owner.clone(),
            });
        }
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes() -> FieldNodes {
        FieldNodes::from_catalog(&serde_json::json!({"fields": [
            {"schema": "rule::1.0", "path": "metadata.tlp", "title": "Tlp",
             "enum": ["clear", "red"], "enum_docs": ["Anyone", "Eyes only"], "required": true},
            {"schema": "rule::1.0", "path": "severity", "title": "Severity",
             "enum": ["High"], "enum_docs": ["Bad"]},
            {"schema": "rule::1.0", "path": "detection_model", "title": "Detection Model",
             "description": "The  objective\n it implements."},
            {"schema": "rule::1.0", "path": "references", "title": "References",
             "recommended": true},
            {"schema": "rule::1.0", "path": "response", "title": "Response"},
            {"schema": "rule::1.0", "path": "response.playbook", "title": "Playbook"},
            {"schema": "rule::1.0", "path": "configurations", "title": "Platforms"},
            {"schema": "rule::1.0", "path": "configurations.sentinel", "title": "Sentinel"},
            {"schema": "rule::1.0", "path": "configurations.sentinel.query", "title": "Query",
             "required": true},
            {"schema": "rule::1.0", "path": "hidden_one", "hidden": true},
            {"schema": "rule::1.1", "path": "metadata.tlp", "title": "Tlp"}
        ]}))
    }

    const RULE: &str = "name: R\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  \
        schema: rule::1.0\n  tlp: red\n  author: me\nseverity: High\n\
        detection_model: 00000000-0000-4000-8002-000000000001\nenabled: true\n\
        configurations:\n  sentinel:\n    query: T | take 1\n    tags: [a, b]\n";

    #[test]
    fn the_page_reads_each_value_under_its_field() {
        let document = opentide_schema::node::load(RULE).unwrap();
        let objective = LinkTarget {
            uuid: "00000000-0000-4000-8002-000000000001".into(),
            name: "Objective".into(),
            kind: "objective".into(),
            opens: "00000000-0000-4000-8002-000000000001".into(),
        };
        let links = BTreeMap::from([(objective.uuid.clone(), objective.clone())]);
        let view = build_object_view(document.root().unwrap(), "rule", &links, &nodes());
        assert_eq!(view.name, "R");
        assert_eq!(
            view.header.keys().collect::<Vec<_>>(),
            ["uuid", "schema", "tlp"]
        );
        assert_eq!(view.tlp_meaning, "Eyes only");
        let titles: Vec<&str> = view.sections.iter().map(|s| s.title.as_str()).collect();
        assert_eq!(titles, ["Overview", "Metadata", "Platforms"]);
        let overview = &view.sections[0].rows;
        assert_eq!(overview[0].title, "Severity");
        assert!(overview[0].severity);
        assert_eq!(overview[0].meanings, ["Bad"]);
        // The title only respells the key: the key, read as words.
        assert_eq!(overview[1].title, "Detection model");
        assert_eq!(overview[1].description, "The objective it implements.");
        assert_eq!(overview[1].links, [Some(objective.clone())]);
        assert_eq!(overview[2].values, [Scalar::Bool(true)]);
        let platforms = &view.sections[2].rows;
        assert_eq!(platforms[0].kind, RowKind::Group);
        assert_eq!(platforms[1].path, "configurations.sentinel.query");
        assert_eq!(platforms[2].values.len(), 2);
        assert_eq!(view.links, [objective]);
        // Not set: optional, not hidden, top-level or under a set parent.
        let unset: Vec<(&str, bool)> = view
            .unset
            .iter()
            .map(|field| (field.path.as_str(), field.recommended))
            .collect();
        assert_eq!(unset, [("references", true), ("response", false)]);
        assert!(view.unknown_schema.is_none());
    }

    #[test]
    fn an_unknown_revision_is_shown_as_written() {
        let text = RULE.replace("rule::1.0", "rule::9.9");
        let document = opentide_schema::node::load(&text).unwrap();
        let view = build_object_view(document.root().unwrap(), "rule", &BTreeMap::new(), &nodes());
        assert_eq!(
            view.unknown_schema.as_deref(),
            Some("opentide does not know the fields of \"rule::9.9\": they are shown as written")
        );
        assert!(view.unset.is_empty());
        // A bare family takes its newest revision.
        assert!(nodes().resolve("rule").is_some_and(|f| f.len() == 1));
    }

    #[test]
    fn a_list_of_mappings_is_a_group_of_named_items() {
        let text = "name: O\nobjective:\n  signals:\n    - name: First\n      severity: High\n    - uuid: x\n";
        let document = opentide_schema::node::load(text).unwrap();
        let view = build_object_view(
            document.root().unwrap(),
            "objective",
            &BTreeMap::new(),
            &nodes(),
        );
        let rows = &view.sections[0].rows;
        let read: Vec<(&str, &str, usize)> = rows
            .iter()
            .map(|row| (row.path.as_str(), row.title.as_str(), row.depth))
            .collect();
        assert_eq!(
            read,
            [
                ("objective.signals", "Signals (2)", 0),
                ("objective.signals.0", "1. First", 1),
                ("objective.signals.0.name", "Name", 2),
                ("objective.signals.0.severity", "Severity", 2),
                ("objective.signals.1", "2.", 1),
                ("objective.signals.1.uuid", "Uuid", 2),
            ]
        );
        assert!(rows[3].severity);
        assert_eq!(rows[3].schema_path, "objective.signals.severity");
    }
}
