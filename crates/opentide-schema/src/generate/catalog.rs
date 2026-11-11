//! The language server's Tide field catalog (`lsp_catalog.py`): what
//! `opentide generate schemas` writes to `.opentide/lsp/catalogs/generated/`
//! and what the engine compiles in (`data/catalogs/tide/generated/`).
//!
//! - `fields.json`: every field of every registered object revision
//!   (`rule::1.0` and `rule::1.1` each have their own rows), with its title,
//!   description, type, whether validation requires it (`required`, from the
//!   model) or only the templates ask for it (`recommended`), its enum values
//!   and their short docs, whether an object forbids keys it does not define
//!   (`closed`), its string default and its minimum item count.
//! - `deprecations.json`: the root and platform fields marked deprecated
//!   (`tide.meta.deprecation`).
//!
//! Each row is read from the revision's editor schema with its hover
//! annotations, `configurations` left as the model declares it
//! ([`super::schema::unrecomposed_revision_schema`]: the rows do not depend on
//! which platforms a workspace enables), and from the revision's model schema,
//! which keeps the `tide.*` keywords and says which fields validation
//! requires. The shapes are
//! the engine's (`opentide_tide::intel`); the module is I/O-free and serves
//! both the CLI and the language server (#926).

use serde::Serialize;
use serde_json::{Map, Value};

use super::json::{Json, Object};
use super::schema::{Sources, revision_model_schema, unrecomposed_revision_schema};
use super::workspace::{CORE_OBJECT_TYPES, identifiers_for_families};
use crate::keys;
use crate::objects::platform::schema::all_root_extras;

/// Where the catalogs go, relative to the workspace root.
pub const CATALOG_DIR: &str = ".opentide/lsp/catalogs/generated";
/// The field catalog's file name.
pub const FIELDS_FILE: &str = "fields.json";
/// The deprecation catalog's file name.
pub const DEPRECATIONS_FILE: &str = "deprecations.json";
/// The `generator` label of both documents: the shapes' name, which the
/// engine and `opentide doctor` know them by.
pub const GENERATOR: &str = "opentide.generation.lsp_catalog";
/// Keys that say where a catalog came from rather than what it holds.
pub const LABEL_KEYS: [&str; 2] = ["opentide", "generator"];

/// Vocabulary essays dominate the catalog and are not needed at hover time:
/// every enum value is kept, short docs only for enums this small.
const ENUM_DOC_MAX: usize = 40;
/// The longest enum doc, in characters, the ellipsis included.
const DOC_CAP: usize = 160;

/// A reference field's name and the family whose objects it names
/// (`_REF_LEAF_TO_TYPE`).
pub const REF_LEAVES: [(&str, &str); 3] = [
    ("threats", "threat"),
    ("detection_model", "objective"),
    ("vector", "threat"),
];

/// Both catalogs as written, by file name: `fields.json`, then
/// `deprecations.json`. `version` is the `opentide` label.
pub fn catalog_texts(version: &str, sources: &Sources) -> Vec<(&'static str, String)> {
    vec![
        (FIELDS_FILE, dump(&fields_catalog(version, sources))),
        (DEPRECATIONS_FILE, dump(&deprecations_catalog(version))),
    ]
}

/// A catalog as the files hold it: two-space indentation, `": "` between a
/// key and its value, UTF-8 unescaped, a final newline.
pub fn dump(document: &Json) -> String {
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"  ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, formatter);
    if document.serialize(&mut serializer).is_err() {
        return String::new();
    }
    out.push(b'\n');
    String::from_utf8(out).unwrap_or_default()
}

/// The `deprecations.json` document: the platform block fields whose root
/// extras carry `tide.meta.deprecation`, sorted by schema and path. The core
/// families' root extras deprecate no field.
pub fn deprecations_catalog(version: &str) -> Json {
    Json::Object(Object::from([
        ("opentide".to_owned(), Json::from(version)),
        ("generator".to_owned(), Json::from(GENERATOR)),
        (
            "fields".to_owned(),
            Json::Array(deprecation_rows(all_root_extras())),
        ),
    ]))
}

/// The `fields` of `deprecations.json` from each platform's root extras: a
/// `rule` row at `configurations.{platform}.{name}` for every property extra
/// whose `tide.meta.deprecation` is truthy, with that message, sorted by
/// schema, path and message.
fn deprecation_rows(extras: impl IntoIterator<Item = (&'static str, Value)>) -> Vec<Json> {
    let mut rows: Vec<(String, String, String)> = Vec::new();
    for (platform, extras) in extras {
        let Some(Value::Object(properties)) = extras.get("property_extras") else {
            continue;
        };
        for (name, spec) in properties {
            if let Some(message) = spec.get(keys::META_DEPRECATION)
                && truthy(message)
            {
                rows.push((
                    "rule".to_owned(),
                    format!("configurations.{platform}.{name}"),
                    scalar_text(message),
                ));
            }
        }
    }
    rows.sort();
    rows.into_iter()
        .map(|(schema, path, message)| {
            Json::Object(Object::from([
                ("schema".to_owned(), Json::from(schema)),
                ("path".to_owned(), Json::from(path)),
                ("message".to_owned(), Json::from(message)),
            ]))
        })
        .collect()
}

/// The `fields.json` document for every registered object revision, from
/// the workspace's `sources`.
pub fn fields_catalog(version: &str, sources: &Sources) -> Json {
    let ids = identifiers_for_families(&CORE_OBJECT_TYPES);
    let mut rows: Vec<Row> = Vec::new();
    let mut roots: Vec<(String, Json)> = Vec::new();
    for id in &ids {
        let identifier = id.to_string();
        let (Some(model), Some(editor)) = (
            revision_model_schema(&identifier),
            unrecomposed_revision_schema(&identifier, sources),
        ) else {
            continue;
        };
        let editor = annotated(editor.as_value());
        let facts = Facts::of(model.as_value());
        let family = id.family().to_owned();
        rows.extend(flatten(&editor, &identifier, &facts));
        roots.push((
            identifier,
            Json::Object(Object::from([
                ("family".to_owned(), Json::from(family)),
                ("closed".to_owned(), Json::Bool(closed(&editor))),
            ])),
        ));
    }
    // `metadata.schema` offers every revision of the family: changing it is
    // how an object moves to another revision.
    for row in &mut rows {
        if row.path == "metadata.schema" {
            let family = row.schema.split("::").next().unwrap_or_default();
            let mut revisions: Vec<&crate::revisions::SchemaId> =
                ids.iter().filter(|id| id.family() == family).collect();
            revisions.sort_by_key(|id| revision_key(&id.to_string()));
            let names: Vec<String> = revisions.iter().map(ToString::to_string).collect();
            row.set("enum", strings(&names));
            row.set("enum_docs", Json::Array(Vec::new()));
            let constant = match names.as_slice() {
                [one] => Json::from(one.clone()),
                _ => Json::Null,
            };
            row.set("const", constant);
        }
    }
    rows.sort_by(|a, b| (schema_key(&a.schema), &a.path).cmp(&(schema_key(&b.schema), &b.path)));
    roots.sort_by_key(|(identifier, _)| schema_key(identifier));
    let ref_leaves = REF_LEAVES
        .iter()
        .map(|(leaf, family)| ((*leaf).to_owned(), Json::from(*family)))
        .collect::<Object>();
    Json::Object(Object::from([
        ("opentide".to_owned(), Json::from(version)),
        ("generator".to_owned(), Json::from(GENERATOR)),
        ("ref_leaves".to_owned(), Json::Object(ref_leaves)),
        (
            "schemas".to_owned(),
            Json::Object(roots.into_iter().collect()),
        ),
        (
            "fields".to_owned(),
            Json::Array(rows.into_iter().map(|row| Json::Object(row.node)).collect()),
        ),
    ]))
}

/// The editor schema as `generate schemas` writes it, hover texts included.
fn annotated(schema: &Value) -> Value {
    let mut json = Json::from(schema);
    super::annotate::annotate_editor_schema(&mut json);
    serde_json::to_value(&json).unwrap_or(Value::Null)
}

/// `family::1.0` sorts by family, then by its revision's numbers.
fn schema_key(identifier: &str) -> (String, Vec<u64>) {
    let (family, revision) = identifier.split_once("::").unwrap_or((identifier, ""));
    (family.to_owned(), revision_key(revision))
}

fn revision_key(revision: &str) -> Vec<u64> {
    let revision = revision.rsplit("::").next().unwrap_or(revision);
    revision
        .split('.')
        .filter_map(|part| part.parse::<u64>().ok())
        .collect()
}

fn strings(values: &[String]) -> Json {
    Json::Array(values.iter().cloned().map(Json::from).collect())
}

/// Whether a schema object forbids keys it does not list.
fn closed(node: &Value) -> bool {
    node.get("additionalProperties") == Some(&Value::Bool(false))
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
    }
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

// --- what the model says ------------------------------------------------------------------

/// What the model schema says that the editor schema does not, by dotted
/// path: whether validation requires a field, its `tide.template.*` flags
/// and its string default.
#[derive(Debug, Default)]
struct Facts {
    required: std::collections::HashMap<String, bool>,
    multiline: std::collections::HashSet<String>,
    hidden: std::collections::HashSet<String>,
    defaults: std::collections::HashMap<String, String>,
}

impl Facts {
    fn of(model: &Value) -> Self {
        let mut facts = Self::default();
        let mut seen = Vec::new();
        facts.walk(model, model, "", &mut seen);
        facts
    }

    fn walk(&mut self, root: &Value, node: &Value, path: &str, seen: &mut Vec<String>) {
        let Some(object) = object_of(root, node) else {
            return;
        };
        let Some(Value::Object(properties)) = object.get("properties") else {
            return;
        };
        let required: Vec<&str> = object
            .get("required")
            .and_then(Value::as_array)
            .map(|keys| keys.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        for (key, spec) in properties {
            let child = join(path, key);
            self.required
                .insert(child.clone(), required.contains(&key.as_str()));
            let merged = effective(root, spec);
            if merged.get(keys::TEMPLATE_MULTILINE).is_some_and(truthy) {
                self.multiline.insert(child.clone());
            }
            if merged.get(keys::TEMPLATE_HIDE).is_some_and(truthy) {
                self.hidden.insert(child.clone());
            }
            if let Some(Value::String(default)) = merged.get("default")
                && !default.is_empty()
            {
                self.defaults.insert(child.clone(), default.clone());
            }
            // A recursive model is walked once along a path.
            let target = definition_name(root, spec);
            if let Some(name) = &target {
                if seen.contains(name) {
                    continue;
                }
                seen.push(name.clone());
            }
            // Only a field that holds one model, or a list of one model, is
            // walked: a union's models (`int | ElasticRisk`) are not.
            if let Some(model) = single_model(root, spec) {
                self.walk(root, model, &child, seen);
            } else if let Some(items) = array_items(root, spec)
                && let Some(model) = single_model(root, items)
            {
                self.walk(root, model, &child, seen);
            }
            if target.is_some() {
                seen.pop();
            }
        }
    }
}

/// The one model a field holds, `null` aside: a `$ref`, or a union of one
/// `$ref` and `null`, to a definition with properties.
fn single_model<'s>(root: &'s Value, node: &'s Value) -> Option<&'s Value> {
    let target = if node.get("$ref").is_some() {
        deref(root, node)
    } else if let Some(Value::Array(branches)) = node.get("anyOf") {
        let mut models = branches
            .iter()
            .filter(|branch| branch.get("type").and_then(Value::as_str) != Some("null"));
        let only = models.next()?;
        if models.next().is_some() || only.get("$ref").is_none() {
            return None;
        }
        deref(root, only)
    } else {
        node
    };
    has_properties(Some(target)).then_some(target)
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

// --- the schema walk ----------------------------------------------------------------------

/// A row of `fields.json`, keyed as the engine reads it.
struct Row {
    schema: String,
    path: String,
    node: Object,
}

impl Row {
    fn set(&mut self, key: &str, value: Json) {
        self.node.insert(key.to_owned(), value);
    }
}

/// The definition a `$ref` names (`#/$defs/<name>`), followed through
/// definitions that only refer to another.
fn deref<'s>(root: &'s Value, node: &'s Value) -> &'s Value {
    let mut current = node;
    for _ in 0..16 {
        let Some(reference) = current.get("$ref").and_then(Value::as_str) else {
            return current;
        };
        match reference
            .strip_prefix("#/$defs/")
            .and_then(|name| root.get("$defs").and_then(|defs| defs.get(name)))
        {
            Some(target) => current = target,
            None => return current,
        }
    }
    current
}

fn definition_name(root: &Value, node: &Value) -> Option<String> {
    let reference = node.get("$ref").and_then(Value::as_str).or_else(|| {
        node.get("anyOf")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find_map(|alt| alt.get("$ref").and_then(Value::as_str))
    })?;
    let _ = root;
    reference.strip_prefix("#/$defs/").map(str::to_owned)
}

/// `node` with the keywords of the definition it refers to: the node's own
/// keywords win (a property's `description` beside its `$ref`).
fn effective(root: &Value, node: &Value) -> Map<String, Value> {
    let mut merged = match node {
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    };
    if merged.contains_key("$ref") {
        let target = deref(root, node);
        if let Value::Object(target) = target {
            for (key, value) in target {
                merged.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
        merged.remove("$ref");
    }
    merged
}

/// The object schema a field holds, through `$ref` and `anyOf` branches
/// (unions of unions included); `None` for a field that holds no object with
/// properties (`_unwrap`).
fn object_of<'s>(root: &'s Value, node: &'s Value) -> Option<&'s Value> {
    object_in(root, node, 0)
}

fn object_in<'s>(root: &'s Value, node: &'s Value, depth: usize) -> Option<&'s Value> {
    if !node.is_object() || depth > 8 {
        return None;
    }
    let target = if node.get("$ref").is_some() {
        deref(root, node)
    } else {
        node
    };
    if has_properties(Some(target)) {
        return Some(target);
    }
    target
        .get("anyOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find_map(|alt| object_in(root, alt, depth + 1))
}

fn has_properties(node: Option<&Value>) -> bool {
    node.and_then(|node| node.get("properties"))
        .and_then(Value::as_object)
        .is_some_and(|map| !map.is_empty())
}

/// The JSON Schema types a node names: `"string"`, or `["string", "null"]`.
fn types(node: &Map<String, Value>) -> Vec<&str> {
    match node.get("type") {
        Some(Value::String(kind)) => vec![kind.as_str()],
        Some(Value::Array(kinds)) => kinds.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn is_type(node: &Map<String, Value>, kind: &str) -> bool {
    types(node).contains(&kind)
}

/// The non-null alternatives of a node: its `anyOf` branches, each with the
/// keywords of the definition it refers to, and a branch that is itself a
/// union (`RiskChoice`, `int | ElasticRisk`) as its own branches.
fn alternatives(root: &Value, node: &Map<String, Value>) -> Vec<Map<String, Value>> {
    let mut found = Vec::new();
    collect_alternatives(root, node, &mut found, 0);
    found
}

fn collect_alternatives(
    root: &Value,
    node: &Map<String, Value>,
    found: &mut Vec<Map<String, Value>>,
    depth: usize,
) {
    for alt in node
        .get("anyOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let alt = effective(root, alt);
        if types(&alt) == ["null"] {
            continue;
        }
        if depth < 8 && is_union(&alt) {
            collect_alternatives(root, &alt, found, depth + 1);
        } else {
            found.push(alt);
        }
    }
}

/// A schema that is only a union of others: `anyOf`, no type, no properties.
fn is_union(node: &Map<String, Value>) -> bool {
    node.contains_key("anyOf") && !node.contains_key("type") && !node.contains_key("properties")
}

/// An array field's `items`, through the definition it refers to and its
/// `anyOf` branches.
fn array_items<'s>(root: &'s Value, node: &'s Value) -> Option<&'s Value> {
    let node = if node.get("$ref").is_some() {
        deref(root, node)
    } else {
        node
    };
    let map = node.as_object()?;
    if is_type(map, "array") {
        return map.get("items").filter(|items| items.is_object());
    }
    for alt in node
        .get("anyOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let alt = deref(root, alt);
        if alt.as_object().is_some_and(|map| is_type(map, "array")) {
            return alt.get("items").filter(|items| items.is_object());
        }
    }
    None
}

fn flatten(schema: &Value, identifier: &str, facts: &Facts) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut seen = Vec::new();
    walk(schema, schema, "", identifier, facts, &mut rows, &mut seen);
    rows
}

fn walk(
    root: &Value,
    node: &Value,
    path: &str,
    identifier: &str,
    facts: &Facts,
    rows: &mut Vec<Row>,
    seen: &mut Vec<String>,
) {
    let object = if path.is_empty() {
        Some(node)
    } else {
        object_of(root, node)
    };
    let Some(object) = object else {
        return;
    };
    let Some(Value::Object(properties)) = object.get("properties") else {
        return;
    };
    let required: Vec<&str> = object
        .get("required")
        .and_then(Value::as_array)
        .map(|keys| keys.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for (key, spec) in properties {
        if !spec.is_object() {
            continue;
        }
        let child = join(path, key);
        let listed = required.contains(&key.as_str());
        let is_required = facts.required.get(&child).copied().unwrap_or(listed);
        let mut row = field_row(root, identifier, &child, key, spec, is_required, facts);
        if listed && !is_required {
            // Templates ask for it, validation does not require it.
            row.set("recommended", Json::Bool(true));
        }
        let index = rows.len();
        rows.push(row);
        let target = definition_name(root, spec);
        if let Some(name) = &target {
            if seen.contains(name) {
                continue;
            }
            seen.push(name.clone());
        }
        let nested = object_of(root, spec);
        if has_properties(nested) {
            if nested.is_some_and(closed) {
                rows[index].set("closed", Json::Bool(true));
            }
            walk(root, spec, &child, identifier, facts, rows, seen);
        }
        if let Some(items) = array_items(root, spec) {
            let nested = object_of(root, items);
            if has_properties(nested) {
                if nested.is_some_and(closed) {
                    rows[index].set("closed", Json::Bool(true));
                }
                walk(root, items, &child, identifier, facts, rows, seen);
            }
        }
        if target.is_some() {
            seen.pop();
        }
    }
}

fn field_row(
    root: &Value,
    identifier: &str,
    path: &str,
    name: &str,
    raw: &Value,
    required: bool,
    facts: &Facts,
) -> Row {
    let spec = effective(root, raw);
    // `clean_enum` drops an empty value, so an enum of `""` alone is empty.
    let (mut values, docs, is_array) = enum_of(root, &spec);
    let mut docs: Vec<String> = if values.len() > ENUM_DOC_MAX {
        Vec::new()
    } else {
        docs.iter().map(|doc| cap_doc(doc)).collect()
    };
    let kind = type_name(root, &spec, is_array);
    let constant = const_of(root, &spec);
    let reference = if kind == "string" || kind == "array" {
        REF_LEAVES
            .iter()
            .find(|(leaf, _)| *leaf == name)
            .map(|(_, family)| *family)
    } else {
        None
    };
    if reference.is_some() {
        // A reference is checked, and completed, against the live index of
        // the workspace's objects, never against a snapshot of their UUIDs.
        values.clear();
        docs.clear();
    }
    // An empty constant offers no value (the oracle tests it for truth).
    if let Some(constant) = &constant
        && !constant.is_empty()
        && values.is_empty()
    {
        values = vec![constant.clone()];
        docs = vec![String::new()];
    }
    let mut default = facts.defaults.get(path).cloned();
    if default
        .as_ref()
        .is_some_and(|default| !values.is_empty() && !values.contains(default))
    {
        // A model default can sit outside the schema enum.
        default = None;
    }
    let title = raw
        .get("title")
        .and_then(Value::as_str)
        .filter(|title| !title.is_empty())
        .map_or_else(|| default_title(name), str::to_owned);
    let description = raw
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    docs.truncate(values.len());
    docs.resize(values.len(), String::new());
    let mut node = Object::new();
    node.insert("schema".into(), Json::from(identifier));
    node.insert("path".into(), Json::from(path));
    node.insert("name".into(), Json::from(name));
    node.insert("title".into(), Json::from(title));
    node.insert("description".into(), Json::from(description));
    node.insert("type".into(), Json::from(kind.clone()));
    node.insert("required".into(), Json::Bool(required));
    node.insert(
        "markdown".into(),
        Json::Bool(facts.multiline.contains(path)),
    );
    node.insert("hidden".into(), Json::Bool(facts.hidden.contains(path)));
    // Every key takes one capture, so nesting never recolours a key.
    node.insert("capture".into(), Json::from("tide.property"));
    node.insert("enum".into(), strings(&values));
    let docs = if docs.iter().any(|doc| !doc.is_empty()) {
        docs
    } else {
        Vec::new()
    };
    node.insert("enum_docs".into(), strings(&docs));
    node.insert("ref".into(), reference.map_or(Json::Null, Json::from));
    node.insert("const".into(), constant.map_or(Json::Null, Json::from));
    node.insert("array".into(), Json::Bool(is_array || kind == "array"));
    if let Some(default) = default {
        node.insert("default".into(), Json::from(default));
    }
    if let Some(min_items) = min_items(root, &spec) {
        node.insert("min_items".into(), Json::Number(min_items.into()));
    }
    Row {
        schema: identifier.to_owned(),
        path: path.to_owned(),
        node,
    }
}

/// A field's title where its schema gives none: its name, words split at
/// `_`, each capitalised (`mitre_attack` is `Mitre Attack`), as the models'
/// titles have always been written.
fn default_title(name: &str) -> String {
    name.split('_')
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map_or_else(String::new, |first| {
                first
                    .to_uppercase()
                    .chain(chars.flat_map(char::to_lowercase))
                    .collect()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn min_items(root: &Value, spec: &Map<String, Value>) -> Option<u64> {
    if let Some(count) = spec.get("minItems").and_then(Value::as_u64) {
        return Some(count);
    }
    alternatives(root, spec)
        .iter()
        .find_map(|alt| alt.get("minItems").and_then(Value::as_u64))
}

/// A field's enum values and their docs, and whether it is an array.
fn enum_of(root: &Value, spec: &Map<String, Value>) -> (Vec<String>, Vec<String>, bool) {
    if is_type(spec, "array") {
        return array_enum(root, spec);
    }
    // An enum beside `anyOf` applies only when the value can be one of
    // those strings.
    if let Some(Value::Array(values)) = spec.get("enum")
        && scalar_enum_applies(root, spec)
    {
        let (values, docs) = clean_enum(values, enum_docs(spec));
        return (values, docs, false);
    }
    for alt in alternatives(root, spec) {
        if is_type(&alt, "array") {
            return array_enum(root, &alt);
        }
        if let Some(Value::Array(values)) = alt.get("enum") {
            let (values, docs) = clean_enum(values, enum_docs(&alt));
            return (values, docs, false);
        }
    }
    (Vec::new(), Vec::new(), is_type(spec, "array"))
}

fn enum_docs(spec: &Map<String, Value>) -> &[Value] {
    spec.get("markdownEnumDescriptions")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn items_of(root: &Value, spec: &Map<String, Value>) -> Map<String, Value> {
    spec.get("items")
        .filter(|items| items.is_object())
        .map(|items| effective(root, items))
        .unwrap_or_default()
}

fn array_enum(root: &Value, spec: &Map<String, Value>) -> (Vec<String>, Vec<String>, bool) {
    let items = items_of(root, spec);
    if let Some(Value::Array(values)) = items.get("enum") {
        let (values, docs) = clean_enum(values, enum_docs(&items));
        return (values, docs, true);
    }
    (Vec::new(), Vec::new(), true)
}

fn scalar_enum_applies(root: &Value, spec: &Map<String, Value>) -> bool {
    let kinds: Vec<&str> = types(spec)
        .into_iter()
        .filter(|kind| *kind != "null")
        .collect();
    if kinds
        .iter()
        .any(|kind| matches!(*kind, "array" | "object" | "integer" | "number" | "boolean"))
    {
        return false;
    }
    let alternatives = alternatives(root, spec);
    if alternatives.is_empty() {
        return kinds.is_empty() || kinds == ["string"];
    }
    if alternatives.iter().any(|alt| is_object_array(root, alt)) {
        return false;
    }
    alternatives.iter().any(|alt| holds_string(root, alt))
}

fn is_object_array(root: &Value, alt: &Map<String, Value>) -> bool {
    if !is_type(alt, "array") {
        return false;
    }
    let items = items_of(root, alt);
    is_type(&items, "object")
        || items.contains_key("properties")
        || items.contains_key("additionalProperties")
}

fn holds_string(root: &Value, alt: &Map<String, Value>) -> bool {
    if is_type(alt, "string") {
        return true;
    }
    if !is_type(alt, "array") {
        return false;
    }
    let items = items_of(root, alt);
    (types(&items).is_empty() || is_type(&items, "string")) && !items.contains_key("properties")
}

/// An enum value as YAML writes it; `None` for an empty or null value.
fn yaml_scalar(value: &Value) -> Option<String> {
    match value {
        Value::Bool(true) => Some("true".into()),
        Value::Bool(false) => Some("false".into()),
        Value::Null => None,
        Value::String(text) if text.is_empty() => None,
        Value::String(text) => Some(text.clone()),
        other => Some(other.to_string()),
    }
}

fn clean_enum(values: &[Value], docs: &[Value]) -> (Vec<String>, Vec<String>) {
    // A nullable field's enum ends in `null`, which has no doc of its own.
    let non_null = values.iter().filter(|value| !value.is_null()).count();
    let every_value = docs.len() == values.len();
    let paired = every_value || docs.len() == non_null;
    let mut docs = docs.iter();
    let mut cleaned = Vec::new();
    let mut short = Vec::new();
    for value in values {
        let doc = if paired && (every_value || !value.is_null()) {
            docs.next()
        } else {
            None
        };
        let Some(rendered) = yaml_scalar(value) else {
            continue;
        };
        cleaned.push(rendered);
        short.push(
            doc.and_then(Value::as_str)
                .map(short_doc)
                .unwrap_or_default(),
        );
    }
    (cleaned, short)
}

/// The part of a dropdown's Markdown after its last `---`, on one line.
fn short_doc(markdown: &str) -> String {
    let text = markdown.trim();
    let text = text.rsplit("---").next().unwrap_or(text).trim();
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn cap_doc(text: &str) -> String {
    if text.chars().count() <= DOC_CAP {
        return text.to_owned();
    }
    let kept: String = text.chars().take(DOC_CAP - 1).collect();
    format!("{}…", kept.trim_end())
}

fn const_of(root: &Value, spec: &Map<String, Value>) -> Option<String> {
    if let Some(Value::String(constant)) = spec.get("const") {
        return Some(constant.clone());
    }
    alternatives(root, spec)
        .iter()
        .find_map(|alt| alt.get("const").and_then(Value::as_str).map(str::to_owned))
}

fn type_name(root: &Value, spec: &Map<String, Value>, is_array: bool) -> String {
    let alternatives = alternatives(root, spec);
    if is_array || is_type(spec, "array") || alternatives.iter().any(|alt| is_type(alt, "array")) {
        return "array".into();
    }
    let node = Value::Object(spec.clone());
    if has_properties(object_of(root, &node))
        || alternatives
            .iter()
            .any(|alt| alt.contains_key("properties"))
    {
        return "object".into();
    }
    if let Some(kind) = types(spec).into_iter().find(|kind| *kind != "null") {
        return kind.to_owned();
    }
    for alt in &alternatives {
        if let Some(kind) = types(alt).into_iter().find(|kind| *kind != "null") {
            return kind.to_owned();
        }
    }
    if spec.get("format").and_then(Value::as_str) == Some("date") {
        "string".into()
    } else {
        "any".into()
    }
}

#[cfg(test)]
mod tests;
