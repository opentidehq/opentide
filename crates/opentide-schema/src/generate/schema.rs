//! The editor JSON Schema of each object revision (`rule`, `threat`,
//! `objective`, `*.schema.json`) and of `visibility.toml` (UC-1.8b, #900):
//! what `opentide generate schemas` writes, from the Rust models.
//!
//! The base of every document is the model's derived schema (schemars,
//! draft 2020-12). opentide's own additions are schemars [`Transform`]s
//! applied to it in order, never a port of Pydantic's schema pipeline:
//!
//! 1. [`RootExtras`]: the family's title, description, required keys and
//!    closure (`_CORE_ROOT_EXTRAS_BASE`), and the property hints a family
//!    adds (`detection_model` draws from the workspace's objectives,
//!    `configurations` is recomposed from the enabled platforms);
//! 2. [`ApplyPins`]: each vocabulary contract the revision pins
//!    (`metadata.tlp` = `tlp::1.0`), set as the field's `tide.vocab`;
//! 3. [`Recompose`]: `configurations` gets one property per enabled
//!    platform, the block's schema with its status, tenants and `schema`
//!    choices (`recomposition_handler`, `platform_root_extras`);
//! 4. [`ResolveValues`]: every `tide.vocab` becomes an `enum` with its
//!    Markdown dropdowns, plain descriptions and search hints, and every
//!    `tide.config.*` key the configured values (statuses, tenants,
//!    responders, log sources, detectors, enabled platforms, parameter
//!    lists);
//! 5. [`CloseObjects`]: an object property that does not say otherwise
//!    takes no unknown keys;
//! 6. [`PinIdentifier`]: `metadata.schema` is the revision's identifier;
//! 7. [`StripFrameworkKeywords`]: no `tide.*` keyword is left;
//!
//! then [`super::annotate::annotate_editor_schema`] adds the hover texts.
//!
//! The comparison with the oracle is by verdict, not by text: `cargo xtask
//! codegen --check` validates every corpus object and fault against both
//! documents and requires the same verdict. The text differences (titles,
//! descriptions, key order, `type` arrays where Pydantic writes `anyOf` with
//! `null`) are recorded in `tests/golden/APPROVED_DIFFS.toml`.

use std::sync::Arc;

use schemars::generate::SchemaSettings;
use schemars::transform::Transform;
use schemars::{JsonSchema, Schema};
use serde_json::{Map, Value, json};

use crate::configuration::models::VisibilityConfig;
use crate::configuration::types::StatusStrategy;
use crate::keys;
use crate::node::{Node, Value as NodeValue};
use crate::objects::objective::ObjectiveV1_0;
use crate::objects::platform::schema::root_extras as platform_root_extras;
use crate::objects::platform::{PLATFORM_CONFIG_MODELS, Registered};
use crate::objects::rule::{RuleV1_0, RuleV1_1};
use crate::objects::threat::ThreatVectorV1_0;
use crate::pins::{PinTable, Pins};
use crate::vocab::{Entry, KeyKind, OBJECT_TYPES, VocabRef, Vocabularies, Vocabulary};

use super::annotate::{annotate_editor_schema, first_sentence, plain_text};
use super::json::Json;
use super::workspace::enabled_platforms;

/// What a revision's schema draws on besides its model: the workspace's
/// resolved configuration and its vocabularies, the workspace's object
/// vocabularies (`threat`, `objective`, `rule`) included.
#[derive(Clone)]
pub struct Sources {
    /// The resolved configuration (`configuration::resolve`).
    pub config: Arc<Node>,
    /// The vocabularies, with the workspace's object vocabularies inserted.
    pub vocabularies: Arc<Vocabularies>,
}

/// The schemars schema of `T`, draft 2020-12.
pub fn model_schema<T: JsonSchema>() -> Schema {
    SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<T>()
}

/// The derived schema of a registered object revision, or `None` for an
/// identifier that names none.
pub fn revision_model_schema(identifier: &str) -> Option<Schema> {
    Some(match identifier {
        "rule::1.0" => model_schema::<RuleV1_0>(),
        "rule::1.1" => model_schema::<RuleV1_1>(),
        "threat::1.0" => model_schema::<ThreatVectorV1_0>(),
        "objective::1.0" => model_schema::<ObjectiveV1_0>(),
        _ => return None,
    })
}

/// The editor schema of the object revision `identifier`, every transform
/// applied, before the hover annotations; `None` for an identifier that
/// names no revision.
pub fn revision_schema(identifier: &str, sources: &Sources) -> Option<Schema> {
    let mut schema = revision_model_schema(identifier)?;
    let family = identifier.split("::").next().unwrap_or_default();
    RootExtras { family }.transform(&mut schema);
    if let Some(pins) = PinTable::bundled().get(identifier) {
        ApplyPins { pins }.transform(&mut schema);
    }
    Recompose {
        config: &sources.config,
    }
    .transform(&mut schema);
    ResolveValues { sources }.transform(&mut schema);
    CloseObjects.transform(&mut schema);
    PinIdentifier { identifier }.transform(&mut schema);
    StripFrameworkKeywords.transform(&mut schema);
    Some(schema)
}

/// `visibility.toml`'s schema as `generate schemas` writes it: the
/// configuration schema of [`VisibilityConfig`] (one schema source for the
/// file, #374).
pub fn visibility_schema() -> Schema {
    let mut schema = model_schema::<VisibilityConfig>();
    InlineRoot.transform(&mut schema);
    StripFrameworkKeywords.transform(&mut schema);
    schema.insert("title".to_owned(), "visibility.toml".into());
    schema
}

/// The text written for an editor schema: the hover annotations added, keys
/// in `serde_json`'s order, four-space indentation, non-ASCII escaped, a
/// final newline.
pub fn editor_text(schema: &Schema) -> String {
    let mut json = Json::from(schema.as_value());
    annotate_editor_schema(&mut json);
    json.to_python_text()
}

// --- the transforms -----------------------------------------------------------------------

/// Runs `f` on the schema's JSON value.
fn with_value(schema: &mut Schema, f: impl FnOnce(&mut Value)) {
    let mut value = std::mem::replace(schema, Schema::from(true)).to_value();
    f(&mut value);
    *schema = Schema::try_from(value).unwrap_or_else(|_| Schema::from(true));
}

/// A root that only refers to a definition (a `#[serde(transparent)]`
/// model, `VisibilityConfig`) becomes that definition, so the document's
/// root holds its properties.
#[derive(Debug, Clone, Copy)]
pub struct InlineRoot;

impl Transform for InlineRoot {
    fn transform(&mut self, schema: &mut Schema) {
        with_value(schema, |value| {
            let Some(name) = value
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(|reference| reference.strip_prefix("#/$defs/"))
                .map(str::to_owned)
            else {
                return;
            };
            let Some(Value::Object(definition)) = value
                .get_mut("$defs")
                .and_then(Value::as_object_mut)
                .and_then(|defs| defs.remove(&name))
            else {
                return;
            };
            if let Value::Object(root) = value {
                root.remove("$ref");
                for (key, keyword) in definition {
                    root.entry(key).or_insert(keyword);
                }
                if root
                    .get("$defs")
                    .and_then(Value::as_object)
                    .is_some_and(Map::is_empty)
                {
                    root.remove("$defs");
                }
            }
        });
    }
}

/// Removes every `tide.*` keyword, at any depth (`strip_framework_keywords`).
#[derive(Debug, Clone, Copy)]
pub struct StripFrameworkKeywords;

impl Transform for StripFrameworkKeywords {
    fn transform(&mut self, schema: &mut Schema) {
        with_value(schema, strip);
    }
}

fn strip(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|key, _| !key.starts_with("tide."));
            map.values_mut().for_each(strip);
        }
        Value::Array(items) => items.iter_mut().for_each(strip),
        _ => {}
    }
}

/// A family's title, description, required keys, closure and property
/// hints (`_CORE_ROOT_EXTRAS_BASE`). A required key the family adds comes
/// first; the model's required keys are all kept.
#[derive(Debug, Clone, Copy)]
pub struct RootExtras<'a> {
    /// `rule`, `threat` or `objective`.
    pub family: &'a str,
}

impl Transform for RootExtras<'_> {
    fn transform(&mut self, schema: &mut Schema) {
        let (title, description, required): (&str, Option<&str>, &[&str]) = match self.family {
            "rule" => (
                "Detection Rule Schema",
                Some("A detection rule defines how a detection opportunity is implemented."),
                &[
                    "name",
                    "metadata",
                    "response",
                    "description",
                    "configurations",
                ],
            ),
            "objective" => (
                "Detection Objective Schema",
                None,
                &["name", "metadata", "objective"],
            ),
            "threat" => (
                "Threat Vector Schema",
                None,
                &["name", "criticality", "metadata", "threat"],
            ),
            _ => return,
        };
        schema.insert("title".to_owned(), title.into());
        if let Some(description) = description {
            schema.insert("description".to_owned(), description.into());
        }
        schema.insert("additionalProperties".to_owned(), false.into());
        let model: Vec<Value> = schema
            .get("required")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut merged: Vec<Value> = required.iter().map(|&key| Value::from(key)).collect();
        for key in model {
            if !merged.contains(&key) {
                merged.push(key);
            }
        }
        schema.insert("required".to_owned(), Value::Array(merged));
        if self.family == "rule"
            && let Some(Value::Object(properties)) = schema.get_mut("properties")
        {
            if let Some(Value::Object(field)) = properties.get_mut("detection_model") {
                field.insert(keys::VOCAB.to_owned(), "objective".into());
            }
            if let Some(Value::Object(field)) = properties.get_mut("configurations") {
                field.insert(
                    "title".to_owned(),
                    "Detection System Technical Setup".into(),
                );
                field.insert(RECOMPOSITION.to_owned(), "systems".into());
            }
        }
    }
}

/// The keyword that names the configuration table whose enabled platforms
/// become an object's properties (`recomposition`). It stays in the written
/// schema, as the oracle leaves it.
pub const RECOMPOSITION: &str = "recomposition";

/// Sets each contract a revision pins (`metadata.tlp` = `tlp::1.0`) as the
/// `tide.vocab` of the field it names, through nested models, `$ref`s,
/// `anyOf` branches and list items (`apply_pin_map`).
#[derive(Debug, Clone, Copy)]
pub struct ApplyPins<'a> {
    /// The revision's pins.
    pub pins: &'a Pins,
}

impl Transform for ApplyPins<'_> {
    fn transform(&mut self, schema: &mut Schema) {
        with_value(schema, |value| apply_pins(value, self.pins));
    }
}

/// [`ApplyPins`] on a schema held as a value.
pub fn apply_pins(schema: &mut Value, pins: &Pins) {
    for (path, contract) in pins.contracts() {
        let parts: Vec<&str> = path.split('.').filter(|part| !part.is_empty()).collect();
        if !parts.is_empty() {
            set_vocab(schema, "/properties", &parts, &contract.to_string());
        }
    }
}

/// A JSON Pointer token.
fn token(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// The pointer of the node at `pointer` with its local `$ref` followed.
fn deref_pointer(schema: &Value, pointer: &str) -> String {
    schema
        .pointer(pointer)
        .and_then(|node| node.get("$ref"))
        .and_then(Value::as_str)
        .and_then(|reference| reference.rsplit('/').next())
        .filter(|name| {
            schema
                .get("$defs")
                .and_then(|defs| defs.get(*name))
                .is_some_and(Value::is_object)
        })
        .map_or_else(
            || pointer.to_owned(),
            |name| format!("/$defs/{}", token(name)),
        )
}

fn set_vocab(schema: &mut Value, properties: &str, parts: &[&str], contract: &str) {
    let field = format!("{properties}/{}", token(parts[0]));
    if !schema.pointer(&field).is_some_and(Value::is_object) {
        return;
    }
    if parts.len() == 1 {
        if let Some(Value::Object(node)) = schema.pointer_mut(&field) {
            node.insert(keys::VOCAB.to_owned(), Value::String(contract.to_owned()));
        }
        return;
    }
    let resolved = deref_pointer(schema, &field);
    let alternatives = ["anyOf", "oneOf"].into_iter().find_map(|key| {
        schema
            .pointer(&format!("{resolved}/{key}"))
            .and_then(Value::as_array)
            .filter(|list| !list.is_empty())
            .map(|list| (key, list.len()))
    });
    let branches: Vec<String> = match alternatives {
        Some((key, count)) => (0..count)
            .map(|index| format!("{resolved}/{key}/{index}"))
            .filter(|pointer| schema.pointer(pointer).is_some_and(Value::is_object))
            .map(|pointer| deref_pointer(schema, &pointer))
            .collect(),
        None => vec![resolved],
    };
    for branch in branches {
        let is_array = schema
            .pointer(&format!("{branch}/type"))
            .is_some_and(|kind| kind == "array" || has_type(kind, "array"));
        if is_array {
            let items = format!("{branch}/items");
            if !schema.pointer(&items).is_some_and(Value::is_object) {
                continue;
            }
            let item = deref_pointer(schema, &items);
            if let Some(Value::Object(node)) = schema.pointer_mut(&item) {
                node.entry("properties")
                    .or_insert_with(|| Value::Object(Map::new()));
            }
            set_vocab(schema, &format!("{item}/properties"), &parts[1..], contract);
            continue;
        }
        let nested = format!("{branch}/properties");
        if schema.pointer(&nested).is_some_and(Value::is_object) {
            set_vocab(schema, &nested, &parts[1..], contract);
        }
    }
}

/// Whether a `type` keyword (a name or a list of names) includes `name`.
fn has_type(kind: &Value, name: &str) -> bool {
    match kind {
        Value::String(kind) => kind == name,
        Value::Array(kinds) => kinds.iter().any(|kind| kind == name),
        _ => false,
    }
}

/// `configurations`' properties: one per platform the configuration
/// enables, its block's schema with the block's title, description,
/// required keys, status, tenants and `schema` choices
/// (`recomposition_handler`). A platform opentide has no rule block for adds
/// nothing.
#[derive(Debug, Clone, Copy)]
pub struct Recompose<'a> {
    /// The resolved configuration.
    pub config: &'a Node,
}

impl Transform for Recompose<'_> {
    fn transform(&mut self, schema: &mut Schema) {
        let Some(Value::Object(properties)) = schema.get("properties") else {
            return;
        };
        let targets: Vec<String> = properties
            .iter()
            .filter(|(_, field)| field.get(RECOMPOSITION).is_some())
            .map(|(key, _)| key.clone())
            .collect();
        if targets.is_empty() {
            return;
        }
        let defs = schema.get("$defs").cloned().unwrap_or(Value::Null);
        let mut recomposed = Map::new();
        for (identifier, title) in enabled_platforms(self.config) {
            let Some(registered) = PLATFORM_CONFIG_MODELS
                .iter()
                .find(|registered| registered.key == identifier)
            else {
                continue;
            };
            let description = self
                .config
                .get("platforms")
                .and_then(|platforms| platforms.get(&identifier))
                .and_then(|platform| platform.get("platform"))
                .and_then(|platform| platform.get("description"))
                .and_then(|description| description.value.as_str())
                .unwrap_or_default()
                .to_owned();
            recomposed.insert(
                identifier.clone(),
                platform_property(&defs, registered, &title, &description),
            );
        }
        if let Some(Value::Object(properties)) = schema.get_mut("properties") {
            for target in targets {
                if let Some(Value::Object(field)) = properties.get_mut(&target) {
                    field.insert("properties".to_owned(), Value::Object(recomposed.clone()));
                }
            }
        }
    }
}

/// One enabled platform's property under `configurations`.
fn platform_property(
    defs: &Value,
    registered: &Registered,
    title: &str,
    description: &str,
) -> Value {
    let mut block = defs
        .get(registered.model)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let extras = platform_root_extras(registered);
    let mut required: Vec<Value> = extras["required"].as_array().cloned().unwrap_or_default();
    for key in block
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if !required.contains(&key) {
            required.push(key);
        }
    }
    block.insert("required".to_owned(), Value::Array(required));
    if let (Some(Value::Object(properties)), Some(Value::Object(property_extras))) = (
        block.get_mut("properties"),
        extras.get("property_extras").cloned(),
    ) {
        for (field, field_extras) in property_extras {
            if let (Some(Value::Object(property)), Value::Object(field_extras)) =
                (properties.get_mut(&field), field_extras)
            {
                property.extend(field_extras);
            }
        }
    }
    block.insert("title".to_owned(), title.into());
    block.insert("description".to_owned(), description.into());
    block.insert("type".to_owned(), "object".into());
    Value::Object(block)
}

/// Every value a `tide.vocab` or `tide.config.*` keyword asks for, written as
/// the field's `enum` with its editor texts (`gen_json_schema`).
#[derive(Clone, Copy)]
pub struct ResolveValues<'a> {
    /// What the values come from.
    pub sources: &'a Sources,
}

impl Transform for ResolveValues<'_> {
    fn transform(&mut self, schema: &mut Schema) {
        with_value(schema, |value| resolve_node(value, None, self.sources));
    }
}

/// The keywords whose values are maps of property names to subschemas.
const SCHEMA_MAPS: [&str; 4] = [
    "properties",
    "$defs",
    "patternProperties",
    "dependentSchemas",
];

fn resolve_node(node: &mut Value, key: Option<&str>, sources: &Sources) {
    match node {
        Value::Object(map) => {
            resolve_field(map, key, sources);
            for (name, child) in map.iter_mut() {
                if SCHEMA_MAPS.contains(&name.as_str()) {
                    if let Value::Object(children) = child {
                        for (child_key, grandchild) in children.iter_mut() {
                            resolve_node(grandchild, Some(child_key), sources);
                        }
                    }
                } else if name != "enum" && name != "const" && name != "default" {
                    resolve_node(child, None, sources);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                resolve_node(item, None, sources);
            }
        }
        _ => {}
    }
}

/// The values, Markdown dropdowns and plain descriptions a field offers.
#[derive(Debug, Default, Clone, PartialEq)]
struct Offer {
    values: Vec<Value>,
    markdown: Vec<String>,
    plain: Vec<String>,
}

impl Offer {
    /// The keywords to write: `enum`, `markdownEnumDescriptions`, and
    /// `enumDescriptions` when there is one per value.
    fn keywords(&self, plain: bool) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("enum".to_owned(), Value::Array(self.values.clone()));
        map.insert(
            "markdownEnumDescriptions".to_owned(),
            self.markdown
                .iter()
                .map(|text| Value::from(text.as_str()))
                .collect(),
        );
        if plain && self.plain.len() == self.values.len() {
            map.insert(
                "enumDescriptions".to_owned(),
                self.plain
                    .iter()
                    .map(|text| Value::from(text.as_str()))
                    .collect(),
            );
        }
        map
    }
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null | Value::Bool(false)) => false,
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(_) => true,
    }
}

fn resolve_field(map: &mut Map<String, Value>, key: Option<&str>, sources: &Sources) {
    if let Some(message) = map.get(keys::META_DEPRECATION).and_then(Value::as_str) {
        let message = message.to_owned();
        map.insert("title".to_owned(), " DEPRECATION WARNING".into());
        map.insert(
            "description".to_owned(),
            format!(" DEPRECATED : {message}").into(),
        );
    }
    let config = &sources.config;
    if truthy(map.get(keys::CONFIG_VISIBILITY_LOGSOURCE_NAMES))
        && let Some(offer) = logsources(config)
    {
        let mut items = offer.keywords(false);
        items.insert("uniqueItems".to_owned(), true.into());
        map.insert("items".to_owned(), Value::Object(items));
    }
    if truthy(map.get(keys::CONFIG_VISIBILITY_DETECTORS))
        && let Some(offer) = detectors(config)
    {
        set_typed(map, &offer.keywords(false));
    }
    if let Some(path) = map.get(keys::CONFIG_PARAMETER_LIST).and_then(Value::as_str) {
        let values = parameter_list(config, path);
        let mut keywords = Map::new();
        keywords.insert("enum".to_owned(), Value::Array(values));
        set_typed(map, &keywords);
    }
    if truthy(map.get(keys::CONFIG_SYSTEMS_ENABLED)) {
        let values: Vec<Value> = enabled_platforms(config)
            .into_iter()
            .map(|(identifier, _)| Value::from(identifier))
            .collect();
        let mut keywords = Map::new();
        keywords.insert("enum".to_owned(), Value::Array(values));
        set_typed(map, &keywords);
    }
    if let Some(platform) = map.get(keys::CONFIG_SYSTEM_TENANTS).and_then(Value::as_str) {
        let offer = tenants(config, platform);
        if !offer.values.is_empty() {
            apply_enum(map, &offer.keywords(false));
        }
    }
    if truthy(map.get(keys::CONFIG_STATUSES)) {
        let offer = statuses(config);
        set_typed(map, &offer.keywords(false));
    }
    if truthy(map.get(keys::CONFIG_RESPONDERS)) {
        let offer = responders(config);
        if !offer.values.is_empty() {
            apply_enum(map, &offer.keywords(false));
        }
    }
    let Some(vocab) = map.get(keys::VOCAB).cloned() else {
        return;
    };
    let references: Vec<String> = match vocab {
        Value::Bool(true) => key.map(str::to_owned).into_iter().collect(),
        Value::String(reference) => vec![reference],
        Value::Array(references) => references
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    if references.is_empty() {
        return;
    }
    let scoped = truthy(map.get(keys::VOCAB_SCOPED));
    let no_wrap = truthy(map.get(keys::VOCAB_HINTS_NO_WRAP));
    let stages: Vec<String> = match map.get(keys::VOCAB_STAGES) {
        Some(Value::String(stage)) => vec![stage.clone()],
        Some(Value::Array(stages)) => stages
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    let mut offer = Offer::default();
    for reference in &references {
        let one = vocabulary_offer(
            &sources.vocabularies,
            reference,
            &VocabOptions {
                scoped,
                no_wrap,
                stages: &stages,
            },
        );
        offer.values.extend(one.values);
        offer.markdown.extend(one.markdown);
        offer.plain.extend(one.plain);
    }
    apply_enum(map, &offer.keywords(true));
}

/// Sets `keywords` on a field by its declared `type`: on the field for a
/// string, on its `items` (with `uniqueItems`) for an array.
fn set_typed(map: &mut Map<String, Value>, keywords: &Map<String, Value>) {
    let kind = map.get("type").cloned().unwrap_or(Value::Null);
    if has_type(&kind, "string") {
        let mut keywords = keywords.clone();
        if has_type(&kind, "null")
            && let Some(Value::Array(values)) = keywords.get_mut("enum")
        {
            values.push(Value::Null);
        }
        map.extend(keywords);
    } else if has_type(&kind, "array") {
        let mut items = keywords.clone();
        items.insert("uniqueItems".to_owned(), true.into());
        map.insert("items".to_owned(), Value::Object(items));
    }
}

/// Whether an array schema's items are objects, where a string enum does
/// not belong.
fn items_are_objects(array: &Map<String, Value>) -> bool {
    let Some(Value::Object(items)) = array.get("items") else {
        return false;
    };
    items.get("type").is_some_and(|kind| kind == "object")
        || items.contains_key("properties")
        || items.contains_key("$ref")
}

/// Attaches an enum to a field (`_apply_vocab_enum`): each string branch of a
/// union takes it, and each array branch as its `items`; a plain string
/// field takes it (with `null` when the field is nullable, so an optional
/// field stays optional), a plain array field as its `items`. A list of
/// objects, and a field with no string branch, take none.
fn apply_enum(field: &mut Map<String, Value>, keywords: &Map<String, Value>) {
    let alternatives = ["anyOf", "oneOf"]
        .into_iter()
        .find(|key| field.get(*key).is_some_and(Value::is_array));
    if let Some(key) = alternatives {
        if let Some(Value::Array(branches)) = field.get_mut(key) {
            for branch in branches.iter_mut() {
                let Value::Object(branch) = branch else {
                    continue;
                };
                let kind = branch.get("type").cloned().unwrap_or(Value::Null);
                if has_type(&kind, "array") {
                    if items_are_objects(branch) {
                        continue;
                    }
                    branch.insert("items".to_owned(), Value::Object(keywords.clone()));
                    branch.insert("uniqueItems".to_owned(), true.into());
                } else if has_type(&kind, "string") {
                    branch.extend(keywords.clone());
                }
            }
        }
        return;
    }
    let kind = field.get("type").cloned();
    match &kind {
        None => field.extend(keywords.clone()),
        Some(kind) if has_type(kind, "string") => {
            let mut keywords = keywords.clone();
            if has_type(kind, "null")
                && let Some(Value::Array(values)) = keywords.get_mut("enum")
            {
                values.push(Value::Null);
            }
            field.extend(keywords);
        }
        Some(kind) if has_type(kind, "array") => {
            if items_are_objects(field) {
                return;
            }
            field.insert("items".to_owned(), Value::Object(keywords.clone()));
            field.insert("uniqueItems".to_owned(), true.into());
        }
        Some(_) => {}
    }
}

// --- vocabularies -------------------------------------------------------------------------

/// How a field asks for a vocabulary.
struct VocabOptions<'a> {
    scoped: bool,
    no_wrap: bool,
    stages: &'a [String],
}

/// The longest stage description a dropdown quotes, in characters.
const STAGE_DESCRIPTION_LIMIT: usize = 300;

/// The abbreviations that shorten a search hint longer than
/// [`HINT_WRAP`] characters, in order.
const HINT_ABBREVIATIONS: [(&str, &str); 10] = [
    (" and ", " & "),
    (" without ", " w/o "),
    (" with ", " w/ "),
    (" to ", " "),
    (" of ", " "),
    (" a ", " "),
    (" an ", " "),
    ("Use", " "),
    ("used", " "),
    ("Using", " "),
];

/// The length past which a search hint is abbreviated.
const HINT_WRAP: usize = 60;

/// The values, dropdowns and plain descriptions of one vocabulary reference
/// (`field` or `field::M.m`). The values are [`Vocabularies::allowed`]'s;
/// a model vocabulary (keyed by id, or a workspace's objects) also offers a
/// search hint per value (`T1059 #Command and Scripting Interpreter`),
/// unless its document turns them off. A vocabulary that gives no value
/// offers the empty string, so the field is never left without an `enum`.
fn vocabulary_offer(vocabularies: &Vocabularies, reference: &str, options: &VocabOptions) -> Offer {
    let mut offer = Offer::default();
    let Ok(vocab) = reference.parse::<VocabRef>() else {
        offer.values.push("".into());
        return offer;
    };
    let vocabulary = vocabularies.get(&vocab.field);
    let Some(vocabulary) = vocabulary else {
        offer.values.push("".into());
        return offer;
    };
    let model =
        vocabulary.metadata.key == KeyKind::Id || OBJECT_TYPES.contains(&vocab.field.as_str());
    let hints = model && vocabulary.search_hints();
    let mut hint_offer = Offer::default();
    let active = vocabulary
        .entries
        .values()
        .filter(|entry| vocab.pin.is_none_or(|pin| entry.active_at(pin)));
    for entry in active {
        let emit = |offer: &mut Offer, value: String, stages: &[String]| -> bool {
            if offer
                .values
                .iter()
                .any(|known| known == &Value::from(value.as_str()))
            {
                return false;
            }
            offer.markdown.push(dropdown(&vocabulary, entry, stages));
            offer.plain.push(plain(&value, entry));
            offer.values.push(value.into());
            true
        };
        if model {
            let value = match entry.stages.first() {
                Some(stage) if options.scoped => format!("{stage}::{}", entry.key),
                _ => entry.key.clone(),
            };
            if emit(&mut offer, value.clone(), &entry.stages) && hints {
                hint_offer
                    .values
                    .push(search_hint(&value, entry, options.no_wrap).into());
                hint_offer.markdown.extend(offer.markdown.last().cloned());
                hint_offer.plain.extend(offer.plain.last().cloned());
            }
            continue;
        }
        let matching: Vec<&String> = entry
            .stages
            .iter()
            .filter(|stage| options.stages.is_empty() || options.stages.contains(stage))
            .collect();
        if options.scoped {
            for stage in matching {
                emit(
                    &mut offer,
                    format!("{stage}::{}", entry.key),
                    std::slice::from_ref(stage),
                );
            }
        } else if options.stages.is_empty() || !matching.is_empty() {
            emit(&mut offer, entry.key.clone(), &entry.stages);
        }
    }
    if offer.values.is_empty() {
        offer.values.push("".into());
    }
    offer.values.extend(hint_offer.values);
    offer.markdown.extend(hint_offer.markdown);
    offer.plain.extend(hint_offer.plain);
    offer
}

/// A string from an entry's other keys.
fn extra<'e>(entry: &'e Entry, key: &str) -> Option<&'e str> {
    entry
        .extra
        .get(key)
        .and_then(toml::Value::as_str)
        .filter(|text| !text.is_empty())
}

/// The text an editor searches: the value, then `#` and the entry's name
/// and aliases, abbreviated past [`HINT_WRAP`] characters unless the field
/// says not to wrap.
fn search_hint(value: &str, entry: &Entry, no_wrap: bool) -> String {
    let mut tips = entry.name.clone();
    if let Some(toml::Value::Array(aliases)) = entry.extra.get("alias")
        && !aliases.is_empty()
    {
        let aliases: Vec<String> = aliases
            .iter()
            .map(|alias| {
                alias
                    .as_str()
                    .map_or_else(|| alias.to_string(), str::to_owned)
            })
            .collect();
        tips.push_str(", ");
        tips.push_str(&aliases.join(", "));
    }
    let mut hint = format!("{value} #{}", tips.trim());
    if !no_wrap && hint.chars().count() > HINT_WRAP {
        for (long, short) in HINT_ABBREVIATIONS {
            hint = hint.replace(long, short);
        }
    }
    hint
}

/// Plain hover text: the entry's name (unless the value ends with it), then
/// the first sentence of its description.
fn plain(value: &str, entry: &Entry) -> String {
    let display = if entry.name.is_empty() {
        entry.key.trim()
    } else {
        entry.name.trim()
    };
    let description = first_sentence(&plain_text(&entry.description, true));
    if !display.is_empty() && !value.ends_with(display) {
        if description.is_empty() {
            display.to_owned()
        } else {
            format!("{display}: {description}")
        }
    } else {
        description
    }
}

/// Capitalises the first letter of each word of a lower-case name.
fn title_case(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut start = true;
    for c in text.chars() {
        if c.is_alphabetic() {
            if start {
                out.extend(c.to_uppercase());
            } else {
                out.push(c);
            }
            start = false;
        } else {
            out.push(c);
            start = true;
        }
    }
    out
}

/// The Markdown an editor shows for an entry in a dropdown: its name, its
/// identifier and vocabulary, its level and TLP (an object), its stages, its
/// link and its description; empty parts are left out.
fn dropdown(vocabulary: &Vocabulary, entry: &Entry, stages: &[String]) -> String {
    let identifier = extra(entry, "id").unwrap_or(&entry.key);
    let mut display = if entry.name.is_empty() {
        entry.key.clone()
    } else {
        entry.name.clone()
    };
    if display.chars().any(char::is_alphabetic) && !display.chars().any(char::is_uppercase) {
        display = title_case(&display);
    }
    let mut parts = vec![
        format!("### {display}"),
        format!("**Identifier**: `{identifier}`"),
        format!("_Vocabulary_ : `{}`", vocabulary.metadata.name),
    ];
    let mut level = String::new();
    if OBJECT_TYPES.contains(&vocabulary.field()) {
        level = ["criticality", "priority", "severity"]
            .iter()
            .zip(["Criticality", "Priority", "Severity"])
            .find_map(|(key, label)| {
                entry
                    .extra
                    .get(*key)
                    .map(|value| {
                        value
                            .as_str()
                            .map_or_else(|| value.to_string(), str::to_owned)
                    })
                    .filter(|value| !value.is_empty())
                    .map(|value| format!("**{label}**: {value}"))
            })
            .unwrap_or_else(|| "**Criticality**: No Criticality Assigned".to_owned());
    }
    if let Some(tlp) = extra(entry, "tlp") {
        let tlp = format!("**TLP:{}**", tlp.to_uppercase());
        level = if level.is_empty() {
            tlp
        } else {
            format!("{level} | {tlp}")
        };
    }
    if !level.is_empty() {
        parts.push(level);
    }
    if !stages.is_empty() {
        let documented = stage_doc(vocabulary, stages);
        parts.push(if documented.is_empty() {
            format!("`{}`", stages.join(", "))
        } else {
            documented
        });
    }
    if !entry.link.is_empty() {
        parts.push(entry.link.clone());
    }
    parts.push("---".to_owned());
    if !entry.description.is_empty() {
        parts.push(entry.description.clone());
    }
    let mut text = parts.join("\n\n");
    text.push('\n');
    text
}

/// Each stage's name and description, from the vocabulary's stages.
fn stage_doc(vocabulary: &Vocabulary, stages: &[String]) -> String {
    let mut parts = Vec::new();
    for stage in stages {
        let Some(found) = vocabulary.metadata.stages.iter().find(|candidate| {
            candidate.id.as_deref().or(candidate.name.as_deref()) == Some(stage.as_str())
        }) else {
            continue;
        };
        let name = found.name.as_deref().unwrap_or(stage);
        let mut description = found
            .description
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_owned();
        if description.chars().count() > STAGE_DESCRIPTION_LIMIT {
            description = description.chars().take(STAGE_DESCRIPTION_LIMIT).collect();
            description.push_str("...");
        }
        parts.push(format!("**{name}**: _{description}_"));
    }
    parts.join("\n\n")
}

// --- configured values --------------------------------------------------------------------

fn text(node: Option<&Arc<Node>>) -> Option<&str> {
    node.and_then(|node| node.value.as_str())
}

fn display(node: Option<&Arc<Node>>) -> String {
    node.map(|node| node.value.to_string()).unwrap_or_default()
}

fn sequence(node: Option<&Arc<Node>>) -> &[Arc<Node>] {
    match node.map(|node| &node.value) {
        Some(NodeValue::Seq(items)) => items,
        _ => &[],
    }
}

/// The deployment statuses, each described by its strategy.
fn statuses(config: &Node) -> Offer {
    let mut offer = Offer::default();
    let deployment = config.get("deployment");
    for status in sequence(deployment.and_then(|deployment| deployment.get("statuses"))) {
        let Some(name) = text(status.get("name")) else {
            continue;
        };
        let strategy = text(status.get("strategy")).unwrap_or_default();
        let meaning = StatusStrategy::from_name(strategy).map_or("", StatusStrategy::description);
        offer.values.push(name.into());
        offer.markdown.push(format!(
            "**Strategy**: `{strategy}` - _{meaning}_\n\n{}",
            display(status.get("description"))
        ));
    }
    offer
}

/// The alert-handling teams `deployment.toml` declares; none leaves the
/// field unconstrained.
fn responders(config: &Node) -> Offer {
    let mut offer = Offer::default();
    let deployment = config.get("deployment");
    for responder in sequence(deployment.and_then(|deployment| deployment.get("responders"))) {
        let Some(name) = text(responder.get("name")).filter(|name| !name.is_empty()) else {
            continue;
        };
        offer.values.push(name.into());
        offer.markdown.push(display(responder.get("description")));
    }
    offer
}

/// The tenants configured for `platform`; none leaves the field
/// unconstrained.
fn tenants(config: &Node, platform: &str) -> Offer {
    let mut offer = Offer::default();
    let section = config
        .get("platforms")
        .and_then(|platforms| platforms.get(platform));
    for tenant in sequence(section.and_then(|section| section.get("tenants"))) {
        let Some(name) = tenant.get("name") else {
            continue;
        };
        offer.values.push(name.value.to_string().into());
        offer.markdown.push(
            text(tenant.get("description"))
                .unwrap_or("No Description")
                .to_owned(),
        );
    }
    offer
}

fn visibility_assets(visibility: Option<&Arc<Node>>) -> Vec<Arc<Node>> {
    sequence(visibility.and_then(|visibility| visibility.get("assets"))).to_vec()
}

/// An asset's Markdown, or a warning when no `[[assets]]` entry declares it.
fn format_asset(name: &str, assets: &[Arc<Node>]) -> String {
    let Some(asset) = assets
        .iter()
        .find(|asset| text(asset.get("name")) == Some(name))
    else {
        return format!(
            "\n- **{name}**\n  - _Warning_: Asset not found in configuration\n  - _Action \
             Required_: Define this asset in the assets section"
        );
    };
    let mut out = format!(
        "\n- **{name}**\n  - _Criticality_: {}\n  - _Description_: {}",
        display(asset.get("criticality")),
        display(asset.get("description"))
    );
    if let Some(NodeValue::Map(details)) = asset.get("custom_details").map(|node| &node.value)
        && !details.is_empty()
    {
        out.push_str("\n  - _Custom Details_:");
        for detail in details {
            out.push_str(&format!(
                "\n    - {}: {}",
                detail.key.value, detail.value.value
            ));
        }
    }
    out
}

fn strings(node: Option<&Arc<Node>>) -> Vec<String> {
    sequence(node)
        .iter()
        .map(|item| item.value.to_string())
        .collect()
}

/// The log source names a signal may name (`<name>`, `<system>::<name>`,
/// `<system>::<tenant>::<name>`); `None` when `visibility.toml` declares
/// none. A name two systems declare is one bare value described for both.
fn logsources(config: &Node) -> Option<Offer> {
    let visibility = config.get("visibility");
    let sources = sequence(visibility.and_then(|visibility| visibility.get("logsources")));
    if sources.is_empty() {
        return None;
    }
    let assets = visibility_assets(visibility);
    let mut offer = Offer::default();
    let mut qualified: Vec<(String, String)> = Vec::new();
    for source in sources {
        let name = display(source.get("name"));
        let system = display(source.get("system"));
        let tenants = strings(source.get("tenants"));
        let mut description = format!(
            "### {name}\n**System**: {system}\n**Description**: {}\n\n",
            display(source.get("description"))
        );
        if !tenants.is_empty() {
            description.push_str(&format!("**Tenants**: {}\n\n", tenants.join(", ")));
        }
        let asset_names = strings(source.get("assets"));
        if !asset_names.is_empty() {
            description.push_str("### Associated Assets:\n");
            for asset in &asset_names {
                description.push_str(&format_asset(asset, &assets));
                description.push('\n');
            }
        }
        let bare = Value::from(name.as_str());
        if let Some(index) = offer.values.iter().position(|known| *known == bare) {
            offer.markdown[index].push_str(&format!("---\n\n{description}"));
        } else {
            offer.values.push(bare);
            offer.markdown.push(description.clone());
        }
        qualified.push((format!("{system}::{name}"), description.clone()));
        for tenant in &tenants {
            qualified.push((format!("{system}::{tenant}::{name}"), description.clone()));
        }
    }
    for (value, description) in qualified {
        let value = Value::from(value);
        if !offer.values.contains(&value) {
            offer.values.push(value);
            offer.markdown.push(description);
        }
    }
    Some(offer)
}

/// The external detectors `visibility.toml` declares; `None` when it
/// declares none.
fn detectors(config: &Node) -> Option<Offer> {
    let visibility = config.get("visibility");
    let detectors = sequence(visibility.and_then(|visibility| visibility.get("detectors")));
    if detectors.is_empty() {
        return None;
    }
    let assets = visibility_assets(visibility);
    let mut offer = Offer::default();
    for detector in detectors {
        let name = display(detector.get("name"));
        let mut description = format!(
            "### {name}\n**Description**: {}\n\n",
            display(detector.get("description"))
        );
        let references = strings(detector.get("references"));
        if !references.is_empty() {
            description.push_str("### References:\n");
            for reference in references {
                description.push_str(&format!("- {reference}\n"));
            }
            description.push('\n');
        }
        let asset_names = strings(detector.get("assets"));
        if !asset_names.is_empty() {
            description.push_str("### Monitored Assets:\n");
            for asset in &asset_names {
                description.push_str(&format_asset(asset, &assets));
                description.push('\n');
            }
        }
        offer.values.push(name.into());
        offer.markdown.push(description);
    }
    Some(offer)
}

/// A configuration list by dot path; under `tenants`, every tenant's
/// values of the next key, each as `<tenant>::<value>`. A path that names
/// no list gives none.
fn parameter_list(config: &Node, path: &str) -> Vec<Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut node = config;
    for (index, part) in parts.iter().enumerate() {
        if *part == "tenants" {
            let Some(key) = parts.get(index + 1) else {
                return Vec::new();
            };
            let mut values = Vec::new();
            for tenant in sequence(node.get("tenants")) {
                let name = display(tenant.get("name"));
                let parameters = tenant.get("parameters");
                for value in strings(parameters.and_then(|parameters| parameters.get(key))) {
                    values.push(format!("{}::{}", name.trim(), value.trim()).into());
                }
            }
            return values;
        }
        let Some(next) = node.get(part) else {
            return Vec::new();
        };
        node = next;
    }
    match &node.value {
        NodeValue::Seq(items) => items
            .iter()
            .map(|item| Value::from(item.value.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// An object property that does not allow other keys takes none: every
/// `type: object` node reached through property maps and subschema
/// keywords (not union branches) without a truthy `additionalProperties`
/// gets `additionalProperties: false`, so a misspelled or misindented key is
/// flagged.
#[derive(Debug, Clone, Copy)]
pub struct CloseObjects;

impl Transform for CloseObjects {
    fn transform(&mut self, schema: &mut Schema) {
        if let Some(root) = schema.as_object_mut() {
            for value in root.values_mut() {
                close(value);
            }
        }
    }
}

fn close(node: &mut Value) {
    let Value::Object(map) = node else {
        return;
    };
    if map.get("type").is_some_and(|kind| kind == "object")
        && !truthy(map.get("additionalProperties"))
    {
        map.insert("additionalProperties".to_owned(), false.into());
    }
    for (key, value) in map.iter_mut() {
        if key == "enum" || key == "const" || key == "default" || key == "examples" {
            continue;
        }
        close(value);
    }
}

/// `metadata.schema` accepts only the revision's identifier
/// (`pin_schema_identifier`), on the metadata property or the definition it
/// refers to.
#[derive(Debug, Clone, Copy)]
pub struct PinIdentifier<'a> {
    /// The revision's identifier.
    pub identifier: &'a str,
}

impl Transform for PinIdentifier<'_> {
    fn transform(&mut self, schema: &mut Schema) {
        with_value(schema, |value| self.pin(value));
    }
}

impl PinIdentifier<'_> {
    fn pin(&self, value: &mut Value) {
        if !value
            .pointer("/properties/metadata")
            .is_some_and(Value::is_object)
        {
            return;
        }
        let metadata = deref_pointer(value, "/properties/metadata");
        let pinned = json!({
            "title": "Schema",
            "description": format!(
                "Schema identifier. This schema validates `{}` objects only.",
                self.identifier
            ),
            "const": self.identifier,
            "type": "string",
        });
        if let Some(Value::Object(node)) = value.pointer_mut(&metadata) {
            let properties = node
                .entry("properties")
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(properties) = properties {
                properties.insert("schema".to_owned(), pinned);
            }
        }
    }
}

#[cfg(test)]
mod tests;
