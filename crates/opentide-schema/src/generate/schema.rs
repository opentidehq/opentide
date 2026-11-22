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
//!    `tide.config.*` key a model carries the configured values (statuses,
//!    tenants, responders, log sources). The keywords no model carries
//!    (`tide.config.visibility.detectors`, `tide.config.parameter-list`,
//!    `tide.config.systems::enabled`, `tide.meta.deprecation`, a field's
//!    `tide.vocab.stages`) are not resolved, and a test keeps them out of
//!    the models;
//! 5. [`CloseObjects`]: an object property that does not say otherwise
//!    takes no unknown keys;
//! 6. [`PinIdentifier`]: `metadata.schema` is the revision's identifier;
//! 7. [`StripFrameworkKeywords`]: no `tide.*` keyword is left;
//!
//! then [`super::annotate::annotate_editor_schema`] adds the hover texts.
//!
//! The comparison with the oracle was by verdict, not by text (`cargo xtask
//! codegen --check --oracle`, retired in #1142): every corpus object and
//! fault got the same verdict from both documents. The text (titles,
//! descriptions, key order, `type` arrays where Pydantic writes `anyOf` with
//! `null`) is schemars'.

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
use crate::vocab::offer::{Offer, VocabOptions, offer_of};
use crate::vocab::{VocabRef, Vocabularies, bundled_offer};

use super::annotate::annotate_editor_schema;
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
    transformed(identifier, sources, true)
}

/// [`revision_schema`] without [`Recompose`]: `configurations` stays the
/// model's, every platform block as its model declares it. The language
/// server's catalog is built from it ([`super::catalog`]), so its rows are
/// the same whichever platforms a workspace enables.
pub fn unrecomposed_revision_schema(identifier: &str, sources: &Sources) -> Option<Schema> {
    transformed(identifier, sources, false)
}

fn transformed(identifier: &str, sources: &Sources, recompose: bool) -> Option<Schema> {
    let mut schema = revision_model_schema(identifier)?;
    let family = identifier.split("::").next().unwrap_or_default();
    RootExtras { family }.transform(&mut schema);
    if let Some(pins) = PinTable::bundled().get(identifier) {
        ApplyPins { pins }.transform(&mut schema);
    }
    if recompose {
        Recompose {
            config: &sources.config,
        }
        .transform(&mut schema);
    }
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
/// in `serde_json`'s order, four-space indentation, UTF-8, a
/// final newline.
pub fn editor_text(schema: &Schema) -> String {
    let mut json = Json::from(schema.as_value());
    annotate_editor_schema(&mut json);
    super::json::to_text(&json)
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
        with_value(schema, |value| {
            inline_vocabulary_unions(value);
            resolve_node(value, None, self.sources);
        });
    }
}

/// A vocabulary field whose union is a definition of its own
/// (`killchain: str | list[str]`, `{"anyOf": [{"$ref": "#/$defs/Killchain"},
/// {"type": "null"}]}`) gets that definition's branches in place of the
/// reference, so its string and array branches take the vocabulary's enum as
/// a union written in place does; the definition, which other fields share,
/// stays as it is.
fn inline_vocabulary_unions(schema: &mut Value) {
    let Some(Value::Object(defs)) = schema.get("$defs").cloned() else {
        return;
    };
    inline_unions_in(schema, &defs);
}

fn inline_unions_in(node: &mut Value, defs: &Map<String, Value>) {
    match node {
        Value::Object(map) => {
            if map.contains_key(keys::VOCAB)
                && let Some(Value::Array(branches)) = map.get_mut("anyOf")
            {
                let mut inlined = Vec::with_capacity(branches.len());
                for branch in branches.drain(..) {
                    let union = branch
                        .get("$ref")
                        .and_then(Value::as_str)
                        .and_then(|reference| reference.strip_prefix("#/$defs/"))
                        .and_then(|name| defs.get(name))
                        .filter(|target| target.get("properties").is_none())
                        .and_then(|target| target.get("anyOf"))
                        .and_then(Value::as_array);
                    match union {
                        Some(union) if branch.as_object().is_some_and(|map| map.len() == 1) => {
                            inlined.extend(union.iter().cloned());
                        }
                        _ => inlined.push(branch),
                    }
                }
                *branches = inlined;
            }
            for (name, child) in map.iter_mut() {
                if name != "enum" && name != "const" && name != "default" {
                    inline_unions_in(child, defs);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                inline_unions_in(item, defs);
            }
        }
        _ => {}
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

impl Offer {
    /// The keywords to write: `enum`, `markdownEnumDescriptions`, and
    /// `enumDescriptions` when there is one per value.
    fn keywords(&self, plain: bool) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert(
            "enum".to_owned(),
            self.values
                .iter()
                .map(|value| Value::from(value.as_str()))
                .collect(),
        );
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

/// Whether a schema flag (`tide.config.statuses`, ...) is `true`.
fn flag(value: Option<&Value>) -> bool {
    value.and_then(Value::as_bool) == Some(true)
}

fn resolve_field(map: &mut Map<String, Value>, key: Option<&str>, sources: &Sources) {
    let config = &sources.config;
    if flag(map.get(keys::CONFIG_VISIBILITY_LOGSOURCE_NAMES))
        && let Some(offer) = logsources(config)
    {
        let mut items = offer.keywords(false);
        items.insert("uniqueItems".to_owned(), true.into());
        map.insert("items".to_owned(), Value::Object(items));
    }
    if let Some(platform) = map.get(keys::CONFIG_SYSTEM_TENANTS).and_then(Value::as_str) {
        let offer = tenants(config, platform);
        if !offer.values.is_empty() {
            apply_enum(map, &offer.keywords(false));
        }
    }
    if flag(map.get(keys::CONFIG_STATUSES)) {
        let offer = statuses(config);
        set_typed(map, &offer.keywords(false));
    }
    if flag(map.get(keys::CONFIG_RESPONDERS)) {
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
    let scoped = flag(map.get(keys::VOCAB_SCOPED));
    let no_wrap = flag(map.get(keys::VOCAB_HINTS_NO_WRAP));
    let options = VocabOptions { scoped, no_wrap };
    // The same reference is offered by every revision of every object that
    // names it: made once.
    let offered = |reference: &str| {
        sources.vocabularies.memoized(
            &format!("offer\u{0}{reference}\u{0}{scoped}\u{0}{no_wrap}"),
            || vocabulary_offer(&sources.vocabularies, reference, options),
        )
    };
    if let [reference] = references.as_slice() {
        // A field that names one vocabulary, which is nearly every field: the
        // keywords it writes are made once too.
        let keywords = sources.vocabularies.memoized(
            &format!("keywords\u{0}{reference}\u{0}{scoped}\u{0}{no_wrap}"),
            || offered(reference).keywords(true),
        );
        apply_enum(map, &keywords);
        return;
    }
    let mut offer = Offer::default();
    for reference in &references {
        let one = offered(reference);
        offer.values.extend(one.values.iter().cloned());
        offer.markdown.extend(one.markdown.iter().cloned());
        offer.plain.extend(one.plain.iter().cloned());
    }
    apply_enum(map, &offer.keywords(true));
}

/// Sets `keywords` on a field by its declared `type`: on the field for a
/// string, on its `items` (with `uniqueItems`) for an array.
fn set_typed(map: &mut Map<String, Value>, keywords: &Map<String, Value>) {
    let kind = map.get("type").cloned().unwrap_or(Value::Null);
    if has_type(&kind, "string") {
        map.extend(keywords.clone());
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

// The bundled offers asked for on this thread: `(reference, scoped)`, for the test that says which
// offers `build.rs` makes.
#[cfg(test)]
thread_local! {
    static ASKED: std::cell::RefCell<Vec<(String, bool)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// What a field that names the vocabulary `reference` (`field` or `field::M.m`)
/// offers. A bundled vocabulary that no document of the workspace replaces,
/// asked for with wrapped hints, is read from what the build made of it ([`bundled_offer`]); every other is worked out
/// ([`offer_of`]). A vocabulary that gives no value offers the empty string,
/// so the field is never left without an `enum`.
fn vocabulary_offer(vocabularies: &Vocabularies, reference: &str, options: VocabOptions) -> Offer {
    let empty = || Offer {
        values: vec![String::new()],
        ..Offer::default()
    };
    let Ok(vocab) = reference.parse::<VocabRef>() else {
        return empty();
    };
    if !options.no_wrap && vocabularies.uses_bundled(&vocab.field) {
        #[cfg(test)]
        ASKED.with(|asked| {
            asked
                .borrow_mut()
                .push((reference.to_owned(), options.scoped));
        });
        if let Some(offer) = bundled_offer(reference, options.scoped) {
            return offer.clone();
        }
    }
    let Some(vocabulary) = vocabularies.get(&vocab.field) else {
        return empty();
    };
    offer_of(&vocabulary, &vocab, options)
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
        offer.values.push(name.value.to_string());
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
        let bare = name.clone();
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
        if !offer.values.contains(&value) {
            offer.values.push(value);
            offer.markdown.push(description);
        }
    }
    Some(offer)
}

/// An object property that does not allow other keys takes none: every
/// `type: object` node reached through property maps and subschema
/// keywords (not union branches) whose `additionalProperties` is neither
/// `true` nor a schema gets `additionalProperties: false`, so a misspelled or misindented key is
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
        && !matches!(
            map.get("additionalProperties"),
            Some(Value::Bool(true) | Value::Object(_))
        )
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
