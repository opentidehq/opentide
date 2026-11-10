//! The checks of one object (`validation/session.py` `_validate_work_item`):
//! its UUID's format, its schema, its vocabulary values, its configured
//! values, its deprecated fields, its platform blocks, its vendor ids, its
//! references and its chaining relations.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use opentide_schema::node::{Document, Node, Value};
use opentide_schema::objects::platform::deprecation::deprecated_fields;
use opentide_schema::revisions::dispatch::{self, Rejection, Selection};
use opentide_schema::vocab::{Selector, VocabRef, Vocabularies, Vocabulary, quote};
use opentide_schema::{ErrorKind, SchemaError, Surface};
use serde_json::Value as Json;

use super::states;
use crate::diagnostic::Diagnostic;
use crate::fs::FileSystem;
use crate::index::{Index, Object, truthy};

/// The platform blocks a rule may carry (`PLATFORM_CONFIG_MODELS`).
pub const PLATFORMS: [&str; 9] = [
    "sentinel",
    "defender_for_endpoint",
    "splunk",
    "sentinel_one",
    "crowdstrike",
    "harfanglab",
    "carbon_black_cloud",
    "elastic",
    "sysdig",
];

/// Leaf names of the fields that hold another object's UUID, and the family
/// they name (`_REF_LEAF_TO_TYPE`).
const REFERENCE_LEAVES: [(&str, &str); 3] = [
    ("threats", "threat"),
    ("detection_model", "objective"),
    ("vector", "threat"),
];

/// Pydantic error types about how vocabulary names are laid out: a
/// suggestion would recommend dropping the other names.
const VOCAB_SHAPE_ERRORS: [&str; 2] = ["vocab_list_type", "vocab_packed_names"];

/// What the per-object checks read about the whole workspace, built once
/// per run (`PreflightGraph`).
pub struct Graph<'a> {
    /// The index.
    pub index: &'a Index,
    /// The bundled vocabularies and the workspace's object vocabularies.
    pub vocabularies: Vocabularies,
    /// Each object's and signal's name, by UUID, with its family.
    names: HashMap<&'a str, (&'a str, String)>,
    /// `[[statuses]]` names of `deployment.toml`.
    pub statuses: Vec<String>,
    /// `[[responders]]` names of `deployment.toml`.
    pub responders: Vec<String>,
    /// The platforms deploy sends to; `None` when no rule is schema-checked.
    pub enabled: Option<BTreeSet<String>>,
    /// Each platform's `[platform]` key that misspells `enabled`.
    pub misspelled_enabled: HashMap<String, String>,
    /// Where each platform's configuration lives, for the messages.
    pub platform_files: HashMap<String, String>,
}

fn object_name(object: &Object) -> String {
    object
        .root()
        .and_then(|root| root.get("name"))
        .map_or_else(|| object.uuid.clone(), |name| name.value.to_string())
}

impl<'a> Graph<'a> {
    /// The graph of `index`, with `vocabularies` and the configuration's
    /// `deployment` table.
    pub fn new(
        index: &'a Index,
        mut vocabularies: Vocabularies,
        deployment: Option<&Node>,
    ) -> Self {
        let mut names: HashMap<&'a str, (&'a str, String)> = HashMap::new();
        for (family, objects) in &index.objects {
            for object in objects.values() {
                names.insert(object.uuid.as_str(), (family.as_str(), object_name(object)));
            }
        }
        for signal in index.signals.values() {
            let name = signal
                .node
                .get("name")
                .map_or_else(|| signal.uuid.clone(), |name| name.value.to_string());
            names
                .entry(signal.uuid.as_str())
                .or_insert(("signal", name));
        }
        for family in opentide_schema::vocab::OBJECT_TYPES {
            if let Some(vocabulary) = object_vocabulary(index, family) {
                vocabularies.insert(vocabulary);
            }
        }
        let statuses = deployment
            .map(opentide_schema::configuration::checks::status_names)
            .unwrap_or_default();
        let responders = deployment.map(responder_names).unwrap_or_default();
        Self {
            index,
            vocabularies,
            names,
            statuses,
            responders,
            enabled: None,
            misspelled_enabled: HashMap::new(),
            platform_files: HashMap::new(),
        }
    }

    /// Whether `uuid` is an object of `family` (or a signal, for `signal`).
    fn has(&self, family: &str, uuid: &str) -> bool {
        if family == "signal" {
            return self.index.signals.contains_key(uuid);
        }
        self.index
            .objects
            .get(family)
            .is_some_and(|objects| objects.contains_key(uuid))
    }

    /// The UUID of the object of `family` whose name `value` most likely
    /// means (`suggest_ref`), by the engines' one suggestion rule.
    fn suggest_ref(&self, family: &str, value: &str) -> Option<String> {
        let mut candidates: Vec<(&str, &str)> = self
            .names
            .iter()
            .filter(|(_, (kind, _))| *kind == family)
            .map(|(uuid, (_, name))| (*uuid, name.as_str()))
            .collect();
        candidates.sort_unstable();
        let name = opentide_core::suggest::closest(value, candidates.iter().map(|(_, n)| *n))?;
        candidates
            .iter()
            .find(|(_, candidate)| *candidate == name)
            .map(|(uuid, _)| (*uuid).to_owned())
    }

    fn format_invalid_ref(&self, family: &str, value: &str) -> String {
        match self.suggest_ref(family, value) {
            Some(uuid) => {
                let label = self
                    .names
                    .get(uuid.as_str())
                    .map_or_else(|| uuid.clone(), |(_, name)| name.clone());
                format!(
                    "Unknown {family} reference {} — did you mean {} ({uuid})?",
                    quote(value),
                    quote(&label)
                )
            }
            None => format!("Unknown {family} reference {}", quote(value)),
        }
    }
}

/// The `[[responders]]` names of a `deployment` table.
fn responder_names(deployment: &Node) -> Vec<String> {
    let Some(Value::Seq(responders)) = deployment.get("responders").map(|node| &node.value) else {
        return Vec::new();
    };
    responders
        .iter()
        .filter_map(|responder| responder.get("name"))
        .filter(|name| truthy(name))
        .map(|name| name.value.to_string())
        .collect()
}

/// The vocabulary of a family's objects, keyed by UUID
/// (`build_object_vocabularies`).
fn object_vocabulary(index: &Index, family: &str) -> Option<Vocabulary> {
    let objects = index.objects.get(family)?;
    let mut table = toml::Table::new();
    table.insert("name".to_owned(), toml::Value::String(family.to_owned()));
    table.insert("field".to_owned(), toml::Value::String(family.to_owned()));
    table.insert("key".to_owned(), toml::Value::String("id".to_owned()));
    let keys = objects
        .values()
        .map(|object| {
            let mut entry = toml::Table::new();
            entry.insert("id".to_owned(), toml::Value::String(object.uuid.clone()));
            entry.insert("name".to_owned(), toml::Value::String(object_name(object)));
            toml::Value::Table(entry)
        })
        .collect();
    table.insert("keys".to_owned(), toml::Value::Array(keys));
    Vocabulary::from_table(table, family).ok()
}

/// The JSON Schema of an object revision, with its `tide.*` keys and its
/// vocabulary pins applied: what the vocabulary walk reads
/// (`index["metaschemas"]`, `build_schema_source_for_identifier`).
pub fn revision_schema(identifier: &str) -> Option<&'static Json> {
    use opentide_schema::objects::{ObjectiveV1_0, RuleV1_0, RuleV1_1, ThreatVectorV1_0};
    static SCHEMAS: OnceLock<Vec<(&str, Json)>> = OnceLock::new();
    let schemas = SCHEMAS.get_or_init(|| {
        [
            ("rule::1.0", schemars::schema_for!(RuleV1_0).to_value()),
            ("rule::1.1", schemars::schema_for!(RuleV1_1).to_value()),
            (
                "threat::1.0",
                schemars::schema_for!(ThreatVectorV1_0).to_value(),
            ),
            (
                "objective::1.0",
                schemars::schema_for!(ObjectiveV1_0).to_value(),
            ),
        ]
        .into_iter()
        .map(|(id, mut schema)| {
            if let Some(pins) = opentide_schema::PinTable::bundled().get(id) {
                opentide_schema::generate::schema::apply_pins(&mut schema, pins);
            }
            (id, schema)
        })
        .collect()
    });
    schemas
        .iter()
        .find(|(id, _)| *id == identifier)
        .map(|(_, schema)| schema)
}

/// The findings of one object: its errors and its warnings.
#[derive(Debug, Default)]
pub struct Found {
    /// Errors.
    pub issues: Vec<Diagnostic>,
    /// Warnings.
    pub warnings: Vec<Diagnostic>,
}

/// What [`check_object`] runs.
#[derive(Debug, Clone, Copy)]
pub struct ObjectChecks {
    /// `uuid-format`.
    pub uuid_format: bool,
    /// `schema`.
    pub schema: bool,
    /// Whether the run checks each rule's own shard (a narrow run), rather
    /// than the whole state directory once.
    pub check_shard: bool,
}

/// A displaced copy of an object (another file with the same UUID), or an
/// indexed object: what the per-object checks read.
pub struct Subject<'d> {
    /// The UUID the index keys it by.
    pub uuid: &'d str,
    /// Its family.
    pub family: &'d str,
    /// Its file.
    pub path: &'d Path,
    /// Its document.
    pub document: &'d Arc<Document>,
}

/// Every check of one object.
pub fn check_object(
    subject: &Subject<'_>,
    graph: &Graph<'_>,
    checks: ObjectChecks,
    fs: &dyn FileSystem,
    workspace: &Path,
) -> Found {
    let mut found = Found::default();
    let Some(root) = subject.document.root() else {
        return found;
    };
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let new = |code: &str, message: String| {
        Diagnostic::error(code, message)
            .object(subject.uuid, subject.family)
            .file(subject.path)
    };
    if checks.uuid_format {
        let raw = root.get("uuid").filter(|node| truthy(node)).or_else(|| {
            root.get("metadata")
                .filter(|m| matches!(m.value, Value::Map(_)))
                .and_then(|m| m.get("uuid"))
        });
        if !raw.is_some_and(|node| is_uuid_v4(node)) {
            let shown = raw.map_or_else(|| "None".to_owned(), |node| python_repr(node));
            let name = root
                .get("name")
                .map_or_else(String::new, |name| name.value.to_string());
            issues.push(
                new(
                    "invalid_uuid",
                    format!("UUID {shown} is not a valid UUIDv4"),
                )
                .at(["metadata", "uuid"])
                .with("name", name),
            );
        }
    }
    if checks.schema {
        let mut shape_rejections: BTreeSet<(Vec<String>, String)> = BTreeSet::new();
        let mut schema = None;
        match dispatch::read(subject.document, subject.family) {
            Ok(read) => {
                if let Selection::Registered(revision) = &read.selection {
                    schema = revision_schema(revision.identifier);
                }
                if let Err(errors) = read.result {
                    for error in errors {
                        if let Some(input) = &error.input
                            && let ErrorKind::InvalidType(kind) | ErrorKind::InvalidValue(kind) =
                                error.kind
                            && VOCAB_SHAPE_ERRORS.contains(&kind)
                        {
                            shape_rejections
                                .insert((without_indexes(&error.field_path()), input.clone()));
                        }
                        if is_superseded_extra_key(&error) {
                            continue;
                        }
                        issues.push(schema_issue(&error, subject, graph));
                    }
                }
            }
            Err(Rejection::MetadataNotAMapping(error)) => {
                issues.push(schema_issue(&error, subject, graph));
            }
            Err(rejection) => {
                issues
                    .push(new(rejection.code(), rejection.to_string()).at(["metadata", "schema"]));
            }
        }
        if let Some(schema) = schema {
            let mut vocab = Vec::new();
            let walk = Walk { graph };
            walk_vocab(root, schema, schema, &mut Vec::new(), &walk, &mut vocab);
            let seen: BTreeSet<Vec<String>> = vocab.iter().map(|(path, _)| path.clone()).collect();
            vocab.extend(
                platform_status_issues(root, graph)
                    .into_iter()
                    .filter(|(path, _)| !seen.contains(path)),
            );
            for (field_path, diagnostic) in vocab {
                if let Some(value) = diagnostic.value()
                    && shape_rejections.contains(&(without_indexes(&field_path), value.to_owned()))
                {
                    continue;
                }
                issues.push(
                    diagnostic
                        .object(subject.uuid, subject.family)
                        .file(subject.path)
                        .at(field_path),
                );
            }
            warnings.extend(deprecated_warnings(subject, root, schema));
        }
        if subject.family == "rule"
            && let Some(enabled) = &graph.enabled
        {
            warnings.extend(
                platform_not_enabled(root, enabled, graph)
                    .into_iter()
                    .map(|d| d.object(subject.uuid, "rule").file(subject.path)),
            );
        }
        if subject.family == "rule" {
            for (platform, key) in states::legacy_external_id_keys(root) {
                issues.push(
                    new(
                        "external_id_in_rule",
                        format!(
                            "Vendor rule id key {} is not allowed on the {platform} block; \
                             external ids live in .opentide/states/deployment/<uuid>.json",
                            quote(&key)
                        ),
                    )
                    .at(["configurations".to_owned(), platform, key])
                    .suggest(Some(states::MIGRATE_SUGGESTION.to_owned())),
                );
            }
            if checks.check_shard
                && let Err(Some(error)) = states::check_shard(fs, workspace, subject.uuid)
            {
                let shard = error.path.clone().unwrap_or_default();
                issues.push(
                    new(error.code, error.message).with("shard", shard.display().to_string()),
                );
            }
        }
        issues.extend(references(subject, root, graph));
        if subject.family == "threat" {
            issues.extend(chaining(subject, root, graph));
        }
    }
    let mut issues = merge_reference_findings(issues);
    let locator = subject.document.locator();
    for issue in issues.iter_mut().chain(warnings.iter_mut()) {
        if issue.yaml_line.is_none() {
            issue.yaml_line = locator.yaml_line(&issue.field_path);
        }
    }
    found.issues = issues;
    found.warnings = warnings;
    found
}

/// A `deprecated_field` warning for every deprecated field `root` sets, by
/// `schema` (the bundled models (0.23.0) deprecate none).
fn deprecated_warnings(subject: &Subject<'_>, root: &Node, schema: &Json) -> Vec<Diagnostic> {
    deprecated_fields(root, schema)
        .into_iter()
        .map(|deprecated| {
            Diagnostic::warning("deprecated_field", deprecated.message)
                .object(subject.uuid, subject.family)
                .file(subject.path)
                .at(deprecated.field_path)
                .with("deprecation", deprecated.deprecation)
        })
        .collect()
}

/// Whether a node is a version 4 UUID written `8-4-4-4-12`, hex digits in
/// either case (`_is_uuid_v4`).
fn is_uuid_v4(node: &Node) -> bool {
    let text = node.value.to_string();
    uuid::Uuid::try_parse(&text).is_ok_and(|parsed| {
        parsed.get_version_num() == 4 && parsed.hyphenated().to_string() == text.to_lowercase()
    })
}

/// Python's `repr` of a scalar, as the messages that quote a value show it.
fn python_repr(node: &Node) -> String {
    match &node.value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Str(text) | Value::Datetime(text) => quote(text),
        other => other.to_string(),
    }
}

fn without_indexes(path: &[String]) -> Vec<String> {
    path.iter()
        .filter(|part| !part.chars().all(|c| c.is_ascii_digit()) || part.is_empty())
        .cloned()
        .collect()
}

fn leaf(path: &[String]) -> Option<&str> {
    path.iter()
        .rev()
        .find(|part| !part.chars().all(|c| c.is_ascii_digit()))
        .map(String::as_str)
}

/// A schema error for a legacy vendor-id key, which `external_id_in_rule`
/// reports instead.
fn is_superseded_extra_key(error: &SchemaError) -> bool {
    let path = error.field_path();
    error.code(Surface::Object) == "schema_validation"
        && path.len() == 3
        && path[0] == "configurations"
        && states::is_legacy_external_id_key(&path[2])
}

/// One schema error as a finding (`issues_from_pydantic`): a dangling UUID
/// in a reference field is `invalid_ref`, a near miss of a vocabulary named
/// like the field is `vocab_unknown`, anything else `schema_validation`.
fn schema_issue(error: &SchemaError, subject: &Subject<'_>, graph: &Graph<'_>) -> Diagnostic {
    let field_path = error.field_path();
    let mut code = error.code(Surface::Object).to_owned();
    let mut suggestion = None;
    let mut context_value = None;
    if let Some(input) = &error.input
        && let Some(last) = leaf(&field_path).or_else(|| field_path.last().map(String::as_str))
    {
        if let Some((_, family)) = REFERENCE_LEAVES
            .iter()
            .find(|(name, _)| Some(*name) == leaf(&field_path))
        {
            suggestion = graph.suggest_ref(family, input);
            "invalid_ref".clone_into(&mut code);
            context_value = Some(input.clone());
        }
        let shape = matches!(error.kind, ErrorKind::InvalidType(kind) | ErrorKind::InvalidValue(kind) if VOCAB_SHAPE_ERRORS.contains(&kind));
        if suggestion.is_none() && !shape {
            let vocab = graph
                .vocabularies
                .get(last)
                .and_then(|_| last.parse::<VocabRef>().ok())
                .and_then(|vocab| graph.vocabularies.suggest(input, &Selector::new(vocab)));
            if vocab.is_some() {
                suggestion = vocab;
                "vocab_unknown".clone_into(&mut code);
                context_value = None;
            }
        }
    }
    let mut diagnostic = Diagnostic::error(code, error.message.clone())
        .object(subject.uuid, subject.family)
        .file(subject.path)
        .at(field_path)
        .suggest(suggestion);
    if let Some(value) = context_value
        && diagnostic.code == "invalid_ref"
    {
        diagnostic = diagnostic.with("value", value);
    }
    diagnostic.yaml_line = error.yaml_line;
    diagnostic
}

/// A schema node with its local `$ref` followed (`_deref_schema_node`).
fn deref<'s>(node: &'s Json, root: &'s Json) -> &'s Json {
    node.get("$ref")
        .and_then(Json::as_str)
        .and_then(|reference| reference.rsplit('/').next())
        .and_then(|name| root.get("$defs").and_then(|defs| defs.get(name)))
        .filter(|target| target.is_object())
        .unwrap_or(node)
}

/// `$ref`, `anyOf` and `oneOf` expanded (`_schema_branch_nodes`).
fn branches<'s>(node: &'s Json, root: &'s Json) -> Vec<&'s Json> {
    let resolved = deref(node, root);
    let alternatives = resolved
        .get("anyOf")
        .or_else(|| resolved.get("oneOf"))
        .and_then(Json::as_array);
    if let Some(alternatives) = alternatives {
        let found: Vec<&Json> = alternatives
            .iter()
            .filter(|alt| alt.is_object())
            .map(|alt| deref(alt, root))
            .collect();
        if !found.is_empty() {
            return found;
        }
    }
    vec![resolved]
}

type Located = (Vec<String>, Diagnostic);

/// What the vocabulary walk reads besides the object and its schema (the
/// schema carries its revision's pins: [`revision_schema`]).
struct Walk<'g> {
    graph: &'g Graph<'g>,
}

/// The `tide.vocab` and configured-value fields of `payload`
/// (`walk_vocab_fields`).
fn walk_vocab(
    payload: &Node,
    schema: &Json,
    root: &Json,
    path: &mut Vec<String>,
    walk: &Walk<'_>,
    out: &mut Vec<Located>,
) {
    let graph = walk.graph;
    let properties = schema.get("properties").unwrap_or(schema);
    let Some(properties) = properties.as_object() else {
        return;
    };
    for (name, field) in properties {
        if !field.is_object() {
            continue;
        }
        path.push(name.clone());
        let value = match &payload.value {
            Value::Map(_) => payload.get(name).map(AsRef::as_ref),
            _ => None,
        };
        let resolved = deref(field, root);
        let vocab_schema = if field.get("tide.vocab").is_some() {
            field
        } else {
            resolved
        };
        if vocab_schema.get("tide.vocab").is_some() {
            out.extend(vocab_values(value, vocab_schema, path, walk));
        }
        let config_schema = if config_keyword(field).is_some() {
            field
        } else {
            resolved
        };
        if config_keyword(config_schema).is_some() {
            out.extend(config_values(value, config_schema, path, graph));
        }
        for branch in branches(field, root) {
            if let (Some(_), Some(value)) = (branch.get("properties"), value)
                && matches!(value.value, Value::Map(_))
            {
                walk_vocab(value, branch, root, path, walk, out);
            }
            let Some(items) = branch.get("items").filter(|items| items.is_object()) else {
                continue;
            };
            let Some(Value::Seq(list)) = value.map(|value| &value.value) else {
                continue;
            };
            let item_schema = deref(items, root);
            if item_schema.get("properties").is_some_and(Json::is_object) {
                for (index, item) in list.iter().enumerate() {
                    if matches!(item.value, Value::Map(_)) {
                        path.push(index.to_string());
                        walk_vocab(item, item_schema, root, path, walk, out);
                        path.pop();
                    }
                }
            }
            let item_vocab = if items.get("tide.vocab").is_some() {
                items
            } else {
                item_schema
            };
            if item_vocab.get("tide.vocab").is_some() {
                for (index, item) in list.iter().enumerate() {
                    path.push(index.to_string());
                    out.extend(vocab_values(Some(item), item_vocab, path, walk));
                    path.pop();
                }
            }
        }
        path.pop();
    }
}

fn strings(value: &Node) -> Vec<&str> {
    match &value.value {
        Value::Seq(items) => items
            .iter()
            .filter_map(|item| item.value.as_str())
            .collect(),
        other => other.as_str().into_iter().collect(),
    }
}

/// `_validate_vocab_value`.
fn vocab_values(
    value: Option<&Node>,
    schema: &Json,
    path: &[String],
    walk: &Walk<'_>,
) -> Vec<Located> {
    let graph = walk.graph;
    let Some(value) = value.filter(|value| !matches!(value.value, Value::Null)) else {
        return Vec::new();
    };
    let vocab = match schema.get("tide.vocab") {
        Some(Json::Bool(true)) => leaf(path).unwrap_or("unknown").to_owned(),
        Some(Json::String(vocab)) => vocab.clone(),
        Some(Json::Array(list)) => match list.first().and_then(Json::as_str) {
            Some(vocab) => vocab.to_owned(),
            None => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    let Ok(reference) = vocab.parse::<VocabRef>() else {
        return Vec::new();
    };
    let stages: Vec<String> = match schema.get("tide.vocab.stages") {
        Some(Json::String(stage)) => vec![stage.clone()],
        Some(Json::Array(list)) => list
            .iter()
            .filter_map(Json::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    let scoped = schema
        .get("tide.vocab.scoped")
        .is_some_and(|scoped| scoped.as_bool().unwrap_or(!scoped.is_null()));
    let selector = Selector::new(reference).scoped(scoped).stages(stages);
    let resolved = graph.vocabularies.resolve(&selector);
    strings(value)
        .into_iter()
        .filter(|item| !resolved.is_valid(item))
        .map(|item| {
            let suggestion = resolved.suggest(item);
            let diagnostic = Diagnostic::error(
                "vocab_unknown",
                format!(
                    "Value {} is not a valid {} vocabulary entry",
                    quote(item),
                    quote(&vocab)
                ),
            )
            .suggest(suggestion)
            .with("vocab", vocab.as_str())
            .with("value", item);
            (path.to_vec(), diagnostic)
        })
        .collect()
}

/// The configured-value keyword of a field (`tide.config.responders`,
/// `tide.config.statuses`).
fn config_keyword(schema: &Json) -> Option<&'static str> {
    ["tide.config.responders", "tide.config.statuses"]
        .into_iter()
        .find(|keyword| {
            schema
                .get(*keyword)
                .is_some_and(|flag| flag != &Json::Bool(false) && !flag.is_null())
        })
}

/// `_validate_config_enum_value`: a value the workspace's configuration
/// does not declare. A workspace that declares none leaves the field open.
fn config_values(
    value: Option<&Node>,
    schema: &Json,
    path: &[String],
    graph: &Graph<'_>,
) -> Vec<Located> {
    let Some(value) = value.filter(|value| !matches!(value.value, Value::Null)) else {
        return Vec::new();
    };
    let Some(keyword) = config_keyword(schema) else {
        return Vec::new();
    };
    let declared: Vec<String> = [Some(schema), schema.get("items")]
        .into_iter()
        .flatten()
        .find_map(|candidate| {
            candidate
                .get("enum")
                .and_then(Json::as_array)
                .filter(|list| !list.is_empty())
                .map(|list| {
                    list.iter()
                        .map(|item| {
                            item.as_str()
                                .map_or_else(|| item.to_string(), str::to_owned)
                        })
                        .collect()
                })
        })
        .unwrap_or_else(|| {
            if keyword.ends_with("statuses") {
                graph.statuses.clone()
            } else {
                graph.responders.clone()
            }
        });
    if declared.is_empty() {
        return Vec::new();
    }
    let setting = keyword.rsplit('.').next().unwrap_or(keyword);
    strings(value)
        .into_iter()
        .filter(|item| !declared.iter().any(|allowed| allowed == item))
        .map(|item| {
            let suggestion =
                opentide_core::suggest::closest(item, declared.iter().map(String::as_str))
                    .map(str::to_owned);
            let diagnostic = Diagnostic::error(
                "config_enum_unknown",
                format!(
                    "Value {} is not a configured {setting} value. Declare it in the \
                     [[{setting}]] block of your deployment configuration, or use one of: {}",
                    quote(item),
                    declared.join(", ")
                ),
            )
            .suggest(suggestion)
            .with("setting", setting)
            .with("value", item)
            .with("allowed", declared.clone());
            (path.to_vec(), diagnostic)
        })
        .collect()
}

/// Each platform block's `status` against `[[statuses]]`
/// (`_platform_status_issues`).
fn platform_status_issues(root: &Node, graph: &Graph<'_>) -> Vec<Located> {
    let Some(Value::Map(blocks)) = root.get("configurations").map(|node| &node.value) else {
        return Vec::new();
    };
    let schema = serde_json::json!({"tide.config.statuses": true});
    let mut out = Vec::new();
    for block in blocks {
        if let Some(status) = block.value.get("status") {
            let path = vec![
                "configurations".to_owned(),
                block.key.value.to_string(),
                "status".to_owned(),
            ];
            out.extend(config_values(Some(status), &schema, &path, graph));
        }
    }
    out
}

/// One warning per known platform block whose platform the workspace has
/// not enabled (`platform_not_enabled_warnings`).
fn platform_not_enabled(
    root: &Node,
    enabled: &BTreeSet<String>,
    graph: &Graph<'_>,
) -> Vec<Diagnostic> {
    let Some(Value::Map(blocks)) = root.get("configurations").map(|node| &node.value) else {
        return Vec::new();
    };
    blocks
        .iter()
        .filter_map(|block| block.key.value.as_str())
        .filter(|platform| PLATFORMS.contains(platform) && !enabled.contains(*platform))
        .map(|platform| {
            let (message, key) = match graph.misspelled_enabled.get(platform) {
                Some(key) => {
                    let file = graph
                        .platform_files
                        .get(platform)
                        .cloned()
                        .unwrap_or_else(|| {
                            format!(".opentide/configurations/platforms/{platform}.toml")
                        });
                    (
                        format!(
                            "this block will not deploy: {file} sets '{key}' in [platform], not \
                             'enabled', so {platform} is disabled; rename the key to 'enabled'"
                        ),
                        Some(key.clone()),
                    )
                }
                None => (
                    format!(
                        "this block will not deploy while {platform} is disabled in this \
                         workspace; enable {platform} with '{}'",
                        enable_platform_command(platform)
                    ),
                    None,
                ),
            };
            let mut diagnostic = Diagnostic::warning("platform_not_enabled", message)
                .at(["configurations", platform])
                .with("platform", platform);
            if let Some(key) = key {
                diagnostic = diagnostic.with("key", key);
            }
            diagnostic
        })
        .collect()
}

/// The `setup platforms` call that enables `platform`.
pub fn enable_platform_command(platform: &str) -> String {
    format!("opentide setup platforms --{}", platform.replace('_', "-"))
}

/// `check_references_for_object`.
fn references(subject: &Subject<'_>, root: &Node, graph: &Graph<'_>) -> Vec<Diagnostic> {
    let new =
        |field_path: Vec<String>, message: String, suggestion: Option<String>, value: String| {
            Diagnostic::error("invalid_ref", message)
                .object(subject.uuid, subject.family)
                .file(subject.path)
                .at(field_path)
                .suggest(suggestion)
                .with("value", value)
        };
    let block = |key: &str| {
        root.get(key)
            .filter(|node| matches!(node.value, Value::Map(_)))
    };
    let mut out = Vec::new();
    match subject.family {
        "rule" => {
            if let Some(parent) = root.get("detection_model")
                && truthy(parent)
                && matches!(parent.value, Value::Str(_) | Value::Int(_) | Value::Bool(_))
            {
                let parent = parent.value.to_string();
                if !graph.has("objective", &parent) && !graph.has("signal", &parent) {
                    let found = ["objective", "signal"].into_iter().find_map(|family| {
                        graph.suggest_ref(family, &parent).map(|suggestion| {
                            (graph.format_invalid_ref(family, &parent), suggestion)
                        })
                    });
                    let (message, suggestion) = match found {
                        Some((message, suggestion)) => (message, Some(suggestion)),
                        None => (
                            format!("Unknown objective or signal reference {}", quote(&parent)),
                            None,
                        ),
                    };
                    out.push(new(
                        vec!["detection_model".to_owned()],
                        message,
                        suggestion,
                        parent,
                    ));
                }
            }
        }
        "objective" => {
            if let Some(Value::Seq(threats)) = block("objective")
                .and_then(|objective| objective.get("threats"))
                .map(|node| &node.value)
            {
                for threat in threats {
                    let value = threat.value.to_string();
                    if !graph.has("threat", &value) {
                        out.push(new(
                            vec!["objective".to_owned(), "threats".to_owned()],
                            graph.format_invalid_ref("threat", &value),
                            graph.suggest_ref("threat", &value),
                            value,
                        ));
                    }
                }
            }
        }
        "threat" => {
            for (index, link) in chain_links(root) {
                if let Some(vector) = link.get("vector").filter(|vector| truthy(vector)) {
                    let value = vector.value.to_string();
                    if !graph.has("threat", &value) {
                        out.push(new(
                            vec![
                                "threat".to_owned(),
                                "chaining".to_owned(),
                                index.to_string(),
                                "vector".to_owned(),
                            ],
                            graph.format_invalid_ref("threat", &value),
                            graph.suggest_ref("threat", &value),
                            value,
                        ));
                    }
                }
            }
        }
        _ => {}
    }
    out
}

fn chain_links(root: &Node) -> Vec<(usize, &Node)> {
    let Some(Value::Seq(links)) = root
        .get("threat")
        .filter(|threat| matches!(threat.value, Value::Map(_)))
        .and_then(|threat| threat.get("chaining"))
        .map(|node| &node.value)
    else {
        return Vec::new();
    };
    links
        .iter()
        .enumerate()
        .filter(|(_, link)| matches!(link.value, Value::Map(_)))
        .map(|(index, link)| (index, link.as_ref()))
        .collect()
}

/// `check_chaining_for_object`.
fn chaining(subject: &Subject<'_>, root: &Node, graph: &Graph<'_>) -> Vec<Diagnostic> {
    let Ok(vocab) = "chaining_relations".parse::<VocabRef>() else {
        return Vec::new();
    };
    let resolved = graph
        .vocabularies
        .resolve(&Selector::new(vocab).scoped(true));
    chain_links(root)
        .into_iter()
        .filter_map(|(index, link)| {
            let relation = link.get("relation").filter(|relation| truthy(relation))?;
            let relation = relation.value.to_string();
            if resolved.is_valid(&relation) {
                return None;
            }
            Some(
                Diagnostic::error(
                    "chaining_relation_unknown",
                    format!("Unknown chaining relation {}", quote(&relation)),
                )
                .object(subject.uuid, "threat")
                .file(subject.path)
                .at([
                    "threat".to_owned(),
                    "chaining".to_owned(),
                    index.to_string(),
                    "relation".to_owned(),
                ])
                .suggest(resolved.suggest(&relation)),
            )
        })
        .collect()
}

/// `(object, field without list indexes, value)` of a finding about one
/// value.
fn reference_key(diagnostic: &Diagnostic) -> Option<(String, Vec<String>, String)> {
    let value = diagnostic.value()?;
    Some((
        diagnostic.object_uuid.clone(),
        without_indexes(&diagnostic.field_path),
        value.to_owned(),
    ))
}

/// One finding per cause: drop a `vocab_unknown` an `invalid_ref` already
/// reports, giving the reference its suggestion (`merge_reference_findings`).
pub fn merge_reference_findings(issues: Vec<Diagnostic>) -> Vec<Diagnostic> {
    let refs: BTreeSet<_> = issues
        .iter()
        .filter(|issue| issue.code == "invalid_ref")
        .filter_map(reference_key)
        .collect();
    if refs.is_empty() {
        return issues;
    }
    let mut suggestions = HashMap::new();
    let mut kept = Vec::new();
    for issue in issues {
        let key = reference_key(&issue);
        if issue.code == "vocab_unknown"
            && let Some(key) = key.filter(|key| refs.contains(key))
        {
            if let Some(suggestion) = &issue.suggestion {
                suggestions.entry(key).or_insert_with(|| suggestion.clone());
            }
            continue;
        }
        kept.push(issue);
    }
    for issue in &mut kept {
        if issue.code == "invalid_ref"
            && issue.suggestion.is_none()
            && let Some(suggestion) = reference_key(issue).and_then(|key| suggestions.get(&key))
        {
            issue.suggestion = Some(suggestion.clone());
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Severity;

    #[test]
    fn a_deprecated_field_is_a_warning_on_the_object_at_its_field() {
        let document = Arc::new(opentide_schema::node::load("name: A\nold: x\nkept: y\n").unwrap());
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "old": {"type": "string", "tide.meta.deprecation": "use `new`"},
                "kept": {"type": "string"},
            },
        });
        let subject = Subject {
            uuid: "u",
            family: "rule",
            path: Path::new("/ws/objects/rules/a.yaml"),
            document: &document,
        };
        let found = deprecated_warnings(&subject, document.root().unwrap(), &schema);
        assert_eq!(found.len(), 1);
        let warning = &found[0];
        assert_eq!(warning.code, "deprecated_field");
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.message, "Field 'old' is deprecated: use `new`");
        assert_eq!(warning.field_path, ["old"]);
        assert_eq!(
            (warning.object_uuid.as_str(), warning.object_type.as_str()),
            ("u", "rule")
        );
        assert_eq!(warning.file_path.as_deref(), Some(subject.path));
        assert_eq!(
            warning.context.get("deprecation").and_then(|v| v.as_str()),
            Some("use `new`")
        );
    }
}
