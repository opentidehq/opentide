//! `opentide generate exports`: the ATT&CK Navigator layer
//! (`export/attack_navigator_layer.py`), the objects table
//! (`export/table_export.py`) and the revisions snapshot
//! (`export/revisions_export.py`).
//!
//! The layer is laid out at four spaces in its keys' order; the table and the
//! snapshot at two, keys sorted. Every file is ASCII ([`super::json_text`]).

use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use opentide_schema::configuration::models::ObjectFamily;
use opentide_schema::node::{Node, Value};
use opentide_schema::vocab::{Entry, Vocabularies};
use opentide_workspace::config::Configuration;
use opentide_workspace::{Index, index::truthy};

use super::json_text::{pretty, sorted};
use super::relations::{Relations, py_str};
use super::{Cause, Output, PhaseError};
use crate::json::{Json, Object};

/// One export (`generate exports <target>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `attack-navigator.json`.
    Navigator,
    /// `objects.export.json`.
    Objects,
    /// `revisions.export.json`.
    Revisions,
}

impl Target {
    /// Every export, in the order `generate exports` writes them.
    pub const ALL: [Target; 3] = [Target::Navigator, Target::Objects, Target::Revisions];

    /// The command's word for it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Navigator => "navigator",
            Self::Objects => "objects",
            Self::Revisions => "revisions",
        }
    }
}

/// What the exports read from the configuration.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The exports folder (`[paths.exports] root`).
    pub dir: PathBuf,
    /// The file name of each export (`[artifacts.exports]`).
    pub navigator: String,
    /// The objects table's file name.
    pub objects: String,
    /// The revisions snapshot's file name.
    pub revisions: String,
    /// The object families, in `objects`' order.
    pub families: Vec<String>,
    /// `documentation.toml` `[object_names]`.
    pub object_names: IndexMap<String, String>,
}

impl Settings {
    /// The settings of `configuration`, for the workspace at `root`.
    pub fn new(configuration: &Configuration, root: &Path) -> Self {
        let paths = &configuration.paths;
        let folder = paths
            .paths
            .as_ref()
            .and_then(|paths| paths.exports.as_ref())
            .and_then(|exports| exports.root.clone())
            .filter(|root| !root.is_empty())
            .unwrap_or_else(|| ".opentide/exports/".to_owned());
        let names = paths
            .artifacts
            .as_ref()
            .and_then(|artifacts| artifacts.exports.as_ref());
        let name = |pick: fn(
            &opentide_schema::configuration::models::ExportArtifacts,
        ) -> Option<&String>,
                    default: &str| {
            names
                .and_then(pick)
                .cloned()
                .unwrap_or_else(|| default.to_owned())
        };
        let families = paths
            .objects
            .as_ref()
            .map(|families| {
                families
                    .iter()
                    .map(|family| {
                        match family {
                            ObjectFamily::Threat => "threat",
                            ObjectFamily::Objective => "objective",
                            ObjectFamily::Rule => "rule",
                        }
                        .to_owned()
                    })
                    .collect()
            })
            .unwrap_or_default();
        let object_names = configuration
            .resolved
            .get("documentation")
            .and_then(|documentation| documentation.get("object_names"))
            .map(|names| match &names.value {
                Value::Map(entries) => entries
                    .iter()
                    .map(|entry| (py_str(&entry.key), py_str(&entry.value)))
                    .collect(),
                _ => IndexMap::new(),
            })
            .unwrap_or_default();
        Self {
            dir: root.join(folder),
            navigator: name(|names| names.attack_layer.as_ref(), "attack-navigator.json"),
            objects: name(|names| names.objects.as_ref(), "objects.export.json"),
            revisions: name(|names| names.revisions.as_ref(), "revisions.export.json"),
            families,
            object_names,
        }
    }
}

/// The export `target` of `index`.
///
/// # Errors
///
/// An object the export cannot read, named with what it lacks.
pub fn export(
    target: Target,
    index: &Index,
    settings: &Settings,
    vocabularies: &Vocabularies,
) -> Result<Output, PhaseError> {
    let relations = Relations::new(index);
    match target {
        Target::Navigator => navigator(&relations, settings),
        Target::Objects => objects(&relations, settings, vocabularies),
        Target::Revisions => Ok(revisions(index, settings)),
    }
}

const RED: &str = "#fc6b6b";
const BLUE: &str = "#6baed6";
const GREEN: &str = "#74c476";

/// The technique → objects mapping of one family: `[THREAT] name` labels and
/// UUIDs, objects visited by name (case-folded), then UUID.
fn techniques_of(
    relations: &Relations<'_>,
    family: &str,
) -> Result<IndexMap<String, Vec<String>>, PhaseError> {
    let index = relations.index();
    let Some(members) = index.objects.get(family) else {
        return Ok(IndexMap::new());
    };
    let mut ordered: Vec<(String, &str, &Node)> = members
        .values()
        .filter_map(|object| {
            let root = object.root()?;
            let name = root
                .get("name")
                .filter(|name| truthy(name))
                .map(|name| py_str(name))
                .unwrap_or_default();
            Some((name.to_lowercase(), object.uuid.as_str(), root))
        })
        .collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    let label = family.to_uppercase();
    let mut mapping: IndexMap<String, Vec<String>> = IndexMap::new();
    for (_, uuid, root) in ordered {
        let techniques = crate::attack::techniques(index, uuid)
            .map_err(|missing| PhaseError::rendering(uuid, &Cause::from(missing)))?;
        let fail = |key: &str| PhaseError::rendering(uuid, &Cause::MissingKey(key.into()));
        let name = root
            .get("name")
            .map(|name| py_str(name))
            .ok_or_else(|| fail("name"))?;
        root.get("metadata")
            .ok_or_else(|| fail("metadata"))?
            .get("uuid")
            .ok_or_else(|| fail("uuid"))?;
        for technique in techniques {
            mapping
                .entry(technique)
                .or_default()
                .push(format!("[{label}] {name}"));
        }
    }
    Ok(mapping)
}

fn navigator(relations: &Relations<'_>, settings: &Settings) -> Result<Output, PhaseError> {
    let threats = techniques_of(relations, "threat")?;
    let rules = techniques_of(relations, "rule")?;
    let mut layer: Vec<(String, &str, String)> = Vec::new();
    for (technique, names) in &threats {
        match rules.get(technique) {
            None => layer.push((technique.clone(), RED, names.join(", "))),
            Some(rule_names) => {
                let all: Vec<&str> = names.iter().chain(rule_names).map(String::as_str).collect();
                layer.push((technique.clone(), GREEN, all.join(", ")));
            }
        }
    }
    for (technique, names) in &rules {
        if !threats.contains_key(technique) {
            layer.push((technique.clone(), BLUE, names.join(", ")));
        }
    }
    layer.sort_by(|a, b| a.0.cmp(&b.0));
    let techniques = layer
        .into_iter()
        .map(|(technique, color, comment)| {
            let mut entry = Object::new();
            entry.insert("techniqueID".into(), Json::Str(technique));
            entry.insert("color".into(), Json::from(color));
            entry.insert("comment".into(), Json::Str(comment));
            entry.insert("enabled".into(), Json::Bool(true));
            Json::Object(entry)
        })
        .collect();
    let legend = [
        ("TVM Only", RED),
        ("Full Coverage", GREEN),
        ("Rule Only - Needs to be checked", BLUE),
    ]
    .into_iter()
    .map(|(label, color)| {
        let mut entry = Object::new();
        entry.insert("label".into(), Json::from(label));
        entry.insert("color".into(), Json::from(color));
        Json::Object(entry)
    })
    .collect();
    let mut versions = Object::new();
    versions.insert("layer".into(), Json::from("4.5"));
    let mut document = Object::new();
    document.insert("versions".into(), Json::Object(versions));
    document.insert("techniques".into(), Json::Array(techniques));
    document.insert("name".into(), Json::from("layer"));
    document.insert("domain".into(), Json::from("enterprise-attack"));
    document.insert("hideDisabled".into(), Json::Bool(false));
    document.insert("legendItems".into(), Json::Array(legend));
    Ok(Output::text(
        settings.dir.join(&settings.navigator),
        pretty(&Json::Object(document), 4),
    ))
}

/// The value of `key`, or the oracle's `KeyError`.
fn required<'n>(node: &'n Node, key: &str) -> Result<&'n Node, Cause> {
    node.get(key)
        .map(AsRef::as_ref)
        .ok_or_else(|| Cause::MissingKey(key.to_owned()))
}

/// `body.get(section, {}).get("description", "")` as text.
fn description(root: &Node, section: Option<&str>) -> String {
    let holder = match section {
        Some(section) => root.get(section).map(AsRef::as_ref),
        None => Some(root),
    };
    holder
        .and_then(|holder| holder.get("description"))
        .map_or_else(String::new, |value| py_str(value))
}

/// A vocabulary entry by key, after its stage prefix, or by `legacy`
/// (`get_vocab_entry`).
fn vocab_entry(vocabularies: &Vocabularies, field: &str, id: &str) -> Option<Entry> {
    let vocabulary = vocabularies.get(field)?;
    let key = vocabularies.identifier(field, id);
    if let Some(entry) = vocabulary.entries.get(key) {
        return Some(entry.clone());
    }
    vocabulary
        .entries
        .values()
        .find(|entry| {
            entry
                .extra
                .get("legacy")
                .and_then(|value| value.as_str())
                .is_some_and(|legacy| legacy == key)
        })
        .cloned()
}

/// `threat.actors` as display names: each actor's `name` before ` #`,
/// without its `actor::` prefix, named as the `actors` vocabulary names it.
fn actor_names(actors: &Node, vocabularies: &Vocabularies) -> Vec<String> {
    let Value::Seq(items) = &actors.value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|actor| {
            if !matches!(actor.value, Value::Map(_)) {
                return None;
            }
            let raw = actor
                .get("name")
                .filter(|name| truthy(name))
                .map(|name| py_str(name))
                .unwrap_or_default();
            let token = raw.split(" #").next().unwrap_or_default().trim().to_owned();
            let identifier = token
                .strip_prefix("actor::")
                .map_or(token.clone(), str::to_owned);
            if identifier.is_empty() {
                return None;
            }
            let named = vocab_entry(vocabularies, "actors", &identifier)
                .map(|entry| entry.name)
                .filter(|name| !name.is_empty());
            Some(named.unwrap_or(identifier))
        })
        .collect()
}

/// `{'relation': ['vector', ...]}`, as Python writes the dict.
fn chaining_text(chains: &Node) -> Result<String, Cause> {
    let Value::Seq(items) = &chains.value else {
        return Ok(String::new());
    };
    let mut flat: IndexMap<String, Vec<String>> = IndexMap::new();
    for chain in items {
        let relation = py_str(required(chain, "relation")?);
        let vector = required(chain, "vector")?;
        flat.entry(relation)
            .or_default()
            .push(opentide_schema::configuration::repr::node(vector));
    }
    let quote = opentide_schema::configuration::repr::quote;
    Ok(format!(
        "{{{}}}",
        flat.iter()
            .map(|(relation, vectors)| format!("{}: [{}]", quote(relation), vectors.join(", ")))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn joined(node: &Node) -> String {
    match &node.value {
        Value::Seq(items) => items
            .iter()
            .map(|item| py_str(item))
            .collect::<Vec<_>>()
            .join(", "),
        // `", ".join` of a string joins its characters.
        Value::Str(text) => text
            .chars()
            .map(String::from)
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
}

/// One row of the objects table (`TableExporter._create_entry`), its
/// fields read in the oracle's order so the first missing one is named.
fn row(
    relations: &Relations<'_>,
    uuid: &str,
    family: &str,
    root: &Node,
    settings: &Settings,
    vocabularies: &Vocabularies,
) -> Result<Json, Cause> {
    let name = Json::from_node(required(root, "name")?);
    let type_name = settings
        .object_names
        .get(family)
        .cloned()
        .ok_or_else(|| Cause::MissingKey(family.to_owned()))?;
    let metadata = required(root, "metadata")?;
    let tlp = Json::from_node(required(metadata, "tlp")?);
    let version = py_str(required(metadata, "version")?);
    let created = Json::from_node(required(metadata, "created")?);
    let modified = Json::from_node(required(metadata, "modified")?);
    let children = relations.children(uuid)?.join(", ");
    let parents = relations.parents(uuid)?.join(", ");
    let (mut description_text, mut chaining, mut actors, mut attack) =
        (String::new(), String::new(), String::new(), String::new());
    match family {
        "threat" => {
            description_text = description(root, Some("threat"));
            let threat = required(root, "threat")?;
            if let Some(chains) = threat.get("chaining").filter(|chains| truthy(chains)) {
                chaining = chaining_text(chains)?;
            }
            if let Some(list) = threat.get("actors").filter(|actors| truthy(actors)) {
                actors = actor_names(list, vocabularies).join(", ");
            }
            attack = joined(required(threat, "mitre_attack")?);
        }
        "objective" => {
            description_text = description(root, Some("objective"));
            let objective = required(root, "objective")?;
            if let Some(techniques) = objective
                .get("mitre_attack")
                .filter(|techniques| truthy(techniques))
            {
                attack = joined(techniques);
            }
        }
        "rule" => description_text = description(root, None),
        _ => {}
    }
    let mut entry = Object::new();
    entry.insert("uuid".into(), Json::from(uuid));
    entry.insert("name".into(), name);
    entry.insert("type".into(), Json::Str(type_name));
    entry.insert("tlp".into(), tlp);
    entry.insert("description".into(), Json::Str(description_text));
    entry.insert("version".into(), Json::Str(version));
    entry.insert("created".into(), created);
    entry.insert("modified".into(), modified);
    entry.insert("childs".into(), Json::Str(children));
    entry.insert("parents".into(), Json::Str(parents));
    entry.insert("chaining".into(), Json::Str(chaining));
    entry.insert("actors".into(), Json::Str(actors));
    entry.insert("attack".into(), Json::Str(attack));
    Ok(Json::Object(entry))
}

fn objects(
    relations: &Relations<'_>,
    settings: &Settings,
    vocabularies: &Vocabularies,
) -> Result<Output, PhaseError> {
    let index = relations.index();
    let mut rows = Vec::new();
    for family in &settings.families {
        let Some(members) = index.objects.get(family) else {
            continue;
        };
        for object in members.values() {
            let Some(root) = object.root() else {
                continue;
            };
            rows.push(
                row(
                    relations,
                    &object.uuid,
                    family,
                    root,
                    settings,
                    vocabularies,
                )
                .map_err(|cause| PhaseError::rendering(&object.uuid, &cause))?,
            );
        }
    }
    Ok(Output::text(
        settings.dir.join(&settings.objects),
        pretty(&sorted(Json::Array(rows)), 2),
    ))
}

fn revisions(index: &Index, settings: &Settings) -> Output {
    let mut export: IndexMap<String, Object> = IndexMap::new();
    for family in &settings.families {
        let Some(members) = index.objects.get(family) else {
            continue;
        };
        for object in members.values() {
            let Some(root) = object.root() else {
                continue;
            };
            let metadata = root
                .get("metadata")
                .map(AsRef::as_ref)
                .filter(|metadata| truthy(metadata));
            let field = |key: &str| metadata.and_then(|metadata| metadata.get(key));
            let version = field("version").map_or_else(String::new, |version| py_str(version));
            if version.is_empty() {
                continue;
            }
            let entry = export.entry(object.uuid.clone()).or_insert_with(|| {
                let section = match family.as_str() {
                    "rule" => Some(None),
                    "threat" => Some(Some("threat")),
                    "objective" => Some(Some("objective")),
                    _ => None,
                };
                let mut entry = Object::new();
                entry.insert(
                    "name".into(),
                    root.get("name")
                        .map_or_else(|| Json::from(""), |name| Json::from_node(name)),
                );
                entry.insert(
                    "object".into(),
                    Json::Str(
                        settings
                            .object_names
                            .get(family)
                            .cloned()
                            .unwrap_or_else(|| family.clone()),
                    ),
                );
                entry.insert(
                    "description".into(),
                    Json::Str(
                        section.map_or_else(String::new, |section| description(root, section)),
                    ),
                );
                entry.insert("versions".into(), Json::Object(Object::new()));
                entry
            });
            let value = |key: &str| field(key).map_or(Json::Null, |node| Json::from_node(node));
            let mut revision = Object::new();
            revision.insert("schema".into(), value("schema"));
            revision.insert("modified".into(), value("modified"));
            revision.insert("created".into(), value("created"));
            revision.insert("author".into(), value("author"));
            if let Some(Json::Object(versions)) = entry.get_mut("versions") {
                versions.insert(version, Json::Object(revision));
            }
        }
    }
    let document: Object = export
        .into_iter()
        .map(|(uuid, entry)| (uuid, Json::Object(entry)))
        .collect();
    Output::text(
        settings.dir.join(&settings.revisions),
        pretty(&sorted(Json::Object(document)), 2),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(text: &str) -> std::sync::Arc<Node> {
        opentide_schema::node::load(text)
            .unwrap()
            .root()
            .unwrap()
            .clone()
    }

    #[test]
    fn chaining_is_written_as_a_python_dict() {
        let chains = node(
            "- {relation: leads_to, vector: a}\n- {relation: leads_to, vector: b}\n- {relation: x, vector: c}\n",
        );
        assert_eq!(
            chaining_text(&chains).unwrap(),
            "{'leads_to': ['a', 'b'], 'x': ['c']}"
        );
        let broken = node("- {vector: a}\n");
        assert_eq!(
            chaining_text(&broken).unwrap_err(),
            Cause::MissingKey("relation".into())
        );
    }

    #[test]
    fn actors_are_named_by_the_vocabulary() {
        let vocabularies = Vocabularies::bundled();
        let actors = node("- name: 'actor::G0006 # note'\n- name: Unknown Crew\n- plain\n");
        assert_eq!(
            actor_names(&actors, &vocabularies),
            ["[Enterprise] APT1", "Unknown Crew"]
        );
    }

    #[test]
    fn a_string_joins_its_characters() {
        assert_eq!(joined(&node("T1")), "T, 1");
        assert_eq!(joined(&node("[T1, T2]")), "T1, T2");
    }
}
