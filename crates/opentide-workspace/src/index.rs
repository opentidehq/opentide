//! The index: every object by family and UUID, with what the registry
//! could not load (`registry/builder.py` `_load_objects`, `_ingest_object`;
//! `registry/signals.py`; `core/chaining.py`; the references
//! `validation/checks/cross_object.py` follows).
//!
//! Assembly is a pure function of the files' parses, taken in discovery
//! order, so a full load and an incremental one build the same index from the
//! same parses ([`crate::Workspace::invalidate`]).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use indexmap::IndexMap;
use opentide_schema::node::{Document, Node, Value};

use crate::discover::{FolderProblem, Scan};
use crate::load::{Failure, Parsed};

/// The code of a file that did not load.
pub const YAML_PARSE: &str = "yaml_parse";
/// The code of an object without a UUID.
pub const MISSING_UUID: &str = "missing_uuid";
/// The code of a UUID two files of one family use.
pub const DUPLICATE_ID: &str = "duplicate_id";
/// The family the registry files signals under.
pub const SIGNAL_FAMILY: &str = "signal";
/// The index-only field naming the objective a signal is defined in.
pub const SIGNAL_OWNER_FIELD: &str = "owner";

/// One indexed object.
#[derive(Debug, Clone)]
pub struct Object {
    /// Its UUID, as the index keys it (`uuid`, else `metadata.uuid`).
    pub uuid: String,
    /// Its family (`rule`).
    pub family: String,
    /// The file it was read from.
    pub path: PathBuf,
    /// The document.
    pub document: Arc<Document>,
}

impl Object {
    /// The document's root mapping.
    pub fn root(&self) -> Option<&Node> {
        self.document.root().map(AsRef::as_ref)
    }

    /// The file's name (`files` in the Python index).
    pub fn file_name(&self) -> String {
        file_name(&self.path)
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// A file the index holds no object for (`parse_errors`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError {
    /// The file.
    pub path: PathBuf,
    /// Its family.
    pub family: String,
    /// `yaml_parse` or `missing_uuid`.
    pub code: &'static str,
    /// The problem, in words.
    pub error: String,
    /// The finding's message, where the registry writes one
    /// (`missing_uuid`); otherwise `validate` writes
    /// `Could not parse object YAML: <error>`.
    pub message: Option<String>,
    /// How the file failed; `None` for `missing_uuid`.
    pub failure: Option<crate::load::FailureKind>,
}

impl LoadError {
    /// The finding's message.
    pub fn message(&self) -> String {
        self.message
            .clone()
            .unwrap_or_else(|| format!("Could not parse object YAML: {}", self.error))
    }
}

/// A file whose object a later file with the same UUID in the same family
/// replaced (`duplicate_files`): kept, with its document, for the finding.
#[derive(Debug, Clone)]
pub struct Duplicate {
    /// The file replaced.
    pub path: PathBuf,
    /// Its family.
    pub family: String,
    /// The UUID both use.
    pub uuid: String,
    /// `UUID <uuid> is also used by <the later file>`.
    pub message: String,
    /// The replaced document.
    pub document: Arc<Document>,
}

/// A YAML file in a subfolder of an object folder (`nested_object_files`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nested {
    /// The file.
    pub path: PathBuf,
    /// The object folder it is under.
    pub folder: PathBuf,
    /// The folder's family.
    pub family: String,
}

/// An object folder the registry did not scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedFolder {
    /// The family.
    pub family: String,
    /// The folder, when `paths.toml` names one.
    pub path: Option<PathBuf>,
    /// Why.
    pub problem: FolderProblem,
}

/// A signal of an objective, indexed on its own (`registry/signals.py`).
#[derive(Debug, Clone)]
pub struct Signal {
    /// Its UUID.
    pub uuid: String,
    /// The objective it is defined in.
    pub owner: String,
    /// The signal's mapping as written.
    pub node: Arc<Node>,
}

/// What a reference names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReferenceKind {
    /// A rule's `detection_model`: an objective or a signal.
    DetectionModel,
    /// An entry of an objective's `objective.threats`.
    Threat,
    /// A signal an objective defines (`objective.signals[].uuid`).
    Signal,
    /// A threat's `threat.chaining[].vector`, with its relation.
    Chaining {
        /// The link's `relation`, when it has one.
        relation: Option<String>,
    },
}

impl ReferenceKind {
    /// The kind's name in the JSON export.
    pub fn name(&self) -> &'static str {
        match self {
            Self::DetectionModel => "detection_model",
            Self::Threat => "threat",
            Self::Signal => "signal",
            Self::Chaining { .. } => "chaining",
        }
    }
}

/// A reference from one object to another UUID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Reference {
    /// The object it is written in.
    pub from: String,
    /// What it names.
    pub kind: ReferenceKind,
    /// The UUID it names, as text.
    pub target: String,
    /// Where it is written (`["objective", "threats", "0"]`).
    pub field_path: Vec<String>,
}

/// The index of a workspace.
#[derive(Debug, Clone, Default)]
pub struct Index {
    /// The families of `[metaschemas]`, in order.
    pub families: Vec<String>,
    /// Objects by family, then by UUID, in the order the registry met them.
    pub objects: IndexMap<String, IndexMap<String, Object>>,
    /// The file each UUID was last read from, across families
    /// (`file_paths`).
    pub file_paths: IndexMap<String, PathBuf>,
    /// Signals by UUID.
    pub signals: IndexMap<String, Signal>,
    /// Files that did not load, or loaded without a UUID.
    pub load_errors: Vec<LoadError>,
    /// Objects a later file with the same UUID replaced.
    pub duplicates: Vec<Duplicate>,
    /// YAML files in subfolders.
    pub nested: Vec<Nested>,
    /// Object folders not scanned.
    pub skipped_folders: Vec<SkippedFolder>,
    /// References, object by object in index order.
    pub references: Vec<Reference>,
    /// `{threat: {relation: [vector, ...]}}` (`compute_chains`).
    pub chaining: IndexMap<String, IndexMap<String, Vec<String>>>,
}

/// Python's truthiness of a YAML value.
pub fn truthy(node: &Node) -> bool {
    match &node.value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Int(integer) => *integer != 0,
        Value::Float(float) => *float != 0.0,
        Value::Str(text) | Value::Datetime(text) => !text.is_empty(),
        Value::Seq(items) => !items.is_empty(),
        Value::Map(entries) => !entries.is_empty(),
    }
}

/// A value as a key or reference: its text (`str()` in Python).
fn text(node: &Node) -> String {
    node.value.to_string()
}

/// The mapping under `key`, or `None` when it is not one (`_block`).
fn block<'n>(node: &'n Node, key: &str) -> Option<&'n Node> {
    node.get(key)
        .map(AsRef::as_ref)
        .filter(|child| matches!(child.value, Value::Map(_)))
}

fn items(node: Option<&Arc<Node>>) -> &[Arc<Node>] {
    match node.map(|node| &node.value) {
        Some(Value::Seq(items)) => items,
        _ => &[],
    }
}

/// The identifier of an object body: `uuid` when truthy, else
/// `metadata.uuid` (`body.get("uuid") or meta_uuid`).
fn identifier(root: &Node) -> Option<&Node> {
    let top = root
        .get("uuid")
        .map(AsRef::as_ref)
        .filter(|node| truthy(node));
    top.or_else(|| {
        block(root, "metadata")
            .and_then(|metadata| metadata.get("uuid"))
            .map(AsRef::as_ref)
    })
    .filter(|node| truthy(node))
}

/// Where the registry's messages show a path: relative to `base` when inside
/// it, else as it is (`_shown_path`).
pub fn shown_path(path: &Path, base: &Path) -> String {
    path.strip_prefix(base)
        .map_or_else(|_| path.to_string_lossy().into_owned(), posix)
}

/// A relative path with `/` between its parts.
pub fn posix(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// One family's scan, or why it was not scanned.
#[derive(Debug, Clone)]
pub struct FamilyScan {
    /// The family.
    pub family: String,
    /// The folder.
    pub folder: Option<PathBuf>,
    /// The scan.
    pub scan: Result<Scan, FolderProblem>,
}

/// Builds the index from the families' scans and each file's parse.
///
/// `parsed` must hold every file of every scan; `display_base` is the
/// directory the duplicate messages show paths from (the working directory).
pub fn assemble<S: std::hash::BuildHasher>(
    families: &[String],
    scans: &[FamilyScan],
    parsed: &HashMap<PathBuf, Arc<Parsed>, S>,
    display_base: &Path,
) -> Index {
    let mut index = Index {
        families: families.to_vec(),
        ..Index::default()
    };
    for family in families {
        index.objects.insert(family.clone(), IndexMap::new());
    }
    for family_scan in scans {
        match &family_scan.scan {
            Ok(scan) => index.nested.extend(scan.nested.iter().map(|path| Nested {
                path: path.clone(),
                folder: family_scan.folder.clone().unwrap_or_default(),
                family: family_scan.family.clone(),
            })),
            Err(problem) => index.skipped_folders.push(SkippedFolder {
                family: family_scan.family.clone(),
                path: family_scan.folder.clone(),
                problem: problem.clone(),
            }),
        }
    }
    for family_scan in scans {
        let Ok(scan) = &family_scan.scan else {
            continue;
        };
        for path in &scan.files {
            let Some(result) = parsed.get(path) else {
                continue;
            };
            match result.as_ref() {
                Parsed::Failed(Failure { kind, error }) => index.load_errors.push(LoadError {
                    path: path.clone(),
                    family: family_scan.family.clone(),
                    code: YAML_PARSE,
                    error: error.clone(),
                    message: None,
                    failure: Some(*kind),
                }),
                Parsed::Document(document) => {
                    ingest(
                        &mut index,
                        &family_scan.family,
                        path,
                        document,
                        display_base,
                    );
                }
            }
        }
    }
    references(&mut index);
    index
}

fn ingest(
    index: &mut Index,
    family: &str,
    path: &Path,
    document: &Arc<Document>,
    display_base: &Path,
) {
    let Some(root) = document.root() else {
        return;
    };
    let Some(id) = identifier(root) else {
        index.load_errors.push(LoadError {
            path: path.to_path_buf(),
            family: family.to_owned(),
            code: MISSING_UUID,
            error: "object YAML has no uuid".to_owned(),
            message: Some(format!("Object YAML has no uuid: {}", file_name(path))),
            failure: None,
        });
        return;
    };
    if matches!(id.value, Value::Seq(_) | Value::Map(_)) {
        // Python cannot key an index on a list or a mapping (it crashed).
        index.load_errors.push(LoadError {
            path: path.to_path_buf(),
            family: family.to_owned(),
            code: MISSING_UUID,
            error: format!("object YAML uuid is a {}, not text", id.value.type_name()),
            message: Some(format!("Object YAML has no uuid: {}", file_name(path))),
            failure: None,
        });
        return;
    }
    let uuid = text(id);
    let bucket = index.objects.entry(family.to_owned()).or_default();
    // `assemble` ingests one family at a time and a scan lists a path once,
    // so the displaced file is never `path` itself.
    if let Some(previous) = bucket.get(&uuid)
        && let Some(displaced) = index.file_paths.get(&uuid)
    {
        let message = format!(
            "UUID {uuid} is also used by {}",
            shown_path(path, display_base)
        );
        index.duplicates.push(Duplicate {
            path: displaced.clone(),
            family: family.to_owned(),
            uuid: uuid.clone(),
            message,
            document: Arc::clone(&previous.document),
        });
    }
    bucket.insert(
        uuid.clone(),
        Object {
            uuid: uuid.clone(),
            family: family.to_owned(),
            path: path.to_path_buf(),
            document: Arc::clone(document),
        },
    );
    index.file_paths.insert(uuid.clone(), path.to_path_buf());
    if family == "objective" {
        index_signals(index, &uuid, root);
    }
}

/// The signal mappings an objective body authors.
fn objective_signals(root: &Node) -> impl Iterator<Item = &Arc<Node>> {
    let signals = block(root, "objective").and_then(|objective| objective.get("signals"));
    items(signals)
        .iter()
        .filter(|signal| matches!(signal.value, Value::Map(_)))
}

/// `index_objective_signals`: a UUID already indexed under another objective,
/// or repeated in this one, keeps its first definition; a re-ingest of the
/// same objective replaces its own.
fn index_signals(index: &mut Index, objective: &str, root: &Node) {
    let mut here: HashSet<String> = HashSet::new();
    for signal in objective_signals(root) {
        let Some(id) = signal.get("uuid").filter(|id| truthy(id)) else {
            continue;
        };
        let key = text(id);
        let elsewhere = index
            .signals
            .get(&key)
            .is_some_and(|existing| existing.owner != objective);
        if here.contains(&key) || elsewhere {
            continue;
        }
        index.signals.insert(
            key.clone(),
            Signal {
                uuid: key.clone(),
                owner: objective.to_owned(),
                node: Arc::clone(signal),
            },
        );
        here.insert(key);
    }
}

fn references(index: &mut Index) {
    let mut found = Vec::new();
    let mut chaining: IndexMap<String, IndexMap<String, Vec<String>>> = IndexMap::new();
    for (family, objects) in &index.objects {
        for object in objects.values() {
            let Some(root) = object.root() else {
                continue;
            };
            let from = || object.uuid.clone();
            match family.as_str() {
                "rule" => {
                    if let Some(parent) = root.get("detection_model")
                        && truthy(parent)
                        && !matches!(parent.value, Value::Seq(_) | Value::Map(_))
                    {
                        found.push(Reference {
                            from: from(),
                            kind: ReferenceKind::DetectionModel,
                            target: text(parent),
                            field_path: vec!["detection_model".to_owned()],
                        });
                    }
                }
                "objective" => {
                    let objective = block(root, "objective");
                    for (position, threat) in items(objective.and_then(|o| o.get("threats")))
                        .iter()
                        .enumerate()
                    {
                        found.push(Reference {
                            from: from(),
                            kind: ReferenceKind::Threat,
                            target: text(threat),
                            field_path: vec![
                                "objective".to_owned(),
                                "threats".to_owned(),
                                position.to_string(),
                            ],
                        });
                    }
                    let signals = objective.and_then(|o| o.get("signals"));
                    for (position, signal) in items(signals).iter().enumerate() {
                        if let Some(id) = signal.get("uuid").filter(|id| truthy(id)) {
                            found.push(Reference {
                                from: from(),
                                kind: ReferenceKind::Signal,
                                target: text(id),
                                field_path: vec![
                                    "objective".to_owned(),
                                    "signals".to_owned(),
                                    position.to_string(),
                                    "uuid".to_owned(),
                                ],
                            });
                        }
                    }
                }
                "threat" => {
                    let links = items(block(root, "threat").and_then(|t| t.get("chaining")));
                    if !links.is_empty() {
                        chaining.entry(object.uuid.clone()).or_default();
                    }
                    for (position, link) in links.iter().enumerate() {
                        if !matches!(link.value, Value::Map(_)) {
                            continue;
                        }
                        let relation = link.get("relation").filter(|r| truthy(r)).map(|r| text(r));
                        let Some(vector) = link.get("vector").filter(|v| truthy(v)) else {
                            continue;
                        };
                        let vector = text(vector);
                        found.push(Reference {
                            from: from(),
                            kind: ReferenceKind::Chaining {
                                relation: relation.clone(),
                            },
                            target: vector.clone(),
                            field_path: vec![
                                "threat".to_owned(),
                                "chaining".to_owned(),
                                position.to_string(),
                                "vector".to_owned(),
                            ],
                        });
                        if let Some(relation) = relation {
                            let targets = chaining
                                .entry(object.uuid.clone())
                                .or_default()
                                .entry(relation)
                                .or_default();
                            if !targets.contains(&vector) {
                                targets.push(vector);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    index.references = found;
    index.chaining = chaining;
}

impl Index {
    /// The objects of `family`.
    pub fn family(&self, family: &str) -> impl Iterator<Item = &Object> {
        self.objects
            .get(family)
            .into_iter()
            .flat_map(IndexMap::values)
    }

    /// The rules.
    pub fn rules(&self) -> impl Iterator<Item = &Object> {
        self.family("rule")
    }

    /// The threat vectors.
    pub fn threats(&self) -> impl Iterator<Item = &Object> {
        self.family("threat")
    }

    /// The detection objectives.
    pub fn objectives(&self) -> impl Iterator<Item = &Object> {
        self.family("objective")
    }

    /// The object `uuid` of `family`.
    pub fn get(&self, family: &str, uuid: &str) -> Option<&Object> {
        self.objects.get(family)?.get(uuid)
    }

    /// The object `uuid`, looked up across the rules, threats and objectives
    /// in that order (`Opentide.lookup`).
    pub fn lookup(&self, uuid: &str) -> Option<&Object> {
        ["rule", "threat", "objective"]
            .iter()
            .find_map(|family| self.get(family, uuid))
    }

    /// The file name of each UUID (`files`).
    pub fn files(&self) -> IndexMap<String, String> {
        self.objects
            .values()
            .flat_map(IndexMap::values)
            .map(|object| (object.uuid.clone(), object.file_name()))
            .collect()
    }

    /// How many objects the index holds.
    pub fn len(&self) -> usize {
        self.objects.values().map(IndexMap::len).sum()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The references that name `uuid`.
    pub fn referrers<'a>(&'a self, uuid: &'a str) -> impl Iterator<Item = &'a Reference> + 'a {
        self.references
            .iter()
            .filter(move |reference| reference.target == uuid)
    }
}
