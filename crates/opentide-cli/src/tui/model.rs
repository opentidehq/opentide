//! What `opentide tui` shows, without a terminal (`cli/services/tui.py`):
//! a snapshot of the workspace, built off the UI thread and read on it.
//!
//! The catalogue comes from the workspace's index, the coverage table from
//! the lookup behind `opentide info coverage --technique …` (own and
//! inherited techniques), the language server's findings from what `opentide
//! lsp start` publishes (`validate`'s findings by file, and the engine's
//! analysis of each object file), the Visibility tab from the report `generate
//! explorer --include-visibility` writes, the Chains tab and the object page
//! from `opentide_workspace::views`.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use indexmap::IndexMap;
use opentide_analysis::{LanguageId, LineStarts, MemoryWorkspace};
use opentide_schema::node::{Document, Node, Value};
use opentide_workspace::Workspace;
use opentide_workspace::views::chains::{ChainEdge, chain_edges};
use opentide_workspace::views::object::{
    FieldNodes, LinkTarget, ObjectView, build_object_view, catalogue_links,
};

use super::Launch;

/// An object family, in the order the tree nests them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A threat.
    Threat,
    /// An objective.
    Objective,
    /// A rule.
    Rule,
}

impl Kind {
    /// The family's name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Threat => "threat",
            Self::Objective => "objective",
            Self::Rule => "rule",
        }
    }
}

/// One object as the tree shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its UUID.
    pub uuid: String,
    /// Its family.
    pub kind: Kind,
    /// Its name, or its UUID when it has none.
    pub name: String,
    /// The file it was read from.
    pub path: Option<PathBuf>,
    /// The threats an objective covers; the objective a rule implements.
    pub parents: Vec<String>,
}

/// One ATT&CK technique: the rules that detect it and the objects that name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechniqueCoverage {
    /// The technique, upper-cased.
    pub technique: String,
    /// Every rule that covers it: those that list it, then those that inherit it.
    pub rules: Vec<String>,
    /// Threats and objectives that list it.
    pub referenced_by: Vec<String>,
    /// Rules that list it (or a sub-technique) themselves.
    pub own: Vec<String>,
    /// Rules that cover it only through their objective or its threats.
    pub inherited: Vec<String>,
}

/// An object file the index could not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError {
    /// The file.
    pub path: Option<PathBuf>,
    /// Why.
    pub message: String,
}

/// Who reported a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A validate run.
    Validate,
    /// A validate run's queries check: the engine's, which the language
    /// server reports too.
    Engine,
    /// The language server.
    LanguageServer,
}

/// Codes whose suggestion is the value to write instead: an object UUID or
/// a vocabulary entry. Every other code's suggestion is prose.
const VALUE_SUGGESTION_CODES: [&str; 3] =
    ["invalid_ref", "vocab_unknown", "chaining_relation_unknown"];

/// A finding as the detail pane shows it. `line` and `column` are 1-based.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Its code.
    pub code: String,
    /// `error`, `warning` or `note`.
    pub severity: String,
    /// One sentence.
    pub message: String,
    /// The object it is about, when known.
    pub object_uuid: String,
    /// The file it is in.
    pub path: Option<PathBuf>,
    /// Its line.
    pub line: Option<usize>,
    /// Its column.
    pub column: Option<usize>,
    /// Where its span ends on `line`, exclusive.
    pub end_column: Option<usize>,
    /// The field it is about.
    pub field_path: Vec<String>,
    /// The suggestion or help.
    pub help: Option<String>,
    /// Who reported it.
    pub source: Source,
}

fn text_at<'v>(value: &'v serde_json::Value, key: &str) -> Option<&'v str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

fn number_at(value: &serde_json::Value, key: &str) -> Option<usize> {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
}

impl Finding {
    /// From one entry of `report.issues` or `report.warnings` in the
    /// validate document.
    pub fn from_issue(issue: &serde_json::Value) -> Self {
        let context = issue.get("context").cloned().unwrap_or_default();
        let position = context.get("position").cloned().unwrap_or_default();
        let end_column = if position.get("end_line") == position.get("line") {
            number_at(&position, "end_column")
        } else {
            None
        };
        Self {
            code: text_at(issue, "code").unwrap_or("invalid").to_owned(),
            severity: text_at(issue, "severity").unwrap_or("error").to_owned(),
            message: text_at(issue, "message").unwrap_or_default().to_owned(),
            object_uuid: text_at(issue, "object_uuid").unwrap_or_default().to_owned(),
            path: text_at(issue, "file_path")
                .filter(|path| !path.is_empty())
                .map(PathBuf::from),
            line: number_at(issue, "yaml_line").map(|line| line + 1),
            field_path: issue
                .get("field_path")
                .and_then(serde_json::Value::as_array)
                .map(|parts| {
                    parts
                        .iter()
                        .map(|part| match part {
                            serde_json::Value::String(text) => text.clone(),
                            other => other.to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            help: text_at(issue, "suggestion")
                .filter(|text| !text.is_empty())
                .map(str::to_owned),
            column: number_at(&position, "column"),
            end_column,
            source: if text_at(&context, "source") == Some("engine") {
                Source::Engine
            } else {
                Source::Validate
            },
        }
    }

    /// `did you mean 'clear'?` when the suggestion is a value, else the
    /// suggestion as written.
    pub fn help_text(&self) -> Option<String> {
        let help = self.help.as_deref()?;
        if self.source == Source::Validate && VALUE_SUGGESTION_CODES.contains(&self.code.as_str()) {
            return Some(format!(
                "did you mean {}?",
                opentide_schema::vocab::quote(help)
            ));
        }
        Some(help.to_owned())
    }

    /// Whether this finding is about `entry`: by UUID, else by file.
    pub fn concerns(&self, entry: &Entry) -> bool {
        if !self.object_uuid.is_empty() {
            return self.object_uuid == entry.uuid;
        }
        same_file(self.path.as_deref(), entry.path.as_deref())
    }
}

fn same_file(left: Option<&Path>, right: Option<&Path>) -> bool {
    let (Some(left), Some(right)) = (left, right) else {
        return false;
    };
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

/// The issues, then the warnings, of a validate document (`report`).
pub fn findings_from(document: &serde_json::Value) -> Vec<Finding> {
    let report = document.get("report").cloned().unwrap_or_default();
    ["issues", "warnings"]
        .iter()
        .filter_map(|key| report.get(*key).and_then(serde_json::Value::as_array))
        .flatten()
        .map(Finding::from_issue)
        .collect()
}

/// What the language server reports for each object file, as an editor
/// shows it.
#[derive(Clone, Default)]
pub struct LanguageServer {
    /// Resolved object file → its findings, in file order.
    pub findings: HashMap<PathBuf, Vec<Finding>>,
    /// Why nothing was checked, when it was not.
    pub unavailable: Option<String>,
    /// What to do about it.
    pub advice: Option<String>,
    /// The engine's view of the workspace, for [`LanguageServer::hover`].
    host: Option<Arc<MemoryWorkspace>>,
}

impl std::fmt::Debug for LanguageServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LanguageServer")
            .field("findings", &self.findings)
            .field("unavailable", &self.unavailable)
            .finish_non_exhaustive()
    }
}

impl LanguageServer {
    /// The findings on `path`.
    pub fn for_path(&self, path: Option<&Path>) -> &[Finding] {
        path.and_then(|path| path.canonicalize().ok())
            .and_then(|path| self.findings.get(&path))
            .map_or(&[], Vec::as_slice)
    }

    /// What an editor's hover shows at 1-based `line` and `column` of
    /// `text`, as Markdown; `None` where it has nothing to say.
    pub fn hover(&self, text: &str, line: usize, column: usize) -> Option<String> {
        let host = self.host.as_ref()?;
        let offset = LineStarts::new(text).offset(text, line, column);
        opentide_analysis::hover(host.as_ref(), LanguageId::TideYaml, text, offset)
    }
}

/// One declared log source, and what uses it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogSource {
    /// The dataset.
    pub name: String,
    /// Its system.
    pub system: String,
    /// What it records.
    pub description: String,
    /// `(name, type, description)` of each column.
    pub columns: Vec<(String, String, String)>,
    /// The tenants that hold it.
    pub tenants: Vec<String>,
    /// Rules whose queries read it.
    pub read_by: Vec<String>,
    /// Objectives one of whose signals names it.
    pub objectives: Vec<String>,
    /// Rules that implement such a signal, or its objective.
    pub signal_rules: Vec<String>,
    /// Every rule that uses it.
    pub rules: Vec<String>,
}

impl LogSource {
    /// Whether a rule or an objective uses it.
    pub fn used(&self) -> bool {
        !self.rules.is_empty() || !self.objectives.is_empty()
    }
}

/// A dataset rules read that no log source of its system declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Undeclared {
    /// Its system.
    pub system: String,
    /// The dataset.
    pub name: String,
    /// The rules that read it.
    pub rules: Vec<String>,
    /// Whether the workspace declares any log source for the system.
    pub system_declares: bool,
}

/// The Visibility tab's report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Visibility {
    /// Whether the workspace declares its log sources.
    pub present: bool,
    /// Why `visibility.toml` could not be read.
    pub problem: Option<String>,
    /// Why the datasets queries read are not known.
    pub reads_unavailable: Option<String>,
    /// Per system: `(log sources, with columns, used)`.
    pub systems: Vec<(String, (usize, usize, usize))>,
    /// The declared log sources.
    pub logsources: Vec<LogSource>,
    /// What rules read that nothing declares.
    pub undeclared: Vec<Undeclared>,
}

fn strings(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

impl Visibility {
    /// From the report `generate explorer --include-visibility` writes.
    pub fn from_report(report: &serde_json::Value) -> Self {
        let text = |value: &serde_json::Value, key: &str| {
            text_at(value, key).unwrap_or_default().to_owned()
        };
        let list = |key: &str| {
            report
                .get(key)
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        Self {
            present: report.get("present").and_then(serde_json::Value::as_bool) == Some(true),
            problem: text_at(report, "problem").map(str::to_owned),
            reads_unavailable: text_at(report, "reads_unavailable").map(str::to_owned),
            systems: report
                .get("systems")
                .and_then(serde_json::Value::as_object)
                .map(|systems| {
                    systems
                        .iter()
                        .map(|(name, counts)| {
                            let count = |key: &str| number_at(counts, key).unwrap_or(0);
                            (
                                name.clone(),
                                (count("logsources"), count("with_columns"), count("used")),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
            logsources: list("logsources")
                .iter()
                .map(|source| LogSource {
                    name: text(source, "name"),
                    system: text(source, "system"),
                    description: text(source, "description"),
                    columns: source
                        .get("columns")
                        .and_then(serde_json::Value::as_array)
                        .map(|columns| {
                            columns
                                .iter()
                                .map(|column| {
                                    (
                                        text(column, "name"),
                                        text(column, "type"),
                                        text(column, "description"),
                                    )
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    tenants: strings(source, "tenants"),
                    read_by: strings(source, "read_by"),
                    objectives: strings(source, "objectives"),
                    signal_rules: strings(source, "signal_rules"),
                    rules: strings(source, "rules"),
                })
                .collect(),
            undeclared: list("undeclared")
                .iter()
                .map(|item| Undeclared {
                    system: text(item, "system"),
                    name: text(item, "name"),
                    rules: strings(item, "rules"),
                    system_declares: item
                        .get("system_declares")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true),
                })
                .collect(),
        }
    }
}

/// A snapshot of the workspace. Built off the UI thread, read on it.
#[derive(Debug, Clone, Default)]
pub struct Catalogue {
    /// The workspace's root.
    pub repo: PathBuf,
    /// Every object, by UUID.
    pub entries: IndexMap<String, Entry>,
    /// One row per technique, sorted.
    pub coverage: Vec<TechniqueCoverage>,
    /// The files that did not load.
    pub load_errors: Vec<LoadError>,
    /// What the language server reports.
    pub language_server: LanguageServer,
    /// The Visibility tab.
    pub visibility: Visibility,
    /// Every threat chaining link, each once (the Chains tab).
    pub chains: Vec<ChainEdge>,
    /// Each object's document, for its page.
    documents: HashMap<String, Arc<Document>>,
    /// What each UUID a reference can name is: the objects and every signal.
    links: std::collections::BTreeMap<String, LinkTarget>,
    /// The fields of each revision, from the field catalog.
    fields: Arc<FieldNodes>,
}

impl Catalogue {
    /// Objects of `kind`, by name.
    pub fn of_kind(&self, kind: Kind) -> Vec<&Entry> {
        let mut found: Vec<&Entry> = self
            .entries
            .values()
            .filter(|entry| entry.kind == kind)
            .collect();
        found.sort_by_key(|entry| (entry.name.to_lowercase(), entry.uuid.clone()));
        found
    }

    /// Objectives under a threat, rules under an objective.
    pub fn children(&self, uuid: &str) -> Vec<&Entry> {
        let mut found: Vec<&Entry> = self
            .entries
            .values()
            .filter(|entry| entry.parents.iter().any(|parent| parent == uuid))
            .collect();
        found.sort_by_key(|entry| (entry.name.to_lowercase(), entry.uuid.clone()));
        found
    }

    /// Objects of `kind` whose parent is not in the catalogue (or that name none).
    pub fn unlinked(&self, kind: Kind) -> Vec<&Entry> {
        self.of_kind(kind)
            .into_iter()
            .filter(|entry| {
                !entry
                    .parents
                    .iter()
                    .any(|parent| self.entries.contains_key(parent))
            })
            .collect()
    }

    /// How many objects of `kind`.
    pub fn count(&self, kind: Kind) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.kind == kind)
            .count()
    }

    /// The page of `uuid`.
    pub fn object_view(&self, uuid: &str) -> Option<ObjectView> {
        let entry = self.entries.get(uuid)?;
        let root = self.documents.get(uuid)?.root()?;
        Some(build_object_view(
            root,
            entry.kind.as_str(),
            &self.links,
            &self.fields,
        ))
    }

    /// `1 threat · 1 objective · 1 rule`, plus load errors when there are any.
    pub fn summary_line(&self) -> String {
        use crate::commands::counted;
        let mut parts = vec![
            counted(self.count(Kind::Threat), "threat"),
            counted(self.count(Kind::Objective), "objective"),
            counted(self.count(Kind::Rule), "rule"),
        ];
        if !self.load_errors.is_empty() {
            parts.push(counted(self.load_errors.len(), "load error"));
        }
        parts.join(" · ")
    }

    /// The rules under each threat's objectives, by threat.
    pub fn threat_rules(&self) -> HashMap<String, usize> {
        self.of_kind(Kind::Threat)
            .into_iter()
            .map(|threat| {
                let rules: BTreeSet<&str> = self
                    .children(&threat.uuid)
                    .into_iter()
                    .flat_map(|objective| self.children(&objective.uuid))
                    .map(|rule| rule.uuid.as_str())
                    .collect();
                (threat.uuid.clone(), rules.len())
            })
            .collect()
    }

    /// Per threat: how many of the techniques it names some rule covers.
    pub fn threat_techniques(&self) -> HashMap<String, (usize, usize)> {
        let mut found: HashMap<String, (usize, usize)> = HashMap::new();
        for row in &self.coverage {
            for uuid in &row.referenced_by {
                let counts = found.entry(uuid.clone()).or_default();
                counts.1 += 1;
                if !row.rules.is_empty() {
                    counts.0 += 1;
                }
            }
        }
        found
    }
}

/// The text of a node, for names and references.
fn scalar_text(node: &Node) -> Option<String> {
    match &node.value {
        Value::Null | Value::Seq(_) | Value::Map(_) => None,
        other => Some(other.to_string()),
    }
}

/// A reference field as UUIDs: `detection_model` may be a string or a list.
fn uuids(node: Option<&Node>) -> Vec<String> {
    match node.map(|node| &node.value) {
        Some(Value::Str(text)) if !text.is_empty() => vec![text.clone()],
        Some(Value::Seq(items)) => items
            .iter()
            .filter_map(|item| item.value.as_str())
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// Signal UUID → the objective that declares it.
fn signal_owners(workspace: &Workspace) -> HashMap<String, String> {
    workspace
        .index()
        .signals
        .values()
        .map(|signal| (signal.uuid.clone(), signal.owner.clone()))
        .collect()
}

fn parents(kind: Kind, root: &Node, owners: &HashMap<String, String>) -> Vec<String> {
    match kind {
        Kind::Threat => Vec::new(),
        Kind::Objective => uuids(
            root.get("objective")
                .and_then(|section| section.get("threats"))
                .map(AsRef::as_ref),
        ),
        Kind::Rule => {
            let mut found: Vec<String> = Vec::new();
            for reference in uuids(root.get("detection_model").map(AsRef::as_ref)) {
                let parent = owners.get(&reference).cloned().unwrap_or(reference);
                if !found.contains(&parent) {
                    found.push(parent);
                }
            }
            found
        }
    }
}

/// The families of the index, in the order the tree nests them.
const FAMILIES: [(&str, Kind); 3] = [
    ("threat", Kind::Threat),
    ("objective", Kind::Objective),
    ("rule", Kind::Rule),
];

/// Opens the workspace `launch` names and snapshots what the UI shows.
///
/// # Errors
///
/// The workspace's configuration does not resolve: the message.
pub fn load(launch: &Launch) -> Result<Catalogue, String> {
    let (_, options) = crate::commands::placement(launch.repo.as_deref(), &launch.env, &launch.cwd);
    let workspace = crate::commands::open(options)?;
    let index = workspace.index();
    let owners = signal_owners(&workspace);
    let mut entries: IndexMap<String, Entry> = IndexMap::new();
    let mut documents = HashMap::new();
    for (family, kind) in FAMILIES {
        for (uuid, object) in index.objects.get(family).into_iter().flatten() {
            let Some(root) = object.root() else {
                continue;
            };
            documents.insert(uuid.clone(), Arc::clone(&object.document));
            entries.insert(
                uuid.clone(),
                Entry {
                    uuid: uuid.clone(),
                    kind,
                    name: root
                        .get("name")
                        .and_then(|name| scalar_text(name))
                        .unwrap_or_else(|| uuid.clone()),
                    path: index.file_paths.get(uuid).cloned(),
                    parents: parents(kind, root, &owners),
                },
            );
        }
    }
    let coverage = coverage(&workspace);
    let names: std::collections::BTreeMap<String, (String, String)> = entries
        .values()
        .map(|entry| {
            (
                entry.uuid.clone(),
                (entry.name.clone(), entry.kind.as_str().to_owned()),
            )
        })
        .collect();
    let links = catalogue_links(index, &names);
    let threats: IndexMap<String, &Node> = index
        .objects
        .get("threat")
        .into_iter()
        .flatten()
        .filter_map(|(uuid, object)| Some((uuid.clone(), object.root()?)))
        .collect();
    let chains = chain_edges(&threats);
    let load_errors = index
        .load_errors
        .iter()
        .map(|error| LoadError {
            path: Some(error.path.clone()),
            message: error.message.clone().unwrap_or_else(|| error.error.clone()),
        })
        .collect();
    let root = workspace.root().to_path_buf();
    // The Visibility tab reads the datasets the queries read (it installs a
    // probe in the engines, then the workspace's declarations again): before
    // the language server's checks, which hold the engines.
    let visibility = visibility(&workspace, &root);
    let (catalog, fields) = field_nodes(&workspace, &launch.version);
    let language_server = language_server(&workspace, &root, &catalog);
    Ok(Catalogue {
        repo: root,
        entries,
        coverage,
        load_errors,
        language_server,
        visibility,
        chains,
        documents,
        links,
        fields,
    })
}

/// One row per technique named by a threat, an objective or a rule.
fn coverage(workspace: &Workspace) -> Vec<TechniqueCoverage> {
    use opentide_workspace::coverage::{match_technique, own_techniques, rule_technique_index};
    let index = workspace.index();
    let mut referenced: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut techniques: BTreeSet<String> = BTreeSet::new();
    for (family, _) in FAMILIES {
        for (uuid, object) in index.objects.get(family).into_iter().flatten() {
            let Some(root) = object.root() else {
                continue;
            };
            for technique in own_techniques(root) {
                let key = technique.trim().to_uppercase();
                techniques.insert(key.clone());
                if family != "rule" {
                    referenced.entry(key).or_default().insert(uuid.clone());
                }
            }
        }
    }
    let rules = rule_technique_index(index);
    techniques
        .into_iter()
        .map(|technique| {
            let found = match_technique(&technique, &rules);
            TechniqueCoverage {
                referenced_by: referenced
                    .get(&technique)
                    .map(|uuids| uuids.iter().cloned().collect())
                    .unwrap_or_default(),
                technique,
                rules: found.rules,
                own: found.own,
                inherited: found.inherited,
            }
        })
        .collect()
}

fn visibility(workspace: &Workspace, root: &Path) -> Visibility {
    let report = crate::commands::generate::visibility_report(workspace, workspace.index(), root);
    serde_json::to_value(&report)
        .map(|report| Visibility::from_report(&report))
        .unwrap_or_default()
}

/// The field catalog the models generate for the workspace (`fields.json`
/// and `deprecations.json`, as `generate schemas` writes them), and its
/// fields by revision.
fn field_nodes(
    workspace: &Workspace,
    version: &str,
) -> (opentide_analysis::Catalog, Arc<FieldNodes>) {
    use opentide_schema::generate::catalog::{deprecations_catalog, dump, fields_catalog};
    let sources = crate::commands::generate::schema_sources(workspace);
    let fields = fields_catalog(version, &sources);
    let text = dump(&fields);
    let nodes = serde_json::from_str::<serde_json::Value>(&text)
        .map(|document| FieldNodes::from_catalog(&document))
        .unwrap_or_default();
    let catalog = opentide_analysis::Catalog {
        fields: Some(text),
        deprecations: Some(dump(&deprecations_catalog(version))),
        visibility: None,
    };
    (catalog, Arc::new(nodes))
}

/// What the language server reports for every object file of the workspace,
/// with the catalog the models generate for it.
fn language_server(
    workspace: &Workspace,
    root: &Path,
    catalog: &opentide_analysis::Catalog,
) -> LanguageServer {
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check_files(workspace, root, catalog)
    }));
    checked.unwrap_or_else(|payload| LanguageServer {
        unavailable: Some(format!(
            "The language server failed: {}",
            crate::crash::panic_message(payload.as_ref())
        )),
        advice: Some("opentide doctor checks the analysis engine and its catalogs".into()),
        ..LanguageServer::default()
    })
}

fn check_files(
    workspace: &Workspace,
    root: &Path,
    catalog: &opentide_analysis::Catalog,
) -> LanguageServer {
    let _engine = crate::queries::ENGINE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // opentide's own catalog for the workspace, as the Python host installs
    // it; when it cannot be installed, the engine's bundled one stays.
    let _ = opentide_analysis::install_catalog(catalog);
    // The workspace's declared datasets and Elastic tenants, as the editor
    // reads them.
    let profiles = crate::queries::Profiles::install(&opentide_workspace::OsFs, Some(root));
    let index = workspace.index();
    let mut paths: Vec<PathBuf> = index.file_paths.values().cloned().collect();
    paths.sort();
    paths.dedup();
    let mut files: Vec<(String, String)> = Vec::new();
    // The object files first: the configuration file after them is not one.
    for path in &paths {
        if let Some(text) = std::fs::read(path)
            .ok()
            .and_then(|bytes| crate::queries::decode(&bytes).ok())
        {
            files.push((path.to_string_lossy().into_owned(), text));
        }
    }
    let objects_read = files.len();
    let elastic = root.join(crate::queries::ELASTIC_CONFIGURATION);
    if let Some(text) = std::fs::read(&elastic)
        .ok()
        .and_then(|bytes| crate::queries::decode(&bytes).ok())
    {
        files.push((crate::queries::ELASTIC_CONFIGURATION.to_owned(), text));
    }
    let host = Arc::new(MemoryWorkspace { files });
    let objects = opentide_lsp::ObjectFindings::validate(root);
    let engine_index = opentide_analysis::index_workspace(host.as_ref());
    let mut findings = HashMap::new();
    for (path, text) in &host.files[..objects_read] {
        let file = Path::new(path);
        let mut found: Vec<opentide_core::Diagnostic> = objects.for_file(file, text);
        found.extend(
            opentide_analysis::analyze_with_index(
                host.as_ref(),
                &engine_index,
                opentide_analysis::AnalyzeRequest {
                    uri: path.clone(),
                    language: LanguageId::TideYaml,
                    text: text.clone(),
                },
            )
            .diagnostics,
        );
        let lines = LineStarts::new(text);
        let placed = found
            .into_iter()
            .map(|diagnostic| {
                let item = crate::queries::finding(text, &lines, diagnostic);
                let help = crate::queries::engine_help(
                    &item.code,
                    &item.message,
                    item.suggestion.as_deref(),
                );
                Finding {
                    severity: match item.severity {
                        opentide_core::Severity::Error => "error",
                        opentide_core::Severity::Warning => "warning",
                        _ => "note",
                    }
                    .to_owned(),
                    end_column: Some(if item.end_line == item.line {
                        item.end_column
                    } else {
                        item.column + 1
                    }),
                    code: item.code,
                    message: item.message,
                    object_uuid: String::new(),
                    path: Some(file.to_path_buf()),
                    line: Some(item.line),
                    column: Some(item.column),
                    field_path: item.field_path,
                    help: Some(help),
                    source: Source::LanguageServer,
                }
            })
            .collect();
        let key = file.canonicalize().unwrap_or_else(|_| file.to_path_buf());
        findings.insert(key, placed);
    }
    drop(profiles);
    LanguageServer {
        findings,
        unavailable: None,
        advice: None,
        host: Some(host),
    }
}
