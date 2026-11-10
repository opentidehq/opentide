//! `opentide info catalog`: every object, how they relate, and the ATT&CK
//! skeleton, in one document for an editor's catalogue, coverage graph,
//! ATT&CK matrix and search (`cli/services/catalog.py`; vscode-extension
//! `docs/CONTRACTS.md`).
//!
//! It is built in one pass over the index: each edge comes from the field
//! that holds the reference, so the cost is linear in the catalogue.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::OnceLock;

use indexmap::IndexMap;
use opentide_schema::node::{self, Node, Value};
use opentide_schema::objects::FieldRole;
use opentide_schema::pins::PinTable;
use opentide_schema::vocab::{Version, Vocabularies, attack};
use regex::Regex;
use serde::Serialize;

use crate::coverage::{bucket, inherited_techniques};
use crate::fields::{as_list, get, mapping, py_str, role_values, str_at, string, text};
use crate::fs::FileSystem;
use crate::index::{DUPLICATE_ID, Index, YAML_PARSE, posix};
use crate::state::{self, Binding};
use crate::workspace::Workspace;

/// Object families, in the order the document lists them.
pub const FAMILIES: [&str; 3] = ["threat", "objective", "rule"];

/// Every `kind` an edge can have, in the order the summary lists them.
pub const EDGE_KINDS: [&str; 6] = [
    "covers",
    "implements",
    "parent",
    "chains",
    "technique",
    "logsource",
];

/// The status strategies a `deployment.toml` status may map to.
const STRATEGIES: [&str; 6] = [
    "INERT",
    "RELEASE",
    "PREVIEW",
    "DISABLEMENT",
    "DELETION",
    "UNIVERSAL",
];

/// A rule's platform block, as the catalogue lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlatformBlock {
    /// The platform's key.
    pub id: String,
    /// Whether `enabled` is `true`.
    pub enabled: bool,
    /// The block's `status`.
    pub status: Option<String>,
    /// The strategy `deployment.toml` maps the status to.
    pub strategy: Option<String>,
}

/// An object's techniques, kept apart by where they come from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct Techniques {
    /// Listed by the object.
    pub own: Vec<String>,
    /// From its parents, without its own.
    pub inherited: Vec<String>,
}

/// One object that loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObjectRow {
    /// Its UUID.
    pub uuid: String,
    /// Its family.
    #[serde(rename = "type")]
    pub family: String,
    /// `metadata.schema`.
    pub schema: Option<String>,
    /// `name`.
    pub name: String,
    /// The path from the workspace, with `/`.
    pub path: Option<String>,
    /// The absolute path.
    pub file_path: Option<String>,
    /// The line of the root `name:` key, or 1.
    pub line: usize,
    /// `metadata.tlp`.
    pub tlp: Option<String>,
    /// `metadata.author`.
    pub author: Option<String>,
    /// `metadata.created`.
    pub created: Option<String>,
    /// `metadata.modified`.
    pub modified: Option<String>,
    /// `metadata.reviewed`.
    pub reviewed: Option<String>,
    /// Own and inherited techniques.
    pub techniques: Techniques,
    /// The short names of their tactics, in matrix order.
    pub tactics: Vec<String>,
    /// The actors of the threats it descends from.
    pub actors: Vec<String>,
    /// A rule's platform blocks.
    pub platforms: Vec<PlatformBlock>,
    /// A rule's deployment bindings.
    pub deployment: Vec<Binding>,
    /// Always `null` here.
    pub load_error: Option<LoadErrorDetail>,
}

/// Why a file did not load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadErrorDetail {
    /// `yaml_parse`, `missing_uuid` or `duplicate_id`.
    pub code: String,
    /// The finding's message.
    pub message: String,
    /// The line of a YAML problem.
    pub line: Option<usize>,
}

/// A file the index holds no object for: what can be read of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadErrorRow {
    /// The UUID its text names, except for a duplicate (the kept object's).
    pub uuid: Option<String>,
    /// Its family.
    #[serde(rename = "type")]
    pub family: Option<String>,
    /// The schema its text names.
    pub schema: Option<String>,
    /// The name its text gives, else the file's stem.
    pub name: String,
    /// The path from the workspace.
    pub path: Option<String>,
    /// The absolute path.
    pub file_path: Option<String>,
    /// The line of the root `name:` key, or 1.
    pub line: usize,
    /// Always `null`.
    pub tlp: Option<String>,
    /// Always `null`.
    pub author: Option<String>,
    /// Always `null`.
    pub created: Option<String>,
    /// Always `null`.
    pub modified: Option<String>,
    /// Always `null`.
    pub reviewed: Option<String>,
    /// Always empty.
    pub platforms: Vec<PlatformBlock>,
    /// Always empty.
    pub deployment: Vec<Binding>,
    /// Always empty.
    pub techniques: Techniques,
    /// Always empty.
    pub tactics: Vec<String>,
    /// Always empty.
    pub actors: Vec<String>,
    /// Why it did not load.
    pub load_error: LoadErrorDetail,
}

/// A row of `objects`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Row {
    /// An object.
    Object(Box<ObjectRow>),
    /// A file that did not load.
    LoadError(Box<LoadErrorRow>),
}

impl Row {
    /// The row's family, when it loaded.
    pub fn loaded_family(&self) -> Option<&str> {
        match self {
            Self::Object(row) => Some(&row.family),
            Self::LoadError(_) => None,
        }
    }

    /// Own and inherited techniques.
    pub fn techniques(&self) -> &Techniques {
        match self {
            Self::Object(row) => &row.techniques,
            Self::LoadError(row) => &row.techniques,
        }
    }
}

/// An edge between two objects, or from an object to a technique or log source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Edge {
    /// Where it starts.
    pub from: String,
    /// What it names.
    pub to: String,
    /// One of [`EDGE_KINDS`].
    pub kind: &'static str,
    /// The field that holds it.
    pub field_path: String,
    /// A chain's relation.
    pub relation: Option<String>,
    /// Whether it names no object.
    pub missing: bool,
}

/// A signal of an objective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignalRow {
    /// Its UUID.
    pub uuid: String,
    /// Its name.
    pub name: String,
    /// The objective that defines it.
    pub objective: Option<String>,
    /// The signal it derives from.
    pub parent: Option<String>,
}

/// The catalogue's counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Rows of `objects`, load errors included.
    pub objects: usize,
    /// Threats.
    pub threats: usize,
    /// Objectives.
    pub objectives: usize,
    /// Rules.
    pub rules: usize,
    /// Signals.
    pub signals: usize,
    /// Edges.
    pub edges: usize,
    /// Files that did not load.
    pub load_errors: usize,
}

/// The catalogue.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Catalogue {
    /// Objects by family (threats, objectives, rules), each by path, then
    /// the files that did not load.
    pub objects: Vec<Row>,
    /// Every edge.
    pub edges: Vec<Edge>,
    /// Every signal.
    pub signals: Vec<SignalRow>,
    /// The ATT&CK Enterprise matrix.
    pub attack: attack::Matrix,
    /// The counts (not part of the document: `info` merges them into its
    /// summary).
    #[serde(skip)]
    pub summary: Summary,
}

#[expect(clippy::expect_used, reason = "regex literals")]
fn patterns() -> &'static [Regex; 4] {
    static PATTERNS: OnceLock<[Regex; 4]> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            Regex::new(r"(?m)^name[ \t]*:").expect("a valid pattern"),
            Regex::new(r"^([ \t]*)([A-Za-z_][\w-]*)[ \t]*:(?:[ \t]+(.*?))?[ \t]*$")
                .expect("a valid pattern"),
            Regex::new(r"^[0-9A-Fa-f-]{32,36}$").expect("a valid pattern"),
            Regex::new(r"^[\w:.]+$").expect("a valid pattern"),
        ]
    })
}

/// The 1-based line of the root `name:` key, or 1.
pub fn name_line(text: &str) -> usize {
    patterns()[0]
        .find(text)
        .map_or(1, |found| text[..found.start()].matches('\n').count() + 1)
}

/// Python's `str.splitlines`.
fn split_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((at, ch)) = chars.next() {
        let breaks = matches!(
            ch,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !breaks {
            continue;
        }
        lines.push(&text[start..at]);
        let mut next = at + ch.len_utf8();
        if ch == '\r' && chars.peek().map(|(_, c)| *c) == Some('\n') {
            chars.next();
            next += 1;
        }
        start = next;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// A plain or quoted YAML scalar written on one line, without its comment.
fn scalar(raw: Option<&str>) -> Option<String> {
    let raw = raw?;
    if raw.is_empty() || raw.starts_with('#') {
        return None;
    }
    let mut chars = raw.chars();
    let first = chars.next()?;
    if first == '\'' || first == '"' {
        let rest: Vec<char> = chars.collect();
        let mut value = String::new();
        let mut index = 0;
        while index < rest.len() {
            let mut ch = rest[index];
            if first == '\'' && ch == '\'' && rest.get(index + 1) == Some(&'\'') {
                value.push('\'');
                index += 2;
                continue;
            }
            if ch == first {
                break;
            }
            if first == '"' && ch == '\\' && index + 1 < rest.len() {
                index += 1;
                ch = rest[index];
            }
            value.push(ch);
            index += 1;
        }
        let value = value.trim();
        return (!value.is_empty()).then(|| value.to_owned());
    }
    let mut cut = raw.len();
    for (at, _) in raw.match_indices('#') {
        if at > 0 && matches!(raw.as_bytes()[at - 1], b' ' | b'\t') {
            cut = at - 1;
            break;
        }
    }
    let value = raw[..cut].trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// `name`, `uuid` and `schema` read from the text of a file that did not
/// load: `name` is the root key; `uuid` the root key, else `metadata.uuid`;
/// `schema` `metadata.schema`, else the root key.
pub fn text_fields(text: &str) -> HashMap<&'static str, String> {
    let key_line = &patterns()[1];
    let mut root: HashMap<String, String> = HashMap::new();
    let mut metadata: HashMap<String, String> = HashMap::new();
    let mut in_metadata = false;
    let mut child_indent: Option<String> = None;
    for line in split_lines(text) {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let found = key_line.captures(line);
        let indent = match &found {
            Some(found) => found.get(1).map_or("", |m| m.as_str()).to_owned(),
            None => line[..line.len() - line.trim_start().len()].to_owned(),
        };
        let key = found.as_ref().and_then(|f| f.get(2)).map(|m| m.as_str());
        let value = found.as_ref().and_then(|f| f.get(3)).map(|m| m.as_str());
        if indent.is_empty() {
            in_metadata = found.is_some() && key == Some("metadata") && scalar(value).is_none();
            child_indent = None;
            if let (Some(key), Some(value)) = (key, value) {
                root.entry(key.to_owned())
                    .or_insert_with(|| value.to_owned());
            }
            continue;
        }
        if !in_metadata || found.is_none() {
            continue;
        }
        let child = child_indent.get_or_insert_with(|| indent.clone());
        if *child == indent
            && let (Some(key), Some(value)) = (key, value)
        {
            metadata
                .entry(key.to_owned())
                .or_insert_with(|| value.to_owned());
        }
    }
    let mut fields = HashMap::new();
    if let Some(name) = scalar(root.get("name").map(String::as_str)) {
        fields.insert("name", name);
    }
    for (key, pattern, sources) in [
        ("uuid", &patterns()[2], [&root, &metadata]),
        ("schema", &patterns()[3], [&metadata, &root]),
    ] {
        for source in sources {
            if let Some(value) = scalar(source.get(key).map(String::as_str))
                && pattern.is_match(&value)
            {
                fields.insert(key, value);
                break;
            }
        }
    }
    fields
}

/// The path from the workspace with `/`, and the absolute path.
fn paths(
    fs: &dyn FileSystem,
    file: Option<&Path>,
    workspace: &Path,
) -> (Option<String>, Option<String>) {
    let Some(file) = file else {
        return (None, None);
    };
    let absolute = if file.is_absolute() {
        file.to_path_buf()
    } else {
        workspace.join(file)
    };
    let shown = absolute.to_string_lossy().into_owned();
    if let Ok(relative) = absolute.strip_prefix(workspace) {
        return (Some(posix(relative)), Some(shown));
    }
    let (base, resolved) = (fs.resolve(workspace), fs.resolve(&absolute));
    if let Ok(relative) = resolved.strip_prefix(&base) {
        return (Some(posix(relative)), Some(shown));
    }
    (Some(posix(&absolute)), Some(shown))
}

/// Status name to strategy, from `deployment.toml` as written.
fn status_strategies(deployment: Option<&Node>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let statuses = deployment.and_then(|d| get(d, "statuses"));
    if let Some(Value::Seq(entries)) = statuses.map(|s| &s.value) {
        for entry in entries {
            if let (Some(name), Some(strategy)) = (str_at(entry, "name"), str_at(entry, "strategy"))
            {
                let upper = strategy.to_uppercase();
                if STRATEGIES.contains(&upper.as_str()) {
                    out.insert(name.to_owned(), upper);
                }
            }
        }
    }
    out
}

fn platform_blocks(rule: &Node, strategies: &HashMap<String, String>) -> Vec<PlatformBlock> {
    let Some(Value::Map(blocks)) = get(rule, "configurations").map(|n| &n.value) else {
        return Vec::new();
    };
    blocks
        .iter()
        .filter(|entry| matches!(entry.value.value, Value::Map(_)))
        .map(|entry| {
            let status = text(get(&entry.value, "status"));
            PlatformBlock {
                id: py_str(&entry.key),
                enabled: matches!(
                    get(&entry.value, "enabled").map(|n| &n.value),
                    Some(Value::Bool(true))
                ),
                strategy: status.as_ref().and_then(|s| strategies.get(s).cloned()),
                status,
            }
        })
        .collect()
}

/// The `att&ck` vocabulary's Enterprise entries at the newest revision an
/// object schema pins, and the matrix.
fn attack_matrix(vocabularies: &Vocabularies) -> (attack::Matrix, HashMap<String, Vec<String>>) {
    let definition = vocabularies.get("att&ck");
    let pinned: Option<Version> = PinTable::bundled()
        .iter()
        .flat_map(|(_, pins)| pins.contracts().map(|(_, contract)| contract.clone()))
        .filter(|contract| contract.field == "att&ck")
        .map(|contract| contract.version)
        .max();
    let Some(definition) = definition else {
        return (attack::matrix(None, &IndexMap::new()), HashMap::new());
    };
    let entries = attack::enterprise(&definition, pinned);
    let matrix = attack::matrix(Some(&definition), &entries);
    let stage_of = attack::technique_tactics(&entries)
        .into_iter()
        .map(|(key, tactics)| (key.to_owned(), tactics))
        .collect();
    (matrix, stage_of)
}

/// The threats an object carries the actors of: itself, or those its
/// objective covers.
fn parent_threats<'n>(
    uuid: &'n str,
    family: &str,
    root: &'n Node,
    index: &'n Index,
) -> Vec<&'n str> {
    let objective = match family {
        "threat" => return vec![uuid],
        "rule" => match crate::coverage::rule_objective(root, index) {
            Some(objective) => objective,
            None => return Vec::new(),
        },
        _ => root,
    };
    let threats = mapping(objective, "objective").and_then(|section| get(section, "threats"));
    as_list(threats)
        .into_iter()
        .filter_map(|threat| match &threat.value {
            Value::Str(text) => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

struct Builder<'a> {
    index: &'a Index,
    edges: Vec<Edge>,
}

impl Builder<'_> {
    fn edge(
        &mut self,
        from: &str,
        to: &str,
        kind: &'static str,
        field_path: &str,
        relation: Option<&str>,
        missing: bool,
    ) {
        self.edges.push(Edge {
            from: from.to_owned(),
            to: to.to_owned(),
            kind,
            field_path: field_path.to_owned(),
            relation: relation.map(str::to_owned),
            missing,
        });
    }

    fn has(&self, family: &str, uuid: &str) -> bool {
        self.index
            .objects
            .get(family)
            .is_some_and(|objects| objects.contains_key(uuid))
    }

    /// `covers` to each threat, and each of its signals' `parent` and
    /// `logsource`.
    fn objective_edges(&mut self, uuid: &str, root: &Node) {
        let Some(section) = mapping(root, "objective") else {
            return;
        };
        for threat in as_list(get(section, "threats")) {
            if let Value::Str(target) = &threat.value
                && !target.is_empty()
            {
                let missing = !self.has("threat", target);
                self.edge(uuid, target, "covers", "objective.threats", None, missing);
            }
        }
        let Some(Value::Seq(signals)) = get(section, "signals").map(|n| &n.value) else {
            return;
        };
        for (position, signal) in signals.iter().enumerate() {
            if !matches!(signal.value, Value::Map(_)) {
                continue;
            }
            let Some(signal_uuid) = get(signal, "uuid").filter(|n| crate::index::truthy(n)) else {
                continue;
            };
            let signal_uuid = py_str(signal_uuid);
            // A signal UUID another objective defined first is indexed under that one.
            if self
                .index
                .signals
                .get(&signal_uuid)
                .is_none_or(|indexed| indexed.owner != uuid)
            {
                continue;
            }
            let prefix = format!("objective.signals.{position}");
            if let Some(Value::Str(parent)) = get(signal, "parent").map(|n| &n.value)
                && !parent.is_empty()
            {
                let missing = !self.index.signals.contains_key(parent);
                self.edge(
                    &signal_uuid,
                    parent,
                    "parent",
                    &format!("{prefix}.parent"),
                    None,
                    missing,
                );
            }
            let logsources = mapping(signal, "data").and_then(|data| get(data, "logsources"));
            for name in as_list(logsources) {
                if let Value::Str(name) = &name.value
                    && !name.is_empty()
                {
                    self.edge(
                        &signal_uuid,
                        name,
                        "logsource",
                        &format!("{prefix}.data.logsources"),
                        None,
                        false,
                    );
                }
            }
        }
    }
}

/// The catalogue of `workspace`.
pub fn build(workspace: &Workspace) -> Catalogue {
    build_from(
        workspace.fs().as_ref(),
        workspace.index(),
        workspace.configuration().resolved.get("deployment"),
        &workspace.roots().workspace,
        &Vocabularies::bundled(),
    )
}

/// The catalogue of an index: `deployment` is the resolved
/// `deployment.toml`, `root` the workspace folder (paths are shown from it,
/// and the deployment state is read under it).
pub fn build_from(
    fs: &dyn FileSystem,
    index: &Index,
    deployment: Option<&Node>,
    root: &Path,
    vocabularies: &Vocabularies,
) -> Catalogue {
    let (matrix, stage_of) = attack_matrix(vocabularies);
    let strategies = status_strategies(deployment);
    let bindings = state::bindings(fs, root);
    let tactic_order: HashMap<&str, usize> = matrix
        .tactics
        .iter()
        .enumerate()
        .map(|(n, tactic)| (tactic.shortname.as_str(), n))
        .collect();
    let threat_actors: HashMap<&str, Vec<String>> = bucket(index, "threat")
        .into_iter()
        .map(|(uuid, body)| {
            let actors = role_values(body, FieldRole::Actors)
                .into_iter()
                .map(|(_, actor)| actor)
                .collect();
            (uuid, actors)
        })
        .collect();
    let mut builder = Builder {
        index,
        edges: Vec::new(),
    };
    let mut objects: Vec<Row> = Vec::new();
    for family in FAMILIES {
        let mut rows: Vec<ObjectRow> = Vec::new();
        for (uuid, body) in bucket(index, family) {
            let own = role_values(body, FieldRole::Techniques);
            let own_ids: Vec<String> = own.iter().map(|(_, t)| t.clone()).collect();
            let inherited: Vec<String> = inherited_techniques(family, body, index)
                .into_iter()
                .filter(|t| !own_ids.contains(t))
                .collect();
            let tactic_names: BTreeSet<&str> = own_ids
                .iter()
                .chain(&inherited)
                .flat_map(|t| stage_of.get(t).into_iter().flatten())
                .map(String::as_str)
                .collect();
            let mut tactics: Vec<&str> = tactic_names.into_iter().collect();
            tactics.sort_by_key(|name| {
                tactic_order
                    .get(name)
                    .copied()
                    .unwrap_or(tactic_order.len())
            });
            let mut actors: Vec<String> = Vec::new();
            for threat in parent_threats(uuid, family, body, index) {
                for actor in threat_actors.get(threat).into_iter().flatten() {
                    if !actors.contains(actor) {
                        actors.push(actor.clone());
                    }
                }
            }
            let file = index.file_paths.get(uuid);
            let (path, file_path) = paths(fs, file.map(AsRef::as_ref), root);
            let object = index.objects.get(family).and_then(|o| o.get(uuid));
            // The line is read from the file `file_paths` names, which is
            // another family's when two families share the UUID.
            let line = match (object, file) {
                (Some(object), Some(file)) if object.path == *file => {
                    name_line(object.document.source())
                }
                (_, Some(file)) => read_text(fs, file).as_deref().map_or(1, name_line),
                _ => 1,
            };
            let metadata = mapping(body, "metadata");
            let meta = |key: &str| text(metadata.and_then(|m| get(m, key)));
            rows.push(ObjectRow {
                uuid: uuid.to_owned(),
                family: family.to_owned(),
                schema: meta("schema"),
                name: text(get(body, "name")).unwrap_or_default(),
                path,
                file_path,
                line,
                tlp: meta("tlp"),
                author: meta("author"),
                created: meta("created"),
                modified: meta("modified"),
                reviewed: meta("reviewed"),
                techniques: Techniques {
                    own: own_ids.clone(),
                    inherited,
                },
                tactics: tactics.into_iter().map(str::to_owned).collect(),
                actors,
                platforms: if family == "rule" {
                    platform_blocks(body, &strategies)
                } else {
                    Vec::new()
                },
                deployment: bindings
                    .get(&uuid.trim().to_lowercase())
                    .cloned()
                    .unwrap_or_default(),
                load_error: None,
            });
            for (field_path, technique) in &own {
                builder.edge(uuid, technique, "technique", field_path, None, false);
            }
            match family {
                "threat" => {
                    if let Some(chains) = index.chaining.get(uuid) {
                        for (relation, targets) in chains {
                            for target in targets {
                                let missing = !builder.has("threat", target);
                                builder.edge(
                                    uuid,
                                    target,
                                    "chains",
                                    "threat.chaining",
                                    Some(relation),
                                    missing,
                                );
                            }
                        }
                    }
                }
                "objective" => builder.objective_edges(uuid, body),
                _ => {
                    if let Some(Value::Str(target)) = get(body, "detection_model").map(|n| &n.value)
                        && !target.trim().is_empty()
                    {
                        let missing = !builder.has("objective", target)
                            && !index.signals.contains_key(target);
                        builder.edge(uuid, target, "implements", "detection_model", None, missing);
                    }
                }
            }
        }
        // Stable: rows with the same path keep the index's order.
        rows.sort_by(|a, b| {
            a.path
                .as_deref()
                .unwrap_or("")
                .cmp(b.path.as_deref().unwrap_or(""))
        });
        objects.extend(rows.into_iter().map(|row| Row::Object(Box::new(row))));
    }

    let mut load_errors = Vec::new();
    for error in &index.load_errors {
        let text = read_text(fs, &error.path);
        load_errors.push(load_error_row(
            fs,
            root,
            &error.path,
            Some(&error.family),
            error.code,
            error.message(),
            text.as_deref(),
        ));
    }
    for duplicate in &index.duplicates {
        load_errors.push(load_error_row(
            fs,
            root,
            &duplicate.path,
            Some(&duplicate.family),
            DUPLICATE_ID,
            duplicate.message.clone(),
            Some(duplicate.document.source()),
        ));
    }
    let load_error_count = load_errors.len();
    objects.extend(
        load_errors
            .into_iter()
            .map(|row| Row::LoadError(Box::new(row))),
    );

    let signals: Vec<SignalRow> = index
        .signals
        .values()
        .filter(|signal| matches!(signal.node.value, Value::Map(_)))
        .map(|signal| SignalRow {
            uuid: signal.uuid.clone(),
            name: string(get(&signal.node, "name")).unwrap_or_default(),
            objective: Some(signal.owner.clone()).filter(|owner| !owner.trim().is_empty()),
            parent: string(get(&signal.node, "parent")),
        })
        .collect();
    let count = |family: &str| index.objects.get(family).map_or(0, IndexMap::len);
    let summary = Summary {
        objects: objects.len(),
        threats: count("threat"),
        objectives: count("objective"),
        rules: count("rule"),
        signals: signals.len(),
        edges: builder.edges.len(),
        load_errors: load_error_count,
    };
    Catalogue {
        objects,
        edges: builder.edges,
        signals,
        attack: matrix,
        summary,
    }
}

/// A file's text, without a byte order mark; `None` when it cannot be read
/// as UTF-8.
fn read_text(fs: &dyn FileSystem, path: &Path) -> Option<String> {
    let text = String::from_utf8(fs.read(path).ok()?).ok()?;
    Some(match text.strip_prefix('\u{feff}') {
        Some(rest) => rest.to_owned(),
        None => text,
    })
}

fn load_error_row(
    fs: &dyn FileSystem,
    root: &Path,
    file: &Path,
    family: Option<&str>,
    code: &str,
    message: String,
    text: Option<&str>,
) -> LoadErrorRow {
    let (path, file_path) = paths(fs, Some(file), root);
    let line = match (code, text) {
        (YAML_PARSE, Some(text)) => node::load(text)
            .err()
            .and_then(|error| error.mark)
            .map(|mark| mark.line),
        _ => None,
    };
    let fields = text.map(text_fields).unwrap_or_default();
    let stem = file
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    LoadErrorRow {
        uuid: if code == DUPLICATE_ID {
            None
        } else {
            fields.get("uuid").cloned()
        },
        family: family.filter(|f| !f.is_empty()).map(str::to_owned),
        schema: fields.get("schema").cloned(),
        name: fields.get("name").cloned().unwrap_or(stem),
        path,
        file_path,
        line: text.map_or(1, name_line),
        tlp: None,
        author: None,
        created: None,
        modified: None,
        reviewed: None,
        platforms: Vec::new(),
        deployment: Vec::new(),
        techniques: Techniques::default(),
        tactics: Vec::new(),
        actors: Vec::new(),
        load_error: LoadErrorDetail {
            code: code.to_owned(),
            message,
            line,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_line_is_the_root_key() {
        assert_eq!(name_line("a: 1\n  name: x\nname: y\n"), 3);
        assert_eq!(name_line("names: 1\n"), 1);
        assert_eq!(name_line("name : x"), 1);
    }

    #[test]
    fn scalars_as_written_on_one_line() {
        assert_eq!(scalar(Some("x # note")).as_deref(), Some("x"));
        assert_eq!(scalar(Some("a#b")).as_deref(), Some("a#b"));
        assert_eq!(scalar(Some("# note")), None);
        assert_eq!(scalar(Some("'it''s' # c")).as_deref(), Some("it's"));
        assert_eq!(scalar(Some(r#""a\"b""#)).as_deref(), Some("a\"b"));
        assert_eq!(scalar(Some("''")), None);
        assert_eq!(scalar(None), None);
    }

    #[test]
    fn fields_of_a_file_that_did_not_load() {
        let text = "name: 'Broken: rule'\nmetadata:\n  uuid: 0b4d0e4e-1c33-4f53-8a6b-4c5b6e7f8a9b\n  schema: rule::1.1\n    deeper: x\nsignals:\n  uuid: 1b4d0e4e-1c33-4f53-8a6b-4c5b6e7f8a9b\ndetection: [\n";
        let fields = text_fields(text);
        assert_eq!(fields["name"], "Broken: rule");
        assert_eq!(fields["uuid"], "0b4d0e4e-1c33-4f53-8a6b-4c5b6e7f8a9b");
        assert_eq!(fields["schema"], "rule::1.1");
        // A root uuid wins over metadata's; a schema that is not one is dropped.
        let fields = text_fields("uuid: 2b4d0e4e1c334f538a6b4c5b6e7f8a9b\nschema: not a schema\n");
        assert_eq!(fields["uuid"], "2b4d0e4e1c334f538a6b4c5b6e7f8a9b");
        assert!(!fields.contains_key("schema"));
        assert!(text_fields("metadata: {uuid: x}\n").is_empty());
    }

    #[test]
    fn python_line_breaks() {
        assert_eq!(split_lines("a\r\nb\rc\u{2028}d\n"), ["a", "b", "c", "d"]);
        assert_eq!(split_lines(""), Vec::<&str>::new());
    }
}
