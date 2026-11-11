//! What telemetry a workspace declares, and which detections use it
//! (`cli/services/visibility.py`, #776): the report `generate explorer
//! --include-visibility` writes.
//!
//! `visibility.toml` declares each log source: its `name` is the dataset (a
//! KQL table, a Splunk sourcetype, an Elastic index pattern), with its
//! `system`, description and columns. The report joins it with the
//! catalogue:
//!
//! - **Signals:** an objective's signal names log sources in
//!   `data.logsources`; the objective uses them, and so does each rule
//!   implementing that signal, or the objective as a whole.
//! - **Queries:** the datasets each rule's queries read ([`DatasetRead`]),
//!   which the query engines report and the host passes in. A declared name
//!   covers a read as the engines' `DatasetKind::covers` does.

use indexmap::IndexMap;
use opentide_core::datasets::glob_matches;
use opentide_schema::configuration::models::VisibilityConfig;
use opentide_schema::from_node::{Context, FromNode};
use opentide_schema::node::{Node, Value};
use opentide_workspace::Index;

use super::relations::py_str;
use crate::json::{Json, Object};

/// One dataset a rule's query reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DatasetRead {
    /// The rule's UUID.
    pub rule: String,
    /// The `configurations` key the query is under (`sentinel`).
    pub system: String,
    /// The dataset.
    pub name: String,
    /// The query's field path (`configurations.sentinel.query`).
    pub field_path: String,
}

/// One column of a declared log source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    /// The column's name.
    pub name: String,
    /// Its type.
    pub kind: String,
    /// What it holds.
    pub description: String,
}

/// One `[[logsources]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Declared {
    /// The dataset.
    pub name: String,
    /// The system that holds it.
    pub system: String,
    /// What it records.
    pub description: String,
    /// Its columns, in the file's order.
    pub columns: Vec<Column>,
    /// The tenants that hold it.
    pub tenants: Vec<String>,
}

/// The `[[logsources]]` of a merged `visibility.toml` tree, checked by its
/// model (`visibility::1.0`): the sources, or why the file could not be read
/// (its first error).
///
/// # Errors
///
/// The model's first error, as the report's `problem` words it.
pub fn declared(tree: &Node) -> Result<Vec<Declared>, String> {
    let mut cx = Context::new();
    let model = VisibilityConfig::from_node(tree, &mut cx);
    let errors = cx.into_errors();
    let model = match (model, errors.first()) {
        (Some(model), None) => model,
        (_, Some(error)) => {
            let at = error
                .path
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(".");
            return Err(format!(
                "visibility.toml could not be read: {}{}",
                if at.is_empty() {
                    String::new()
                } else {
                    format!("{at}: ")
                },
                error.message
            ));
        }
        (None, None) => return Ok(Vec::new()),
    };
    Ok(model
        .0
        .logsources
        .iter()
        .map(|source| Declared {
            name: source.name.clone(),
            system: source.system.clone(),
            description: source.description.clone(),
            tenants: source.tenants.clone().unwrap_or_default(),
            columns: source
                .columns
                .iter()
                .flatten()
                .map(|(name, column)| Column {
                    name: name.clone(),
                    kind: column.r#type.clone(),
                    description: column.description.clone().unwrap_or_default(),
                })
                .collect(),
        })
        .collect())
}

/// Whether a log source of `system` named `declared` holds the dataset
/// `read`: `*` in either matches any run of characters, the read name is
/// trimmed, and Splunk sourcetypes ignore case.
pub fn covers(system: &str, declared: &str, read: &str) -> bool {
    let read = read.trim();
    let (declared, read) = if system == "splunk" {
        (declared.to_lowercase(), read.to_lowercase())
    } else {
        (declared.to_owned(), read.to_owned())
    };
    glob_matches(&declared, &read) || (read.contains('*') && glob_matches(&read, &declared))
}

/// What the report starts from besides the index.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    /// The declared log sources; `None` when the workspace has no
    /// `visibility.toml`.
    pub declared: Option<Vec<Declared>>,
    /// The datasets the rules' queries read, rule by rule.
    pub reads: Vec<DatasetRead>,
    /// Why the reads are not known, when they are not.
    pub reads_unavailable: Option<String>,
    /// Why `visibility.toml` could not be read, when it could not.
    pub problem: Option<String>,
}

/// A value or values as a list (`_as_list`): a blank string is none.
fn as_list(node: Option<&Node>) -> Vec<&Node> {
    match node.map(|node| &node.value) {
        Some(Value::Str(text)) if !text.trim().is_empty() => node.into_iter().collect(),
        Some(Value::Seq(items)) => items.iter().map(AsRef::as_ref).collect(),
        _ => Vec::new(),
    }
}

/// `str(x or "")`.
fn or_empty(node: Option<&Node>) -> String {
    node.filter(|value| opentide_workspace::index::truthy(value))
        .map(py_str)
        .unwrap_or_default()
}

fn unique<T: Clone + PartialEq>(items: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut out: Vec<T> = Vec::new();
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn strings(items: &[String]) -> Json {
    Json::Array(items.iter().cloned().map(Json::Str).collect())
}

/// One row of the report.
struct Row<'d> {
    source: &'d Declared,
    read_by: Vec<String>,
    objectives: Vec<String>,
    signals: Vec<(String, String, String)>,
    signal_rules: Vec<String>,
}

impl Row<'_> {
    fn rules(&self) -> Vec<String> {
        unique(self.read_by.iter().chain(&self.signal_rules).cloned())
    }

    fn to_json(&self) -> Json {
        let source = self.source;
        let mut row = Object::new();
        row.insert("name".into(), Json::from(source.name.as_str()));
        row.insert("system".into(), Json::from(source.system.as_str()));
        row.insert(
            "description".into(),
            Json::from(source.description.as_str()),
        );
        row.insert("tenants".into(), strings(&source.tenants));
        row.insert(
            "columns".into(),
            Json::Array(
                source
                    .columns
                    .iter()
                    .map(|column| {
                        let mut entry = Object::new();
                        entry.insert("name".into(), Json::from(column.name.as_str()));
                        entry.insert("type".into(), Json::from(column.kind.as_str()));
                        entry.insert(
                            "description".into(),
                            Json::from(column.description.as_str()),
                        );
                        Json::Object(entry)
                    })
                    .collect(),
            ),
        );
        row.insert("read_by".into(), strings(&self.read_by));
        row.insert("objectives".into(), strings(&self.objectives));
        row.insert(
            "signals".into(),
            Json::Array(
                self.signals
                    .iter()
                    .map(|(objective, uuid, name)| {
                        let mut entry = Object::new();
                        entry.insert("objective".into(), Json::from(objective.as_str()));
                        entry.insert("uuid".into(), Json::from(uuid.as_str()));
                        entry.insert("name".into(), Json::from(name.as_str()));
                        Json::Object(entry)
                    })
                    .collect(),
            ),
        );
        row.insert("signal_rules".into(), strings(&self.signal_rules));
        row.insert("rules".into(), strings(&self.rules()));
        Json::Object(row)
    }
}

/// The report (`collect_visibility`, `VisibilityReport.to_dict`).
pub fn report(index: &Index, inputs: &Inputs) -> Json {
    let empty = Vec::new();
    let declared = inputs.declared.as_ref().unwrap_or(&empty);
    // objective → [(signal uuid, name, [log source names])]
    let mut signal_sources: IndexMap<String, Vec<(String, String, Vec<String>)>> = IndexMap::new();
    for object in index.family("objective") {
        let Some(root) = object.root() else {
            continue;
        };
        let section = root.get("objective").map(AsRef::as_ref);
        for signal in as_list(
            section
                .and_then(|section| section.get("signals"))
                .map(AsRef::as_ref),
        ) {
            if !matches!(signal.value, Value::Map(_)) {
                continue;
            }
            let data = signal
                .get("data")
                .map(AsRef::as_ref)
                .filter(|data| matches!(data.value, Value::Map(_)));
            let names = as_list(
                data.and_then(|data| data.get("logsources"))
                    .map(AsRef::as_ref),
            )
            .into_iter()
            .filter_map(|name| name.value.as_str().map(str::to_owned))
            .collect();
            signal_sources
                .entry(object.uuid.clone())
                .or_default()
                .push((
                    or_empty(signal.get("uuid").map(AsRef::as_ref)),
                    or_empty(signal.get("name").map(AsRef::as_ref)),
                    names,
                ));
        }
    }
    let mut implementers: IndexMap<String, Vec<String>> = IndexMap::new();
    for rule in index.family("rule") {
        if let Some(Value::Str(target)) = rule
            .root()
            .and_then(|root| root.get("detection_model"))
            .map(|node| &node.value)
        {
            implementers
                .entry(target.clone())
                .or_default()
                .push(rule.uuid.clone());
        }
    }
    let reads = &inputs.reads;
    let named: Vec<String> = declared.iter().map(|s| s.name.to_lowercase()).collect();
    let mut rows: Vec<Row<'_>> = Vec::new();
    for source in declared {
        let read_by = unique(
            reads
                .iter()
                .filter(|read| {
                    read.system == source.system && covers(&source.system, &source.name, &read.name)
                })
                .map(|read| read.rule.clone()),
        );
        let lowered = source.name.to_lowercase();
        let mut objectives = Vec::new();
        let mut signals = Vec::new();
        let mut signal_rules = Vec::new();
        for (owner, owned) in &signal_sources {
            for (signal, name, names) in owned {
                if !names.iter().any(|n| n.to_lowercase() == lowered) {
                    continue;
                }
                objectives.push(owner.clone());
                signals.push((owner.clone(), signal.clone(), name.clone()));
                signal_rules.extend(implementers.get(signal).into_iter().flatten().cloned());
                signal_rules.extend(implementers.get(owner).into_iter().flatten().cloned());
            }
        }
        rows.push(Row {
            source,
            read_by,
            objectives: unique(objectives),
            signals,
            signal_rules: unique(signal_rules),
        });
    }
    let declaring: Vec<&str> = declared.iter().map(|s| s.system.as_str()).collect();
    let mut missing: IndexMap<(String, String), Vec<String>> = IndexMap::new();
    for read in reads {
        let covered = declared
            .iter()
            .any(|s| s.system == read.system && covers(&s.system, &s.name, &read.name));
        if !covered {
            missing
                .entry((read.system.clone(), read.name.clone()))
                .or_default()
                .push(read.rule.clone());
        }
    }
    missing.sort_keys();
    let undeclared: Vec<Json> = missing
        .into_iter()
        .map(|((system, name), rules)| {
            let mut entry = Object::new();
            entry.insert("system".into(), Json::from(system.as_str()));
            entry.insert("name".into(), Json::Str(name));
            entry.insert("rules".into(), strings(&unique(rules)));
            entry.insert(
                "system_declares".into(),
                Json::Bool(declaring.contains(&system.as_str())),
            );
            Json::Object(entry)
        })
        .collect();
    let mut unknown: IndexMap<String, Vec<String>> = IndexMap::new();
    for (owner, owned) in &signal_sources {
        for (_, _, names) in owned {
            for name in names {
                if !named.contains(&name.to_lowercase()) {
                    unknown.entry(name.clone()).or_default().push(owner.clone());
                }
            }
        }
    }
    unknown.sort_keys();
    let mut systems: IndexMap<String, [i64; 3]> = IndexMap::new();
    for row in &rows {
        let counts = systems.entry(row.source.system.clone()).or_insert([0; 3]);
        counts[0] += 1;
        counts[1] += i64::from(!row.source.columns.is_empty());
        counts[2] += i64::from(!row.rules().is_empty() || !row.objectives.is_empty());
    }
    systems.sort_keys();
    rows.sort_by(|a, b| {
        (a.source.system.as_str(), a.source.name.to_lowercase())
            .cmp(&(b.source.system.as_str(), b.source.name.to_lowercase()))
    });
    let mut out = Object::new();
    out.insert("present".into(), Json::Bool(inputs.declared.is_some()));
    out.insert("problem".into(), opt(inputs.problem.as_deref()));
    out.insert(
        "reads_unavailable".into(),
        opt(inputs.reads_unavailable.as_deref()),
    );
    out.insert(
        "systems".into(),
        Json::Object(
            systems
                .into_iter()
                .map(|(system, [logsources, with_columns, used])| {
                    let mut counts = Object::new();
                    counts.insert("logsources".into(), Json::Int(logsources));
                    counts.insert("with_columns".into(), Json::Int(with_columns));
                    counts.insert("used".into(), Json::Int(used));
                    (system, Json::Object(counts))
                })
                .collect(),
        ),
    );
    out.insert(
        "logsources".into(),
        Json::Array(rows.iter().map(Row::to_json).collect()),
    );
    out.insert("undeclared".into(), Json::Array(undeclared));
    out.insert(
        "unknown_signal_sources".into(),
        Json::Array(
            unknown
                .into_iter()
                .map(|(name, owners)| {
                    let mut entry = Object::new();
                    entry.insert("name".into(), Json::Str(name));
                    entry.insert("objectives".into(), strings(&unique(owners)));
                    Json::Object(entry)
                })
                .collect(),
        ),
    );
    out.insert(
        "reads".into(),
        Json::Array(
            reads
                .iter()
                .map(|read| {
                    let mut entry = Object::new();
                    entry.insert("rule".into(), Json::from(read.rule.as_str()));
                    entry.insert("system".into(), Json::from(read.system.as_str()));
                    entry.insert("name".into(), Json::from(read.name.as_str()));
                    entry.insert("field_path".into(), Json::from(read.field_path.as_str()));
                    Json::Object(entry)
                })
                .collect(),
        ),
    );
    Json::Object(out)
}

fn opt(text: Option<&str>) -> Json {
    text.map_or(Json::Null, Json::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate::json_text::line;
    use std::path::PathBuf;

    fn index_of(objects: &[(&str, &str, &str)]) -> Index {
        let mut index = Index::default();
        for (family, uuid, text) in objects {
            index
                .objects
                .entry((*family).to_owned())
                .or_default()
                .insert(
                    (*uuid).to_owned(),
                    opentide_workspace::Object {
                        uuid: (*uuid).to_owned(),
                        family: (*family).to_owned(),
                        path: PathBuf::from(format!("{uuid}.yaml")),
                        document: std::sync::Arc::new(opentide_schema::node::load(text).unwrap()),
                    },
                );
        }
        index
    }

    fn read(rule: &str, system: &str, name: &str) -> DatasetRead {
        DatasetRead {
            rule: rule.into(),
            system: system.into(),
            name: name.into(),
            field_path: format!("configurations.{system}.query"),
        }
    }

    #[test]
    fn a_declared_pattern_covers_what_rules_read() {
        assert!(covers("elastic", "logs-*", "logs-endpoint"));
        assert!(covers("elastic", "logs-endpoint", "logs-*"));
        assert!(!covers("elastic", "Logs-*", "logs-x"));
        assert!(covers("splunk", "WinEventLog", " wineventlog "));
        assert!(!covers("sentinel", "SecurityEvent", "securityevent"));
    }

    #[test]
    fn the_report_joins_sources_with_signals_and_queries() {
        let index = index_of(&[
            (
                "objective",
                "o1",
                "objective: {signals: [{uuid: s1, name: Logons, data: {logsources: [securityevent, Missing]}}]}\n",
            ),
            ("rule", "r1", "detection_model: s1\n"),
            ("rule", "r2", "detection_model: o1\n"),
        ]);
        let tree = opentide_schema::node::load(
            "logsources:\n- {name: SecurityEvent, system: sentinel, description: d, tenants: [a], columns: {Account: {type: string}}}\n- {name: Other, system: splunk, description: ''}\n",
        )
        .unwrap();
        let inputs = Inputs {
            declared: Some(declared(tree.root().unwrap()).unwrap()),
            reads: vec![
                read("r3", "sentinel", "SecurityEvent"),
                read("r3", "sentinel", "DeviceEvents"),
                read("r4", "elastic", "logs-*"),
                read("r5", "sentinel", "DeviceEvents"),
            ],
            ..Inputs::default()
        };
        let report = report(&index, &inputs);
        assert_eq!(
            line(report.get("logsources").unwrap()),
            "[{\"name\": \"SecurityEvent\", \"system\": \"sentinel\", \"description\": \"d\", \"tenants\": [\"a\"], \
             \"columns\": [{\"name\": \"Account\", \"type\": \"string\", \"description\": \"\"}], \"read_by\": [\"r3\"], \
             \"objectives\": [\"o1\"], \"signals\": [{\"objective\": \"o1\", \"uuid\": \"s1\", \"name\": \"Logons\"}], \
             \"signal_rules\": [\"r1\", \"r2\"], \"rules\": [\"r3\", \"r1\", \"r2\"]}, \
             {\"name\": \"Other\", \"system\": \"splunk\", \"description\": \"\", \"tenants\": [], \"columns\": [], \
             \"read_by\": [], \"objectives\": [], \"signals\": [], \"signal_rules\": [], \"rules\": []}]"
        );
        assert_eq!(
            line(report.get("undeclared").unwrap()),
            "[{\"system\": \"elastic\", \"name\": \"logs-*\", \"rules\": [\"r4\"], \"system_declares\": false}, \
             {\"system\": \"sentinel\", \"name\": \"DeviceEvents\", \"rules\": [\"r3\", \"r5\"], \"system_declares\": true}]"
        );
        assert_eq!(
            line(report.get("unknown_signal_sources").unwrap()),
            "[{\"name\": \"Missing\", \"objectives\": [\"o1\"]}]"
        );
        assert_eq!(
            line(report.get("systems").unwrap()),
            "{\"sentinel\": {\"logsources\": 1, \"with_columns\": 1, \"used\": 1}, \"splunk\": {\"logsources\": 1, \"with_columns\": 0, \"used\": 0}}"
        );
        assert_eq!(report.get("present"), Some(&Json::Bool(true)));
    }

    /// A source only a signal names, with no rule implementing it, is used
    /// through its objective (`used = bool(rules or objectives)`).
    #[test]
    fn a_source_named_only_by_an_objective_is_used() {
        let index = index_of(&[(
            "objective",
            "o1",
            "objective: {signals: [{uuid: s1, name: Logons, data: {logsources: [Syslog]}}]}\n",
        )]);
        let tree = opentide_schema::node::load(
            "logsources:\n- {name: Syslog, system: sentinel, description: d}\n",
        )
        .unwrap();
        let inputs = Inputs {
            declared: Some(declared(tree.root().unwrap()).unwrap()),
            ..Inputs::default()
        };
        let report = report(&index, &inputs);
        assert_eq!(
            line(report.get("systems").unwrap()),
            "{\"sentinel\": {\"logsources\": 1, \"with_columns\": 0, \"used\": 1}}"
        );
        assert_eq!(
            line(report.get("logsources").unwrap()),
            "[{\"name\": \"Syslog\", \"system\": \"sentinel\", \"description\": \"d\", \"tenants\": [], \
             \"columns\": [], \"read_by\": [], \"objectives\": [\"o1\"], \
             \"signals\": [{\"objective\": \"o1\", \"uuid\": \"s1\", \"name\": \"Logons\"}], \
             \"signal_rules\": [], \"rules\": []}]"
        );
    }

    #[test]
    fn a_file_its_model_refuses_is_a_problem() {
        let tree = opentide_schema::node::load("logsources:\n- {name: x}\n").unwrap();
        let problem = declared(tree.root().unwrap()).unwrap_err();
        assert!(
            problem.starts_with("visibility.toml could not be read: "),
            "{problem}"
        );
    }

    #[test]
    fn without_a_file_nothing_is_declared() {
        let report = report(&Index::default(), &Inputs::default());
        assert_eq!(report.get("present"), Some(&Json::Bool(false)));
        assert_eq!(report.get("logsources"), Some(&Json::Array(vec![])));
    }
}
