//! Comparing two JSON Schemas by verdict (UC-1.8b, #900): what each accepts
//! and refuses, never their text. Every corpus object and configuration
//! file, and every fault the catalogue makes, is validated against the
//! oracle's schema and against the one Rust generates with the `jsonschema`
//! crate; the two must agree on each.
//!
//! The instances are the documents an editor validates: an object file's
//! YAML (read by `opentide_schema::node`, YAML 1.2) and a configuration
//! file's TOML (`opentide_schema::configuration::toml`), each as JSON. A file
//! that does not parse is no instance.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use opentide_schema::configuration::checks::file_key;
use opentide_schema::configuration::merge::to_json;
use serde_json::Value;

use crate::corpus::cli::{corpora_dir, load_catalogue};
use crate::corpus::faults;
use crate::corpus::generate::generate;
use crate::corpus::workspace::{Family, Workspace};

/// One document validated against both schemas.
#[derive(Debug, Clone)]
pub struct Instance {
    /// Where it comes from, for messages: `<source>:<path>`.
    pub label: String,
    /// The document, as JSON.
    pub value: Value,
}

/// The documents of a corpus: object files, and configuration files by
/// their router key (`deployment.toml`, `platforms/sentinel.toml`).
#[derive(Debug, Default, Clone)]
pub struct Instances {
    /// Object files.
    pub objects: Vec<Instance>,
    /// Configuration files, each with its router key.
    pub configurations: Vec<(String, Instance)>,
}

impl Instances {
    /// Adds `other`'s documents.
    pub fn extend(&mut self, other: Instances) {
        self.objects.extend(other.objects);
        self.configurations.extend(other.configurations);
    }

    /// The configuration files routed to `key`.
    pub fn configurations_of<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a Instance> {
        self.configurations
            .iter()
            .filter(move |(known, _)| known == key)
            .map(|(_, instance)| instance)
    }

    /// Adds a file by its path relative to the workspace and its text: an
    /// object file under no dot folder, or a configuration file under
    /// `.opentide/configurations/`.
    pub fn add(&mut self, source: &str, path: &str, text: &str) {
        let label = format!("{source}:{path}");
        let path = path.replace('\\', "/");
        if let Some(relative) = path.strip_prefix(".opentide/configurations/") {
            if let (Some(key), Some(value)) = (file_key(relative), toml_instance(text)) {
                self.configurations.push((key, Instance { label, value }));
            }
            return;
        }
        let hidden = path.split('/').any(|part| part.starts_with('.'));
        let yaml = std::path::Path::new(&path)
            .extension()
            .is_some_and(|ext| ext == "yaml" || ext == "yml");
        if yaml
            && !hidden
            && let Some(value) = yaml_instance(text)
        {
            self.objects.push(Instance { label, value });
        }
    }
}

/// A YAML document as JSON, when it parses to a mapping.
pub fn yaml_instance(text: &str) -> Option<Value> {
    let document = opentide_schema::node::load(text).ok()?;
    let root = document.root()?;
    let value = to_json(root);
    value.is_object().then_some(value)
}

/// A TOML document as JSON, when it parses.
pub fn toml_instance(text: &str) -> Option<Value> {
    let node = opentide_schema::configuration::toml::parse(text).ok()?;
    Some(to_json(&node))
}

/// Every object and configuration file of the workspace at `dir`.
pub fn workspace_instances(source: &str, dir: &Path) -> Result<Instances> {
    let mut instances = Instances::default();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(folder) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&folder)
            .with_context(|| format!("read {}", folder.display()))?
            .collect::<std::io::Result<_>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                if entry.file_name() != ".git" {
                    stack.push(path);
                }
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            let relative = path
                .strip_prefix(dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if let Ok(text) = std::fs::read_to_string(&path) {
                instances.add(source, &relative, &text);
            }
        }
    }
    Ok(instances)
}

/// The files of a generated workspace whose index is in `indices`.
fn workspace_files(source: &str, workspace: &Workspace, indices: &BTreeSet<usize>) -> Instances {
    let mut instances = Instances::default();
    for index in indices {
        let file = &workspace.files[*index];
        if file.family == Family::Other {
            continue;
        }
        instances.add(source, &file.path, &file.render());
    }
    instances
}

/// Every fault of `tests/corpora/faults.toml`, each applied alone to the
/// catalogue's base workspace: the files it changes and adds. The base's
/// own files come first.
pub fn fault_instances() -> Result<Instances> {
    let catalogue = load_catalogue(&corpora_dir().join("faults.toml"))?;
    let base = generate(&catalogue.base.options()?);
    let all: BTreeSet<usize> = (0..base.files.len()).collect();
    let mut instances = workspace_files("fault-base", &base, &all);
    for kind in &catalogue.kinds {
        let mut workspace = base.clone();
        let Ok(targets) = faults::select(&workspace, kind, &BTreeSet::new()) else {
            continue;
        };
        let before = workspace.files.len();
        if faults::apply(&mut workspace, kind, &targets).is_err() {
            continue;
        }
        let touched: BTreeSet<usize> = targets
            .iter()
            .copied()
            .chain(before..workspace.files.len())
            .filter(|index| *index < workspace.files.len())
            .collect();
        instances.extend(workspace_files(
            &format!("fault:{}", kind.id),
            &workspace,
            &touched,
        ));
    }
    Ok(instances)
}

/// The configuration texts of `crates/opentide-schema/tests/oracle/config_cases.toml`
/// (`text` cases, each with its path) and the bundled configuration files.
pub fn configuration_case_instances(root: &Path) -> Result<Instances> {
    let mut instances = Instances::default();
    let cases_path = root.join("crates/opentide-schema/tests/oracle/config_cases.toml");
    let text = std::fs::read_to_string(&cases_path)
        .with_context(|| format!("read {}", cases_path.display()))?;
    let cases: toml::Table = toml::from_str(&text).context("parse config_cases.toml")?;
    for case in cases
        .get("case")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let (Some(id), Some(path), Some(text)) = (
            case.get("id").and_then(toml::Value::as_str),
            case.get("path").and_then(toml::Value::as_str),
            case.get("text").and_then(toml::Value::as_str),
        ) else {
            continue;
        };
        let path = path.replace('\\', "/");
        if let Some(at) = path.find(".opentide/configurations/") {
            instances.add(&format!("config-case:{id}"), &path[at..], text);
        }
    }
    let bundled = root.join("src/opentide/data/configurations");
    for folder in [bundled.clone(), bundled.join("platforms")] {
        let mut entries: Vec<_> = std::fs::read_dir(&folder)
            .with_context(|| format!("read {}", folder.display()))?
            .collect::<std::io::Result<_>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let relative = path
                .strip_prefix(&bundled)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&path)?;
            instances.add(
                "bundled",
                &format!(".opentide/configurations/{relative}"),
                &text,
            );
        }
    }
    Ok(instances)
}

/// A compiled schema, or why it does not compile.
fn compile(schema: &Value) -> Result<jsonschema::Validator> {
    jsonschema::validator_for(schema).map_err(|error| anyhow::anyhow!("{error}"))
}

/// Each instance's verdict under `schema`: `None` when it is accepted,
/// else the first reason it is refused.
pub fn verdicts<'a>(
    schema: &Value,
    instances: impl IntoIterator<Item = &'a Instance>,
) -> Result<Vec<Option<String>>> {
    let validator = compile(schema)?;
    Ok(instances
        .into_iter()
        .map(|instance| {
            validator
                .iter_errors(&instance.value)
                .next()
                .map(|error| format!("{} at {}", error, error.instance_path()))
        })
        .collect())
}

/// Compares `oracle` and `rust` on `instances`: pushes a problem for each
/// instance only one of them accepts, and returns the number compared.
pub fn compare(
    name: &str,
    oracle: &Value,
    rust: &Value,
    instances: &[&Instance],
    problems: &mut Vec<String>,
) -> Result<usize> {
    let oracle_verdicts = verdicts(oracle, instances.iter().copied())
        .with_context(|| format!("{name}: the oracle's schema"))?;
    let rust_verdicts = verdicts(rust, instances.iter().copied())
        .with_context(|| format!("{name}: the schema Rust generates"))?;
    for ((instance, oracle), rust) in instances.iter().zip(oracle_verdicts).zip(rust_verdicts) {
        match (oracle, rust) {
            (None, Some(reason)) => problems.push(format!(
                "{name}: {}: the oracle's schema accepts it, Rust's refuses it ({reason})",
                instance.label
            )),
            (Some(reason), None) => problems.push(format!(
                "{name}: {}: the oracle's schema refuses it ({reason}), Rust's accepts it",
                instance.label
            )),
            _ => {}
        }
    }
    Ok(instances.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn instance(value: Value) -> Instance {
        Instance {
            label: "t".to_owned(),
            value,
        }
    }

    #[test]
    fn the_same_verdict_is_no_problem_and_a_different_one_is() {
        let oracle = json!({"type": "object", "properties": {"a": {"enum": ["x", "y"]}}});
        let same =
            json!({"type": "object", "properties": {"a": {"type": "string", "enum": ["y", "x"]}}});
        let narrower = json!({"type": "object", "properties": {"a": {"enum": ["x"]}}});
        let accepted = instance(json!({"a": "x"}));
        let refused = instance(json!({"a": "z"}));
        let only_oracle = instance(json!({"a": "y"}));
        let mut problems = Vec::new();
        let all = [&accepted, &refused, &only_oracle];
        assert_eq!(
            compare("s", &oracle, &same, &all, &mut problems).unwrap(),
            3
        );
        assert!(problems.is_empty(), "{problems:#?}");
        compare("s", &oracle, &narrower, &all, &mut problems).unwrap();
        assert_eq!(problems.len(), 1, "{problems:#?}");
        assert!(
            problems[0].starts_with("s: t: the oracle's schema accepts it, Rust's refuses it"),
            "{problems:#?}"
        );
        problems.clear();
        compare("s", &narrower, &oracle, &all, &mut problems).unwrap();
        assert!(
            problems[0].contains("the oracle's schema refuses it")
                && problems[0].ends_with("Rust's accepts it"),
            "{problems:#?}"
        );
    }

    #[test]
    fn files_are_routed_by_what_they_are() {
        let mut instances = Instances::default();
        instances.add("w", "objects/rules/a.yaml", "name: a\n");
        instances.add("w", "objects/rules/b.yml", "- not a mapping\n");
        instances.add("w", ".opentide/configurations/deployment.toml", "x = 1\n");
        instances.add(
            "w",
            ".opentide/configurations/platforms/sentinel.toml",
            "[platform]\n",
        );
        instances.add(
            "w",
            ".opentide/configurations/platforms/plugin.toml",
            "a = 1\n",
        );
        instances.add("w", ".opentide/configurations/lint.toml", "a = 1\n");
        instances.add("w", ".vscode/settings.yaml", "a: 1\n");
        instances.add("w", "README.md", "# x\n");
        assert_eq!(instances.objects.len(), 1);
        assert_eq!(instances.objects[0].label, "w:objects/rules/a.yaml");
        let keys: Vec<&str> = instances
            .configurations
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        assert_eq!(
            keys,
            [
                "deployment.toml",
                "platforms/sentinel.toml",
                "platforms/*.toml"
            ]
        );
        assert_eq!(instances.configurations_of("deployment.toml").count(), 1);
    }
}
