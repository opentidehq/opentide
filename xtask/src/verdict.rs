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
/// own files come first. A kind that cannot be selected or applied is an
/// error, as it is for `cargo xtask corpus`: the comparison never covers
/// fewer faults than the catalogue holds.
pub fn fault_instances() -> Result<Instances> {
    let catalogue = load_catalogue(&corpora_dir().join("faults.toml"))?;
    let base = generate(&catalogue.base.options()?);
    faults_of(&base, &catalogue.kinds)
}

/// `base`'s files, then each kind's, applied alone to `base`.
fn faults_of(base: &Workspace, kinds: &[faults::Kind]) -> Result<Instances> {
    let all: BTreeSet<usize> = (0..base.files.len()).collect();
    let mut instances = workspace_files("fault-base", base, &all);
    for kind in kinds {
        let mut workspace = base.clone();
        let targets = faults::select(&workspace, kind, &BTreeSet::new())
            .with_context(|| format!("fault kind `{}`: select its targets", kind.id))?;
        let before = workspace.files.len();
        faults::apply(&mut workspace, kind, &targets)
            .with_context(|| format!("fault kind `{}`: apply it", kind.id))?;
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

/// The object files of `crates/opentide-schema/tests/oracle/objects_cases.toml`
/// (each case's `yaml`), labelled `object-case:<id>`.
pub fn object_case_instances(root: &Path) -> Result<Instances> {
    let cases_path = root.join("crates/opentide-schema/tests/oracle/objects_cases.toml");
    let text = std::fs::read_to_string(&cases_path)
        .with_context(|| format!("read {}", cases_path.display()))?;
    object_cases(&text)
}

fn object_cases(text: &str) -> Result<Instances> {
    let cases: toml::Table = toml::from_str(text).context("parse objects_cases.toml")?;
    let mut instances = Instances::default();
    for case in cases
        .get("case")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = case
            .get("id")
            .and_then(toml::Value::as_str)
            .context("objects_cases.toml: a case without an `id`")?;
        let yaml = case
            .get("yaml")
            .and_then(toml::Value::as_str)
            .with_context(|| format!("objects_cases.toml: case `{id}` has no `yaml`"))?;
        if let Some(value) = yaml_instance(yaml) {
            instances.objects.push(Instance {
                label: format!("object-case:{id}"),
                value,
            });
        }
    }
    Ok(instances)
}

/// Documents written for the comparison itself, each with the verdict both
/// schemas must give it (`true`: accepted). They keep every compared
/// document non-vacuous (a minimal `rule::1.0` object, which a workspace
/// whose rules reference its own objectives still accepts; a file of a
/// platform opentide has no model for) and sit on either side of each
/// hand-written constraint (`exclusiveMinimum`, `minLength`, `pattern`), so
/// a schema that moves a boundary gets a different verdict from the
/// oracle's.
pub const PROBES: [(&str, &str, bool); 12] = [
    (
        "rule-1.0-minimal.yaml",
        "name: Probe\nmetadata:\n  uuid: 00000000-0000-4000-8000-0000000000aa\n  schema: rule::1.0\n  \
         version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\n\
         description: d\nresponse: null\nconfigurations: null\n",
        true,
    ),
    (
        ".opentide/configurations/platforms/plugin.toml",
        "[platform]\nenabled = true\nname = \"Plugin\"\n[[tenants]]\nname = \"prod\"\n",
        true,
    ),
    (
        ".opentide/configurations/platforms/plugin.toml",
        "[[tenants]]\nname = \"\"\n",
        false,
    ),
    (
        ".opentide/configurations/documentation.toml",
        "[cve]\ntimeout = 0.1\n",
        true,
    ),
    (
        ".opentide/configurations/documentation.toml",
        "[cve]\ntimeout = 0\n",
        false,
    ),
    (
        ".opentide/configurations/documentation.toml",
        "[cve]\ntimeout = -1.5\n",
        false,
    ),
    (
        ".opentide/configurations/sharing.toml",
        "[[misp]]\nname = \"prod\"\nurl = \"https://misp.example\"\n\
         api_key = \"${MISP_KEY}\"\nmax_tlp = \"amber\"\n",
        true,
    ),
    (
        ".opentide/configurations/sharing.toml",
        "[[misp]]\nname = \"prod\"\nurl = \"https://misp.example\"\n\
         api_key = \"\"\nmax_tlp = \"amber\"\n",
        false,
    ),
    (
        ".opentide/configurations/sharing.toml",
        "[[misp]]\nname = \"\"\nurl = \"https://misp.example\"\n\
         api_key = \"${MISP_KEY}\"\nmax_tlp = \"amber\"\n",
        false,
    ),
    (
        ".opentide/configurations/sharing.toml",
        "[[misp]]\nname = \"Prod\"\nurl = \"https://misp.example\"\n\
         api_key = \"${MISP_KEY}\"\nmax_tlp = \"amber\"\n",
        false,
    ),
    (
        ".opentide/configurations/sharing.toml",
        "[[misp]]\nname = \"prod\"\nurl = \"\"\n\
         api_key = \"${MISP_KEY}\"\nmax_tlp = \"amber\"\n",
        false,
    ),
    (
        ".opentide/configurations/sharing.toml",
        "[[misp]]\nname = \"prod\"\nurl = \"ftp://misp.example\"\n\
         api_key = \"${MISP_KEY}\"\nmax_tlp = \"amber\"\n",
        false,
    ),
];

/// The [`PROBES`], labelled `probe:<n>:<path>`.
pub fn probe_instances() -> Instances {
    let mut instances = Instances::default();
    for (index, (path, text, _)) in PROBES.iter().enumerate() {
        instances.add(&format!("probe:{index}"), path, text);
    }
    instances
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

/// Why a schema refuses an instance: the first error and where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The validator's message.
    pub message: String,
    /// The JSON pointer of the refused value (`/references`).
    pub at: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}", self.message, self.at)
    }
}

/// Each instance's verdict under `schema`: `None` when it is accepted,
/// else the first reason it is refused.
pub fn verdicts<'a>(
    schema: &Value,
    instances: impl IntoIterator<Item = &'a Instance>,
) -> Result<Vec<Option<Refusal>>> {
    let validator = compile(schema)?;
    Ok(instances
        .into_iter()
        .map(|instance| {
            validator
                .iter_errors(&instance.value)
                .next()
                .map(|error| Refusal {
                    message: error.to_string(),
                    at: error.instance_path().to_string(),
                })
        })
        .collect())
}

/// An approved verdict difference: the instance `label`, which the oracle's
/// schema `schema` (a document's file name) refuses at `at` and Rust's
/// accepts. Each is an entry of `tests/golden/APPROVED_DIFFS.toml`, named by
/// `ledger`, and must still occur: an allowance no comparison uses is stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowance {
    /// The instance's label (`<source>:<path or case>`).
    pub label: &'static str,
    /// The file name of the document it applies to.
    pub schema: &'static str,
    /// Where the oracle's schema refuses it.
    pub at: &'static str,
    /// The ledger entry that records the difference.
    pub ledger: &'static str,
}

/// The approved verdict differences.
pub const ALLOWANCES: [Allowance; 1] = [Allowance {
    // `references: null` (objects_cases.toml `rule-configurations-null`):
    // the model accepts it, the oracle's inlined definition refused it.
    label: "object-case:rule-configurations-null",
    schema: "rule.1.1.schema.json",
    at: "/references",
    ledger: "schema-references-null",
}];

/// What one comparison found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    /// Instances validated against both schemas.
    pub compared: usize,
    /// Instances both schemas accept.
    pub accepted: usize,
    /// Instances both schemas refuse.
    pub refused: usize,
    /// The allowances that matched a difference.
    pub allowed: Vec<Allowance>,
}

/// Compares `oracle` and `rust` on `instances`: pushes a problem for each
/// instance only one of them accepts, unless one of `allowances` approves
/// that difference, and a problem when the comparison is vacuous: no
/// instance both accept, or none both refuse (a document handed instances
/// of another kind refuses them all, and agrees).
pub fn compare(
    name: &str,
    oracle: &Value,
    rust: &Value,
    instances: &[&Instance],
    allowances: &[Allowance],
    problems: &mut Vec<String>,
) -> Result<Tally> {
    let oracle_verdicts = verdicts(oracle, instances.iter().copied())
        .with_context(|| format!("{name}: the oracle's schema"))?;
    let rust_verdicts = verdicts(rust, instances.iter().copied())
        .with_context(|| format!("{name}: the schema Rust generates"))?;
    let file_name = name.rsplit(['/', ' ']).next().unwrap_or(name);
    let mut tally = Tally {
        compared: instances.len(),
        ..Tally::default()
    };
    for ((instance, oracle), rust) in instances.iter().zip(oracle_verdicts).zip(rust_verdicts) {
        match (oracle, rust) {
            (None, None) => tally.accepted += 1,
            (Some(_), Some(_)) => tally.refused += 1,
            (None, Some(reason)) => problems.push(format!(
                "{name}: {}: the oracle's schema accepts it, Rust's refuses it ({reason})",
                instance.label
            )),
            (Some(reason), None) => {
                if let Some(allowance) = allowances.iter().find(|allowance| {
                    allowance.label == instance.label
                        && allowance.schema == file_name
                        && allowance.at == reason.at
                }) {
                    tally.allowed.push(*allowance);
                } else {
                    problems.push(format!(
                        "{name}: {}: the oracle's schema refuses it ({reason}), Rust's accepts it",
                        instance.label
                    ));
                }
            }
        }
    }
    if tally.accepted == 0 {
        problems.push(format!(
            "{name}: no instance is accepted by both schemas, so the comparison proves nothing"
        ));
    }
    if tally.refused == 0 {
        problems.push(format!(
            "{name}: no instance is refused by both schemas, so the comparison proves nothing"
        ));
    }
    Ok(tally)
}

/// A problem for each allowance no comparison used.
pub fn stale_allowances(allowances: &[Allowance], used: &[Allowance]) -> Vec<String> {
    allowances
        .iter()
        .filter(|allowance| !used.contains(allowance))
        .map(|allowance| {
            format!(
                "the approved difference `{}` ({} on {}) no longer occurs: remove its allowance",
                allowance.ledger, allowance.label, allowance.schema
            )
        })
        .collect()
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
        let tally = compare("s", &oracle, &same, &all, &[], &mut problems).unwrap();
        assert_eq!(
            tally,
            Tally {
                compared: 3,
                accepted: 2,
                refused: 1,
                allowed: Vec::new()
            }
        );
        assert!(problems.is_empty(), "{problems:#?}");
        compare("s", &oracle, &narrower, &all, &[], &mut problems).unwrap();
        assert_eq!(problems.len(), 1, "{problems:#?}");
        assert!(
            problems[0].starts_with("s: t: the oracle's schema accepts it, Rust's refuses it"),
            "{problems:#?}"
        );
        problems.clear();
        compare("s", &narrower, &oracle, &all, &[], &mut problems).unwrap();
        assert_eq!(problems.len(), 1, "{problems:#?}");
        assert!(
            problems[0].contains("the oracle's schema refuses it")
                && problems[0].ends_with("Rust's accepts it"),
            "{problems:#?}"
        );
    }

    #[test]
    fn a_comparison_where_both_accept_nothing_or_refuse_nothing_is_a_problem() {
        let schema = json!({"type": "object", "required": ["a"]});
        let with_a = instance(json!({"a": 1}));
        let without_a = instance(json!({"b": 1}));
        // Instances of another kind: both schemas refuse every one, and agree.
        let mut problems = Vec::new();
        compare("doc", &schema, &schema, &[&without_a], &[], &mut problems).unwrap();
        assert_eq!(
            problems,
            ["doc: no instance is accepted by both schemas, so the comparison proves nothing"]
        );
        let mut problems = Vec::new();
        compare("doc", &schema, &schema, &[&with_a], &[], &mut problems).unwrap();
        assert_eq!(
            problems,
            ["doc: no instance is refused by both schemas, so the comparison proves nothing"]
        );
        let mut problems = Vec::new();
        compare("doc", &schema, &schema, &[], &[], &mut problems).unwrap();
        assert_eq!(problems.len(), 2, "{problems:#?}");
        let mut problems = Vec::new();
        compare(
            "doc",
            &schema,
            &schema,
            &[&with_a, &without_a],
            &[],
            &mut problems,
        )
        .unwrap();
        assert!(problems.is_empty(), "{problems:#?}");
    }

    #[test]
    fn an_allowance_approves_only_its_own_difference() {
        let oracle = json!({"type": "object", "properties": {"r": {"type": "object"}}});
        let rust = json!({"type": "object", "properties": {"r": {"type": ["object", "null"]}}});
        let base = [instance(json!({})), instance(json!({"r": 1}))];
        let null = Instance {
            label: "object-case:n".to_owned(),
            value: json!({"r": null}),
        };
        let allowance = Allowance {
            label: "object-case:n",
            schema: "rule.1.1.schema.json",
            at: "/r",
            ledger: "x",
        };
        let all = [&base[0], &base[1], &null];
        let mut problems = Vec::new();
        let tally = compare(
            "case: .opentide/schemas/rule.1.1.schema.json",
            &oracle,
            &rust,
            &all,
            &[allowance],
            &mut problems,
        )
        .unwrap();
        assert!(problems.is_empty(), "{problems:#?}");
        assert_eq!(tally.allowed, [allowance]);
        assert!(stale_allowances(&[allowance], &tally.allowed).is_empty());
        // Another document, another place or the other direction is not approved.
        for (name, allowance, oracle, rust) in [
            ("rule.1.0.schema.json", allowance, &oracle, &rust),
            (
                "rule.1.1.schema.json",
                Allowance {
                    at: "/s",
                    ..allowance
                },
                &oracle,
                &rust,
            ),
            ("rule.1.1.schema.json", allowance, &rust, &oracle),
        ] {
            let mut problems = Vec::new();
            let tally = compare(name, oracle, rust, &all, &[allowance], &mut problems).unwrap();
            assert_eq!(problems.len(), 1, "{name}: {problems:#?}");
            assert!(tally.allowed.is_empty());
            assert_eq!(
                stale_allowances(&[allowance], &tally.allowed),
                [
                    "the approved difference `x` (object-case:n on rule.1.1.schema.json) no \
                  longer occurs: remove its allowance"
                ]
            );
        }
    }

    #[test]
    fn the_object_cases_are_instances_and_the_null_references_case_is_among_them() {
        let instances = object_case_instances(&crate::corpus::cli::repo_root()).unwrap();
        assert!(instances.objects.len() > 50, "{}", instances.objects.len());
        let null = instances
            .objects
            .iter()
            .find(|instance| instance.label == ALLOWANCES[0].label)
            .unwrap();
        assert_eq!(null.value["references"], Value::Null);
        let malformed = object_cases("[[case]]\nid = \"a\"\n");
        assert!(malformed.is_err());
    }

    #[test]
    fn a_fault_kind_that_cannot_be_applied_fails_the_comparison() {
        let catalogue = load_catalogue(&corpora_dir().join("faults.toml")).unwrap();
        let base = generate(&catalogue.base.options().unwrap());
        let mut kinds = catalogue.kinds[..2].to_vec();
        assert!(faults_of(&base, &kinds).is_ok());
        // More targets than the base has files: the kind selects too few.
        kinds[1].count = base.files.len() + 1;
        let error = faults_of(&base, &kinds).unwrap_err();
        assert!(
            format!("{error:#}")
                .starts_with(&format!("fault kind `{}`: select its targets", kinds[1].id)),
            "{error:#}"
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
