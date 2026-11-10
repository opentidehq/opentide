//! The object models against the oracle (UC-1.3, #809): every case of
//! `tests/oracle/objects_cases.toml` and every object file of
//! `tests/fixtures/tide_corpus` and of the VS Code fixture workspace, read by
//! `node::load` and converted by `from_node` into the revision
//! `metadata.schema` names. `tests/oracle/objects_table.json` is what the
//! oracle reports (`objects_table.py`): each error's type, path, message,
//! input, context, span and `yaml_line`, or the validated value.
//!
//! A case that differs from the oracle names a `[[difference]]` of the cases
//! file (its reason and the bold lead of its CHANGELOG.md entry); one that
//! names a difference and does not differ fails, as does an entry no case
//! uses. Errors inside a platform block (`configurations.<platform>…`) are
//! UC-1.4's (#810) and are left out on both sides. Every Rust result is the
//! reviewed snapshot in `src/objects/snapshots/`. A unit test, not an
//! integration test: reading a rule needs `cfg(test)` or the
//! `unchecked-platform-blocks` feature until UC-1.4.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::SchemaError;
use crate::from_node;
use crate::node::{self, Document};
use crate::objects::{ObjectiveV1_0, RuleConfigurations, RuleV1_0, RuleV1_1, ThreatVectorV1_0};
use serde::Serialize;
use serde_json::{Value as Json, json};

const TABLE: &str = include_str!("../../tests/oracle/objects_table.json");

/// The model `metadata.schema` selects for a family, or the loader's verdict.
fn convert(family: &str, document: &Document) -> Json {
    fn value<T: Serialize>(result: Result<T, Vec<SchemaError>>) -> Json {
        match result {
            Ok(model) => {
                let mut value = serde_json::to_value(&model).unwrap();
                let map = value.as_object_mut().unwrap();
                map.remove("file");
                if let Some(Json::Object(blocks)) = map.get_mut("configurations") {
                    for block in blocks.values_mut() {
                        *block = json!({});
                    }
                }
                json!({ "value": value })
            }
            Err(errors) => {
                json!({ "errors": errors.iter().filter(|e| !in_block(&e.field_path())).map(error_json).collect::<Vec<_>>() })
            }
        }
    }
    let schema = document
        .root()
        .and_then(|root| root.get("metadata"))
        .and_then(|metadata| metadata.get("schema"))
        .and_then(|schema| schema.value.as_str().map(str::to_owned));
    match (family, schema.as_deref()) {
        ("rule", Some("rule::1.0")) => value(from_node::from_document::<RuleV1_0>(document)),
        ("rule", Some("rule::1.1")) => value(from_node::from_document::<RuleV1_1>(document)),
        ("threat", Some("threat::1.0")) => {
            value(from_node::from_document::<ThreatVectorV1_0>(document))
        }
        ("objective", Some("objective::1.0")) => {
            value(from_node::from_document::<ObjectiveV1_0>(document))
        }
        (_, other) => json!({ "loader": other }),
    }
}

/// Whether a field path is inside a platform block (UC-1.4).
fn in_block(path: &[String]) -> bool {
    path.len() >= 2
        && path[0] == "configurations"
        && RuleConfigurations::PLATFORMS.contains(&path[1].as_str())
}

fn error_json(error: &SchemaError) -> Json {
    json!({
        "type": error.kind.pydantic_type(),
        "field_path": error.field_path(),
        "msg": error.message,
        "input": error.input,
        "ctx": error.context,
        "span": error.span.as_ref().map(|s| json!([s.line, s.column, s.end_column, s.found])),
        "yaml_line": error.yaml_line,
    })
}

#[derive(Debug, serde::Deserialize)]
struct Difference {
    id: String,
    changelog: String,
}

#[derive(Debug, serde::Deserialize)]
struct CaseNote {
    id: String,
    #[serde(default)]
    difference: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct Cases {
    difference: Vec<Difference>,
    case: Vec<CaseNote>,
}

fn repo() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

#[test]
fn every_case_is_compared_with_the_oracle_and_every_difference_is_explained() {
    let table: Json = serde_json::from_str(TABLE).unwrap();
    assert_eq!(table["oracle"], "0.23.0");
    let notes: Cases =
        toml::from_str(include_str!("../../tests/oracle/objects_cases.toml")).unwrap();
    let differences: BTreeMap<&str, &Difference> = notes
        .difference
        .iter()
        .map(|difference| (difference.id.as_str(), difference))
        .collect();
    let named: BTreeMap<&str, &[String]> = notes
        .case
        .iter()
        .map(|case| (case.id.as_str(), case.difference.as_slice()))
        .collect();
    let changelog = std::fs::read_to_string(repo().join("CHANGELOG.md")).unwrap();
    let cases = table["cases"].as_array().unwrap();
    let written = cases
        .iter()
        .filter(|case| !case["id"].as_str().unwrap().starts_with("file:"))
        .count();
    assert_eq!(written, named.len(), "run objects_table.py");
    let mut failures = Vec::new();
    for difference in differences.values() {
        if !changelog.contains(&difference.changelog) {
            failures.push(format!(
                "difference {}: CHANGELOG.md has no {:?}",
                difference.id, difference.changelog
            ));
        }
    }
    let mut used = BTreeSet::new();
    let mut results = BTreeMap::new();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let text = case["yaml"].as_str().unwrap();
        if let Some(path) = id.strip_prefix("file:") {
            let current = std::fs::read_to_string(repo().join(path))
                .unwrap_or_else(|error| panic!("{path}: {error}; run objects_table.py"));
            assert_eq!(current, text, "{path} changed: run objects_table.py");
        }
        let actual = match node::load(text) {
            Err(_) => json!({ "yaml_error": true }),
            Ok(document) => convert(case["family"].as_str().unwrap(), &document),
        };
        let mut expected = json!({});
        for key in ["value", "errors", "yaml_error", "loader", "crash"] {
            if let Some(value) = case.get(key) {
                expected[key] = value.clone();
            }
        }
        if let Some(Json::Array(errors)) = expected.get_mut("errors") {
            errors.retain(|error| {
                let path: Vec<String> = error["field_path"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|part| part.as_str().unwrap().to_owned())
                    .collect();
                !in_block(&path)
            });
        }
        let listed = named.get(id).copied().unwrap_or_default();
        match (listed.is_empty(), actual == expected) {
            (true, false) => failures.push(format!(
                "{id}: differs from the oracle without a difference entry\n  oracle: {expected}\n  rust:   {actual}"
            )),
            (false, true) => failures.push(format!(
                "{id}: names {listed:?} but converts as the oracle does"
            )),
            _ => {}
        }
        for name in listed {
            if !differences.contains_key(name.as_str()) {
                failures.push(format!("{id}: no difference entry {name}"));
            }
            used.insert(name.as_str());
        }
        results.insert(id.to_owned(), actual);
    }
    for id in differences.keys() {
        if !used.contains(id) {
            failures.push(format!("difference {id}: no case names it"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
    insta::assert_snapshot!(
        "rust_results",
        serde_json::to_string_pretty(&results).unwrap()
    );
}

#[test]
fn every_object_file_of_the_corpora_is_in_the_table() {
    let table: Json = serde_json::from_str(TABLE).unwrap();
    let listed: BTreeSet<String> = table["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|case| {
            case["id"]
                .as_str()?
                .strip_prefix("file:")
                .map(str::to_owned)
        })
        .collect();
    let mut found = BTreeSet::new();
    for source in [
        "tests/fixtures/tide_corpus/current/Objects",
        "tests/golden/fixtures/vscode-workspace/objects",
    ] {
        let mut stack = vec![repo().join(source)];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("a fixture directory") {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "yaml") {
                    let relative = path.strip_prefix(repo()).unwrap();
                    found.insert(relative.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }
    assert_eq!(found, listed, "run objects_table.py");
}
