//! The object models against the oracle (UC-1.3, #809): every case of
//! `tests/oracle/objects_cases.toml` and every object file of
//! `tests/fixtures/tide_corpus` and of the VS Code fixture workspace, read by
//! `node::load` and dispatched by the revision registry
//! ([`crate::revisions::read`]) into the revision `metadata.schema` names. `tests/oracle/objects_table.json` is what the
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
//! `unchecked-platform-blocks` feature until UC-1.4. It reads nothing from
//! the disk (the crate's sources stay I/O-free,
//! `scripts/engine/check-io-free.sh`): `tests/objects_table_files.rs` checks
//! that the table holds every corpus file as it is on disk and that each
//! difference's CHANGELOG.md entry exists.

use std::collections::{BTreeMap, BTreeSet};

use crate::SchemaError;
use crate::node::{self, Document};
use crate::objects::RuleConfigurations;
use crate::revisions::{self, Rejection};
use serde_json::{Value as Json, json};

const TABLE: &str = include_str!("../../tests/oracle/objects_table.json");

/// The registry's verdict (`revisions::read`): the model `metadata.schema`
/// selects, or the loader's.
fn convert(family: &str, document: &Document) -> Json {
    match revisions::read(document, family) {
        Ok(read) => match read.result {
            Ok(object) => {
                let mut value = serde_json::to_value(&object).unwrap();
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
        },
        Err(Rejection::SchemaMissing) => json!({ "loader": "schema_missing" }),
        Err(Rejection::MetadataNotAMapping(error)) => json!({ "errors": [error_json(&error)] }),
        Err(rejection) => json!({ "loader": rejection.to_string() }),
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
    let cases = table["cases"].as_array().unwrap();
    let written = cases
        .iter()
        .filter(|case| !case["id"].as_str().unwrap().starts_with("file:"))
        .count();
    assert_eq!(written, named.len(), "run objects_table.py");
    let mut failures = Vec::new();
    let mut used = BTreeSet::new();
    let mut results = BTreeMap::new();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let text = case["yaml"].as_str().unwrap();
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
