//! The object models' table (UC-1.3, #809): every case of
//! `tests/oracle/objects_cases.toml` and every object file of
//! `tests/fixtures/tide_corpus` and of the VS Code fixture workspace, read by
//! `node::load` and dispatched by the revision registry
//! ([`crate::revisions::read`]) into the revision `metadata.schema` names.
//! `tests/oracle/objects_table.json` holds each case's input and the
//! recorded result of the frozen Python models (`objects_table.py`): each
//! error's type, path, message, input, context, span and `yaml_line`, or the
//! validated value.
//!
//! A case whose result differs from the recorded one names a `[[difference]]`
//! of the cases file (its reason and the bold lead of its CHANGELOG.md
//! entry). [`compare`] lists the cases that differ without naming one, the
//! cases that name one and do not differ, and the entries no case uses; the
//! recorded results drift by design (#1139), so the tests drop that list and
//! assert the reviewed snapshot. The platform blocks (UC-1.4, #810) are
//! compared whole, errors and values; their own cases, `tests/oracle/platform_cases.toml`, are compared
//! by `objects::platform::table` with [`compare`]. Every Rust result is the
//! reviewed snapshot in `src/objects/snapshots/`. It reads nothing from
//! the disk (the crate's sources stay I/O-free,
//! `scripts/engine/check-io-free.sh`): `tests/objects_table_files.rs` checks
//! that the table holds every corpus file as it is on disk and that each
//! difference's CHANGELOG.md entry exists.

use std::collections::{BTreeMap, BTreeSet};

use crate::SchemaError;
use crate::node::{self, Document};
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
                json!({ "value": value })
            }
            Err(errors) => {
                json!({ "errors": errors.iter().map(error_json).collect::<Vec<_>>() })
            }
        },
        Err(Rejection::SchemaMissing) => json!({ "loader": "schema_missing" }),
        Err(Rejection::MetadataNotAMapping(error)) => json!({ "errors": [error_json(&error)] }),
        Err(rejection) => json!({ "loader": rejection.to_string() }),
    }
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
    #[serde(default)]
    difference: Vec<Difference>,
    case: Vec<CaseNote>,
}

/// Compares the table's cases that `select` picks, and the file cases when
/// `files`, with their recorded results, by the notes (`[[case]]` and
/// `[[difference]]`) of a cases file. The mismatches, and every Rust result
/// by case id.
pub(crate) fn compare(
    notes: &str,
    select: fn(&str) -> bool,
    files: bool,
) -> (Vec<String>, BTreeMap<String, Json>) {
    let table: Json = serde_json::from_str(TABLE).unwrap();
    assert_eq!(table["oracle"], "0.28.1");
    let notes: Cases = toml::from_str(notes).unwrap();
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
    let cases: Vec<&Json> = table["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| {
            let id = case["id"].as_str().unwrap();
            if id.starts_with("file:") {
                files
            } else {
                select(id)
            }
        })
        .collect();
    let written = cases
        .iter()
        .filter(|case| !case["id"].as_str().unwrap().starts_with("file:"))
        .count();
    assert_eq!(written, named.len(), "run objects_table.py");
    let mut failures = Vec::new();
    let mut used = BTreeSet::new();
    let mut results = BTreeMap::new();
    for case in &cases {
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
        let listed = named.get(id).copied().unwrap_or_default();
        match (listed.is_empty(), actual == expected) {
            (true, false) => failures.push(format!(
                "{id}: differs from its recorded result without a difference entry\n  recorded: {expected}\n  rust:     {actual}"
            )),
            (false, true) => failures.push(format!(
                "{id}: names {listed:?} but converts as recorded"
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
    (failures, results)
}

#[test]
fn every_case_converts_as_its_reviewed_snapshot() {
    let (failures, results) = compare(
        include_str!("../../tests/oracle/objects_cases.toml"),
        |id| !id.starts_with("platform-"),
        true,
    );
    // The recorded results are not asserted (they drift by design, #1139):
    // the reviewed snapshot below is the contract.
    drop(failures);
    insta::assert_snapshot!(
        "rust_results",
        serde_json::to_string_pretty(&results).unwrap()
    );
}
