//! The object models on a table of cases (UC-1.3, #809):
//! `tests/tables/objects.json`, each a Tide object file and its family, the
//! platform blocks' cases (`platform-*`, UC-1.4, #810) and every object file
//! of `tests/fixtures/tide_corpus` and of the VS Code fixture workspace as
//! they were when the table was written (`file:*`), read by `node::load` and
//! dispatched by the revision registry ([`crate::revisions::read`]) into the
//! revision `metadata.schema` names. Each result (every error's type, path,
//! message, input, context, span and `yaml_line`, or the validated value) is
//! held to the reviewed snapshot in `src/objects/snapshots/`; the platform
//! cases' in `src/objects/platform/snapshots/`. The cases were first written
//! to hold the models to the Python CLI's (opentide 0.28.1). It reads nothing
//! from the disk (the crate's sources stay I/O-free,
//! `scripts/engine/check-io-free.sh`).

use std::collections::BTreeMap;

use crate::SchemaError;
use crate::node::{self, Document};
use crate::revisions::{self, Rejection};
use serde_json::{Value as Json, json};

const TABLE: &str = include_str!("../../tests/tables/objects.json");

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

/// Every Rust result, by case id, of the table's cases that `select` picks
/// (`file:` cases count as their family's).
pub(crate) fn results(select: fn(&str) -> bool) -> BTreeMap<String, Json> {
    let table: Json = serde_json::from_str(TABLE).unwrap();
    let mut results = BTreeMap::new();
    for case in table["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        if !select(id) {
            continue;
        }
        let actual = match node::load(case["yaml"].as_str().unwrap()) {
            Err(_) => json!({ "yaml_error": true }),
            Ok(document) => convert(case["family"].as_str().unwrap(), &document),
        };
        results.insert(id.to_owned(), actual);
    }
    results
}

#[test]
fn every_case_converts_as_its_snapshot_says() {
    let results = results(|id| !id.starts_with("platform-"));
    assert!(results.len() > 100, "{} cases", results.len());
    insta::assert_snapshot!(
        "rust_results",
        serde_json::to_string_pretty(&results).unwrap()
    );
}
