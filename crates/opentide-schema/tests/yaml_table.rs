//! The YAML 1.1 resolution table (UC-1.2, #808): every case of
//! `tests/oracle/yaml_cases.toml`, read by the Rust loader, against what the
//! oracle's loader read (`tests/oracle/yaml_table.json`, written by
//! `tests/oracle/yaml_table.py` with the oracle's interpreter).

#![expect(
    clippy::unwrap_used,
    reason = "a helper of the tests: a fixture that does not parse fails them"
)]

use opentide_schema::node::{self, LoadErrorKind, Node, Value, python_float_repr};
use serde_json::{Value as Json, json};

const TABLE: &str = include_str!("oracle/yaml_table.json");

/// The tagged tree `yaml_table.py` writes, from a Rust node.
fn tagged(node: &Node) -> Json {
    match &node.value {
        Value::Null => json!({ "null": null }),
        Value::Bool(flag) => json!({ "bool": flag }),
        Value::Int(integer) => json!({ "int": integer.to_string() }),
        Value::Float(float) => json!({ "float": python_float_repr(*float) }),
        Value::Str(text) => json!({ "str": text }),
        Value::Seq(items) => {
            json!({ "seq": items.iter().map(|item| tagged(item)).collect::<Vec<_>>() })
        }
        Value::Map(entries) => json!({
            "map": entries
                .iter()
                .map(|entry| json!([tagged(&entry.key), tagged(&entry.value)]))
                .collect::<Vec<_>>()
        }),
    }
}

fn bytes_of(case_id: &str) -> Vec<u8> {
    let cases: toml::Value = toml::from_str(include_str!("oracle/yaml_cases.toml")).unwrap();
    let case = cases["case"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"].as_str() == Some(case_id))
        .unwrap_or_else(|| panic!("{case_id} is not in yaml_cases.toml"));
    if let Some(hex) = case.get("bytes_hex").and_then(toml::Value::as_str) {
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect()
    } else {
        case["yaml"].as_str().unwrap().as_bytes().to_vec()
    }
}

#[test]
fn every_case_reads_as_the_oracle_reads_it() {
    let table: Json = serde_json::from_str(TABLE).unwrap();
    assert_eq!(table["oracle"], "0.23.0");
    assert_eq!(
        table["loader"], "CSafeLoader",
        "the oracle reads with libyaml"
    );
    let cases = table["cases"].as_array().unwrap();
    assert!(cases.len() > 100, "{} cases", cases.len());
    let mut failures = Vec::new();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let read = node::load_bytes(&bytes_of(id));
        let expected = if let Some(value) = case.get("value") {
            Ok(value.clone())
        } else if case.get("unsupported").is_some() {
            Err(LoadErrorKind::Unsupported)
        } else {
            Err(match case["error"].as_str().unwrap() {
                "yaml" => LoadErrorKind::Yaml,
                "python" => LoadErrorKind::Python,
                "not_utf8" => LoadErrorKind::NotUtf8,
                other => panic!("{id}: unknown error kind {other}"),
            })
        };
        let actual = match &read {
            Ok(document) => Ok(document
                .root()
                .map_or_else(|| json!({ "null": null }), |root| tagged(root))),
            Err(error) => Err(error.kind),
        };
        if actual != expected {
            failures.push(format!(
                "{id}:\n  oracle: {expected:?}\n  rust:   {actual:?}\n  ({:?})",
                read.as_ref().err()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The four tags PyYAML constructs into bytes, tuples and sets: the oracle
/// reads them, the Rust tree refuses them. No Tide field takes such a value
/// (Pydantic would reject a set or a tuple where the models want a string, a
/// list or a mapping, except `!!binary` into a `str` field).
#[test]
fn unsupported_tags_are_the_known_difference() {
    let table: Json = serde_json::from_str(TABLE).unwrap();
    let unsupported: Vec<&str> = table["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case.get("unsupported").is_some())
        .map(|case| case["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        unsupported,
        ["tag-binary", "tag-set", "tag-omap", "tag-pairs"]
    );
}

#[test]
fn every_group_of_the_issue_has_cases() {
    let table: Json = serde_json::from_str(TABLE).unwrap();
    let groups: std::collections::BTreeSet<&str> = table["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["group"].as_str().unwrap())
        .collect();
    for group in [
        "bool",
        "null",
        "timestamp",
        "int",
        "underscore",
        "sexagesimal",
        "float",
        "duplicate",
        "alias",
        "merge",
        "documents",
        "bom",
        "tabs",
        "crlf",
    ] {
        assert!(groups.contains(group), "no case for {group}");
    }
}
