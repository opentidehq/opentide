//! The YAML resolution table (UC-1.2, #808): every case of
//! `tests/tables/yaml.toml`, read by `opentide_schema::node` (saphyr, YAML
//! 1.2), what it reads (the value, or why it refuses the document) held to
//! the reviewed snapshot `tests/snapshots/yaml_table__rust_results.snap`.
//! `crates/opentide-schema/YAML.md` is the table the cases were written
//! for: each read beside the Python CLI's (PyYAML, YAML 1.1), with the reason
//! for every difference, frozen when the CLI became Rust's.

#![expect(
    clippy::unwrap_used,
    reason = "helpers of the tests: a fixture that does not parse fails them"
)]

use std::fmt::Write as _;

use opentide_schema::node::{self, LoadErrorKind, Node, Value};
use serde_json::{Value as Json, json};

const CASES: &str = include_str!("tables/yaml.toml");

/// A node as a tagged tree: each value under its kind.
fn tagged(node: &Node) -> Json {
    match &node.value {
        Value::Null => json!({ "null": null }),
        Value::Bool(flag) => json!({ "bool": flag }),
        Value::Int(integer) => json!({ "int": integer.to_string() }),
        Value::Float(float) => json!({ "float": float_text(*float) }),
        Value::Str(text) => json!({ "str": text }),
        Value::Datetime(text) => json!({ "datetime": text }),
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

fn float_text(float: f64) -> String {
    if float.is_nan() {
        "nan".to_owned()
    } else if float.is_infinite() {
        if float > 0.0 { "inf" } else { "-inf" }.to_owned()
    } else {
        format!("{float:?}")
    }
}

fn kind_name(kind: LoadErrorKind) -> &'static str {
    match kind {
        LoadErrorKind::NotUtf8 => "not_utf8",
        LoadErrorKind::Syntax => "syntax",
        LoadErrorKind::DuplicateKey => "duplicate_key",
        LoadErrorKind::ComplexKey => "complex_key",
        LoadErrorKind::Tag => "tag",
        LoadErrorKind::RecursiveAlias => "recursive_alias",
        LoadErrorKind::MultipleDocuments => "multiple_documents",
        LoadErrorKind::TooDeep => "too_deep",
        LoadErrorKind::OutOfRange => "out_of_range",
    }
}

/// What the Rust loader reads: a tagged value, or the refusal.
fn rust_result(bytes: &[u8]) -> Json {
    match node::load_bytes(bytes) {
        Ok(document) => match document.root() {
            Some(root) => json!({ "value": tagged(root) }),
            None => json!({ "value": { "null": null } }),
        },
        Err(error) => {
            let at = error
                .mark
                .map(|m| format!(" (line {}, column {})", m.line, m.column))
                .unwrap_or_default();
            json!({ "error": kind_name(error.kind), "detail": format!("{}{at}", error.problem) })
        }
    }
}

/// A value as a short flow-style line for the table.
fn show(value: &Json) -> String {
    let object = value.as_object().unwrap();
    let (tag, inner) = object.iter().next().unwrap();
    match tag.as_str() {
        "null" => "null".to_owned(),
        "bool" | "int" => inner
            .as_str()
            .map_or_else(|| inner.to_string(), str::to_owned),
        "float" => inner.as_str().unwrap().to_owned() + "f",
        "str" => serde_json::to_string(inner.as_str().unwrap()).unwrap(),
        "seq" => format!(
            "[{}]",
            inner
                .as_array()
                .unwrap()
                .iter()
                .map(show)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        "map" => format!(
            "{{{}}}",
            inner
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| format!("{}: {}", show(&pair[0]), show(&pair[1])))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => panic!("unknown tag {other}"),
    }
}

fn show_result(result: &Json) -> String {
    if let Some(value) = result.get("value") {
        return show(value);
    }
    let detail = result
        .get("detail")
        .and_then(Json::as_str)
        .filter(|d| !d.is_empty());
    match detail {
        Some(detail) => format!("refused: {detail}"),
        None => format!("refused ({})", result["error"].as_str().unwrap()),
    }
}

#[derive(Debug, serde::Deserialize)]
struct Case {
    id: String,
    group: String,
    yaml: Option<String>,
    bytes_hex: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct Cases {
    case: Vec<Case>,
}

fn bytes(case: &Case) -> Vec<u8> {
    if let Some(hex) = &case.bytes_hex {
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect()
    } else {
        case.yaml.clone().unwrap().into_bytes()
    }
}

#[test]
fn every_case_reads_as_its_snapshot_says() {
    let cases: Cases = toml::from_str(CASES).unwrap();
    assert!(cases.case.len() > 100, "{} cases", cases.case.len());
    let mut shown = String::new();
    let mut group = "";
    for case in &cases.case {
        if case.group != group {
            group = &case.group;
            let _ = writeln!(shown, "\n## {group}\n");
        }
        let _ = writeln!(
            shown,
            "{}: {}",
            case.id,
            show_result(&rust_result(&bytes(case)))
        );
    }
    insta::assert_snapshot!("rust_results", shown);
}
