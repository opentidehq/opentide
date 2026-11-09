//! The YAML resolution table (UC-1.2, #808): every case of
//! `tests/oracle/yaml_cases.toml`, read by `opentide_schema::node` (saphyr,
//! YAML 1.2) and by the oracle (`tests/oracle/yaml_table.json`, written by
//! `tests/oracle/yaml_table.py` with the oracle's interpreter: PyYAML's YAML
//! 1.1 loader).
//!
//! The two are compared case by case. A case where they differ must name one
//! of the file's `[[difference]]` entries, each with its reason and the bold
//! lead of its CHANGELOG.md entry; a case that names one and does not differ
//! fails, as does an entry no case uses. The whole comparison is written to
//! `crates/opentide-schema/YAML.md`, which this test keeps current:
//! `UPDATE_YAML_TABLE=1 cargo test -p opentide-schema --test yaml_table`
//! rewrites it after an intended change.

#![expect(
    clippy::unwrap_used,
    reason = "helpers of the tests: a fixture that does not parse fails them"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use opentide_schema::node::{self, LoadErrorKind, Node, Value};
use serde_json::{Value as Json, json};

const TABLE: &str = include_str!("oracle/yaml_table.json");
const CASES: &str = include_str!("oracle/yaml_cases.toml");

/// The tagged tree `yaml_table.py` writes, from a Rust node.
fn tagged(node: &Node) -> Json {
    match &node.value {
        Value::Null => json!({ "null": null }),
        Value::Bool(flag) => json!({ "bool": flag }),
        Value::Int(integer) => json!({ "int": integer.to_string() }),
        Value::Float(float) => json!({ "float": float_text(*float) }),
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

/// What the Rust loader reads, in the oracle table's shape.
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

/// Two tagged values are the same data: floats compare as numbers (the
/// oracle writes Python's `repr`), everything else exactly.
fn same_value(a: &Json, b: &Json) -> bool {
    match (a, b) {
        (Json::Object(a), Json::Object(b)) => {
            if let (Some(Json::String(x)), Some(Json::String(y))) = (a.get("float"), b.get("float"))
            {
                let parse = |text: &str| -> f64 { text.parse().unwrap() };
                let (x, y) = (parse(x), parse(y));
                return x.to_bits() == y.to_bits() || (x.is_nan() && y.is_nan());
            }
            a.len() == b.len()
                && a.iter()
                    .all(|(key, value)| b.get(key).is_some_and(|other| same_value(value, other)))
        }
        (Json::Array(a), Json::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same_value(x, y))
        }
        _ => a == b,
    }
}

/// The oracle and Rust agree: the same value, or both refuse the document.
fn agree(oracle: &Json, rust: &Json) -> bool {
    match (oracle.get("value"), rust.get("value")) {
        (Some(a), Some(b)) => same_value(a, b),
        (None, None) => oracle.get("error").is_some() && rust.get("error").is_some(),
        _ => false,
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
    if let Some(repr) = result.get("unsupported") {
        return format!("read as Python's {}", repr.as_str().unwrap());
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

fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

#[derive(Debug, serde::Deserialize)]
struct Difference {
    id: String,
    reason: String,
    changelog: String,
    /// Whether a workspace file that the oracle accepts can now be refused,
    /// or read with another value (a question for the maintainers).
    workspace: bool,
}

#[derive(Debug, serde::Deserialize)]
struct Case {
    id: String,
    group: String,
    yaml: Option<String>,
    bytes_hex: Option<String>,
    difference: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct Cases {
    #[serde(default)]
    difference: Vec<Difference>,
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
fn every_case_is_compared_with_the_oracle_and_every_difference_is_explained() {
    let table: Json = serde_json::from_str(TABLE).unwrap();
    assert_eq!(table["oracle"], "0.23.0");
    let oracle: BTreeMap<&str, &Json> = table["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| (case["id"].as_str().unwrap(), case))
        .collect();
    let cases: Cases = toml::from_str(CASES).unwrap();
    let differences: BTreeMap<&str, &Difference> = cases
        .difference
        .iter()
        .map(|difference| (difference.id.as_str(), difference))
        .collect();
    let changelog =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../CHANGELOG.md"))
            .unwrap();
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
    let mut groups: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut order: Vec<&str> = Vec::new();
    for case in &cases.case {
        let Some(expected) = oracle.get(case.id.as_str()) else {
            failures.push(format!(
                "{}: not in yaml_table.json (run yaml_table.py)",
                case.id
            ));
            continue;
        };
        let rust = rust_result(&bytes(case));
        let agreed = agree(expected, &rust);
        match (&case.difference, agreed) {
            (None, false) => failures.push(format!(
                "{}: differs from the oracle without a difference entry\n  oracle: {}\n  rust:   {}",
                case.id,
                show_result(expected),
                show_result(&rust)
            )),
            (Some(id), true) => failures.push(format!(
                "{}: names difference {id} but reads as the oracle does",
                case.id
            )),
            (Some(id), false) if !differences.contains_key(id.as_str()) => {
                failures.push(format!("{}: no difference entry {id}", case.id));
            }
            _ => {}
        }
        if let Some(id) = &case.difference {
            used.insert(id.as_str());
        }
        if !groups.contains_key(case.group.as_str()) {
            order.push(case.group.as_str());
        }
        let source = case.yaml.as_deref().map_or_else(
            || format!("bytes `{}`", case.bytes_hex.as_deref().unwrap()),
            |yaml| format!("`{}`", serde_json::to_string(yaml).unwrap()),
        );
        groups.entry(case.group.as_str()).or_default().push(format!(
            "| {} | {} | {} | {} | {} |",
            case.id,
            cell(&source),
            cell(&show_result(expected)),
            cell(&show_result(&rust)),
            case.difference
                .as_deref()
                .map_or_else(|| "same".to_owned(), |id| format!("[{id}](#{id})")),
        ));
    }
    for id in differences.keys() {
        if !used.contains(id) {
            failures.push(format!("difference {id}: no case names it"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    let mut doc = String::new();
    doc.push_str(
        "# YAML: opentide-schema against the oracle\n\n\
         <!-- Generated by crates/opentide-schema/tests/yaml_table.rs from \
         tests/oracle/yaml_cases.toml and tests/oracle/yaml_table.json. Do not edit: \
         UPDATE_YAML_TABLE=1 cargo test -p opentide-schema --test yaml_table -->\n\n\
         opentide-schema reads an object file as **YAML 1.2** (the core schema) with saphyr \
         (`src/node.rs`). The oracle, opentide 0.23.0, reads it with PyYAML's YAML 1.1 loader. \
         Each row is one document: what the oracle reads (Python's value, or why it refuses \
         the file), what opentide-schema reads, and, where they differ, why. Strings are \
         quoted, floats end in `f`.\n\n## Differences\n\n",
    );
    for difference in differences.values() {
        let _ = write!(
            doc,
            "### {}\n\n{}\n\nChangelog: {}. Changes how an existing workspace file reads: {}.\n\n",
            difference.id,
            difference.reason,
            difference.changelog,
            if difference.workspace {
                "**yes** (a question for the maintainers in the PR)"
            } else {
                "no"
            }
        );
    }
    doc.push_str("## Cases\n");
    for group in order {
        let _ = write!(
            doc,
            "\n### {group}\n\n| Case | YAML | Oracle (PyYAML, YAML 1.1) | opentide-schema (saphyr, YAML 1.2) | |\n|---|---|---|---|---|\n"
        );
        for row in &groups[group] {
            doc.push_str(row);
            doc.push('\n');
        }
    }
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("YAML.md");
    if std::env::var_os("UPDATE_YAML_TABLE").is_some() {
        std::fs::write(&path, &doc).unwrap();
    } else {
        // A Windows checkout may have turned the file's line feeds into CRLF.
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        assert!(
            committed == doc,
            "{} is not current: UPDATE_YAML_TABLE=1 cargo test -p opentide-schema --test yaml_table",
            path.display()
        );
    }
}
