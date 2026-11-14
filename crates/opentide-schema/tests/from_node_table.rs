//! The structural conversion against the oracle (UC-1.2, #808): every case of
//! `tests/oracle/from_node_cases.toml` converted with the models below, which
//! mirror the Pydantic models of `tests/oracle/from_node_table.py` field for
//! field. `tests/oracle/from_node_table.json` is what the oracle reports: each
//! error's type, path, message, input and context, the span the CLI prints
//! and the `yaml_line` it attaches, or the validated value.
//!
//! A case whose result differs from the oracle's names one of the file's
//! `[[difference]]` entries (its reason and the bold lead of its CHANGELOG.md
//! entry); a case that names one and does not differ fails, as does an entry
//! no case uses. Every Rust result, the same or not, is the reviewed snapshot
//! `tests/snapshots/from_node_table__rust_results.snap`.

#![expect(
    clippy::unwrap_used,
    reason = "helpers of the tests: a fixture that does not parse fails them"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use opentide_schema::from_node::{self, Context};
use opentide_schema::node::{self, Node};
use opentide_schema::sample::SampleV1_1;
use opentide_schema::{ErrorKind, FromNode, SchemaError};
use serde::Serialize;
use serde_json::{Value as Json, json};

const TABLE: &str = include_str!("oracle/from_node_table.json");

#[expect(
    clippy::ref_option,
    reason = "serde's serialize_with passes the field by reference"
)]
fn ratio_json<S: serde::Serializer>(value: &Option<f64>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(float) if float.is_nan() => serializer.serialize_str("nan"),
        Some(float) if float.is_infinite() => {
            serializer.serialize_str(if *float > 0.0 { "inf" } else { "-inf" })
        }
        other => other.serialize(serializer),
    }
}

#[derive(Debug, Serialize, FromNode)]
#[serde(deny_unknown_fields)]
struct Inner {
    label: String,
    #[serde(default)]
    count: Option<i64>,
}

#[derive(Debug, Clone, Copy, Serialize, FromNode)]
#[serde(rename_all = "lowercase")]
#[from_node(literal)]
enum Choice {
    One,
    Two,
}

#[derive(Debug, Clone, Copy, Serialize, FromNode)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Alpha,
    Beta,
    Gamma,
}

#[derive(Debug, Serialize, FromNode)]
#[serde(untagged)]
#[from_node(union)]
enum Either {
    #[from_node(tag = "str")]
    Str(String),
    #[from_node(tag = "int")]
    Int(i64),
}

#[derive(Debug, Serialize, FromNode)]
#[serde(untagged)]
#[from_node(union)]
enum StrOrList {
    #[from_node(tag = "str")]
    Str(String),
    #[from_node(tag = "list[str]")]
    List(Vec<String>),
}

const fn yes() -> bool {
    true
}

#[derive(Debug, Serialize, FromNode)]
#[serde(deny_unknown_fields)]
struct Probe {
    text: String,
    #[serde(default)]
    number: i64,
    #[serde(default, serialize_with = "ratio_json")]
    ratio: Option<f64>,
    #[serde(default = "yes")]
    flag: bool,
    #[serde(default)]
    items: Option<Vec<String>>,
    #[serde(default)]
    inners: Option<Vec<Inner>>,
    #[serde(default)]
    inner: Option<Inner>,
    #[serde(default)]
    mapping: Option<BTreeMap<String, i64>>,
    #[serde(default)]
    choice: Option<Choice>,
    #[serde(default)]
    kind: Option<Kind>,
    #[serde(default)]
    either: Option<Either>,
    #[serde(default)]
    some: Option<StrOrList>,
    #[serde(default, rename = "schema", alias = "schema_id")]
    schema_id: Option<String>,
    #[serde(default)]
    #[from_node(before = "from_node::require_vocab_list")]
    vocab: Option<Vec<String>>,
}

fn no_legacy(node: &Node, cx: &mut Context) -> bool {
    if node.get("legacy").is_some() {
        cx.error_with(
            ErrorKind::InvalidValue("value_error"),
            "Value error, legacy is not supported",
            node,
            &[("error", "legacy is not supported".to_owned())],
        );
        return false;
    }
    true
}

#[derive(Debug, Serialize, FromNode)]
#[serde(deny_unknown_fields)]
#[from_node(before = "no_legacy")]
struct Guarded {
    name: String,
    #[serde(default)]
    other: Option<String>,
}

fn convert(model: &str, document: &node::Document) -> Result<Json, Vec<SchemaError>> {
    fn json_of<T: Serialize>(value: &T) -> Json {
        serde_json::to_value(value).unwrap()
    }
    match model {
        "Probe" => from_node::from_document::<Probe>(document).map(|v| json_of(&v)),
        "Guarded" => from_node::from_document::<Guarded>(document).map(|v| json_of(&v)),
        "SampleV1_1" => from_node::from_document::<SampleV1_1>(document).map(|value| {
            // Pydantic's model_dump writes `None`; serde skips it.
            let mut json = json_of(&value);
            let map = json.as_object_mut().unwrap();
            map.entry("effort").or_insert(Json::Null);
            if let Some(Json::Array(examples)) = map.get_mut("examples") {
                for example in examples {
                    example
                        .as_object_mut()
                        .unwrap()
                        .entry("language")
                        .or_insert(Json::Null);
                }
            }
            map.entry("examples").or_insert(Json::Null);
            // Back into Pydantic's field order.
            let order = [
                "name",
                "uuid",
                "schema",
                "description",
                "severity",
                "effort",
                "enabled",
                "examples",
                "tags",
            ];
            Json::Object(
                order
                    .iter()
                    .map(|k| ((*k).to_owned(), map[*k].clone()))
                    .collect(),
            )
        }),
        other => panic!("no model {other}"),
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
    #[serde(default)]
    difference: Vec<Difference>,
    case: Vec<CaseNote>,
}

#[test]
#[ignore = "byte-level replay against the Python oracle: run by hand with --run-ignored only"]
fn every_case_is_compared_with_the_oracle_and_every_difference_is_explained() {
    let table: Json = serde_json::from_str(TABLE).unwrap();
    assert_eq!(table["oracle"], "0.28.1");
    let notes: Cases = toml::from_str(include_str!("oracle/from_node_cases.toml")).unwrap();
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
    let changelog =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../CHANGELOG.md"))
            .unwrap();
    let cases = table["cases"].as_array().unwrap();
    assert!(cases.len() >= 90, "{} cases", cases.len());
    assert_eq!(cases.len(), named.len(), "run from_node_table.py");
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
        let actual = match node::load(case["yaml"].as_str().unwrap()) {
            Err(error) => json!({ "load_error": error.problem }),
            Ok(document) => match convert(case["model"].as_str().unwrap(), &document) {
                Ok(value) => json!({ "value": value }),
                Err(errors) => {
                    json!({ "errors": errors.iter().map(error_json).collect::<Vec<_>>() })
                }
            },
        };
        let mut expected = json!({});
        for key in ["value", "errors"] {
            if let Some(value) = case.get(key) {
                expected[key] = value.clone();
            }
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
fn a_conversion_reports_every_error_not_the_first() {
    let document = node::load("name: [n]\nschema: 1\nseverity: ~\nextra: 1\n").unwrap();
    let errors = from_node::from_document::<SampleV1_1>(document_ref(&document)).unwrap_err();
    let kinds: Vec<_> = errors
        .iter()
        .map(|e| (e.code(opentide_schema::Surface::Object), e.field_path()))
        .collect();
    assert_eq!(errors.len(), 6, "{kinds:?}");
    assert!(
        errors
            .iter()
            .all(|e| e.code(opentide_schema::Surface::Object) == "schema_validation")
    );
}

fn document_ref(document: &node::Document) -> &node::Document {
    document
}
