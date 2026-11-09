//! The structural conversion against Pydantic and the CLI (UC-1.2, #808):
//! every case of `tests/oracle/from_node_cases.toml` converted with the models
//! below, which mirror the Pydantic models of `tests/oracle/from_node_table.py`
//! field for field. The expectations (`tests/oracle/from_node_table.json`)
//! are what the oracle reports: each error's type, path, message, input and
//! context, the span the CLI prints and the `yaml_line` it attaches, or the
//! validated value.

#![expect(
    clippy::unwrap_used,
    reason = "helpers of the tests: a fixture that does not parse fails them"
)]

use std::collections::BTreeMap;

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
        Some(float) if !float.is_finite() => {
            serializer.serialize_str(&node::python_float_repr(*float))
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

/// Where the Rust result differs from the oracle's on purpose, each with why.
fn known_difference(id: &str, expected: &Json) -> Option<Json> {
    match id {
        // Pydantic's int has no bound; an `i64` field has one. No Tide integer
        // field comes near it (effort, version, risk scores).
        "int-beyond-i64" => Some(json!({"errors": [{
            "type": "int_parsing_size",
            "field_path": ["number"],
            "msg": "Unable to parse input string as an integer, exceeded maximum size",
            "input": null,
            "ctx": {},
            "span": [2, 9, 39, true],
            "yaml_line": 1,
        }]})),
        _ => {
            // `_find_line` crashes (KeyError) on a key a merge brought in: the
            // oracle's `validate` dies there. The Rust conversion reports no line.
            let errors = expected.get("errors")?.as_array()?;
            if errors.iter().any(|e| e["yaml_line"].get("crash").is_some()) {
                let fixed: Vec<Json> = errors
                    .iter()
                    .map(|e| {
                        let mut e = e.clone();
                        if e["yaml_line"].get("crash").is_some() {
                            e["yaml_line"] = Json::Null;
                        }
                        e
                    })
                    .collect();
                return Some(json!({ "errors": fixed }));
            }
            None
        }
    }
}

#[test]
fn every_case_converts_as_the_oracle_validates_it() {
    let table: Json = serde_json::from_str(TABLE).unwrap();
    assert_eq!(table["oracle"], "0.23.0");
    let cases = table["cases"].as_array().unwrap();
    assert!(cases.len() >= 90, "{} cases", cases.len());
    let mut failures = Vec::new();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let document = node::load(case["yaml"].as_str().unwrap()).unwrap();
        let actual = match convert(case["model"].as_str().unwrap(), &document) {
            Ok(value) => json!({ "value": value }),
            Err(errors) => json!({ "errors": errors.iter().map(error_json).collect::<Vec<_>>() }),
        };
        let mut expected = json!({});
        for key in ["value", "errors"] {
            if let Some(value) = case.get(key) {
                expected[key] = value.clone();
            }
        }
        let expected = known_difference(id, &expected).unwrap_or(expected);
        if actual != expected {
            failures.push(format!("{id}:\n  oracle: {expected}\n  rust:   {actual}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
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
