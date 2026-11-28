//! The conversion's API beyond the oracle tables: garde after a successful
//! conversion ([`from_node::validate`]), the work budget on a document of
//! nested aliases, open and tolerant models, and the field types no table
//! model uses.

#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a panic is how the test fails"
)]

use opentide_schema::FromNode;
use opentide_schema::from_node::{self, Context, Invalid};
use opentide_schema::node::{self, Entry, Mark, Node, Value};
use opentide_schema::sample::SampleV1_1;
use opentide_schema::{ErrorKind, Pins, SchemaError};
use std::sync::Arc;

const VALID: &str = "name: n\nuuid: u\nschema: sample::1.1\ndescription: d\nseverity: Low\n";

#[test]
fn validate_runs_garde_after_a_conversion_that_succeeds() {
    let pins = Pins::new([("alert_severity", "1.0")]);
    let document = node::load(VALID).unwrap();
    let sample: SampleV1_1 = from_node::validate(&document, &pins).unwrap();
    assert_eq!(sample.severity, "Low");

    let document = node::load(&format!("{VALID}effort: 11\n")).unwrap();
    match from_node::validate::<SampleV1_1>(&document, &pins) {
        Err(Invalid::Constraints(report)) => {
            assert_eq!(report.iter().count(), 1, "{report:?}");
        }
        other => panic!("{other:?}"),
    }

    let document = node::load("name: [n]\n").unwrap();
    match from_node::validate::<SampleV1_1>(&document, &pins) {
        Err(Invalid::Structure(errors)) => assert_eq!(errors.len(), 5, "{errors:#?}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_empty_document_is_null_to_the_model() {
    let document = node::load("# only a comment\n").unwrap();
    assert!(document.root().is_none());
    let errors = from_node::from_document::<SampleV1_1>(&document).unwrap_err();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ErrorKind::InvalidType("model_type"));
    assert_eq!(
        errors[0].message,
        "Input should be a valid dictionary or instance of SampleV1_1"
    );
}

#[test]
fn a_tree_of_aliases_stops_at_the_budget() {
    // Eight aliases of a mapping of 13,000 unknown keys: about 104,000
    // errors, past the budget. The text writes about 26,000 nodes, so the
    // loader admits the expansion (ten times what is written, #1927) and the
    // conversion's own budget is what stops it.
    let mut text = String::from("base: &m {");
    for key in 0..13_000 {
        text.push_str(&format!("k{key}: 1, "));
    }
    text.push_str("}\nexamples: [");
    text.push_str(&"*m, ".repeat(8));
    text.push_str("]\n");
    let document = node::load(&text).unwrap();
    let errors = from_node::from_document::<SampleV1_1>(&document).unwrap_err();
    let limits = errors
        .iter()
        .filter(|error| error.kind == ErrorKind::Limit)
        .count();
    assert_eq!(limits, 1);
    assert!(errors.len() <= from_node::BUDGET + 1, "{}", errors.len());
    assert_eq!(errors.last().unwrap().kind, ErrorKind::Limit);
}

#[test]
fn boxes_maps_and_unchecked_nodes() {
    let document = node::load("a: [1, 2]\n").unwrap();
    let root = document.root().unwrap();
    let mut cx = Context::new();
    let boxed = <Box<std::collections::BTreeMap<String, Vec<i64>>>>::from_node(root, &mut cx);
    assert_eq!(boxed.unwrap()["a"], [1, 2]);
    let any = <Arc<Node>>::from_node(root, &mut cx).unwrap();
    assert!(any.get("a").is_some());
    assert_eq!(cx.error_count(), 0);
    assert!(cx.path().is_empty());
}

#[test]
fn a_document_writes_back_as_yaml() {
    let document = node::load(VALID).unwrap();
    let sample: SampleV1_1 = from_node::from_document(&document).unwrap();
    let written = node::to_yaml(&sample).unwrap();
    assert_eq!(
        written,
        "name: \"n\"\nuuid: u\nschema: sample::1.1\ndescription: d\nseverity: Low\nenabled: true\ntags: []\n"
    );
}

/// One level of a tree: a closed model whose `next` holds more levels.
#[derive(Debug, FromNode)]
#[serde(deny_unknown_fields)]
struct Level {
    #[serde(default)]
    #[expect(dead_code, reason = "read only by the conversion")]
    next: Vec<Level>,
}

/// A union whose first member walks a tree.
#[derive(Debug, FromNode)]
#[from_node(union)]
enum TreeOrInt {
    Tree(#[expect(dead_code, reason = "read only by the conversion")] Level),
    Int(#[expect(dead_code, reason = "read only by the conversion")] i64),
}

/// A tree of `levels` nested levels, each level's `next` holding the one
/// below `fan_out` times, shared as an alias shares it: `fan_out ^ levels`
/// valid nodes from `levels` written ones. Built directly, as no YAML text
/// past the loader's alias budget (#1927) reaches the conversion: the
/// conversion's budget still guards a tree from any other source (TOML, an
/// SDK caller). Returns each level, the top one last.
fn alias_tree(levels: usize, fan_out: usize) -> Vec<Arc<Node>> {
    let mut tree: Vec<Arc<Node>> = Vec::with_capacity(levels);
    for level in 0..levels {
        let below = match level.checked_sub(1) {
            Some(previous) => vec![Arc::clone(&tree[previous]); fan_out],
            None => Vec::new(),
        };
        tree.push(built(Value::Map(vec![Entry {
            key: built(Value::Str("next".into())),
            value: built(Value::Seq(below)),
        }])));
    }
    tree
}

/// A node no text wrote.
fn built(value: Value) -> Arc<Node> {
    let mark = Mark::new(0, 1, 1);
    Arc::new(Node {
        value,
        start: mark,
        end: mark,
        text: None,
    })
}

fn limits(errors: &[SchemaError]) -> usize {
    errors
        .iter()
        .filter(|error| error.kind == ErrorKind::Limit)
        .count()
}

fn convert<T: FromNode>(text: &str, key: &str) -> (Option<T>, Vec<SchemaError>) {
    let document = node::load(text).unwrap();
    convert_node(document.root().unwrap().get(key).unwrap())
}

fn convert_node<T: FromNode>(node: &Node) -> (Option<T>, Vec<SchemaError>) {
    let mut cx = Context::new();
    let value = T::from_node(node, &mut cx);
    (value, cx.into_errors())
}

#[test]
fn a_tree_of_valid_aliases_stops_at_the_budget() {
    // 10^6 valid nodes from seven written ones: no error but the limit.
    let tree = alias_tree(7, 10);
    let (value, errors) = convert_node::<Level>(tree.last().unwrap());
    assert!(value.is_none());
    assert_eq!(errors.len(), 1, "{errors:#?}");
    assert_eq!(limits(&errors), 1);
    // A smaller tree of the same shape is converted.
    let (value, errors) = convert_node::<Level>(alias_tree(3, 10).last().unwrap());
    assert!(value.is_some(), "{errors:#?}");
    assert!(errors.is_empty());
}

#[test]
fn a_union_member_spends_the_callers_budget() {
    // Each item is a tree of 10^4 levels that the union's first member
    // converts; 20 of them cost twice the budget, which a trial that did not
    // pass its spending back to its caller would never reach.
    let tree = alias_tree(5, 10);
    let top = tree.last().unwrap();
    let (one, errors) = convert_node::<TreeOrInt>(top);
    assert!(matches!(one, Some(TreeOrInt::Tree(_))), "{errors:#?}");
    let items = built(Value::Seq(vec![Arc::clone(top); 20]));
    let (value, errors) = convert_node::<Vec<TreeOrInt>>(&items);
    assert!(value.is_none());
    assert_eq!(limits(&errors), 1, "{errors:#?}");
    assert_eq!(errors.last().unwrap().kind, ErrorKind::Limit);
}

/// A model without `deny_unknown_fields`: unknown keys are not reported.
#[derive(Debug, FromNode)]
struct Open {
    name: String,
}

/// The keys a closed model does not report (the `__legacy_keys__` pre-pass).
const LEGACY: &[&str] = &["old_name"];

/// A closed model that tolerates `LEGACY`.
#[derive(Debug, FromNode)]
#[serde(deny_unknown_fields)]
#[from_node(tolerate = "LEGACY")]
struct Tolerant {
    name: String,
}

#[test]
fn an_open_model_takes_unknown_keys() {
    let document = node::load("name: n\nextra: 1\n2: x\n").unwrap();
    let errors = from_node::from_document::<Open>(&document).unwrap_err();
    // A key that is not a string is still `invalid_key`; `extra` is not
    // reported.
    assert_eq!(errors.len(), 1, "{errors:#?}");
    assert_eq!(errors[0].kind, ErrorKind::InvalidType("invalid_key"));
    let document = node::load("name: n\nextra: 1\n").unwrap();
    let open: Open = from_node::from_document(&document).unwrap();
    assert_eq!(open.name, "n");
}

#[test]
fn a_closed_model_tolerates_only_the_keys_it_names() {
    let document = node::load("name: n\nold_name: m\n").unwrap();
    let tolerant: Tolerant = from_node::from_document(&document).unwrap();
    assert_eq!(tolerant.name, "n");
    let document = node::load("name: n\nold_name: m\nother: o\n").unwrap();
    let errors = from_node::from_document::<Tolerant>(&document).unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:#?}");
    assert_eq!(errors[0].kind, ErrorKind::UnknownKey);
    assert_eq!(errors[0].kind.pydantic_type(), Some("extra_forbidden"));
    assert_eq!(errors[0].field_path(), ["other"]);
}

/// A model's `after` validator runs only once every field validated, extra
/// keys included, as Pydantic's `mode="after"` does: the derive compares
/// `Context::error_count` before and after the fields. A `yara` object with
/// an unknown key reports that key alone, not also its missing decomposed
/// form; without the unknown key, the validator reports the form.
#[test]
fn an_after_validator_waits_for_the_fields() {
    use opentide_schema::objects::platform::harfanglab::HarfangLabYara;

    let (value, errors) = convert::<HarfangLabYara>("yara:\n  strings: s\n  bogus: 1\n", "yara");
    assert!(value.is_none());
    assert_eq!(errors.len(), 1, "{errors:#?}");
    assert_eq!(errors[0].kind, ErrorKind::UnknownKey);
    assert_eq!(errors[0].field_path(), ["bogus"]);

    let (value, errors) = convert::<HarfangLabYara>("yara:\n  strings: s\n", "yara");
    assert!(value.is_none());
    assert_eq!(errors.len(), 1, "{errors:#?}");
    assert_eq!(errors[0].kind, ErrorKind::InvalidValue("value_error"));
}
