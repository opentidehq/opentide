//! The conversion's API beyond the oracle tables: garde after a successful
//! conversion ([`from_node::validate`]), the work budget on a document of
//! nested aliases, and the field types no table model uses.

use opentide_schema::from_node::{self, Context, FromNode, Invalid};
use opentide_schema::node;
use opentide_schema::sample::SampleV1_1;
use opentide_schema::{ErrorKind, Pins};

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
    let mut text = String::from("base: &m {");
    for key in 0..600 {
        text.push_str(&format!("k{key}: 1, "));
    }
    text.push_str("}\nexamples: [");
    text.push_str(&"*m, ".repeat(200));
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
    let any = <std::sync::Arc<node::Node>>::from_node(root, &mut cx).unwrap();
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
