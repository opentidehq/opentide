use serde_json::json;

use super::*;

#[test]
fn a_field_without_a_title_is_titled_from_its_name() {
    assert_eq!(default_title("mitre_attack"), "Mitre Attack");
    assert_eq!(default_title("tlp"), "Tlp");
    assert_eq!(default_title("detection_model"), "Detection Model");
    assert_eq!(default_title("cve"), "Cve");
}

#[test]
fn an_enum_doc_is_the_text_after_its_last_rule_on_one_line_and_capped() {
    assert_eq!(
        short_doc("\n### A\n\n---\n\nfirst  line\nsecond\n"),
        "first line second"
    );
    assert_eq!(short_doc("plain"), "plain");
    let long = "word ".repeat(40);
    let capped = cap_doc(long.trim());
    assert_eq!(capped.chars().count(), DOC_CAP);
    assert!(
        capped.ends_with("word…") || capped.ends_with('…'),
        "{capped}"
    );
    assert!(!capped.contains(" …"), "{capped}");
    assert_eq!(cap_doc("short"), "short");
}

#[test]
fn enum_values_are_written_as_yaml_and_empty_ones_dropped() {
    let (values, docs) = clean_enum(
        &[json!(true), json!(null), json!(""), json!(3), json!("x")],
        &[
            json!("a"),
            json!("b"),
            json!("c"),
            json!("d"),
            json!("--- e"),
        ],
    );
    assert_eq!(values, ["true", "3", "x"]);
    assert_eq!(docs, ["a", "d", "e"]);
}

#[test]
fn a_reference_field_offers_no_snapshot_of_uuids() {
    let root = json!({"properties": {}});
    let spec = json!({"type": "array", "items": {"type": "string", "enum": ["a", "b"]}});
    let row = field_row(
        &root,
        "objective::1.0",
        "objective.threats",
        "threats",
        &spec,
        false,
        &Facts::default(),
    );
    assert_eq!(row.node["ref"], Json::from("threat"));
    assert_eq!(row.node["enum"], Json::Array(Vec::new()));
    assert_eq!(row.node["array"], Json::Bool(true));
}

#[test]
fn the_documents_are_written_with_two_spaces_and_utf8() {
    let document = deprecations_catalog("1.2.3");
    assert_eq!(
        dump(&document),
        "{\n  \"opentide\": \"1.2.3\",\n  \"generator\": \"opentide.generation.lsp_catalog\",\n  \"fields\": []\n}\n"
    );
    let text = dump(&Json::from("é…"));
    assert_eq!(text, "\"é…\"\n");
}

#[test]
fn a_nullable_enum_pairs_its_docs_with_the_other_values() {
    let (values, docs) = clean_enum(
        &[json!("a"), json!("b"), json!(null)],
        &[json!("x"), json!("y")],
    );
    assert_eq!(values, ["a", "b"]);
    assert_eq!(docs, ["x", "y"]);
    let (_, docs) = clean_enum(&[json!("a"), json!("b")], &[json!("x")]);
    assert_eq!(docs, ["", ""]);
}

#[test]
fn a_union_of_unions_is_flattened() {
    let root = json!({"$defs": {
        "Choice": {"anyOf": [{"type": "integer"}, {"$ref": "#/$defs/Risk"}]},
        "Risk": {"type": "object", "properties": {"score": {"type": "integer"}}, "additionalProperties": false},
    }});
    let spec = json!({"anyOf": [{"$ref": "#/$defs/Choice"}, {"type": "null"}]});
    let map = spec.as_object().unwrap();
    let found = alternatives(&root, map);
    assert_eq!(found.len(), 2);
    assert_eq!(type_name(&root, map, false), "object");
    let target = object_of(&root, &spec).unwrap();
    assert!(closed(target));
}
