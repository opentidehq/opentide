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
fn an_enum_doc_joins_only_the_words_the_cap_keeps_and_says_the_same() {
    let whole = |markdown: &str| {
        let text = markdown.trim();
        let text = text.rsplit("---").next().unwrap_or(text).trim();
        cap_doc(&text.split_whitespace().collect::<Vec<_>>().join(" "))
    };
    let mut cases: Vec<String> = vec![
        String::new(),
        "x".repeat(DOC_CAP),
        "x".repeat(DOC_CAP + 1),
        format!("{} y", "x".repeat(DOC_CAP - 2)),
        format!("{} y", "x".repeat(DOC_CAP - 1)),
        format!("{} yy", "x".repeat(DOC_CAP - 2)),
        format!("{}\n\n  tail", "é ".repeat(DOC_CAP)),
        format!("### A\n---\n{}", "word\t ".repeat(100)),
    ];
    for width in 1..12 {
        cases.push(format!("{} ", "w".repeat(width)).repeat(2 * DOC_CAP / width));
    }
    for case in &cases {
        assert_eq!(short_doc(case), whole(case), "{case:?}");
    }
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

/// `deprecations.json`: one `rule` row per platform property extra whose
/// `tide.meta.deprecation` is truthy, at `configurations.{platform}.{name}`,
/// with its message, sorted by path; falsy markers and platforms without
/// property extras give none.
#[test]
fn deprecations_are_the_truthy_platform_extras_sorted_by_path() {
    let rows = deprecation_rows([
        (
            "sentinel",
            json!({"property_extras": {
                "zeta": {"tide.meta.deprecation": "Use `query` instead."},
                "alpha": {"tide.meta.deprecation": ""},
                "beta": {"tide.meta.deprecation": false},
                "delta": {"tide.meta.deprecation": null},
                "eta": {"tide.meta.deprecation": 0},
                "iota": {"tide.meta.deprecation": []},
                "kappa": {"tide.template.hide": true},
                "gamma": {"tide.meta.deprecation": 2},
            }}),
        ),
        ("splunk", json!({"other": {}})),
        (
            "elastic",
            json!({"property_extras": {"query": {"tide.meta.deprecation": "Gone in 2.0"}}}),
        ),
    ]);
    assert_eq!(
        Json::Array(rows),
        Json::Array(
            [
                ("configurations.elastic.query", "Gone in 2.0"),
                ("configurations.sentinel.gamma", "2"),
                ("configurations.sentinel.zeta", "Use `query` instead."),
            ]
            .into_iter()
            .map(|(path, message)| Json::Object(Object::from([
                ("schema".to_owned(), Json::from("rule")),
                ("path".to_owned(), Json::from(path)),
                ("message".to_owned(), Json::from(message)),
            ])))
            .collect()
        )
    );
}

fn row_of(root: &Value, path: &str, spec: &Value, facts: &Facts) -> Row {
    let name = path.rsplit('.').next().unwrap();
    field_row(root, "rule::1.0", path, name, spec, false, facts)
}

/// A model default outside the field's enum is not offered; one inside it
/// is, and so is any default of a field without an enum.
#[test]
fn a_default_outside_the_enum_is_dropped() {
    let root = json!({});
    let spec = json!({"type": "string", "enum": ["red", "green"]});
    let facts = |default: &str| Facts {
        defaults: [("meta.tlp".to_owned(), default.to_owned())].into(),
        ..Facts::default()
    };
    let outside = row_of(&root, "meta.tlp", &spec, &facts("amber"));
    assert!(!outside.node.contains_key("default"), "{:?}", outside.node);
    let inside = row_of(&root, "meta.tlp", &spec, &facts("green"));
    assert_eq!(inside.node["default"], Json::from("green"));
    let free = row_of(
        &root,
        "meta.tlp",
        &json!({"type": "string"}),
        &facts("amber"),
    );
    assert_eq!(free.node["default"], Json::from("amber"));
}

/// `minItems` is read from the field, else from the first alternative that
/// has one; none is written when neither has it.
#[test]
fn min_items_falls_back_to_an_alternative() {
    let root = json!({});
    let facts = Facts::default();
    let direct = json!({"type": "array", "minItems": 2, "items": {"type": "string"}});
    assert_eq!(
        row_of(&root, "a.b", &direct, &facts).node["min_items"],
        Json::Number(2.into())
    );
    let nullable = json!({"anyOf": [
        {"type": "null"},
        {"type": "array", "minItems": 1, "items": {"type": "string"}},
    ]});
    assert_eq!(
        row_of(&root, "a.b", &nullable, &facts).node["min_items"],
        Json::Number(1.into())
    );
    let none = json!({"anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}]});
    assert!(
        !row_of(&root, "a.b", &none, &facts)
            .node
            .contains_key("min_items")
    );
}

/// An enum of the empty string alone offers no value, and neither does an
/// empty constant; a non-empty constant is the one value.
#[test]
fn an_empty_enum_or_constant_offers_no_value() {
    let root = json!({});
    let facts = Facts::default();
    let empty = row_of(
        &root,
        "a.b",
        &json!({"type": "string", "enum": [""]}),
        &facts,
    );
    assert_eq!(empty.node["enum"], Json::Array(Vec::new()));
    assert_eq!(empty.node["enum_docs"], Json::Array(Vec::new()));
    let blank = row_of(
        &root,
        "a.b",
        &json!({"type": "string", "const": ""}),
        &facts,
    );
    assert_eq!(blank.node["enum"], Json::Array(Vec::new()));
    let constant = row_of(
        &root,
        "a.b",
        &json!({"type": "string", "const": "x"}),
        &facts,
    );
    assert_eq!(constant.node["enum"], Json::Array(vec![Json::from("x")]));
    assert_eq!(constant.node["const"], Json::from("x"));
}

/// An `enum` beside other types applies only where the value can be one of
/// those strings: never to an integer, number, boolean or object field, nor
/// to a union with an array of objects.
#[test]
fn a_scalar_enum_applies_only_to_strings() {
    let root = json!({});
    let values = |spec: Value| enum_of(&root, spec.as_object().unwrap()).0;
    assert_eq!(
        values(json!({"type": "string", "enum": ["a", "b"]})),
        ["a", "b"]
    );
    assert_eq!(values(json!({"enum": ["a"]})), ["a"]);
    for kind in ["integer", "number", "boolean", "object"] {
        assert!(
            values(json!({"type": [kind, "null"], "enum": ["1", "2"]})).is_empty(),
            "{kind}"
        );
        assert!(!scalar_enum_applies(
            &root,
            json!({"type": kind, "enum": ["1"]}).as_object().unwrap()
        ));
    }
    // A union of a string and an array of strings: the enum applies.
    let strings = json!({"enum": ["a"], "anyOf": [
        {"type": "string"}, {"type": "array", "items": {"type": "string"}},
    ]});
    assert!(scalar_enum_applies(&root, strings.as_object().unwrap()));
    // A union with an array of objects: it does not, whatever else it holds.
    for items in [
        json!({"type": "object"}),
        json!({"properties": {"x": {}}}),
        json!({"additionalProperties": true}),
    ] {
        let objects = json!({"enum": ["a"], "anyOf": [
            {"type": "string"}, {"type": "array", "items": items},
        ]});
        assert!(
            !scalar_enum_applies(&root, objects.as_object().unwrap()),
            "{objects}"
        );
        assert!(values(objects).is_empty());
    }
    // A union with no string in it: it does not.
    let numbers = json!({"enum": ["a"], "anyOf": [{"type": "integer"}, {"type": "null"}]});
    assert!(!scalar_enum_applies(&root, numbers.as_object().unwrap()));
}

/// `recommended_fields` names the fields the bundled catalog marks
/// `recommended`, schema by schema: what the engine reported as
/// `recommended_field_missing`, and what `opentide lint` reports now.
#[test]
fn recommended_fields_are_the_catalogs() {
    let text = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../data/catalogs/tide/generated/fields.json"
    ));
    let catalog: Value = serde_json::from_str(text).unwrap();
    let schemas = catalog["schemas"].as_object().unwrap();
    assert!(!schemas.is_empty());
    for identifier in schemas.keys() {
        let mut expected: Vec<String> = catalog["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["schema"] == identifier.as_str() && row["recommended"] == true)
            .map(|row| row["path"].as_str().unwrap().to_owned())
            .collect();
        expected.sort();
        assert_eq!(recommended_fields(identifier), expected, "{identifier}");
    }
    assert_eq!(
        recommended_fields("rule::1.1"),
        ["configurations", "response"]
    );
    assert!(recommended_fields("threat::1.0").is_empty());
    assert!(recommended_fields("nope::1.0").is_empty());
}
