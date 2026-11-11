use serde_json::json;

use super::*;

fn path(parts: &[&str]) -> FieldPath {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

#[test]
fn a_scalar_is_plain_where_yaml_reads_it_back() {
    let text = |value: &str| scalar_text(&Scalar::Text(value.to_owned()));
    assert_eq!(text("Credential Dumping"), "Credential Dumping");
    assert_eq!(text("T1548"), "T1548");
    assert_eq!(text("yes"), "\"yes\"");
    assert_eq!(text("true"), "\"true\"");
    assert_eq!(text("12"), "\"12\"");
    assert_eq!(text("-x"), "\"-x\"");
    assert_eq!(text("a: b"), "\"a: b\"");
    assert_eq!(text("it's"), "\"it's\"");
    assert_eq!(text("trailing "), "\"trailing \"");
    assert_eq!(text("Baseline - Negligible"), "Baseline - Negligible");
    assert_eq!(scalar_text(&Scalar::Bool(false)), "false");
    assert_eq!(scalar_text(&Scalar::Int(1)), "1");
    assert_eq!(
        scalar_text(&Scalar::Date("2026-01-01".into())),
        "2026-01-01"
    );
}

#[test]
fn the_schema_id_is_the_templates() {
    assert_eq!(
        template_schema_id("name: \nmetadata:\n  schema: rule::1.1\n").as_deref(),
        Some("rule::1.1")
    );
    assert_eq!(template_schema_id("schema: x\n"), None);
}

#[test]
fn choices_follow_references_unions_and_items() {
    let schema = json!({
        "properties": {
            "metadata": {"$ref": "#/$defs/Meta"},
            "tags": {"anyOf": [{"type": "array", "items": {"enum": ["a", "b"]}}, {"type": "null"}]},
        },
        "$defs": {"Meta": {"properties": {"tlp": {"enum": ["clear", "amber", null]}}}},
    });
    assert_eq!(
        schema_choices(&schema, &path(&["metadata", "tlp"])),
        [json!("clear"), json!("amber"), json!(null)]
    );
    assert_eq!(
        schema_choices(&schema, &path(&["tags"])),
        [json!("a"), json!("b")]
    );
    assert!(schema_choices(&schema, &path(&["nothing"])).is_empty());
}

const TEMPLATE: &str = "name: \nlevel: \n\nmetadata:\n  uuid: \n  tlp: \n  #author: \n  organisation:\n    uuid: \n    name: \nbody:\n  description: |\n    ...\n  tags:\n    - \n  #extra: \n#block:\n  #first: \n  #second: \n";

fn model() -> Value {
    json!({
        "required": ["name", "level", "metadata", "body", "block"],
        "properties": {
            "name": {"type": "string"},
            "level": {"type": "string", "enum": ["low", "high"]},
            "metadata": {"$ref": "#/$defs/Meta"},
            "body": {"$ref": "#/$defs/Body"},
            "block": {"$ref": "#/$defs/Block"},
        },
        "$defs": {
            "Meta": {"required": ["uuid", "tlp"], "properties": {
                "uuid": {"type": "string"}, "tlp": {"type": "string"},
                "author": {"type": ["string", "null"]},
                "organisation": {"anyOf": [{"$ref": "#/$defs/Org"}, {"type": "null"}]},
            }},
            "Org": {"required": ["uuid", "name"], "properties": {"uuid": {"type": "string"}, "name": {"type": "string"}}},
            "Body": {"required": ["description", "tags"], "properties": {
                "description": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "extra": {"type": ["boolean", "null"]},
            }},
            "Block": {"properties": {"first": {"type": ["integer", "null"]}, "second": {"type": ["string", "null"]}}},
        },
    })
}

#[test]
fn required_keys_are_filled_and_stand_ins_marked() {
    let root = model();
    let model = Model::new(&root);
    let fields = collect_fields(&model, &root, &[], &[]);
    let values = HashMap::from([
        (path(&["name"]), Scalar::Text("A Name".into())),
        (path(&["metadata", "uuid"]), Scalar::Text("u-1".into())),
    ]);
    let schema = json!({"properties": {"body": {"properties": {"tags": {"items": {"enum": ["t1", "t2"]}}}}}});
    let filled = fill_template(
        TEMPLATE,
        &Fill {
            fields: &fields,
            values: &values,
            schema: &schema,
            model: &model,
            marked: &HashSet::new(),
            make_uuid: &|| "fresh".to_owned(),
        },
    );
    assert_eq!(
        filled.text,
        "name: A Name\nlevel: low  # opentide:placeholder\n\nmetadata:\n  uuid: u-1\n  tlp: amber\n  #author: \n  #organisation:\n    #uuid: \n    #name: \nbody:\n  description: |  # opentide:placeholder\n    ...\n  tags:\n    - t1  # opentide:placeholder\n  #extra: \nblock:\n  first: 1  # opentide:placeholder\n  #second: \n"
    );
    assert_eq!(
        filled.placeholders,
        ["level", "body.description", "body.tags", "block.first"]
    );
}

#[test]
fn a_wanted_block_is_answered_and_a_list_answer_replaces_the_items() {
    let root = model();
    let model = Model::new(&root);
    let wanted = vec![
        path(&["metadata", "organisation"]),
        path(&["body", "extra"]),
    ];
    let fields = collect_fields(&model, &root, &wanted, &[]);
    let values = HashMap::from([
        (path(&["name"]), Scalar::Text("yes".into())),
        (
            path(&["metadata", "organisation", "uuid"]),
            Scalar::Text("o".into()),
        ),
        (
            path(&["metadata", "organisation", "name"]),
            Scalar::Text("Org".into()),
        ),
        (
            path(&["body", "tags"]),
            Scalar::List(vec![
                Scalar::Text("x".into()),
                Scalar::Text("y".into()),
                Scalar::Text("z".into()),
            ]),
        ),
    ]);
    let marked = HashSet::from([path(&["metadata", "organisation", "name"])]);
    let filled = fill_template(
        TEMPLATE,
        &Fill {
            fields: &fields,
            values: &values,
            schema: &json!({}),
            model: &model,
            marked: &marked,
            make_uuid: &|| "fresh".to_owned(),
        },
    );
    let text = &filled.text;
    assert!(text.starts_with("name: \"yes\"\n"), "{text}");
    assert!(text.contains("\n  uuid: fresh\n"), "{text}");
    assert!(
        text.contains("\n  organisation:\n    uuid: o\n    name: Org  # opentide:placeholder\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "\n  tags:\n    - x\n    - \"y\"\n    - z\n  extra: false  # opentide:placeholder\n"
        ),
        "{text}"
    );
    assert_eq!(
        filled.placeholders,
        [
            "level",
            "metadata.organisation.name",
            "body.description",
            "body.extra",
            "block.first"
        ]
    );
}

#[test]
fn only_the_chosen_platform_blocks_are_kept() {
    let text = "name: x\nconfigurations:\n  #sentinel:\n    #query: \n\n  splunk:\n    query: q\n\n  #elastic:\n    #a: \n";
    let kept = keep_platform_blocks(
        text,
        &["splunk".to_owned()],
        ".opentide/templates/rule.1.1.template.yaml",
    );
    assert_eq!(
        kept,
        "name: x\nconfigurations:\n  # Other platforms: copy a block from .opentide/templates/rule.1.1.template.yaml\n\n  splunk:\n    query: q\n"
    );
    assert_eq!(keep_platform_blocks("name: x\n", &[], "t"), "name: x\n");
}

#[test]
fn a_union_field_is_a_plain_value_and_an_enum_reference_offers_no_choices() {
    let root = json!({"$defs": {"E": {"enum": ["a"]}, "U": {"anyOf": [{"type": "string"}, {"type": "array"}]}}});
    let model = Model::new(&root);
    let union =
        model.shape(&json!({"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}]}));
    assert!(union.is_scalar() && !union.is_int);
    let referred = model.shape(&json!({"$ref": "#/$defs/E"}));
    assert!(referred.choices.is_empty());
    let inline = model.shape(&json!({"enum": ["a", "b"]}));
    assert_eq!(inline.choices, [json!("a"), json!("b")]);
    assert!(model.shape(&json!({"$ref": "#/$defs/U"})).is_scalar());
    assert!(
        model
            .shape(&json!({"type": ["array", "null"], "items": {}}))
            .list
    );
}
