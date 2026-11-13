//! The renderers' invariants on the model. The comparisons with the files
//! the oracle writes read them from disk, so they live in
//! `tests/generate_files.rs` (this crate's `src` stays I/O-free); `cargo
//! xtask codegen --check` compares every golden case that writes them.

use serde_json::Value;

use super::models::{INTEGER_KEYED, model_named, models};
use super::template::{Options, render_schema};
use super::workspace::object_template;

#[test]
fn required_metadata_renders_live_only_inside_metadata() {
    let options = Options {
        required_metadata: vec!["contributors".to_owned()],
        indent: 0,
    };
    let text = object_template("threat::1.0", &options).unwrap().unwrap();
    assert!(text.contains("\n  contributors:\n    - \n"), "{text}");
    assert!(text.contains("\n  #author: \n"), "{text}");
    let none = Options {
        required_metadata: Vec::new(),
        indent: 0,
    };
    let text = object_template("threat::1.0", &none).unwrap().unwrap();
    assert!(text.contains("\n  #organisation:\n    #uuid: \n"), "{text}");
}

fn object_schemas() -> Vec<(String, Value)> {
    use crate::objects::{objective, platform, rule, threat};
    let mut schemas = vec![
        ("DetectionRule", schemars::schema_for!(rule::RuleV1_0)),
        ("DetectionRule_v1_1", schemars::schema_for!(rule::RuleV1_1)),
        (
            "ThreatVector",
            schemars::schema_for!(threat::ThreatVectorV1_0),
        ),
        (
            "DetectionObjective",
            schemars::schema_for!(objective::ObjectiveV1_0),
        ),
        (
            "SentinelConfig",
            schemars::schema_for!(platform::SentinelConfig),
        ),
        (
            "DefenderConfig",
            schemars::schema_for!(platform::DefenderConfig),
        ),
        (
            "SplunkConfig",
            schemars::schema_for!(platform::SplunkConfig),
        ),
        (
            "SentinelOneConfig",
            schemars::schema_for!(platform::SentinelOneConfig),
        ),
        (
            "CrowdstrikeConfig",
            schemars::schema_for!(platform::CrowdstrikeConfig),
        ),
        (
            "HarfangLabConfig",
            schemars::schema_for!(platform::HarfangLabConfig),
        ),
        (
            "CarbonBlackConfig",
            schemars::schema_for!(platform::CarbonBlackConfig),
        ),
        (
            "ElasticConfig",
            schemars::schema_for!(platform::ElasticConfig),
        ),
        (
            "SysdigConfig",
            schemars::schema_for!(platform::SysdigConfig),
        ),
        (
            "ExabeamConfig",
            schemars::schema_for!(platform::ExabeamConfig),
        ),
        (
            "GoogleSecopsConfig",
            schemars::schema_for!(platform::GoogleSecopsConfig),
        ),
    ];
    schemas
        .drain(..)
        .map(|(name, schema)| (name.to_owned(), schema.to_value()))
        .collect()
}

/// Every model with properties a schema reaches, by name, with them.
fn reached(schema: &Value, root: &str) -> Vec<(String, Vec<String>)> {
    let mut found = Vec::new();
    let keys = |node: &Value| -> Vec<String> {
        let mut keys: Vec<String> = node
            .get("properties")
            .and_then(Value::as_object)
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default();
        keys.sort();
        keys
    };
    found.push((root.to_owned(), keys(schema)));
    if let Some(defs) = schema.get("$defs").and_then(Value::as_object) {
        for (name, def) in defs {
            if def.get("properties").is_some() {
                found.push((name.clone(), keys(def)));
            }
        }
    }
    found
}

#[test]
fn the_field_order_names_every_model_and_exactly_its_properties() {
    for (root, schema) in object_schemas() {
        assert_eq!(
            schema.get("title").and_then(Value::as_str),
            Some(root.as_str())
        );
        for (name, properties) in reached(&schema, &root) {
            let model = model_named(&name)
                .unwrap_or_else(|| panic!("{name} (reached from {root}) has no field order"));
            // The fields are the properties, and the aliases serde lists.
            for property in &properties {
                assert!(
                    model.fields.contains(&property.as_str()),
                    "{name}.{property}"
                );
            }
            assert!(model.fields.len() >= properties.len(), "{name}");
        }
    }
    // Every listed model is reached: none is stale.
    let all: Vec<String> = object_schemas()
        .iter()
        .flat_map(|(root, schema)| reached(schema, root))
        .map(|(name, _)| name)
        .collect();
    for model in models() {
        assert!(
            all.iter().any(|name| *name == model.name),
            "{} is not reached",
            model.name
        );
    }
}

#[test]
fn integer_keyed_maps_are_integer_keyed_in_the_model() {
    use crate::objects::metadata::ObjectReferences;
    for (model, field) in INTEGER_KEYED {
        assert!(model_named(model).is_some_and(|m| m.fields.contains(field)));
    }
    // `public` refuses a key that is not an integer; `internal` takes it.
    let document =
        crate::node::load("public:\n  abc: https://x\ninternal:\n  abc: https://x\n").unwrap();
    let errors = crate::from_node::from_document::<ObjectReferences>(&document).unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].to_string().contains("public"), "{errors:?}");
}

#[test]
fn a_schema_the_renderer_cannot_walk_is_an_error_not_a_panic() {
    let unknown = serde_json::json!({"properties": {"a": {"type": "string"}}});
    assert!(render_schema(&unknown, "Unknown", &Options::default()).is_err());
    let missing = serde_json::json!({
        "properties": {"name": {"$ref": "#/$defs/Missing"}},
    });
    assert!(render_schema(&missing, "ThreatActor", &Options::default()).is_err());
}

#[test]
fn a_named_enum_offers_no_placeholder_and_a_literal_its_first_value() {
    let options = Options::default();
    let named = serde_json::json!({
        "properties": {"name": {"$ref": "#/$defs/Colour"}},
        "required": ["name"],
        "$defs": {"Colour": {"type": "string", "enum": ["red", "blue"]}},
    });
    assert_eq!(
        render_schema(&named, "ThreatActor", &options).unwrap(),
        "name: \n"
    );
    let optional_named = serde_json::json!({
        "properties": {"name": {"anyOf": [{"$ref": "#/$defs/Colour"}, {"type": "null"}]}},
        "required": ["name"],
        "$defs": {"Colour": {"type": "string", "enum": ["red", "blue"]}},
    });
    assert_eq!(
        render_schema(&optional_named, "ThreatActor", &options).unwrap(),
        "name: \n"
    );
    let literal = serde_json::json!({
        "properties": {"name": {"type": "string", "enum": ["red", "blue"]}},
        "required": ["name"],
    });
    assert_eq!(
        render_schema(&literal, "ThreatActor", &options).unwrap(),
        "name: red\n"
    );
    let constant = serde_json::json!({
        "properties": {"name": {"const": "red"}},
        "required": ["name"],
    });
    assert_eq!(
        render_schema(&constant, "ThreatActor", &options).unwrap(),
        "name: red\n"
    );
}
