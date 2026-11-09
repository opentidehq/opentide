//! The schema schemars derives from the sample (ADR 0001, "The derive stack").
//! The snapshot is the reviewed copy: `cargo insta review` after a change.

use opentide_schema::keys;
use opentide_schema::sample::{Sample, SampleV1_0};
use serde_json::Value;

fn tide_keys(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key.starts_with("tide.") {
                    found.push(key.clone());
                }
                tide_keys(child, found);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| tide_keys(item, found)),
        _ => {}
    }
}

#[test]
fn sample_schema() {
    let schema = schemars::schema_for!(Sample);
    insta::assert_snapshot!(serde_json::to_string_pretty(&schema).unwrap());
}

#[test]
fn draft_2020_12_closed_with_the_required_keys() {
    let schema = schemars::schema_for!(Sample).to_value();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["$defs"]["SampleExample"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["required"],
        serde_json::json!(["name", "uuid", "schema", "description", "severity"])
    );
    assert_eq!(schema["properties"]["enabled"]["default"], true);
    assert_eq!(schema["properties"]["effort"]["minimum"], 1);
    assert_eq!(schema["properties"]["effort"]["maximum"], 10);
}

#[test]
fn metadata_keys_keep_their_names_and_values() {
    let schema = schemars::schema_for!(Sample).to_value();
    let description = &schema["properties"]["description"];
    assert_eq!(description[keys::TEMPLATE_MULTILINE], true);
    assert_eq!(description[keys::TEMPLATE_SPACER], true);
    assert_eq!(
        schema["properties"]["severity"][keys::VOCAB],
        "alert_severity"
    );
    assert_eq!(
        schema["$defs"]["SampleExample"]["properties"]["description"][keys::TEMPLATE_MULTILINE],
        true
    );
}

#[test]
fn every_tide_key_in_a_schema_is_a_known_key() {
    for schema in [
        schemars::schema_for!(Sample).to_value(),
        schemars::schema_for!(SampleV1_0).to_value(),
    ] {
        let mut found = Vec::new();
        tide_keys(&schema, &mut found);
        assert!(!found.is_empty());
        for key in found {
            assert!(
                keys::ALL.iter().any(|known| known.name == key),
                "{key} is not in opentide_schema::keys::ALL"
            );
        }
    }
}
