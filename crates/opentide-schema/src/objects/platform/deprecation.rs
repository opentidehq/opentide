//! Deprecated fields (`validation/deprecated_fields.py`): a field whose
//! schema carries `tide.meta.deprecation` gives a `deprecated_field` warning
//! when an object sets it (a value other than `null`).
//!
//! The walk follows the oracle's: each field of the schema's `properties`
//! the object sets, and the nested `properties` of a field whose value is a
//! mapping. Fields are visited in the object's order (the oracle visited
//! the schema's, the models' field order, which a schemars schema without
//! `preserve_order` does not keep). A `$ref` to the schema's `$defs`, as schemars
//! writes nested models, is followed to its definition. In the oracle's
//! models (0.23.0) no field is deprecated, so no object gets the warning;
//! the walk is ready for the first marker.

use serde_json::{Map, Value};

use crate::keys;
use crate::node::{Node, Value as NodeValue};

/// The warning's code.
pub const CODE: &str = "deprecated_field";

/// One `deprecated_field` warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deprecated {
    /// The field's path in the object.
    pub field_path: Vec<String>,
    /// `Field 'a.b' is deprecated: <message>`.
    pub message: String,
    /// The schema's deprecation message (the warning's `context.deprecation`).
    pub deprecation: String,
}

/// Every deprecated field `object` sets, by `schema` (a model's JSON Schema).
pub fn deprecated_fields(object: &Node, schema: &Value) -> Vec<Deprecated> {
    let mut out = Vec::new();
    walk(object, schema, schema, &mut Vec::new(), &mut out);
    out
}

/// A schema with its `$ref` to the root's `$defs` followed, the reference's
/// own keywords over the definition's.
fn resolved(schema: &Value, root: &Value) -> Value {
    let Some(reference) = schema.get("$ref").and_then(Value::as_str) else {
        return schema.clone();
    };
    let Some(name) = reference.strip_prefix("#/$defs/") else {
        return schema.clone();
    };
    let Some(Value::Object(definition)) = root.get("$defs").and_then(|defs| defs.get(name)) else {
        return schema.clone();
    };
    let mut merged: Map<String, Value> = definition.clone();
    if let Value::Object(own) = schema {
        for (key, value) in own {
            if key != "$ref" {
                merged.insert(key.clone(), value.clone());
            }
        }
    }
    Value::Object(merged)
}

/// The object schema of a field: itself, or the one non-null member of an
/// optional (`anyOf: [X, null]`), references followed.
fn object_schema(schema: &Value, root: &Value) -> Value {
    let schema = resolved(schema, root);
    if schema.get("properties").is_some() {
        return schema;
    }
    if let Some(Value::Array(members)) = schema.get("anyOf") {
        for member in members {
            let member = resolved(member, root);
            if member.get("properties").is_some() {
                return member;
            }
        }
    }
    schema
}

fn walk(
    object: &Node,
    schema: &Value,
    root: &Value,
    path: &mut Vec<String>,
    out: &mut Vec<Deprecated>,
) {
    let Some(Value::Object(properties)) = schema.get("properties") else {
        return;
    };
    let NodeValue::Map(entries) = &object.value else {
        return;
    };
    for entry in entries {
        let Some(name) = entry.key.value.as_str() else {
            continue;
        };
        let Some(field_schema) = properties.get(name).filter(|schema| schema.is_object()) else {
            continue;
        };
        let field_schema = object_schema(field_schema, root);
        let value = Some(&entry.value);
        let set = !matches!(entry.value.value, NodeValue::Null);
        path.push(name.to_owned());
        if let Some(deprecation) = field_schema.get(keys::META_DEPRECATION)
            && truthy(deprecation)
            && set
        {
            let text = match deprecation {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            out.push(Deprecated {
                field_path: path.clone(),
                message: format!(
                    "Field {} is deprecated: {text}",
                    crate::configuration::repr::quote(&path.join("."))
                ),
                deprecation: text,
            });
        }
        if let Some(value) = value
            && matches!(value.value, NodeValue::Map(_))
            && field_schema.get("properties").is_some()
        {
            walk(value, &field_schema, root, path, out);
        }
        path.pop();
    }
}

/// Python's truthiness of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::node;

    #[test]
    fn a_set_deprecated_field_warns_and_an_unset_or_null_one_does_not() {
        let schema = json!({
            "properties": {
                "old": {"type": "string", "tide.meta.deprecation": "use `new`"},
                "block": {"$ref": "#/$defs/Block"},
                "maybe": {"anyOf": [{"$ref": "#/$defs/Block"}, {"type": "null"}]},
            },
            "$defs": {"Block": {"properties": {
                "legacy": {"type": "integer", "tide.meta.deprecation": "gone in 2.0"},
            }}},
        });
        let document = node::load("old: x\nblock:\n  legacy: 1\nmaybe:\n  legacy: null\n").unwrap();
        let found = deprecated_fields(document.root().unwrap(), &schema);
        assert_eq!(
            found,
            [
                Deprecated {
                    field_path: vec!["old".into()],
                    message: "Field 'old' is deprecated: use `new`".into(),
                    deprecation: "use `new`".into(),
                },
                Deprecated {
                    field_path: vec!["block".into(), "legacy".into()],
                    message: "Field 'block.legacy' is deprecated: gone in 2.0".into(),
                    deprecation: "gone in 2.0".into(),
                },
            ]
        );
    }

    #[test]
    fn no_field_of_the_rule_models_is_deprecated() {
        for schema in [
            schemars::schema_for!(crate::objects::RuleV1_0).to_value(),
            schemars::schema_for!(crate::objects::RuleV1_1).to_value(),
        ] {
            assert!(
                !schema.to_string().contains(keys::META_DEPRECATION),
                "the oracle (0.23.0) deprecates no field"
            );
        }
    }
}
