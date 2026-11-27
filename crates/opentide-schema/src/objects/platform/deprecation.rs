//! Deprecated fields: a field whose schema carries `tide.meta.deprecation`
//! gives a `deprecated_field` warning when an object sets it (a value other
//! than `null`).
//!
//! The walk visits each field of the schema's `properties` the object sets,
//! and the nested `properties` of a field whose value is a mapping, in the
//! object's order (a schemars schema without `preserve_order` does not keep
//! the models' field order). A `$ref` to the schema's `$defs`, as schemars
//! writes nested models, is followed to its definition. No field of the rule
//! models is deprecated today (a test checks it), so no object gets the
//! warning; the walk is ready for the first marker.

use std::borrow::Cow;

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
/// own keywords over the definition's. Borrowed unless the reference has
/// keywords of its own to lay over a definition: the walk visits every field
/// of every object, and a copy of each definition made it the dearest part of
/// checking an object.
fn resolved<'a>(schema: &'a Value, root: &'a Value) -> Cow<'a, Value> {
    let Some(reference) = schema.get("$ref").and_then(Value::as_str) else {
        return Cow::Borrowed(schema);
    };
    let Some(name) = reference.strip_prefix("#/$defs/") else {
        return Cow::Borrowed(schema);
    };
    let Some(definition) = root.get("$defs").and_then(|defs| defs.get(name)) else {
        return Cow::Borrowed(schema);
    };
    let Value::Object(definition_keys) = definition else {
        return Cow::Borrowed(schema);
    };
    let Value::Object(own) = schema else {
        return Cow::Borrowed(definition);
    };
    if own.keys().all(|key| key == "$ref") {
        return Cow::Borrowed(definition);
    }
    let mut merged: Map<String, Value> = definition_keys.clone();
    for (key, value) in own {
        if key != "$ref" {
            merged.insert(key.clone(), value.clone());
        }
    }
    Cow::Owned(Value::Object(merged))
}

/// The object schema of a field: itself, or the one non-null member of an
/// optional (`anyOf: [X, null]`), references followed.
fn object_schema<'a>(schema: &'a Value, root: &'a Value) -> Cow<'a, Value> {
    let schema = resolved(schema, root);
    if schema.get("properties").is_some() {
        return schema;
    }
    match schema {
        Cow::Borrowed(schema) => {
            if let Some(Value::Array(members)) = schema.get("anyOf") {
                for member in members {
                    let member = resolved(member, root);
                    if member.get("properties").is_some() {
                        return member;
                    }
                }
            }
            Cow::Borrowed(schema)
        }
        Cow::Owned(schema) => {
            let found = match schema.get("anyOf") {
                Some(Value::Array(members)) => members
                    .iter()
                    .map(|member| resolved(member, root))
                    .find(|member| member.get("properties").is_some())
                    .map(Cow::into_owned),
                _ => None,
            };
            Cow::Owned(found.unwrap_or(schema))
        }
    }
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
        if let Some(text) = field_schema
            .get(keys::META_DEPRECATION)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            && set
        {
            let text = text.to_owned();
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
                    message: "Field \"old\" is deprecated: use `new`".into(),
                    deprecation: "use `new`".into(),
                },
                Deprecated {
                    field_path: vec!["block".into(), "legacy".into()],
                    message: "Field \"block.legacy\" is deprecated: gone in 2.0".into(),
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
                "no field of the rule models is deprecated"
            );
        }
    }
}
