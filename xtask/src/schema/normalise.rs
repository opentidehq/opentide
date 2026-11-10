//! The normal form two JSON Schemas are compared in (`schema diff`): what
//! Pydantic's `model_json_schema()` and schemars write differently for the
//! same model, made one, so that what is left to compare is the model.
//!
//! - Every `$ref` to `#/$defs/<name>` is replaced by the definition, its own
//!   keywords under the reference's (a field's `description` over its
//!   model's), and `$defs` and `$schema` are dropped: the two name their
//!   definitions differently (`SentinelConfig`, `RuleV1_1`).
//! - An optional value: Pydantic writes `anyOf: [X, {type: null}]` with
//!   `default: null`, schemars `type: [X, "null"]` (or `anyOf` with a
//!   `$ref`). Both become X with `"nullable": true`, and `default: null` is
//!   dropped.
//! - Titles: Pydantic titles every model (its class name) and every field
//!   (`detection_model` is "Detection Model"); schemars titles the root.
//!   Those are dropped; a title a field sets itself (`cve`: "CVE") is kept.
//! - schemars' integer `format`s (`int64`) are dropped: Pydantic writes none.
//! - A `default` of `[]` or `{}` that only schemars writes is dropped:
//!   Pydantic writes none for a `default_factory`.
//! - `required` is a set.
//!
//! Byte equality, with Pydantic's titles and key order, is UC-1.8's (#814).

use serde_json::{Map, Value};

/// Which side a schema comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Pydantic's `model_json_schema(by_alias=True)`.
    Pydantic,
    /// schemars' `schema_for!`.
    Schemars,
}

/// Pydantic's title for a field: `str.title()` of the name with `_` as a
/// space (`mitre_attack` is "Mitre Attack").
pub fn field_title(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut start = true;
    for character in name.chars() {
        let character = if character == '_' { ' ' } else { character };
        if character.is_alphabetic() {
            if start {
                out.extend(character.to_uppercase());
            } else {
                out.extend(character.to_lowercase());
            }
            start = false;
        } else {
            out.push(character);
            start = true;
        }
    }
    out
}

/// `schema` in the normal form. `excluded` are paths of property names from
/// the root whose schema is not compared (each keeps its `description`,
/// `nullable`, `default` and `tide.*` keys): the platform blocks until
/// UC-1.4.
pub fn normalise(schema: &Value, side: Side, excluded: &[&[&str]]) -> Value {
    let defs = schema
        .get("$defs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut root = inline(schema, &defs, 0);
    if let Some(map) = root.as_object_mut() {
        map.remove("$schema");
        map.remove("$defs");
        map.remove("title");
    }
    let mut out = tidy(root, side, None);
    for path in excluded {
        exclude(&mut out, path);
    }
    out
}

fn inline(schema: &Value, defs: &Map<String, Value>, depth: usize) -> Value {
    // The object models nest a few levels deep; a recursive model would not end.
    assert!(depth < 64, "a schema nested more than 64 references deep");
    match schema {
        Value::Object(map) => {
            let mut out = Map::new();
            if let Some(target) = map.get("$ref").and_then(Value::as_str)
                && let Some(name) = target.strip_prefix("#/$defs/")
                && let Some(definition) = defs.get(name)
            {
                if let Value::Object(definition) = inline(definition, defs, depth + 1) {
                    for (key, value) in definition {
                        // A definition's title is its class name.
                        if key == "title" && value.as_str() == Some(name) {
                            continue;
                        }
                        out.insert(key, value);
                    }
                }
            }
            for (key, value) in map {
                if key == "$ref" && !out.is_empty() {
                    continue;
                }
                if key == "$defs" {
                    continue;
                }
                out.insert(key.clone(), inline(value, defs, depth + 1));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(|item| inline(item, defs, depth + 1)).collect()),
        other => other.clone(),
    }
}

fn is_null_schema(value: &Value) -> bool {
    value.as_object().is_some_and(|map| map.len() == 1 && map.get("type") == Some(&Value::from("null")))
}

/// One schema object in the normal form; `field` is the property name it is
/// the schema of, if it is one.
fn tidy(schema: Value, side: Side, field: Option<&str>) -> Value {
    let Value::Object(mut map) = schema else {
        return schema;
    };
    // Optional: anyOf with a null branch.
    if let Some(Value::Array(branches)) = map.get("anyOf").cloned()
        && branches.iter().any(is_null_schema)
    {
        let rest: Vec<Value> = branches.into_iter().filter(|b| !is_null_schema(b)).collect();
        map.remove("anyOf");
        map.insert("nullable".into(), Value::Bool(true));
        if rest.len() == 1 {
            if let Value::Object(branch) = &rest[0] {
                for (key, value) in branch {
                    map.entry(key.clone()).or_insert_with(|| value.clone());
                }
            }
        } else {
            map.insert("anyOf".into(), Value::Array(rest));
        }
    }
    // Optional: a type list with "null".
    if let Some(Value::Array(types)) = map.get("type").cloned()
        && types.contains(&Value::from("null"))
    {
        let rest: Vec<Value> = types.into_iter().filter(|t| t != "null").collect();
        map.insert("nullable".into(), Value::Bool(true));
        if rest.len() == 1 {
            map.insert("type".into(), rest[0].clone());
        } else {
            map.insert("type".into(), Value::Array(rest));
        }
    }
    if map.get("default") == Some(&Value::Null) {
        map.remove("default");
    }
    if side == Side::Schemars
        && matches!(map.get("default"), Some(Value::Array(items)) if items.is_empty())
        || side == Side::Schemars
            && matches!(map.get("default"), Some(Value::Object(fields)) if fields.is_empty())
    {
        map.remove("default");
    }
    if let Some(format) = map.get("format").and_then(Value::as_str)
        && matches!(
            format,
            "int8" | "int16" | "int32" | "int64" | "uint" | "uint8" | "uint16" | "uint32" | "uint64"
        )
    {
        map.remove("format");
    }
    if side == Side::Pydantic
        && let (Some(name), Some(title)) = (field, map.get("title").and_then(Value::as_str))
        && field_title(name) == title
    {
        map.remove("title");
    }
    if let Some(Value::Array(required)) = map.get_mut("required") {
        required.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    }
    let mut out = Map::new();
    for (key, value) in map {
        let value = match key.as_str() {
            "properties" => match value {
                Value::Object(properties) => Value::Object(
                    properties
                        .into_iter()
                        .map(|(name, property)| {
                            let property = tidy(property, side, Some(&name));
                            (name, property)
                        })
                        .collect(),
                ),
                other => other,
            },
            "items" | "additionalProperties" => tidy(value, side, None),
            "anyOf" | "oneOf" | "allOf" => match value {
                Value::Array(branches) => {
                    Value::Array(branches.into_iter().map(|b| tidy(b, side, None)).collect())
                }
                other => other,
            },
            _ => value,
        };
        out.insert(key, value);
    }
    Value::Object(out)
}

fn exclude(schema: &mut Value, path: &[&str]) {
    let Some((first, rest)) = path.split_first() else {
        if let Value::Object(map) = schema {
            map.retain(|key, _| {
                matches!(key.as_str(), "description" | "nullable" | "default") || key.starts_with("tide.")
            });
            map.insert("x-not-compared".into(), Value::from("UC-1.4"));
        }
        return;
    };
    if let Some(next) = schema
        .get_mut("properties")
        .and_then(|properties| properties.get_mut(*first))
    {
        exclude(next, rest);
    }
}

/// Every difference between two normal forms, as `path: pydantic X, rust Y`.
pub fn differences(pydantic: &Value, rust: &Value) -> Vec<String> {
    let mut out = Vec::new();
    walk(pydantic, rust, &mut String::new(), &mut out);
    out
}

fn walk(a: &Value, b: &Value, path: &mut String, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(left), Value::Object(right)) => {
            let mut keys: Vec<&String> = left.keys().chain(right.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let length = path.len();
                path.push('/');
                path.push_str(key);
                match (left.get(key), right.get(key)) {
                    (Some(l), Some(r)) => walk(l, r, path, out),
                    (Some(l), None) => out.push(format!("{path}: pydantic {l}, rust (absent)")),
                    (None, Some(r)) => out.push(format!("{path}: pydantic (absent), rust {r}")),
                    (None, None) => {}
                }
                path.truncate(length);
            }
        }
        (Value::Array(left), Value::Array(right)) if left.len() == right.len() => {
            for (index, (l, r)) in left.iter().zip(right).enumerate() {
                let length = path.len();
                path.push_str(&format!("/{index}"));
                walk(l, r, path, out);
                path.truncate(length);
            }
        }
        _ if a == b => {}
        _ => out.push(format!("{path}: pydantic {a}, rust {b}")),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn titles_are_pythons() {
        assert_eq!(field_title("mitre_attack"), "Mitre Attack");
        assert_eq!(field_title("detection_model"), "Detection Model");
        assert_eq!(field_title("cve"), "Cve");
        assert_eq!(field_title("tlp"), "Tlp");
    }

    #[test]
    fn optional_forms_and_references_meet() {
        let pydantic = json!({
            "title": "M",
            "type": "object",
            "properties": {
                "a": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null, "title": "A"},
                "b": {"anyOf": [{"$ref": "#/$defs/Inner"}, {"type": "null"}], "default": null, "description": "field"},
                "c": {"type": "array", "items": {"type": "string"}, "title": "Custom"},
                "n": {"type": "integer", "title": "N"}
            },
            "required": ["n", "c"],
            "$defs": {"Inner": {"title": "Inner", "type": "object", "description": "model", "properties": {}}}
        });
        let schemars = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "MV1_0",
            "type": "object",
            "properties": {
                "a": {"type": ["string", "null"]},
                "b": {"anyOf": [{"$ref": "#/$defs/I"}, {"type": "null"}], "description": "field"},
                "c": {"type": "array", "items": {"type": "string"}, "title": "Custom", "default": []},
                "n": {"type": "integer", "format": "int64"}
            },
            "required": ["c", "n"],
            "$defs": {"I": {"type": "object", "description": "model", "properties": {}}}
        });
        let a = normalise(&pydantic, Side::Pydantic, &[]);
        let b = normalise(&schemars, Side::Schemars, &[]);
        assert_eq!(differences(&a, &b), Vec::<String>::new(), "{a:#}\n{b:#}");
        assert_eq!(a["properties"]["b"]["description"], "field");
    }

    #[test]
    fn a_difference_is_named_by_its_path() {
        let a = json!({"properties": {"x": {"type": "string"}}});
        let b = json!({"properties": {"x": {"type": "integer"}}});
        assert_eq!(
            differences(&a, &b),
            ["/properties/x/type: pydantic \"string\", rust \"integer\""]
        );
    }

    #[test]
    fn an_excluded_path_keeps_only_its_annotations() {
        let schema = json!({"properties": {"c": {"properties": {"p": {"type": "object", "description": "d", "required": ["q"]}}}}});
        let out = normalise(&schema, Side::Schemars, &[&["c", "p"]]);
        assert_eq!(
            out["properties"]["c"]["properties"]["p"],
            json!({"description": "d", "x-not-compared": "UC-1.4"})
        );
    }
}
