//! The merge of configuration layers (`core/files.py` `deep_merge`): a table
//! merges into a table key by key, and every other value (a scalar, an array,
//! an array of tables) replaces what was there. A key new to the table is
//! added after the others, a replaced key keeps its place.

use std::sync::Arc;

use serde_json::{Map, Value as Json};

use crate::node::{Entry, Mark, Node, Value};

/// An empty table.
pub fn empty() -> Node {
    Node {
        value: Value::Map(Vec::new()),
        start: Mark::default(),
        end: Mark::default(),
    }
}

/// Merges `from` into `into`. When either is not a table, `into` becomes
/// `from`.
pub fn deep_merge(into: &mut Node, from: &Node) {
    let (Value::Map(target), Value::Map(source)) = (&mut into.value, &from.value) else {
        *into = from.clone();
        return;
    };
    for entry in source {
        let Some(key) = entry.key.value.as_str() else {
            continue;
        };
        match target
            .iter_mut()
            .find(|existing| existing.key.value.as_str() == Some(key))
        {
            Some(existing)
                if matches!(existing.value.value, Value::Map(_))
                    && matches!(entry.value.value, Value::Map(_)) =>
            {
                deep_merge(Arc::make_mut(&mut existing.value), &entry.value);
            }
            Some(existing) => existing.value = Arc::clone(&entry.value),
            None => target.push(Entry {
                key: Arc::clone(&entry.key),
                value: Arc::clone(&entry.value),
            }),
        }
    }
}

/// Merges `layers` in order onto an empty table.
pub fn merge_layers<'a>(layers: impl IntoIterator<Item = &'a Node>) -> Node {
    let mut merged = empty();
    for layer in layers {
        deep_merge(&mut merged, layer);
    }
    merged
}

/// The value of `key` in a table node, if it is one.
pub fn get<'n>(node: &'n Node, key: &str) -> Option<&'n Node> {
    node.get(key).map(AsRef::as_ref)
}

/// The tree as JSON: tables as objects, arrays as arrays, a date or time as
/// its TOML text, and a float that JSON cannot hold (`inf`, `-inf`, `nan`) as
/// that word.
pub fn to_json(node: &Node) -> Json {
    match &node.value {
        Value::Null => Json::Null,
        Value::Bool(flag) => Json::Bool(*flag),
        Value::Int(integer) => Json::from(*integer),
        Value::Float(float) => serde_json::Number::from_f64(*float).map_or_else(
            || {
                Json::String(
                    if float.is_nan() {
                        "nan"
                    } else if *float > 0.0 {
                        "inf"
                    } else {
                        "-inf"
                    }
                    .to_owned(),
                )
            },
            Json::Number,
        ),
        Value::Str(text) | Value::Datetime(text) => Json::String(text.clone()),
        Value::Seq(items) => Json::Array(items.iter().map(|item| to_json(item)).collect()),
        Value::Map(entries) => {
            let mut map = Map::new();
            for entry in entries {
                map.insert(entry.key.value.to_string(), to_json(&entry.value));
            }
            Json::Object(map)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::toml::parse;

    #[test]
    fn tables_merge_and_everything_else_replaces() {
        let mut base = parse("a = 1\nlist = [1, 2]\n[t]\nx = 1\ny = 2\n").unwrap();
        let over = parse("list = [3]\nb = 2\n[t]\ny = 3\nz = 4\n").unwrap();
        deep_merge(&mut base, &over);
        assert_eq!(
            to_json(&base),
            serde_json::json!({"a": 1, "list": [3], "b": 2, "t": {"x": 1, "y": 3, "z": 4}})
        );
        let Value::Map(entries) = &base.value else {
            panic!("a table");
        };
        let keys: Vec<_> = entries.iter().map(|e| e.key.value.to_string()).collect();
        assert_eq!(keys, ["a", "list", "t", "b"]);
    }

    #[test]
    fn a_table_replaces_a_scalar_and_a_scalar_replaces_a_table() {
        let mut base = parse("a = 1\n[b]\nx = 1\n").unwrap();
        deep_merge(&mut base, &parse("b = 2\n[a]\ny = 1\n").unwrap());
        assert_eq!(to_json(&base), serde_json::json!({"a": {"y": 1}, "b": 2}));
    }

    #[test]
    fn floats_json_cannot_hold_are_words() {
        let node = parse("a = inf\nb = -inf\nc = nan\nd = 1979-05-27T07:32:00Z\n").unwrap();
        assert_eq!(
            to_json(&node),
            serde_json::json!({"a": "inf", "b": "-inf", "c": "nan", "d": "1979-05-27T07:32:00Z"})
        );
    }
}
