//! The inflight preview: open pull requests' objects, published as shards in
//! `.opentide/inflight/`, overlaid on the index for documentation
//! (`indexing/inflight.py` `inflight_preview`, `apply_inflight_overlay`,
//! `indexing/inflight_shard.py`). Only preview output reads them: deploy and
//! validate read the object files alone.

use std::path::Path;
use std::sync::Arc;

use indexmap::IndexMap;
use opentide_schema::node::{Node, Value, load};
use opentide_workspace::Index;
use serde_json::Value as JsonValue;

/// Whether `body` is a shard envelope (`schema: inflight.shard…`).
fn is_wrapped(body: &JsonValue) -> bool {
    body.get("schema")
        .and_then(JsonValue::as_str)
        .is_some_and(|schema| schema.starts_with("inflight.shard"))
}

/// The object a shard carries (`shard_object`): the envelope's `object`, or
/// a legacy raw shard itself.
fn shard_object(body: &JsonValue) -> &JsonValue {
    if is_wrapped(body)
        && let Some(object) = body.get("object").filter(|object| object.is_object())
    {
        return object;
    }
    body
}

fn json_text(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::String(text) if !text.is_empty() => Some(text.clone()),
        JsonValue::Null | JsonValue::String(_) | JsonValue::Bool(false) => None,
        JsonValue::Array(items) if items.is_empty() => None,
        JsonValue::Object(map) if map.is_empty() => None,
        other => Some(other.to_string()),
    }
}

/// An object's UUID: `uuid`, else `metadata.uuid`.
fn object_uuid(object: &JsonValue) -> Option<String> {
    object
        .get("uuid")
        .and_then(json_text)
        .or_else(|| object.get("metadata")?.get("uuid").and_then(json_text))
}

/// An object's family (`_object_family`): its schema's, else by the block it
/// has.
fn object_family(object: &JsonValue) -> Option<String> {
    if let Some(schema) = object
        .get("metadata")
        .and_then(|metadata| metadata.get("schema"))
        .and_then(JsonValue::as_str)
        && let Some((family, _)) = schema.split_once("::")
    {
        return Some(family.to_owned());
    }
    let has = |key: &str| object.get(key).and_then(json_text).is_some();
    if has("threat") {
        Some("threat".to_owned())
    } else if has("objective") {
        Some("objective".to_owned())
    } else if has("configurations") {
        Some("rule".to_owned())
    } else {
        None
    }
}

/// `int()` of a version, 0 when it is not one.
fn version_number(text: &str) -> i64 {
    text.trim().replace('_', "").parse().unwrap_or(0)
}

fn json_version(object: &JsonValue) -> i64 {
    match object
        .get("metadata")
        .and_then(|metadata| metadata.get("version"))
    {
        Some(JsonValue::Number(number)) => number
            .as_i64()
            .or_else(|| {
                #[expect(clippy::cast_possible_truncation, reason = "int() truncates")]
                number.as_f64().map(|float| float.trunc() as i64)
            })
            .unwrap_or(0),
        Some(JsonValue::String(text)) => version_number(text),
        Some(JsonValue::Bool(flag)) => i64::from(*flag),
        _ => 0,
    }
}

fn node_version(root: &Node) -> i64 {
    match root
        .get("metadata")
        .and_then(|metadata| metadata.get("version"))
        .map(|node| &node.value)
    {
        Some(Value::Int(number)) => *number,
        #[expect(clippy::cast_possible_truncation, reason = "int() truncates")]
        Some(Value::Float(float)) => float.trunc() as i64,
        Some(Value::Str(text)) => version_number(text),
        Some(Value::Bool(flag)) => i64::from(*flag),
        _ => 0,
    }
}

/// The shards of `folder` by object UUID, a later file winning
/// (`load_inflight_shards`): files that are not JSON objects are skipped.
fn shards(folder: &Path) -> IndexMap<String, (std::path::PathBuf, JsonValue)> {
    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(folder)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json") && path.is_file())
        .collect();
    paths.sort();
    let mut found = IndexMap::new();
    for path in paths {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(body) = serde_json::from_str::<JsonValue>(&text) else {
            continue;
        };
        if !body.is_object() {
            continue;
        }
        if let Some(uuid) = object_uuid(shard_object(&body)) {
            found.insert(uuid, (path, body));
        }
    }
    found
}

/// `index` with the shards of `folder` overlaid, or `None` when there are
/// none to apply: a shard adds an object, or replaces one of a lower
/// version, or of the same version when it is an envelope.
pub fn overlay(index: &Index, folder: &Path) -> Option<Index> {
    let shards = shards(folder);
    if shards.is_empty() {
        return None;
    }
    let mut overlaid = index.clone();
    let mut changed = false;
    let mut objectives = Vec::new();
    for (uuid, (path, shard)) in shards {
        let object = shard_object(&shard);
        let Some(family) = object_family(object) else {
            continue;
        };
        let Some(bucket) = overlaid.objects.get(&family) else {
            continue;
        };
        let replace = match bucket.get(&uuid).and_then(|existing| existing.root()) {
            None => true,
            Some(existing) => {
                let (candidate, current) = (json_version(object), node_version(existing));
                candidate > current || (candidate == current && is_wrapped(&shard))
            }
        };
        if !replace {
            continue;
        }
        // JSON is YAML: the object is read as any object file is.
        let Ok(document) = load(&object.to_string()) else {
            continue;
        };
        if overlaid.overlay(&family, &uuid, path, Arc::new(document)) {
            changed = true;
            if family == "objective" {
                objectives.push(uuid);
            }
        }
    }
    if !changed {
        return None;
    }
    overlaid.reindex_signals(&objectives);
    overlaid.refresh_references();
    Some(overlaid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_uuids_and_versions() {
        let wrapped = serde_json::json!({
            "schema": "inflight.shard::1.0",
            "object": {"name": "x", "metadata": {"uuid": "u", "schema": "rule::1.1", "version": "3"}}
        });
        let object = shard_object(&wrapped);
        assert!(is_wrapped(&wrapped));
        assert_eq!(object_uuid(object).as_deref(), Some("u"));
        assert_eq!(object_family(object).as_deref(), Some("rule"));
        assert_eq!(json_version(object), 3);
        let raw =
            serde_json::json!({"uuid": "v", "threat": {"a": 1}, "metadata": {"version": 2.7}});
        assert!(!is_wrapped(&raw));
        assert_eq!(object_family(shard_object(&raw)).as_deref(), Some("threat"));
        assert_eq!(json_version(&raw), 2);
        assert_eq!(version_number("x"), 0);
        assert_eq!(version_number(" 4 "), 4);
    }
}
