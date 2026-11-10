//! Inflight preview shards (`indexing/inflight.py`, `inflight_shard.py`):
//! open pull requests' objects, one `<uuid>.json` per object under
//! `.opentide/inflight/`, published to the default branch so the explorer
//! and the documentation can preview them.
//!
//! A shard is an envelope (`schema: inflight.shard::1.0`, `written_at`,
//! `object`, `change`) or, from before the envelope, the object itself.
//! [`overlay`] lays them over an index, version-gated: a shard replaces the
//! committed object when its `metadata.version` is higher, or equal and the
//! shard is an envelope.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use indexmap::IndexMap;
use opentide_schema::node::{Document, Node, Value};
use opentide_workspace::Index;

use super::json_text::line;
use super::relations::py_str;
use crate::json::Json;

/// The envelope's schema.
pub const SHARD_SCHEMA: &str = "inflight.shard::1.0";

/// One shard file that parsed.
#[derive(Debug, Clone)]
pub struct Shard {
    /// The file.
    pub path: PathBuf,
    /// What it holds.
    pub document: Arc<Document>,
}

impl Shard {
    /// The shard's root mapping.
    pub fn root(&self) -> Option<&Node> {
        self.document
            .root()
            .map(AsRef::as_ref)
            .filter(|root| matches!(root.value, Value::Map(_)))
    }

    /// Whether it is an envelope (`is_wrapped_shard`).
    pub fn is_wrapped(&self) -> bool {
        self.root()
            .and_then(|root| root.get("schema"))
            .and_then(|schema| schema.value.as_str())
            .is_some_and(|schema| schema.starts_with("inflight.shard"))
    }

    /// The object it carries (`shard_object`): an envelope's `object`, or the
    /// shard itself.
    pub fn object(&self) -> Option<&Node> {
        let root = self.root()?;
        if self.is_wrapped()
            && let Some(object) = root.get("object")
            && matches!(object.value, Value::Map(_))
        {
            return Some(object);
        }
        Some(root)
    }
}

/// `int(metadata.version)`, 0 when it is missing or not a number
/// (`_object_version`).
pub fn object_version(body: &Node) -> i64 {
    let Some(metadata) = body
        .get("metadata")
        .filter(|m| matches!(m.value, Value::Map(_)))
    else {
        return 0;
    };
    match metadata.get("version").map(|version| &version.value) {
        Some(Value::Int(version)) => *version,
        #[expect(
            clippy::cast_possible_truncation,
            reason = "int() of a float truncates toward zero, as this cast does; out of range saturates"
        )]
        Some(Value::Float(version)) if version.is_finite() => version.trunc() as i64,
        Some(Value::Bool(flag)) => i64::from(*flag),
        Some(Value::Str(text)) => text.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

/// An object's UUID (`_object_uuid`): `uuid`, else `metadata.uuid`.
pub fn object_uuid(body: &Node) -> Option<String> {
    let truthy = |node: &&Arc<Node>| opentide_workspace::index::truthy(node);
    body.get("uuid")
        .filter(truthy)
        .or_else(|| {
            body.get("metadata")
                .filter(|m| matches!(m.value, Value::Map(_)))
                .and_then(|metadata| metadata.get("uuid"))
                .filter(truthy)
        })
        .map(|uuid| py_str(uuid))
}

/// The family an object says it is (`_object_family`): its schema's prefix,
/// else the first section it has.
pub fn object_family(body: &Node) -> Option<String> {
    if let Some(schema) = body
        .get("metadata")
        .filter(|m| matches!(m.value, Value::Map(_)))
        .and_then(|metadata| metadata.get("schema"))
        .and_then(|schema| schema.value.as_str())
        && schema.contains("::")
    {
        return schema.split("::").next().map(str::to_owned);
    }
    let has = |key: &str| {
        body.get(key)
            .is_some_and(|value| opentide_workspace::index::truthy(value))
    };
    if has("threat") {
        Some("threat".into())
    } else if has("objective") {
        Some("objective".into())
    } else if has("configurations") {
        Some("rule".into())
    } else {
        None
    }
}

/// The shard files of `dir` that parse, by the UUID of the object each
/// carries, in file name order (`load_inflight_shards`): a later file with
/// the same UUID replaces an earlier one. A file that is not JSON is
/// skipped.
pub fn load(dir: &Path) -> IndexMap<String, Shard> {
    let mut shards = IndexMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return shards;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json") && path.is_file())
        .collect();
    paths.sort();
    for path in paths {
        let Some(document) = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| parse(&text))
        else {
            tracing::warn!(path = %path.display(), "inflight_shard_invalid_json");
            continue;
        };
        let shard = Shard {
            path,
            document: Arc::new(document),
        };
        if let Some(uuid) = shard.object().and_then(object_uuid) {
            shards.insert(uuid, shard);
        }
    }
    shards
}

/// A JSON document, as a node tree in its keys' order.
fn parse(text: &str) -> Option<Document> {
    serde_json::from_str::<serde::de::IgnoredAny>(text).ok()?;
    opentide_schema::node::load(text).ok()
}

/// Whether `shard` replaces `existing` (`should_replace_object`).
fn replaces(existing: &Node, shard: &Shard, object: &Node) -> bool {
    let (current, candidate) = (object_version(existing), object_version(object));
    candidate > current || (candidate == current && shard.is_wrapped())
}

/// `index` with `shards` laid over it (`apply_inflight_overlay`): a shard of
/// a family the index has replaces the committed object or adds one; the
/// signals of every objective a shard replaced are indexed again once all are
/// in place.
pub fn overlay(index: &Index, shards: &IndexMap<String, Shard>) -> Index {
    let mut overlaid = index.clone();
    let mut objectives = Vec::new();
    for (uuid, shard) in shards {
        let Some(object) = shard.object() else {
            continue;
        };
        let Some(family) = object_family(object).filter(|f| overlaid.objects.contains_key(f))
        else {
            tracing::warn!(uuid, "inflight_skip_unknown_family");
            continue;
        };
        let bucket = overlaid.objects.entry(family.clone()).or_default();
        if let Some(existing) = bucket.get(uuid).and_then(opentide_workspace::Object::root)
            && !replaces(existing, shard, object)
        {
            continue;
        }
        // The object as a document of its own, read back from its JSON.
        let Ok(document) = opentide_schema::node::load(&line(&Json::from_node(object))) else {
            continue;
        };
        bucket.insert(
            uuid.clone(),
            opentide_workspace::Object {
                uuid: uuid.clone(),
                family: family.clone(),
                path: shard.path.clone(),
                document: Arc::new(document),
            },
        );
        if family == "objective" {
            objectives.push(uuid.clone());
        }
    }
    if !objectives.is_empty() {
        overlaid.reindex_signals(&objectives);
    }
    overlaid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_of(objects: &[(&str, &str, &str)]) -> Index {
        let mut index = Index::default();
        for (family, uuid, text) in objects {
            index
                .objects
                .entry((*family).to_owned())
                .or_default()
                .insert(
                    (*uuid).to_owned(),
                    opentide_workspace::Object {
                        uuid: (*uuid).to_owned(),
                        family: (*family).to_owned(),
                        path: PathBuf::from(format!("{uuid}.yaml")),
                        document: Arc::new(opentide_schema::node::load(text).unwrap()),
                    },
                );
        }
        let objectives: Vec<String> = index
            .objects
            .get("objective")
            .map(|objects| objects.keys().cloned().collect())
            .unwrap_or_default();
        index.reindex_signals(&objectives);
        index
    }

    fn write(dir: &Path, name: &str, text: &str) {
        std::fs::write(dir.join(name), text).unwrap();
    }

    #[test]
    fn versions_read_as_python_int_reads_them() {
        let version =
            |text: &str| object_version(opentide_schema::node::load(text).unwrap().root().unwrap());
        assert_eq!(version("metadata: {version: 3}"), 3);
        assert_eq!(version("metadata: {version: '4'}"), 4);
        assert_eq!(version("metadata: {version: 2.9}"), 2);
        assert_eq!(version("metadata: {version: x}"), 0);
        assert_eq!(version("metadata: {}"), 0);
        assert_eq!(version("name: x"), 0);
    }

    #[test]
    fn shards_replace_older_objects_and_move_signals() {
        let dir = tempfile::tempdir().unwrap();
        let index = index_of(&[
            (
                "objective",
                "o1",
                "metadata: {uuid: o1, version: 1}\nobjective: {signals: [{uuid: s1}]}\n",
            ),
            (
                "objective",
                "o2",
                "metadata: {uuid: o2, version: 5}\nobjective: {}\n",
            ),
            (
                "rule",
                "r1",
                "metadata: {uuid: r1, version: 2}\nconfigurations: {a: {}}\n",
            ),
        ]);
        // o1 drops s1, o2 now defines it: whichever is applied first.
        write(
            dir.path(),
            "a.json",
            r#"{"schema": "inflight.shard::1.0", "object": {"metadata": {"uuid": "o2", "version": 5}, "objective": {"signals": [{"uuid": "s1"}]}}}"#,
        );
        write(
            dir.path(),
            "b.json",
            r#"{"schema": "inflight.shard::1.0", "object": {"metadata": {"uuid": "o1", "version": 2}, "objective": {"signals": []}}}"#,
        );
        // A raw shard at the same version does not replace; a lower one never does.
        write(
            dir.path(),
            "c.json",
            r#"{"metadata": {"uuid": "r1", "version": 2}, "configurations": {"b": {}}}"#,
        );
        write(
            dir.path(),
            "d.json",
            r#"{"metadata": {"uuid": "r2", "version": 1}, "configurations": {"c": {}}}"#,
        );
        write(dir.path(), "e.json", "not json");
        write(
            dir.path(),
            "f.json",
            r#"{"metadata": {"uuid": "x1", "schema": "widget::1.0"}}"#,
        );
        let shards = load(dir.path());
        assert_eq!(
            shards.keys().collect::<Vec<_>>(),
            ["o2", "o1", "r1", "r2", "x1"]
        );
        let overlaid = overlay(&index, &shards);
        assert_eq!(overlaid.signals.get("s1").unwrap().owner, "o2");
        let rules: Vec<&String> = overlaid.objects["rule"].keys().collect();
        assert_eq!(rules, ["r1", "r2"]);
        assert!(
            overlaid.objects["rule"]["r1"]
                .root()
                .unwrap()
                .get("configurations")
                .unwrap()
                .get("a")
                .is_some()
        );
        assert!(!overlaid.objects.contains_key("widget"));
    }
}
