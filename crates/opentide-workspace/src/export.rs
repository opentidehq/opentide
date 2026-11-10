//! The index as one JSON document, the form `cargo xtask registry diff`
//! compares with the Python registry's (`xtask/oracle/registry_export.py`
//! writes the oracle's side in the same shape).
//!
//! Paths are relative to the workspace, `/` separated; a path outside it is
//! written whole. Bodies are the documents as JSON (a float JSON cannot hold
//! as `inf`, `-inf` or `nan`).

use std::path::Path;

use opentide_schema::configuration::merge::to_json;
use serde_json::{Map, Value as Json, json};

use crate::index::{Index, posix};

fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .map_or_else(|_| path.to_string_lossy().into_owned(), posix)
}

impl Index {
    /// The index as JSON, paths relative to `root`.
    pub fn to_json(&self, root: &Path) -> Json {
        let mut objects = Map::new();
        let mut bodies = Map::new();
        for (family, members) in &self.objects {
            objects.insert(
                family.clone(),
                Json::Array(members.keys().map(|uuid| json!(uuid)).collect()),
            );
            bodies.insert(
                family.clone(),
                Json::Object(
                    members
                        .values()
                        .map(|object| {
                            (
                                object.uuid.clone(),
                                object.root().map_or(Json::Null, to_json),
                            )
                        })
                        .collect(),
                ),
            );
        }
        let signals: Map<String, Json> = self
            .signals
            .values()
            .map(|signal| {
                let mut body = to_json(&signal.node);
                if let Json::Object(map) = &mut body {
                    map.insert(
                        crate::index::SIGNAL_OWNER_FIELD.to_owned(),
                        json!(signal.owner),
                    );
                }
                (signal.uuid.clone(), body)
            })
            .collect();
        json!({
            "objects": objects,
            "bodies": bodies,
            "file_paths": self
                .file_paths
                .iter()
                .map(|(uuid, path)| (uuid.clone(), json!(relative(path, root))))
                .collect::<Map<String, Json>>(),
            "files": self
                .files()
                .into_iter()
                .map(|(uuid, name)| (uuid, json!(name)))
                .collect::<Map<String, Json>>(),
            "signals": signals,
            "load_errors": self.load_errors.iter().map(|error| json!({
                "path": relative(&error.path, root),
                "object_type": error.family,
                "code": error.code,
                "error": error.error,
                "message": error.message(),
            })).collect::<Vec<_>>(),
            "duplicates": self.duplicates.iter().map(|duplicate| json!({
                "path": relative(&duplicate.path, root),
                "object_type": duplicate.family,
                "code": crate::index::DUPLICATE_ID,
                "message": duplicate.message,
            })).collect::<Vec<_>>(),
            "nested": self.nested.iter().map(|nested| json!({
                "path": relative(&nested.path, root),
                "folder": relative(&nested.folder, root),
                "object_type": nested.family,
            })).collect::<Vec<_>>(),
            "references": self.references.iter().map(|reference| json!([
                reference.from,
                reference.kind.name(),
                reference.target,
            ])).collect::<Vec<_>>(),
            "chaining": self.chaining,
        })
    }
}
