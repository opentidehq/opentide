//! The index as one JSON document: what the loading tests compare a full
//! load with an incremental one by (and what the retired `cargo xtask
//! registry diff` compared with the Python registry's export). Test support: the product crate carries no export of its own.
//!
//! Paths are relative to the workspace, `/` separated; a path outside it is
//! written whole. Bodies are the documents as JSON (a float JSON cannot hold
//! as `inf`, `-inf` or `nan`). Each signal's body carries `owner`, the
//! objective it is defined in ([`SIGNAL_OWNER_FIELD`]).

use std::path::Path;

use opentide_schema::configuration::merge::to_json;
use opentide_workspace::Index;
use opentide_workspace::index::{DUPLICATE_ID, SIGNAL_OWNER_FIELD, posix};
use serde_json::{Map, Value as Json, json};

fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .map_or_else(|_| path.to_string_lossy().into_owned(), posix)
}

/// `index` as JSON, paths relative to `root`.
pub fn index_json(index: &Index, root: &Path) -> Json {
    let mut objects = Map::new();
    let mut bodies = Map::new();
    for (family, members) in &index.objects {
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
    let signals: Map<String, Json> = index
        .signals
        .values()
        .map(|signal| {
            let mut body = to_json(&signal.node);
            if let Json::Object(map) = &mut body {
                map.insert(SIGNAL_OWNER_FIELD.to_owned(), json!(signal.owner));
            }
            (signal.uuid.clone(), body)
        })
        .collect();
    json!({
        "objects": objects,
        "bodies": bodies,
        "file_paths": index
            .file_paths
            .iter()
            .map(|(uuid, path)| (uuid.clone(), json!(relative(path, root))))
            .collect::<Map<String, Json>>(),
        "files": index
            .files()
            .into_iter()
            .map(|(uuid, name)| (uuid, json!(name)))
            .collect::<Map<String, Json>>(),
        "signals": signals,
        "load_errors": index.load_errors.iter().map(|error| json!({
            "path": relative(&error.path, root),
            "object_type": error.family,
            "code": error.code,
            "error": error.error,
            "message": error.message(),
        })).collect::<Vec<_>>(),
        "duplicates": index.duplicates.iter().map(|duplicate| json!({
            "path": relative(&duplicate.path, root),
            "object_type": duplicate.family,
            "code": DUPLICATE_ID,
            "message": duplicate.message,
        })).collect::<Vec<_>>(),
        "nested": index.nested.iter().map(|nested| json!({
            "path": relative(&nested.path, root),
            "folder": relative(&nested.folder, root),
            "object_type": nested.family,
        })).collect::<Vec<_>>(),
        "references": index.references.iter().map(|reference| json!([
            reference.from,
            reference.kind.name(),
            reference.target,
        ])).collect::<Vec<_>>(),
        "chaining": index.chaining,
    })
}
