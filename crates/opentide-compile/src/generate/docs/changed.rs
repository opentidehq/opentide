//! `generate docs --changed`: the objects whose files changed against the
//! default branch, and the pages to write for them (`documentation/cli.py`
//! `_changed_object_paths_and_uuids`, `_expand_referrer_closure`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use opentide_schema::node::{Node, Value, load};

use super::catalog::{Catalog, Direction, Scope};
use crate::git::ChangedFile;

/// What changed, and the pages a run writes for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    /// The changed object files, from the git top level.
    pub paths: Vec<String>,
    /// The UUIDs of the changed objects that still exist.
    pub uuids: BTreeSet<String>,
    /// The catalogue's objects whose pages are rewritten.
    pub targets: BTreeSet<String>,
}

/// Whether `name` is an object file: `*.yaml` or `*.yml`, case-sensitive,
/// not a `*.debug.yaml` (`is_object_file_name`).
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "case-sensitive as the catalogue reads object files: `r.YAML` is no object"
)]
pub fn is_object_file(name: &str) -> bool {
    (name.ends_with(".yaml") || name.ends_with(".yml"))
        && !(name.ends_with(".debug.yaml") || name.ends_with(".debug.yml"))
}

/// An object's UUID and name, from its top level or its metadata.
fn uuid_and_name(node: Option<&Node>) -> (Option<String>, Option<String>) {
    let Some(node) = node.filter(|node| matches!(node.value, Value::Map(_))) else {
        return (None, None);
    };
    let metadata = node.get("metadata");
    let field = |key: &str| -> Option<String> {
        let top = node.get(key).and_then(|value| value.value.as_str());
        let nested = metadata
            .and_then(|metadata| metadata.get(key))
            .and_then(|value| value.value.as_str());
        top.filter(|text| !text.is_empty())
            .or(nested)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    };
    (field("uuid"), field("name"))
}

fn parse(bytes: &[u8]) -> Option<std::sync::Arc<Node>> {
    let text = std::str::from_utf8(bytes).ok()?;
    load(text).ok()?.root().cloned()
}

/// The pages to rewrite for `files`, the object files git reports as
/// changed: each changed object's, its upstream referrers' (a parent shows
/// its children), and a renamed object's downstream referrers' (its page
/// moved).
pub fn changes(catalog: &Catalog<'_>, files: &[ChangedFile]) -> Changes {
    let mut changes = Changes::default();
    let mut previous_names: BTreeMap<String, String> = BTreeMap::new();
    for file in files {
        changes.paths.push(file.relative.clone());
        let baseline = file.baseline.as_deref().and_then(parse);
        let exists = file.absolute.exists();
        if exists {
            let current = std::fs::read(&file.absolute)
                .ok()
                .and_then(|bytes| parse(&bytes));
            if let (Some(uuid), _) = uuid_and_name(current.as_deref()) {
                changes.uuids.insert(uuid);
            }
        }
        if let (Some(uuid), Some(name)) = uuid_and_name(baseline.as_deref()) {
            previous_names.insert(uuid, name);
        }
    }
    let renamed: BTreeSet<&String> = previous_names
        .iter()
        .filter(|(uuid, name)| {
            catalog
                .record(uuid)
                .is_some_and(|record| &record.name != *name)
        })
        .map(|(uuid, _)| uuid)
        .collect();
    let mut closure: BTreeSet<String> = changes.uuids.clone();
    let walks = changes
        .uuids
        .iter()
        .map(|uuid| (uuid.clone(), Direction::Upstream))
        .chain(
            renamed
                .iter()
                .map(|uuid| ((*uuid).clone(), Direction::Downstream)),
        );
    for (uuid, direction) in walks {
        let Ok(flat) = catalog.flat(&uuid, direction) else {
            continue;
        };
        for related in flat.into_values().flatten() {
            if catalog
                .kind(&related)
                .is_ok_and(|kind| Scope::of_type(&kind).is_some())
            {
                closure.insert(related);
            }
        }
    }
    changes.targets = closure
        .into_iter()
        .filter(|uuid| catalog.record(uuid).is_some())
        .collect();
    changes.paths.sort();
    changes
}

/// The folders of the object families: the paths `--changed` reads.
pub fn folders(configuration: &opentide_workspace::config::Configuration) -> Vec<PathBuf> {
    ["rule", "objective", "threat"]
        .iter()
        .filter_map(|family| configuration.folder(family).map(PathBuf::from))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_files() {
        assert!(is_object_file("a.yaml"));
        assert!(!is_object_file("a.YML"));
        assert!(!is_object_file("a.debug.yaml"));
        assert!(!is_object_file("a.md"));
    }

    #[test]
    fn uuid_and_name_from_the_top_or_the_metadata() {
        let node = load("name: N\nmetadata:\n  uuid: u\n").unwrap();
        assert_eq!(
            uuid_and_name(node.root().map(AsRef::as_ref)),
            (Some("u".to_owned()), Some("N".to_owned()))
        );
        let node = load("- x\n").unwrap();
        assert_eq!(uuid_and_name(node.root().map(AsRef::as_ref)), (None, None));
    }
}
