//! The per-key lifecycle merge of an upstream snapshot into a vocabulary
//! (RFC 0003; `opentide.vocabulary.lifecycle`):
//!
//! - a new identity gets one introducing minor for this cycle (`1.0` on the
//!   first fill of an empty vocabulary);
//! - an identity that disappears gets `removed` at the next major;
//! - a description, name, link or alias edit keeps the key's `version`;
//! - a key without `version` is backfilled to `1.0`;
//! - an identity repeated upstream keeps its first entry, so sources are
//!   listed in priority order.

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use indexmap::IndexMap;

use super::value::{Table, Value, py_strip, tables_eq};

/// The version of a key that names none.
pub const DEFAULT_VERSION: &str = "1.0";
/// The key metadata the payload comparison leaves out.
const SKIP: [&str; 2] = ["version", "removed"];

/// What a merge did.
#[derive(Debug, Clone)]
pub struct Lifecycle {
    /// The merged keys, existing ones first in their order, then the new.
    pub keys: Vec<Table>,
    /// New identities, sorted.
    pub added: Vec<String>,
    /// Identities whose payload changed or that came back, sorted.
    pub updated: Vec<String>,
    /// Identities that disappeared this cycle, sorted.
    pub removed: Vec<String>,
    /// Identities whose missing `version` was set to `1.0`, sorted.
    pub backfilled: Vec<String>,
    /// The minor new keys got, when there were any.
    pub introducing_version: Option<String>,
    /// The major removed keys got, when there were any.
    pub removal_version: Option<String>,
}

impl Lifecycle {
    /// Whether the merged keys differ from the previous ones.
    pub fn dirty(&self) -> bool {
        !(self.added.is_empty()
            && self.updated.is_empty()
            && self.removed.is_empty()
            && self.backfilled.is_empty())
    }

    /// The minor contract this merge opened by adding keys to a populated
    /// vocabulary; no schema revision pins it yet. A first fill opens none.
    pub fn new_contract(&self) -> Option<&str> {
        if self.added.is_empty() {
            return None;
        }
        self.introducing_version
            .as_deref()
            .filter(|version| *version != DEFAULT_VERSION)
    }
}

/// A key's identity: `str(entry[key_field]).strip()`, `None` when absent or
/// blank.
pub fn identity(entry: &Table, key_field: &str) -> Result<Option<String>> {
    let Some(value) = entry.get(key_field) else {
        return Ok(None);
    };
    let text = value.py_str()?;
    let text = py_strip(&text);
    Ok((!text.is_empty()).then(|| text.to_owned()))
}

/// Python's `int()` of a version part: surrounding white space, a sign and
/// digit-separating underscores allowed.
fn py_int(text: &str) -> Result<i64> {
    let trimmed = py_strip(text);
    let body = trimmed.trim_start_matches(['+', '-']);
    let valid = !body.is_empty()
        && !body.starts_with('_')
        && !body.ends_with('_')
        && !body.contains("__")
        && body.chars().all(|c| c.is_ascii_digit() || c == '_');
    anyhow::ensure!(
        valid && trimmed.len() - body.len() <= 1,
        "invalid literal for int() with base 10: {text:?}"
    );
    Ok(trimmed.replace('_', "").parse()?)
}

/// `major.minor` (or a bare major) as numbers (`parse_semver`).
pub fn parse_version(version: &str) -> Result<(i64, i64)> {
    match version.split_once('.') {
        Some((major, minor)) => Ok((py_int(major)?, py_int(minor)?)),
        None => Ok((py_int(version)?, 0)),
    }
}

/// A key's `(major, minor)`, `1.0` when it names none.
fn entry_version(entry: &Table) -> Result<(i64, i64)> {
    let raw = match entry.get("version").filter(|value| value.truthy()) {
        Some(value) => value.py_str()?,
        None => DEFAULT_VERSION.to_owned(),
    };
    parse_version(&raw).with_context(|| format!("version {raw:?}"))
}

fn payload(entry: &Table) -> Table {
    entry
        .iter()
        .filter(|(key, _)| !SKIP.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// `entries` by identity, the first entry of a repeated identity kept.
fn index(entries: &[Table], key_field: &str) -> Result<IndexMap<String, Table>> {
    let mut indexed: IndexMap<String, Table> = IndexMap::new();
    for entry in entries {
        if let Some(identity) = identity(entry, key_field)? {
            indexed.entry(identity).or_insert_with(|| entry.clone());
        }
    }
    Ok(indexed)
}

fn sorted(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Merges `upstream` into `existing` (`merge_vocab_keys`).
pub fn merge(existing: &[Table], upstream: &[Table], key_field: &str) -> Result<Lifecycle> {
    let existing_index = index(existing, key_field)?;
    let upstream_index = index(upstream, key_field)?;

    let has_new = upstream_index
        .keys()
        .any(|identity| !existing_index.contains_key(identity));
    let mut points = existing_index
        .values()
        .map(entry_version)
        .collect::<Result<Vec<_>>>()?;
    let introducing_version = if !has_new {
        None
    } else if let Some((major, minor)) = points.iter().max() {
        Some(format!("{major}.{}", minor + 1))
    } else {
        Some(DEFAULT_VERSION.to_owned())
    };
    if let Some(version) = &introducing_version {
        points.push(parse_version(version)?);
    }
    let next_major = points.iter().map(|(major, _)| *major).max().unwrap_or(1) + 1;
    let removal_version = format!("{next_major}.0");

    let mut added = Vec::new();
    let mut updated = Vec::new();
    let mut removed = Vec::new();
    let mut backfilled = Vec::new();
    let mut result = Vec::new();

    for (identity, old) in &existing_index {
        let mut merged = old.clone();
        let version = match old.get("version").filter(|value| value.truthy()) {
            Some(value) => value.py_str()?,
            None => {
                backfilled.push(identity.clone());
                DEFAULT_VERSION.to_owned()
            }
        };
        merged.insert("version".to_owned(), Value::str(version.clone()));

        if let Some(incoming) = upstream_index.get(identity) {
            let mut incoming = incoming.clone();
            incoming.insert("version".to_owned(), Value::str(version));
            let revived = old.get("removed").is_some_and(Value::truthy);
            incoming.shift_remove("removed");
            if revived || !tables_eq(&payload(&incoming), &payload(old)) {
                updated.push(identity.clone());
            }
            result.push(incoming);
            continue;
        }

        if !merged.get("removed").is_some_and(Value::truthy) {
            merged.insert("removed".to_owned(), Value::str(removal_version.clone()));
            removed.push(identity.clone());
        }
        result.push(merged);
    }

    for (identity, incoming) in &upstream_index {
        if existing_index.contains_key(identity) {
            continue;
        }
        let mut entry = incoming.clone();
        entry.insert(
            "version".to_owned(),
            Value::str(
                introducing_version
                    .clone()
                    .unwrap_or_else(|| DEFAULT_VERSION.to_owned()),
            ),
        );
        entry.shift_remove("removed");
        result.push(entry);
        added.push(identity.clone());
    }

    let removal_version = (!removed.is_empty()).then_some(removal_version);
    Ok(Lifecycle {
        keys: result,
        added: sorted(added),
        updated: sorted(updated),
        removed: sorted(removed),
        backfilled: sorted(backfilled),
        introducing_version,
        removal_version,
    })
}

#[cfg(test)]
mod tests {
    use super::super::value::parse_json;
    use super::*;

    fn tables(json: &str) -> Vec<Table> {
        parse_json(json.as_bytes())
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_table().unwrap().clone())
            .collect()
    }

    fn ids(keys: &[Table], field: &str) -> Vec<String> {
        keys.iter()
            .map(|key| {
                key.get(field)
                    .map(|v| v.py_str().unwrap())
                    .unwrap_or_default()
            })
            .collect()
    }

    #[test]
    fn a_first_fill_is_version_one_and_opens_no_contract() {
        let merged = merge(
            &[],
            &tables(r#"[{"id": "A"}, {"id": "B"}, {"id": "A", "name": "dup"}]"#),
            "id",
        )
        .unwrap();
        assert_eq!(ids(&merged.keys, "version"), ["1.0", "1.0"]);
        assert_eq!(merged.added, ["A", "B"]);
        assert!(
            !merged.keys[0].contains_key("name"),
            "the first of a repeated identity wins"
        );
        assert_eq!(merged.new_contract(), None);
        assert!(merged.dirty());
    }

    #[test]
    fn new_keys_open_the_next_minor_and_gone_keys_are_removed_at_the_next_major() {
        let existing = tables(
            r#"[{"id": "A", "name": "a", "version": "1.1"},
                {"id": "B", "name": "b"},
                {"id": "C", "name": "c", "version": "1.0", "removed": "2.0"},
                {"id": " ", "name": "blank"}]"#,
        );
        let upstream = tables(
            r#"[{"id": "N", "name": "n"}, {"id": "A", "name": "a2"}, {"id": "C", "name": "c"}]"#,
        );
        let merged = merge(&existing, &upstream, "id").unwrap();
        assert_eq!(ids(&merged.keys, "id"), ["A", "B", "C", "N"]);
        assert_eq!(ids(&merged.keys, "version"), ["1.1", "1.0", "1.0", "1.2"]);
        assert_eq!(ids(&merged.keys, "removed"), ["", "2.0", "", ""]);
        assert_eq!(merged.updated, ["A", "C"], "an edit and a revival");
        assert_eq!(merged.removed, ["B"]);
        assert_eq!(merged.backfilled, ["B"]);
        assert_eq!(merged.new_contract(), Some("1.2"));
        assert_eq!(merged.removal_version.as_deref(), Some("2.0"));
        assert_eq!(
            merged.keys[0].keys().collect::<Vec<_>>(),
            ["id", "name", "version"],
            "an upstream entry takes its version last"
        );
    }

    #[test]
    fn an_unchanged_snapshot_is_clean() {
        let existing = tables(r#"[{"name": "x", "description": "d", "version": "1.3"}]"#);
        let upstream = tables(r#"[{"description": "d", "name": "x"}]"#);
        let merged = merge(&existing, &upstream, "name").unwrap();
        assert!(!merged.dirty());
        assert_eq!(merged.removal_version, None);
    }

    #[test]
    fn versions_parse_as_python_int_does() {
        assert_eq!(parse_version("1.2").unwrap(), (1, 2));
        assert_eq!(parse_version(" 3 ").unwrap(), (3, 0));
        assert_eq!(parse_version("1_0.+2").unwrap(), (10, 2));
        assert!(parse_version("1.x").is_err());
        assert!(parse_version("1.2.3").is_err());
    }
}
