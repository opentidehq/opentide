//! The deployment state shards, read only (`states/deployment.py`): one
//! `<uuid>.json` per rule under `.opentide/states/deployment/`, each
//! `(platform, tenant)` bound to the id the platform gave the rule. A shard
//! that does not pass the oracle's checks is skipped here; `validate`
//! reports it.

use std::collections::HashMap;
use std::path::Path;

use indexmap::IndexMap;
use serde::Serialize;

use crate::fs::{EntryKind, FileSystem};

/// The `schema` a shard declares.
pub const SCHEMA_ID: &str = "deployment.state::1.0";
/// Platforms whose deployer addresses the remote rule by a vendor id, by
/// name ([`opentide_schema::platforms::state_platforms`]).
pub fn state_platforms() -> Vec<&'static str> {
    opentide_schema::platforms::state_platforms()
}
/// Whether a shard may bind *platform*'s rules to ids: a built-in platform
/// whose deployer addresses the remote rule by a vendor id
/// ([`state_platforms`]), or a platform plugin's (UC-4.5b, #835): an
/// identifier (lower case letters, digits and `_`, starting with a letter)
/// that no built-in platform has. Whether that plugin is installed where the
/// shard is read does not matter: the shard is the deploying run's record.
pub fn stores_ids(platform: &str) -> bool {
    opentide_schema::platforms::get(platform).is_some_and(|row| row.external_id.is_stored())
        || (!crate::validate::objects::PLATFORMS.contains(&platform)
            && platform.starts_with(|ch: char| ch.is_ascii_lowercase())
            && platform
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
}

/// One binding, as `info catalog` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Binding {
    /// The platform.
    pub platform: String,
    /// The tenant's name.
    pub tenant: String,
    /// Always `true`: a binding is a deployed rule.
    pub deployed: bool,
    /// The platform's id of the rule.
    pub rule_id: String,
}

/// Whether `text` is a UUID in lowercase canonical form
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
pub fn is_canonical_uuid(text: &str) -> bool {
    text.len() == 36
        && text.char_indices().all(|(position, ch)| match position {
            8 | 13 | 18 | 23 => ch == '-',
            _ => ch.is_ascii_digit() || ('a'..='f').contains(&ch),
        })
}

fn canonical_decimal(text: &str) -> bool {
    text == "0"
        || (text.starts_with(|ch: char| ('1'..='9').contains(&ch))
            && text.bytes().all(|byte| byte.is_ascii_digit()))
}

/// The bindings of one shard's text, or `None` when the oracle would refuse
/// it (`DeploymentState.from_file`).
fn parse(stem: &str, text: &str) -> Option<Vec<Binding>> {
    #[derive(serde::Deserialize)]
    struct Shard {
        schema: Option<serde_json::Value>,
        object_uuid: Option<serde_json::Value>,
        // Ordered as written: the tenants' order is the file's.
        platforms: Option<IndexMap<String, IndexMap<String, serde_json::Value>>>,
    }
    let shard: Shard = serde_json::from_str(text).ok()?;
    if shard.schema.as_ref().and_then(serde_json::Value::as_str) != Some(SCHEMA_ID)
        || shard
            .object_uuid
            .as_ref()
            .and_then(serde_json::Value::as_str)
            != Some(stem)
    {
        return None;
    }
    let platforms = shard.platforms?;
    let mut bindings = Vec::new();
    for (platform, tenants) in platforms {
        if !stores_ids(&platform) {
            return None;
        }
        for (tenant, id) in tenants {
            let serde_json::Value::String(id) = id else {
                return None;
            };
            if tenant.trim().is_empty()
                || tenant != tenant.trim()
                || id.trim().is_empty()
                || (opentide_schema::platforms::has_integer_id(&platform)
                    && !canonical_decimal(&id))
                || !opentide_schema::platforms::id_has_shape(&platform, &id)
            {
                return None;
            }
            bindings.push(Binding {
                platform: platform.clone(),
                tenant,
                deployed: true,
                rule_id: id,
            });
        }
    }
    Some(bindings)
}

/// Each rule's bindings, by its canonical UUID, from
/// `<workspace>/.opentide/states/deployment/*.json`. The folder is listed
/// once; a shard that cannot be used is skipped.
pub fn bindings(fs: &dyn FileSystem, workspace: &Path) -> HashMap<String, Vec<Binding>> {
    let folder = workspace
        .join(".opentide")
        .join("states")
        .join("deployment");
    let Ok(mut entries) = fs.read_dir(&folder) else {
        return HashMap::new();
    };
    entries.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    let mut out = HashMap::new();
    for entry in entries {
        let Some(stem) = entry.name.strip_suffix(".json") else {
            continue;
        };
        if entry.kind != EntryKind::File || !is_canonical_uuid(stem) {
            continue;
        }
        let Ok(bytes) = fs.read(&folder.join(&entry.file_name)) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if let Some(found) = parse(stem, text) {
            out.insert(stem.to_owned(), found);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryFs;

    const UUID: &str = "0b4d0e4e-1c33-4f53-8a6b-4c5b6e7f8a9b";

    #[test]
    fn shards_are_read_as_the_oracle_checks_them() {
        let fs = MemoryFs::new();
        let dir = Path::new("/ws/.opentide/states/deployment");
        fs.write(
            dir.join(format!("{UUID}.json")),
            format!(
                r#"{{"schema": "deployment.state::1.0", "object_uuid": "{UUID}", "platforms": {{"sentinel_one": {{"prod": "17", "dev": "4"}}, "crowdstrike": {{}}}}}}"#
            ),
        );
        // Each of these is skipped.
        let other = "1b4d0e4e-1c33-4f53-8a6b-4c5b6e7f8a9b";
        for (name, body) in [
            ("1B4D0E4E-1C33-4F53-8A6B-4C5B6E7F8A9B.json", String::new()),
            (
                &*format!("{other}.json"),
                format!(
                    r#"{{"schema": "deployment.state::1.0", "object_uuid": "{other}", "platforms": {{"sentinel_one": {{"p": "017"}}}}}}"#
                ),
            ),
            ("notes.json", "{}".to_owned()),
        ] {
            fs.write(dir.join(name), body);
        }
        let found = bindings(&fs, Path::new("/ws"));
        assert_eq!(found.len(), 1);
        let tenants: Vec<(&str, &str)> = found[UUID]
            .iter()
            .map(|b| (b.tenant.as_str(), b.rule_id.as_str()))
            .collect();
        assert_eq!(tenants, [("prod", "17"), ("dev", "4")]);
        assert!(bindings(&fs, Path::new("/nowhere")).is_empty());
    }

    #[test]
    fn a_plugins_ids_may_be_kept_but_not_a_builtin_platforms_without_state() {
        for platform in ["crowdstrike", "sysdig", "acme", "acme_2"] {
            assert!(stores_ids(platform), "{platform}");
        }
        for platform in [
            "sentinel", "splunk", "elastic", "Acme", "2acme", "ac-me", "",
        ] {
            assert!(!stores_ids(platform), "{platform}");
        }
        let fs = MemoryFs::new();
        fs.write(
            format!("/ws/.opentide/states/deployment/{UUID}.json"),
            format!(
                r#"{{"schema": "deployment.state::1.0", "object_uuid": "{UUID}", "platforms": {{"acme": {{"lab": "acme-rule-17"}}}}}}"#
            ),
        );
        let found = bindings(&fs, Path::new("/ws"));
        assert_eq!(found[UUID][0].platform, "acme");
        assert_eq!(found[UUID][0].rule_id, "acme-rule-17");
    }

    #[test]
    fn the_checks() {
        assert!(is_canonical_uuid(UUID));
        assert!(!is_canonical_uuid(&UUID.to_uppercase()));
        assert!(!is_canonical_uuid(&UUID.replace('-', "")));
        let shard = |platforms: &str| {
            parse(
                UUID,
                &format!(
                    r#"{{"schema": "deployment.state::1.0", "object_uuid": "{UUID}", "platforms": {platforms}}}"#
                ),
            )
        };
        assert!(shard(r#"{"elastic": {"t": "x"}}"#).is_none());
        assert!(shard(r#"{"crowdstrike": {" t": "x"}}"#).is_none());
        assert!(shard(r#"{"crowdstrike": {"t": 5}}"#).is_none());
        assert!(shard(r#"{"crowdstrike": {"t": " "}}"#).is_none());
        assert!(shard(r#"[]"#).is_none());
        assert_eq!(shard(r#"{"crowdstrike": {"t": "x-1"}}"#).unwrap().len(), 1);
        assert!(parse(UUID, "{}").is_none());
    }
}
