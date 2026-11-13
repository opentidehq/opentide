//! Deployment state shards (RFC 0010, `states/deployment.py`): the files
//! under `.opentide/states/deployment/` that hold each rule's vendor ids,
//! checked for shape, and the vendor-id keys a rule must no longer carry.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use opentide_schema::node::{Node, Value};
use opentide_schema::platforms::IdShape;
use opentide_schema::vocab::quote;
use serde_json::Value as Json;

use crate::fs::{EntryKind, FileSystem};

/// The shard's schema identifier.
pub const SCHEMA_ID: &str = "deployment.state::1.0";

/// Platform-block keys that used to carry the vendor id on the rule.
const LEGACY_MAP_KEYS: [&str; 2] = ["rule_id", "rule_id_bundle"];
const LEGACY_TENANT_PREFIX: &str = "rule_id::";

/// What `validate` says to do about a vendor id on a rule.
pub const MIGRATE_SUGGESTION: &str = "Run 'opentide deploy migrate-state' and commit the rule \
                                      together with .opentide/states/deployment/";

/// A shard, or the rule it belongs to, that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateError {
    /// `deployment_state_shape`, `deployment_state_uuid_mismatch`,
    /// `deployment_state_platform`.
    pub code: &'static str,
    /// What is wrong.
    pub message: String,
    /// The shard it is about, when one is.
    pub path: Option<PathBuf>,
}

impl StateError {
    fn new(code: &'static str, message: String, path: &Path) -> Self {
        Self {
            code,
            message,
            path: Some(path.to_path_buf()),
        }
    }

    fn shape(path: &Path, detail: &str) -> Self {
        Self::new(
            "deployment_state_shape",
            format!("{} {detail}", path.display()),
            path,
        )
    }
}

/// `rule_id`, `rule_id_bundle` or `rule_id::<tenant>`.
pub fn is_legacy_external_id_key(key: &str) -> bool {
    LEGACY_MAP_KEYS.contains(&key) || key.starts_with(LEGACY_TENANT_PREFIX)
}

/// Every `(platform, key)` that still carries a vendor id at a platform
/// block's root.
pub fn legacy_external_id_keys(rule: &Node) -> Vec<(String, String)> {
    let Some(Value::Map(platforms)) = rule.get("configurations").map(|node| &node.value) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for platform in platforms {
        let Value::Map(keys) = &platform.value.value else {
            continue;
        };
        for key in keys {
            if let Some(name) = key.key.value.as_str()
                && is_legacy_external_id_key(name)
            {
                found.push((platform.key.value.to_string(), name.to_owned()));
            }
        }
    }
    found
}

/// `metadata.uuid` in lowercase canonical form, or `None` when it is not a
/// UUID (Python's `uuid.UUID(str(value).strip())`, which also takes braces,
/// `urn:uuid:` and the unhyphenated form).
pub fn canonical_uuid(value: &str) -> Option<String> {
    uuid::Uuid::try_parse(value.trim())
        .ok()
        .map(|parsed| parsed.hyphenated().to_string())
}

/// `.opentide/states/deployment/` of `workspace`.
pub fn deployment_state_dir(workspace: &Path) -> PathBuf {
    workspace
        .join(".opentide")
        .join("states")
        .join("deployment")
}

fn shard_names(fs: &dyn FileSystem, directory: &Path) -> Vec<String> {
    fs.read_dir(directory)
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| entry.name)
                .filter(|name| name.to_lowercase().ends_with(".json"))
                .collect()
        })
        .unwrap_or_default()
}

fn stem_of(name: &str) -> &str {
    &name[..name.len() - ".json".len()]
}

/// The shard of rule `object_uuid`, checked (`DeploymentState.load`): `Ok`
/// when it is missing or usable.
///
/// # Errors
///
/// The shard, or another file naming the same rule, cannot be used.
pub fn check_shard(
    fs: &dyn FileSystem,
    workspace: &Path,
    object_uuid: &str,
) -> Result<(), Option<StateError>> {
    // Not a UUID: `invalid_uuid` already says so.
    let canonical = canonical_uuid(object_uuid).ok_or(None)?;
    let directory = deployment_state_dir(workspace);
    let name = format!("{canonical}.json");
    let path = directory.join(&name);
    let names = shard_names(fs, &directory);
    let mut variants: Vec<&String> = names
        .iter()
        .filter(|other| {
            *other != &name && canonical_uuid(stem_of(other)).as_deref() == Some(&canonical)
        })
        .collect();
    if !variants.is_empty() {
        variants.sort();
        let listed: Vec<&str> = variants.iter().map(|name| name.as_str()).collect();
        return Err(Some(StateError::new(
            "deployment_state_uuid_mismatch",
            format!(
                "{} holds {} for rule {canonical}; the only valid name is {name}. Merge the \
                 bindings into that file and delete the others",
                directory.display(),
                listed.join(", ")
            ),
            &path,
        )));
    }
    if !names.contains(&name) || !fs.is_file(&path) {
        return Ok(());
    }
    read_shard(fs, &path, Some(&canonical)).map_err(Some)
}

/// Every unusable file under `.opentide/states/deployment/`, orphans
/// included (`scan_deployment_states`).
pub fn scan(fs: &dyn FileSystem, workspace: &Path) -> Vec<StateError> {
    let root = deployment_state_dir(workspace);
    if !fs.is_dir(&root) {
        return Vec::new();
    }
    let mut files = Vec::new();
    walk(fs, &root, &mut files);
    files.sort();
    let mut errors = Vec::new();
    let mut by_uuid: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for path in files {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !name.to_lowercase().ends_with(".json") {
            continue;
        }
        if path.parent() != Some(root.as_path()) {
            errors.push(StateError::new(
                "deployment_state_uuid_mismatch",
                format!(
                    "{} is not directly in {}; deploy never reads it",
                    path.display(),
                    root.display()
                ),
                &path,
            ));
            continue;
        }
        if let Some(canonical) = canonical_uuid(stem_of(&name)) {
            by_uuid.entry(canonical).or_default().push(path.clone());
        }
        if let Err(error) = read_shard(fs, &path, None) {
            errors.push(error);
        }
    }
    for (canonical, paths) in by_uuid {
        let valid = root.join(format!("{canonical}.json"));
        if paths.len() > 1 && paths.contains(&valid) {
            let names: Vec<String> = paths
                .iter()
                .filter_map(|path| path.file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .collect();
            errors.push(StateError::new(
                "deployment_state_uuid_mismatch",
                format!(
                    "{} all name rule {canonical}; keep only {canonical}.json",
                    names.join(", ")
                ),
                &valid,
            ));
        }
    }
    errors
}

/// Every file under `dir`, recursively; linked folders are not entered.
fn walk(fs: &dyn FileSystem, dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs.read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = dir.join(&entry.file_name);
        match entry.kind {
            EntryKind::File => out.push(path),
            EntryKind::Dir if !entry.symlink => walk(fs, &path, out),
            _ => {}
        }
    }
}

/// Python's `type(value).__name__` for a JSON value.
fn type_name(value: &Json) -> &'static str {
    match value {
        Json::Null => "NoneType",
        Json::Bool(_) => "bool",
        Json::Number(number) if number.is_f64() => "float",
        Json::Number(_) => "int",
        Json::String(_) => "str",
        Json::Array(_) => "list",
        Json::Object(_) => "dict",
    }
}

/// A JSON value as the messages that quote one show it: a string quoted
/// as every message quotes one, anything else as its JSON (`null`, `true`).
fn shown(value: &Json) -> String {
    match value {
        Json::String(text) => quote(text),
        other => other.to_string(),
    }
}

/// One shard file, checked (`DeploymentState.from_file`).
fn read_shard(fs: &dyn FileSystem, path: &Path, expected: Option<&str>) -> Result<(), StateError> {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = name.strip_suffix(".json");
    let Some(stem) = stem.filter(|stem| canonical_uuid(stem).as_deref() == Some(*stem)) else {
        return Err(StateError::new(
            "deployment_state_uuid_mismatch",
            format!(
                "{} is not named <uuid>.json with a lowercase canonical uuid",
                path.display()
            ),
            path,
        ));
    };
    if let Some(expected) = expected
        && stem != expected
    {
        return Err(StateError::new(
            "deployment_state_uuid_mismatch",
            format!("{} is not the shard of rule {expected}", path.display()),
            path,
        ));
    }
    let payload: Json = fs
        .read(path)
        .map_err(|error| error.to_string())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|error| error.to_string()))
        .and_then(|text| serde_json::from_str(&text).map_err(|error| error.to_string()))
        .map_err(|error| StateError::shape(path, &format!("cannot be read as JSON: {error}")))?;
    let Json::Object(payload) = payload else {
        return Err(StateError::shape(path, "is not a JSON object"));
    };
    let schema = payload.get("schema").unwrap_or(&Json::Null);
    if schema.as_str() != Some(SCHEMA_ID) {
        return Err(StateError::shape(
            path,
            &format!(
                "has schema {}, expected {}",
                shown(schema),
                quote(SCHEMA_ID)
            ),
        ));
    }
    let Some(object_uuid) = payload.get("object_uuid").and_then(Json::as_str) else {
        return Err(StateError::shape(path, "has no string object_uuid"));
    };
    if object_uuid != stem {
        return Err(StateError::new(
            "deployment_state_uuid_mismatch",
            format!(
                "{} records object_uuid {}, but its file name is {}",
                path.display(),
                quote(object_uuid),
                quote(stem)
            ),
            path,
        ));
    }
    let Some(Json::Object(platforms)) = payload.get("platforms") else {
        return Err(StateError::shape(path, "has no platforms object"));
    };
    for (platform, tenants) in platforms {
        if !crate::state::stores_ids(platform) {
            return Err(StateError::new(
                "deployment_state_platform",
                format!(
                    "{} names platform {}; only {} store external ids",
                    path.display(),
                    quote(platform),
                    crate::state::state_platforms().join(", ")
                ),
                path,
            ));
        }
        let Json::Object(tenants) = tenants else {
            return Err(StateError::shape(
                path,
                &format!("platforms.{platform} is not an object"),
            ));
        };
        for (tenant, external_id) in tenants {
            let Json::String(external_id) = external_id else {
                return Err(StateError::shape(
                    path,
                    &format!(
                        "platforms.{platform}.{tenant} is {}, not a string",
                        type_name(external_id)
                    ),
                ));
            };
            if tenant.trim().is_empty() {
                return Err(StateError::shape(
                    path,
                    &format!("platforms.{platform} has an empty tenant name"),
                ));
            }
            if tenant != tenant.trim() {
                return Err(StateError::shape(
                    path,
                    &format!(
                        "platforms.{platform} tenant {} has surrounding whitespace; the key must \
                         be the tenant name exactly ({})",
                        quote(tenant),
                        quote(tenant.trim())
                    ),
                ));
            }
            if let Some(problem) = external_id_problem(platform, external_id) {
                return Err(StateError::shape(
                    path,
                    &format!("platforms.{platform}.{tenant}: {problem}"),
                ));
            }
        }
    }
    Ok(())
}

/// Why a stored external id is not one (`normalise_external_id`).
fn external_id_problem(platform: &str, value: &str) -> Option<String> {
    if value.trim().is_empty() {
        return Some(format!("{platform} external id is empty"));
    }
    match opentide_schema::platforms::external_id_problem(platform, value)? {
        IdShape::CanonicalDecimal => Some(format!(
            "{platform} external id {} is not a canonical decimal integer (no sign, no leading \
             zeroes)",
            quote(value)
        )),
        IdShape::Pattern(pattern) => Some(format!(
            "{platform} external id {} does not match {}",
            quote(value),
            quote(pattern)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemoryFs;

    const UUID: &str = "0b9b4c4c-7c1a-4b0e-9a5e-6b1e1d5c2a11";

    fn shard(body: &str) -> (MemoryFs, PathBuf) {
        let fs = MemoryFs::new();
        let path = deployment_state_dir(Path::new("/w")).join(format!("{UUID}.json"));
        fs.write(&path, body);
        (fs, path)
    }

    #[test]
    fn a_usable_shard_passes_and_a_missing_one_is_empty() {
        let (fs, _) = shard(&format!(
            r#"{{"schema":"deployment.state::1.0","object_uuid":"{UUID}","platforms":{{"sentinel_one":{{"prod":"12"}}}}}}"#
        ));
        assert_eq!(check_shard(&fs, Path::new("/w"), UUID), Ok(()));
        assert!(scan(&fs, Path::new("/w")).is_empty());
        let empty = MemoryFs::new();
        assert_eq!(check_shard(&empty, Path::new("/w"), UUID), Ok(()));
        assert_eq!(check_shard(&empty, Path::new("/w"), "nope"), Err(None));
    }

    #[test]
    fn each_shape_problem_has_its_code() {
        let cases = [
            ("[]", "deployment_state_shape", "is not a JSON object"),
            ("{", "deployment_state_shape", "cannot be read as JSON"),
            (
                r#"{"schema":"x"}"#,
                "deployment_state_shape",
                "has schema 'x', expected 'deployment.state::1.0'",
            ),
            (
                r#"{"schema":"deployment.state::1.0","object_uuid":"0b9b4c4c-7c1a-4b0e-9a5e-6b1e1d5c2a12","platforms":{}}"#,
                "deployment_state_uuid_mismatch",
                "records object_uuid",
            ),
        ];
        for (body, code, needle) in cases {
            let (fs, _) = shard(body);
            let errors = scan(&fs, Path::new("/w"));
            assert_eq!(errors.len(), 1, "{body}");
            assert_eq!(errors[0].code, code, "{body}");
            assert!(errors[0].message.contains(needle), "{}", errors[0].message);
        }
        let (fs, _) = shard(&format!(
            r#"{{"schema":"deployment.state::1.0","object_uuid":"{UUID}","platforms":{{"splunk":{{}}}}}}"#
        ));
        assert_eq!(
            scan(&fs, Path::new("/w"))[0].code,
            "deployment_state_platform"
        );
        let (fs, _) = shard(&format!(
            r#"{{"schema":"deployment.state::1.0","object_uuid":"{UUID}","platforms":{{"sysdig":{{"t":"012"}}}}}}"#
        ));
        assert!(
            scan(&fs, Path::new("/w"))[0]
                .message
                .contains("canonical decimal")
        );
        let (fs, _) = shard(&format!(
            r#"{{"schema":"deployment.state::1.0","object_uuid":"{UUID}","platforms":{{"sysdig":{{"t":12}}}}}}"#
        ));
        assert!(
            scan(&fs, Path::new("/w"))[0]
                .message
                .contains("is int, not a string")
        );
    }

    /// Bitdefender stores GravityZone rule ids, 24 lowercase hex digits: its
    /// row's pattern is enforced where `validate` reads a shard.
    #[test]
    fn a_bitdefender_id_must_match_its_pattern() {
        let body = |id: &str| {
            format!(
                r#"{{"schema":"deployment.state::1.0","object_uuid":"{UUID}","platforms":{{"bitdefender":{{"prod":"{id}"}}}}}}"#
            )
        };
        let (fs, _) = shard(&body("65f1c0de9a1b2c3d4e5f6a7b"));
        assert!(scan(&fs, Path::new("/w")).is_empty());
        for malformed in ["65F1C0DE9A1B2C3D4E5F6A7B", "65f1c0de", "rule-1"] {
            let (fs, _) = shard(&body(malformed));
            let errors = scan(&fs, Path::new("/w"));
            assert_eq!(errors.len(), 1, "{malformed}");
            assert_eq!(
                errors[0].message,
                format!(
                    "/w/.opentide/states/deployment/{UUID}.json platforms.bitdefender.prod: \
                     bitdefender external id '{malformed}' does not match '^[0-9a-f]{{24}}$'"
                ),
            );
        }
    }

    #[test]
    fn misnamed_and_nested_shards_are_mismatches() {
        let fs = MemoryFs::new();
        let dir = deployment_state_dir(Path::new("/w"));
        fs.write(dir.join(format!("{}.json", UUID.to_uppercase())), "{}");
        fs.write(dir.join("team").join(format!("{UUID}.json")), "{}");
        let errors = scan(&fs, Path::new("/w"));
        assert_eq!(errors.len(), 2);
        assert!(
            errors
                .iter()
                .all(|e| e.code == "deployment_state_uuid_mismatch")
        );
        let error = check_shard(&fs, Path::new("/w"), UUID)
            .unwrap_err()
            .unwrap();
        assert!(error.message.contains("the only valid name is"));
    }

    #[test]
    fn legacy_keys_are_found_on_block_roots() {
        let document = opentide_schema::node::load(
            "configurations:\n  sentinel_one:\n    rule_id: 1\n    rule_id::prod: 2\n    status: X\n",
        )
        .unwrap();
        let found = legacy_external_id_keys(document.root().unwrap());
        assert_eq!(
            found,
            vec![
                ("sentinel_one".to_owned(), "rule_id".to_owned()),
                ("sentinel_one".to_owned(), "rule_id::prod".to_owned())
            ]
        );
    }
}
