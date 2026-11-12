//! Deployment state shards, read and written as `states/deployment.py` and
//! `deployment/external_ids.py` do (UC-4.6, #979): one
//! `.opentide/states/deployment/<uuid>.json` per rule, each `(platform,
//! tenant)` bound to the id the platform gave the rule.
//!
//! A writer reads the shard, changes one tenant entry and writes the rest
//! back, root keys this version does not know included. The text is UTF-8
//! JSON with sorted keys, a two-space indent and one trailing newline. A
//! write goes to `.<name>.tmp` beside the shard, is flushed to disk, then
//! replaces the shard: a run that fails part-way leaves the shard as it was.

use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use opentide_connectors::python::python_string_repr;

/// The `schema` a shard declares.
pub const SCHEMA_ID: &str = opentide_workspace::state::SCHEMA_ID;
/// Platforms whose deployer addresses the remote rule by a vendor id.
pub const STATE_PLATFORMS: [&str; 4] = opentide_workspace::state::STATE_PLATFORMS;
/// Platforms whose external id is a canonical decimal integer.
const INTEGER_ID_PLATFORMS: [&str; 3] = ["defender_for_endpoint", "sentinel_one", "sysdig"];
/// The root keys a shard's model reads; any other is kept as written.
const ROOT_KEYS: [&str; 3] = ["object_uuid", "platforms", "schema"];
/// The ignore line `opentide setup` writes, which a workspace that ignores
/// deployment state should use instead.
pub const SHARING_IGNORE: &str = ".opentide/states/sharing.jsonl";

/// A shard, or the rule it belongs to, that cannot be used
/// (`DeploymentStateError`): `code` names the failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateError {
    /// `deployment_state_shape`, `deployment_state_uuid_mismatch`, ...
    pub code: &'static str,
    /// What is wrong.
    pub message: String,
}

impl StateError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn shape(path: &Path, detail: &str) -> Self {
        Self::new(
            "deployment_state_shape",
            format!("{} {detail}", path.display()),
        )
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// `.opentide/states/deployment/` of *workspace*.
pub fn state_dir(workspace: &Path) -> PathBuf {
    workspace
        .join(".opentide")
        .join("states")
        .join("deployment")
}

/// *value* as `uuid.UUID(value.strip())` reads it, in lowercase canonical
/// form; `None` when it is not a UUID.
pub fn canonical(value: &str) -> Option<String> {
    let mut hex = value.trim().replace("urn:", "").replace("uuid:", "");
    hex = hex
        .trim_start_matches('{')
        .trim_end_matches('}')
        .replace('-', "");
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let hex = hex.to_ascii_lowercase();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// *value*'s canonical form, or `deployment_state_shape` (`canonical_uuid`).
pub fn canonical_uuid(value: &str) -> Result<String, StateError> {
    canonical(value).ok_or_else(|| {
        StateError::new(
            "deployment_state_shape",
            format!(
                "{} is not a UUID, so it cannot name a deployment state shard",
                python_string_repr(value)
            ),
        )
    })
}

/// The tenant `name`, without surrounding whitespace (`tenant_key`).
pub fn tenant_key(name: &str) -> &str {
    name.trim()
}

/// An id a platform gave a rule: Graph, SentinelOne and Sysdig answer
/// numbers, CrowdStrike strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExternalId {
    /// A number.
    Int(i64),
    /// A string.
    Text(String),
}

impl ExternalId {
    /// The id as Python's `repr` writes it.
    pub fn repr(&self) -> String {
        match self {
            Self::Int(number) => number.to_string(),
            Self::Text(text) => python_string_repr(text),
        }
    }
}

fn canonical_decimal(text: &str) -> bool {
    text == "0"
        || (text.starts_with(|c: char| ('1'..='9').contains(&c))
            && text.bytes().all(|byte| byte.is_ascii_digit()))
}

/// *value* as the shard stores it, or `external_id_shape`
/// (`normalise_external_id`).
pub fn normalise_external_id(platform: &str, value: &ExternalId) -> Result<String, StateError> {
    match value {
        ExternalId::Int(number) if *number < 0 => Err(StateError::new(
            "external_id_shape",
            format!("{platform} external id {number} is negative"),
        )),
        ExternalId::Int(number) => Ok(number.to_string()),
        ExternalId::Text(text) if text.trim().is_empty() => Err(StateError::new(
            "external_id_shape",
            format!("{platform} external id is empty"),
        )),
        ExternalId::Text(text)
            if INTEGER_ID_PLATFORMS.contains(&platform) && !canonical_decimal(text) =>
        {
            Err(StateError::new(
                "external_id_shape",
                format!(
                    "{platform} external id {} is not a canonical decimal integer (no sign, no \
                     leading zeroes)",
                    python_string_repr(text)
                ),
            ))
        }
        ExternalId::Text(text) => Ok(text.clone()),
    }
}

/// Python's type name of a JSON value (`type(value).__name__`).
fn type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "NoneType",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(number) if number.is_f64() => "float",
        serde_json::Value::Number(_) => "int",
        serde_json::Value::String(_) => "str",
        serde_json::Value::Array(_) => "list",
        serde_json::Value::Object(_) => "dict",
    }
}

/// One rule's shard (`DeploymentState`). A rule with no stored id has no
/// platforms.
#[derive(Clone, Debug, PartialEq)]
pub struct Shard {
    /// The file.
    pub path: PathBuf,
    /// The rule's canonical UUID.
    pub object_uuid: String,
    /// Each platform's tenants and their ids.
    pub platforms: IndexMap<String, IndexMap<String, String>>,
    /// Root keys this version does not read, kept as written.
    pub extra: serde_json::Map<String, serde_json::Value>,
    /// Whether the file exists.
    pub exists: bool,
}

/// The file names directly in *dir* that look like shards (`*.json`, any
/// case).
fn shard_entries(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.to_lowercase().ends_with(".json"))
        .collect()
}

/// The stem of a `*.json` name, whatever the extension's case.
fn json_stem(name: &str) -> &str {
    let cut = name.len().saturating_sub(".json".len());
    name.get(..cut).unwrap_or(name)
}

impl Shard {
    /// Reads and checks the shard of *object_uuid* (`DeploymentState.load`).
    /// A missing file is an empty state. Another file in the folder that
    /// names the same rule is `deployment_state_uuid_mismatch`.
    pub fn load(workspace: &Path, object_uuid: &str) -> Result<Self, StateError> {
        let canonical = canonical_uuid(object_uuid)?;
        let dir = state_dir(workspace);
        let name = format!("{canonical}.json");
        let path = dir.join(&name);
        let entries = shard_entries(&dir);
        let mut variants: Vec<&String> = entries
            .iter()
            .filter(|entry| {
                *entry != &name && self::canonical(json_stem(entry)).as_deref() == Some(&canonical)
            })
            .collect();
        if !variants.is_empty() {
            variants.sort();
            let listed: Vec<&str> = variants.iter().map(|name| name.as_str()).collect();
            return Err(StateError::new(
                "deployment_state_uuid_mismatch",
                format!(
                    "{} holds {} for rule {canonical}; the only valid name is {name}. Merge the \
                     bindings into that file and delete the others",
                    dir.display(),
                    listed.join(", ")
                ),
            ));
        }
        if !(entries.contains(&name) && path.is_file()) {
            return Ok(Self {
                path,
                object_uuid: canonical,
                platforms: IndexMap::new(),
                extra: serde_json::Map::new(),
                exists: false,
            });
        }
        Self::from_file(&path, Some(&canonical))
    }

    /// Parses one shard file (`DeploymentState.from_file`).
    pub fn from_file(path: &Path, expected: Option<&str>) -> Result<Self, StateError> {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let stem = name.strip_suffix(".json");
        let Some(stem) = stem.filter(|stem| canonical(stem).as_deref() == Some(*stem)) else {
            return Err(StateError::new(
                "deployment_state_uuid_mismatch",
                format!(
                    "{} is not named <uuid>.json with a lowercase canonical uuid",
                    path.display()
                ),
            ));
        };
        if let Some(expected) = expected
            && stem != expected
        {
            return Err(StateError::new(
                "deployment_state_uuid_mismatch",
                format!("{} is not the shard of rule {expected}", path.display()),
            ));
        }
        let payload: serde_json::Value = std::fs::read(path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| String::from_utf8(bytes).map_err(|error| error.to_string()))
            .and_then(|text| serde_json::from_str(&text).map_err(|error| error.to_string()))
            .map_err(|error| {
                StateError::shape(path, &format!("cannot be read as JSON: {error}"))
            })?;
        let serde_json::Value::Object(payload) = payload else {
            return Err(StateError::shape(path, "is not a JSON object"));
        };
        let schema = payload.get("schema");
        if schema.and_then(serde_json::Value::as_str) != Some(SCHEMA_ID) {
            let shown = match schema {
                Some(serde_json::Value::String(text)) => python_string_repr(text),
                Some(other) => other.to_string(),
                None => "None".to_owned(),
            };
            return Err(StateError::shape(
                path,
                &format!(
                    "has schema {shown}, expected {}",
                    python_string_repr(SCHEMA_ID)
                ),
            ));
        }
        let Some(object_uuid) = payload.get("object_uuid").and_then(|value| value.as_str()) else {
            return Err(StateError::shape(path, "has no string object_uuid"));
        };
        if object_uuid != stem {
            return Err(StateError::new(
                "deployment_state_uuid_mismatch",
                format!(
                    "{} records object_uuid {}, but its file name is {}",
                    path.display(),
                    python_string_repr(object_uuid),
                    python_string_repr(stem)
                ),
            ));
        }
        let Some(serde_json::Value::Object(raw)) = payload.get("platforms") else {
            return Err(StateError::shape(path, "has no platforms object"));
        };
        // The file's order, as `json.loads` keeps it.
        let ordered: IndexMap<String, IndexMap<String, serde_json::Value>> =
            ordered_platforms(path).unwrap_or_default();
        let mut platforms: IndexMap<String, IndexMap<String, String>> = IndexMap::new();
        for platform in ordered_keys(&ordered, raw) {
            let Some(tenants) = raw.get(&platform) else {
                continue;
            };
            if !opentide_workspace::state::stores_ids(&platform) {
                return Err(StateError::new(
                    "deployment_state_platform",
                    format!(
                        "{} names platform {}; only {} store external ids",
                        path.display(),
                        python_string_repr(&platform),
                        STATE_PLATFORMS.join(", ")
                    ),
                ));
            }
            let serde_json::Value::Object(tenants) = tenants else {
                return Err(StateError::shape(
                    path,
                    &format!("platforms.{platform} is not an object"),
                ));
            };
            let order = ordered
                .get(&platform)
                .map(|tenants| tenants.keys().cloned().collect::<Vec<String>>());
            let names: Vec<String> = order.unwrap_or_else(|| tenants.keys().cloned().collect());
            let mut entries: IndexMap<String, String> = IndexMap::new();
            for tenant in names {
                let Some(value) = tenants.get(&tenant) else {
                    continue;
                };
                let serde_json::Value::String(external_id) = value else {
                    return Err(StateError::shape(
                        path,
                        &format!(
                            "platforms.{platform}.{tenant} is {}, not a string",
                            type_name(value)
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
                            "platforms.{platform} tenant {} has surrounding whitespace; the key \
                             must be the tenant name exactly ({})",
                            python_string_repr(&tenant),
                            python_string_repr(tenant.trim())
                        ),
                    ));
                }
                if let Err(error) =
                    normalise_external_id(&platform, &ExternalId::Text(external_id.clone()))
                {
                    return Err(StateError::shape(
                        path,
                        &format!("platforms.{platform}.{tenant}: {}", error.message),
                    ));
                }
                entries.insert(tenant, external_id.clone());
            }
            if !entries.is_empty() {
                platforms.insert(platform, entries);
            }
        }
        let extra = payload
            .iter()
            .filter(|(key, _)| !ROOT_KEYS.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        Ok(Self {
            path: path.to_path_buf(),
            object_uuid: object_uuid.to_owned(),
            platforms,
            extra,
            exists: true,
        })
    }

    /// The id stored for *platform* and *tenant*.
    pub fn get(&self, platform: &str, tenant: &str) -> Option<&str> {
        self.platforms
            .get(platform)
            .and_then(|tenants| tenants.get(tenant_key(tenant)))
            .map(String::as_str)
    }

    /// Binds one tenant; the id as stored (`set`).
    pub fn set(
        &mut self,
        platform: &str,
        tenant: &str,
        external_id: &ExternalId,
    ) -> Result<String, StateError> {
        if !opentide_workspace::state::stores_ids(platform) {
            return Err(StateError::new(
                "deployment_state_platform",
                format!("{platform} does not store external ids in deployment state"),
            ));
        }
        let tenant = tenant_key(tenant);
        if tenant.is_empty() {
            return Err(StateError::new(
                "external_id_shape",
                format!("{platform} tenant name is empty"),
            ));
        }
        let stored = normalise_external_id(platform, external_id)?;
        self.platforms
            .entry(platform.to_owned())
            .or_default()
            .insert(tenant.to_owned(), stored.clone());
        Ok(stored)
    }

    /// Drops one tenant, then the platform when it has none left; the old id.
    pub fn remove(&mut self, platform: &str, tenant: &str) -> Option<String> {
        let tenants = self.platforms.get_mut(platform)?;
        let removed = tenants.shift_remove(tenant_key(tenant));
        if tenants.is_empty() {
            self.platforms.shift_remove(platform);
        }
        removed
    }

    /// The file's text: sorted keys, a two-space indent, one trailing new
    /// line (`render`).
    pub fn render(&self) -> String {
        let mut payload = self.extra.clone();
        payload.insert("schema".into(), SCHEMA_ID.into());
        payload.insert("object_uuid".into(), self.object_uuid.clone().into());
        let platforms: serde_json::Map<String, serde_json::Value> = self
            .platforms
            .iter()
            .map(|(platform, tenants)| {
                (
                    platform.clone(),
                    serde_json::Value::Object(
                        tenants
                            .iter()
                            .map(|(tenant, id)| (tenant.clone(), id.clone().into()))
                            .collect(),
                    ),
                )
            })
            .collect();
        payload.insert("platforms".into(), serde_json::Value::Object(platforms));
        let mut text = python_dumps(&serde_json::Value::Object(payload));
        text.push('\n');
        text
    }

    /// Writes the shard durably, or removes the file when no platform is
    /// left (`save`).
    pub fn save(&mut self) -> std::io::Result<()> {
        if self.platforms.is_empty() {
            if self.path.exists() {
                std::fs::remove_file(&self.path)?;
                if let Some(parent) = self.path.parent() {
                    sync_dir(parent);
                }
            }
            self.exists = false;
            return Ok(());
        }
        write_durable(&self.path, &self.render())?;
        self.exists = true;
        Ok(())
    }
}

/// The shard's platforms and tenants in the file's order (serde_json's map
/// sorts its keys; Python's dictionary keeps them as written).
fn ordered_platforms(path: &Path) -> Option<IndexMap<String, IndexMap<String, serde_json::Value>>> {
    #[derive(serde::Deserialize)]
    struct Ordered {
        platforms: IndexMap<String, IndexMap<String, serde_json::Value>>,
    }
    let text = std::fs::read_to_string(path).ok()?;
    let ordered: Ordered = serde_json::from_str(&text).ok()?;
    Some(ordered.platforms)
}

/// The platforms in the file's order, any the ordered read missed after.
fn ordered_keys(
    ordered: &IndexMap<String, IndexMap<String, serde_json::Value>>,
    raw: &serde_json::Map<String, serde_json::Value>,
) -> Vec<String> {
    let mut keys: Vec<String> = ordered.keys().cloned().collect();
    for key in raw.keys() {
        if !keys.contains(key) {
            keys.push(key.clone());
        }
    }
    keys
}

/// *value* as `json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)`
/// writes it: serde_json's map sorts its keys, and its pretty printer
/// indents by two spaces with `": "` and `","` between items.
fn python_dumps(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

/// Persists a rename or an unlink; not every platform can open a folder.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Replaces *path* with *text* atomically and flushes it to disk before
/// returning (`write_durable`): the text goes to `.<name>.tmp` beside it,
/// takes the file's permissions, then replaces it. On failure the temporary
/// file is removed and *path* is left as it was.
pub fn write_durable(path: &Path, text: &str) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let permissions = std::fs::metadata(path).ok().map(|meta| meta.permissions());
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temporary = parent.join(format!(".{name}.tmp"));
    let written = (|| {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        if let Some(permissions) = permissions {
            std::fs::set_permissions(&temporary, permissions)?;
        }
        std::fs::rename(&temporary, path)
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    sync_dir(parent);
    Ok(())
}

/// An `OSError` as Python's `str()` writes it: `[Errno 13] Permission
/// denied: '<path>'` (`[WinError 5] ...` on Windows).
pub fn os_error_text(error: &std::io::Error, path: &Path) -> String {
    let text = error.to_string();
    let Some(code) = error.raw_os_error() else {
        return text;
    };
    let reason = text
        .strip_suffix(&format!(" (os error {code})"))
        .unwrap_or(&text);
    let tag = if cfg!(windows) { "WinError" } else { "Errno" };
    format!(
        "[{tag} {code}] {reason}: {}",
        python_string_repr(&path.display().to_string())
    )
}

/// Why a state write failed: an `OSError` or a shard that cannot be used.
fn write_error_text(error: &WriteError) -> String {
    match error {
        WriteError::State(error) => error.to_string(),
        WriteError::Io { error, path } => os_error_text(error, path),
    }
}

enum WriteError {
    State(StateError),
    Io {
        error: std::io::Error,
        path: PathBuf,
    },
}

fn save(shard: &mut Shard) -> Result<(), WriteError> {
    shard.save().map_err(|error| WriteError::Io {
        error,
        path: shard.path.clone(),
    })
}

/// Reads the shard, binds one tenant and writes the rest back
/// (`record_created`); the id as stored, or `deployment_state_write_failed`
/// naming the id the platform created (the remote rule is not removed).
pub fn record_created(
    workspace: &Path,
    object_uuid: &str,
    platform: &str,
    tenant: &str,
    external_id: &ExternalId,
) -> Result<String, StateError> {
    let written = (|| {
        let mut shard = Shard::load(workspace, object_uuid).map_err(WriteError::State)?;
        let stored = shard
            .set(platform, tenant, external_id)
            .map_err(WriteError::State)?;
        save(&mut shard)?;
        Ok(stored)
    })();
    written.map_err(|error| {
        StateError::new(
            "deployment_state_write_failed",
            format!(
                "{platform} created rule {} for {object_uuid} on tenant {}, but the deployment \
                 state could not be written ({}). The remote rule was not removed; add the id to \
                 .opentide/states/deployment/ by hand before the next deploy.",
                external_id.repr(),
                python_string_repr(tenant.trim()),
                write_error_text(&error)
            ),
        )
    })
}

/// Drops the tenant's entry after the platform confirmed the delete
/// (`record_deleted`); the platform and the file go when they are empty.
pub fn record_deleted(
    workspace: &Path,
    object_uuid: &str,
    platform: &str,
    tenant: &str,
) -> Result<(), StateError> {
    let written = (|| {
        let mut shard = Shard::load(workspace, object_uuid).map_err(WriteError::State)?;
        if shard.remove(platform, tenant).is_some() {
            save(&mut shard)?;
        }
        Ok(())
    })();
    written.map_err(|error| {
        StateError::new(
            "deployment_state_write_failed",
            format!(
                "{platform} deleted the rule for {object_uuid} on tenant {}, but the deployment \
                 state could not be updated ({})",
                python_string_repr(tenant.trim()),
                write_error_text(&error)
            ),
        )
    })
}

/// The ignore rule that hides `.opentide/states/deployment/` from git
/// (`IgnoreRule`), as a refusal names it.
pub use opentide_compile::git::IgnoreRule;

/// The refusal while git ignores the shards, naming the replacement line
/// (`ignored_message`).
pub fn ignored_message(rule: &IgnoreRule) -> String {
    format!(
        "git ignores .opentide/states/deployment/ ({}). Deployment state shards must be \
         committed, or the next deploy creates a second remote rule. Replace that ignore line \
         with {SHARING_IGNORE} so only the sharing cache is ignored.",
        rule.describe()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "0b4d0e4e-1c33-4f53-8a6b-4c5b6e7f8a9b";

    fn shard_text(platforms: &str) -> String {
        format!(
            r#"{{"schema": "deployment.state::1.0", "object_uuid": "{UUID}", "platforms": {platforms}}}"#
        )
    }

    #[test]
    fn a_uuid_reads_as_python_reads_it() {
        assert_eq!(canonical(&UUID.to_uppercase()).as_deref(), Some(UUID));
        assert_eq!(
            canonical(&format!("{{urn:uuid:{}}}", UUID.replace('-', ""))).as_deref(),
            Some(UUID)
        );
        assert!(canonical("not-a-uuid").is_none());
        assert_eq!(
            canonical_uuid("nope").unwrap_err().message,
            "'nope' is not a UUID, so it cannot name a deployment state shard"
        );
    }

    #[test]
    fn ids_are_stored_as_the_oracle_stores_them() {
        assert_eq!(
            normalise_external_id("sentinel_one", &ExternalId::Int(17)).unwrap(),
            "17"
        );
        assert_eq!(
            normalise_external_id("sentinel_one", &ExternalId::Text("017".into()))
                .unwrap_err()
                .message,
            "sentinel_one external id '017' is not a canonical decimal integer (no sign, no \
             leading zeroes)"
        );
        assert_eq!(
            normalise_external_id("crowdstrike", &ExternalId::Text("cs-1".into())).unwrap(),
            "cs-1"
        );
        assert!(normalise_external_id("crowdstrike", &ExternalId::Text(" ".into())).is_err());
        assert!(normalise_external_id("sysdig", &ExternalId::Int(-1)).is_err());
    }

    #[test]
    fn a_missing_shard_is_an_empty_state_and_a_write_creates_it() {
        let dir = tempfile::tempdir().unwrap();
        let shard = Shard::load(dir.path(), &UUID.to_uppercase()).unwrap();
        assert!(!shard.exists);
        assert!(shard.platforms.is_empty());
        let stored = record_created(
            dir.path(),
            UUID,
            "sentinel_one",
            " prod ",
            &ExternalId::Int(42),
        )
        .unwrap();
        assert_eq!(stored, "42");
        let path = state_dir(dir.path()).join(format!("{UUID}.json"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!(
                "{{\n  \"object_uuid\": \"{UUID}\",\n  \"platforms\": {{\n    \"sentinel_one\": \
                 {{\n      \"prod\": \"42\"\n    }}\n  }},\n  \"schema\": \
                 \"deployment.state::1.0\"\n}}\n"
            )
        );
        // No temporary file is left behind.
        let names: Vec<String> = std::fs::read_dir(state_dir(dir.path()))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [format!("{UUID}.json")]);
        record_deleted(dir.path(), UUID, "sentinel_one", "prod").unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn a_writer_keeps_the_other_tenants_and_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        let folder = state_dir(dir.path());
        std::fs::create_dir_all(&folder).unwrap();
        let path = folder.join(format!("{UUID}.json"));
        std::fs::write(
            &path,
            format!(
                r#"{{"zeta": [1, {{"b": 2, "a": "é"}}], "schema": "deployment.state::1.0", "object_uuid": "{UUID}", "platforms": {{"crowdstrike": {{"b": "x", "a": "y"}}}}}}"#
            ),
        )
        .unwrap();
        let shard = Shard::load(dir.path(), UUID).unwrap();
        let tenants: Vec<&String> = shard.platforms["crowdstrike"].keys().collect();
        assert_eq!(tenants, ["b", "a"]);
        record_created(
            dir.path(),
            UUID,
            "defender_for_endpoint",
            "lab",
            &ExternalId::Text("7".into()),
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("\"crowdstrike\": {\n      \"a\": \"y\",\n      \"b\": \"x\"\n    }")
        );
        assert!(text.contains("\"zeta\": [\n    1,\n    {\n      \"a\": \"é\",\n      \"b\": 2\n"));
        record_deleted(dir.path(), UUID, "defender_for_endpoint", "lab").unwrap();
        record_deleted(dir.path(), UUID, "crowdstrike", "a").unwrap();
        record_deleted(dir.path(), UUID, "crowdstrike", "b").unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn a_shard_that_cannot_be_used_is_refused_with_its_code() {
        let dir = tempfile::tempdir().unwrap();
        let folder = state_dir(dir.path());
        std::fs::create_dir_all(&folder).unwrap();
        let path = folder.join(format!("{UUID}.json"));
        let refused = |text: &str| {
            std::fs::write(&path, text).unwrap();
            Shard::load(dir.path(), UUID).unwrap_err()
        };
        assert_eq!(refused("[]").code, "deployment_state_shape");
        assert!(refused("{").message.contains("cannot be read as JSON"));
        assert_eq!(
            refused(&shard_text(r#"{"elastic": {"t": "x"}}"#)).code,
            "deployment_state_platform"
        );
        assert!(
            refused(&shard_text(r#"{"crowdstrike": {"t": 5}}"#))
                .message
                .ends_with("platforms.crowdstrike.t is int, not a string")
        );
        assert!(
            refused(&shard_text(r#"{"crowdstrike": {" t": "x"}}"#))
                .message
                .contains("has surrounding whitespace")
        );
        assert!(
            refused(&shard_text(r#"{"sysdig": {"t": "01"}}"#))
                .message
                .contains("platforms.sysdig.t: sysdig external id '01'")
        );
        assert!(
            refused(r#"{"schema": "other"}"#)
                .message
                .ends_with("has schema 'other', expected 'deployment.state::1.0'")
        );
        // The rule's shard under another spelling of its name. Alone in the
        // folder, so a filesystem that folds case (macOS, Windows), where the
        // two spellings are one file, holds the same folder as one that does
        // not.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(folder.join(format!("{}.json", UUID.to_uppercase())), "{}").unwrap();
        let mismatch = Shard::load(dir.path(), UUID).unwrap_err();
        assert_eq!(mismatch.code, "deployment_state_uuid_mismatch");
        assert!(mismatch.message.contains("the only valid name is"));
    }

    #[test]
    fn a_failed_write_leaves_the_shard_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let folder = state_dir(dir.path());
        std::fs::create_dir_all(&folder).unwrap();
        let path = folder.join(format!("{UUID}.json"));
        let before = shard_text(r#"{"sysdig": {"lab": "42"}}"#);
        std::fs::write(&path, &before).unwrap();
        // The temporary file's name is a folder: the write fails before the replace.
        std::fs::create_dir_all(folder.join(format!(".{UUID}.json.tmp"))).unwrap();
        let error =
            record_created(dir.path(), UUID, "sysdig", "other", &ExternalId::Int(43)).unwrap_err();
        assert_eq!(error.code, "deployment_state_write_failed");
        assert!(error.message.starts_with(&format!(
            "sysdig created rule 43 for {UUID} on tenant 'other', but the deployment state could \
             not be written ("
        )));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn an_os_error_reads_as_pythons() {
        let error = std::io::Error::from_raw_os_error(13);
        let text = os_error_text(&error, Path::new("/x/y.json"));
        assert!(
            text.starts_with('[') && text.ends_with(": '/x/y.json'"),
            "{text}"
        );
        assert_eq!(
            os_error_text(&std::io::Error::other("boom"), Path::new("/x")),
            "boom"
        );
    }

    #[test]
    fn a_refusal_names_the_ignore_line() {
        let rule = IgnoreRule {
            pattern: ".opentide/states/".into(),
            source: Some(".gitignore".into()),
            line: Some(3),
        };
        assert!(ignored_message(&rule).starts_with(
            "git ignores .opentide/states/deployment/ (.gitignore:3: .opentide/states/). "
        ));
    }
}
