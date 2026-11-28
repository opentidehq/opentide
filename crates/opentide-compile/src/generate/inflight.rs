//! Inflight preview shards:
//! open pull requests' objects, one `<uuid>.json` per object under
//! `.opentide/inflight/`, published to the default branch so the explorer
//! and the documentation can preview them.
//!
//! A shard is an envelope (`schema: inflight.shard::1.0`, `written_at`,
//! `object`, `change`) or, from before the envelope, the object itself.
//! [`overlay`] lays them over an index, version-gated: a shard replaces the
//! committed object when its `metadata.version` is higher, or equal and the
//! shard is an envelope.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use indexmap::IndexMap;
use opentide_schema::node::{Document, Node, Value};
use opentide_workspace::Index;
use opentide_workspace::index::ReferenceKind;

use super::relations::node_text;
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

/// `metadata.version` as an integer: a float truncated toward zero, a
/// boolean as 0 or 1, a string parsed after trimming; 0 when it is missing
/// or not a number.
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
            reason = "a float version truncates toward zero, as this cast does; out of range saturates"
        )]
        Some(Value::Float(version)) if version.is_finite() => version.trunc() as i64,
        Some(Value::Bool(flag)) => i64::from(*flag),
        Some(Value::Str(text)) => text.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

/// An object's UUID: `uuid`, else `metadata.uuid`.
pub fn object_uuid(body: &Node) -> Option<String> {
    let named = |node: &&Arc<Node>| opentide_workspace::index::holds_name(node);
    body.get("uuid")
        .filter(named)
        .or_else(|| {
            body.get("metadata")
                .filter(|m| matches!(m.value, Value::Map(_)))
                .and_then(|metadata| metadata.get("uuid"))
                .filter(named)
        })
        .map(|uuid| node_text(uuid))
}

/// The family an object says it is: its schema's prefix,
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
            .is_some_and(|value| matches!(&value.value, Value::Map(entries) if !entries.is_empty()))
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
/// in place. A preview that fails its model check, or whose references do not
/// resolve once the others are laid over, is left out ([`vet`]): what it
/// would have replaced stays as committed.
pub fn overlay(index: &Index, shards: &IndexMap<String, Shard>) -> (Index, Vec<Skipped>) {
    vet(
        index,
        previews(index, shards),
        &super::docs::catalog::check_model,
    )
}

/// The objects of `shards` that would replace or add one in `index`.
fn previews(index: &Index, shards: &IndexMap<String, Shard>) -> Vec<Preview> {
    let mut previews = Vec::new();
    for (uuid, shard) in shards {
        let Some(object) = shard.object() else {
            continue;
        };
        let Some(family) = object_family(object).filter(|f| index.objects.contains_key(f)) else {
            tracing::warn!(uuid, "inflight_skip_unknown_family");
            continue;
        };
        if let Some(existing) = index
            .objects
            .get(&family)
            .and_then(|bucket| bucket.get(uuid))
            .and_then(opentide_workspace::Object::root)
            && !replaces(existing, shard, object)
        {
            continue;
        }
        // The object as a document of its own, read back from its JSON.
        let Ok(document) = opentide_schema::node::load(&Json::from_node(object).to_compact())
        else {
            continue;
        };
        previews.push(Preview {
            family,
            uuid: uuid.clone(),
            path: shard.path.clone(),
            document: Arc::new(document),
            change: shard
                .root()
                .filter(|_| shard.is_wrapped())
                .and_then(|root| root.get("change"))
                .map(|change| Json::from_node(change)),
        });
    }
    previews
}

/// An object an inflight shard previews, read and ready to lay over the
/// index.
#[derive(Debug, Clone)]
pub struct Preview {
    /// Its family (`rule`, `threat`, `objective`).
    pub family: String,
    /// Its UUID.
    pub uuid: String,
    /// The shard file.
    pub path: PathBuf,
    /// The object.
    pub document: Arc<Document>,
    /// The shard's `change`: the pull or merge request it comes from.
    pub change: Option<Json>,
}

/// A preview left out of the overlay, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The shard file.
    pub path: PathBuf,
    /// The object's UUID.
    pub uuid: String,
    /// The object's `name`, when it has one.
    pub name: Option<String>,
    /// The pull or merge request, as its forge names it (`PR #12`, `MR !7`),
    /// with its link when the shard has one.
    pub change: Option<String>,
    /// The first error.
    pub error: String,
}

impl Skipped {
    /// The warning a run shows for it: the shard file (from `root` when
    /// inside it), the object, its pull or merge request, the error.
    pub fn warning(&self, root: &Path) -> String {
        let file = self
            .path
            .strip_prefix(root)
            .unwrap_or(&self.path)
            .to_string_lossy()
            .replace('\\', "/");
        let mut object = self.uuid.clone();
        if let Some(name) = &self.name {
            object.push_str(&format!(" {name:?}"));
        }
        if let Some(change) = &self.change {
            object.push_str(&format!(" from {change}"));
        }
        format!(
            "inflight preview {file} skipped: {object}: {}; the committed object is shown instead",
            self.error
        )
    }
}

/// `change` as a reader names it: `PR #12`, `MR !7`, with its URL.
fn change_label(change: &Json) -> Option<String> {
    let number = match change.get("number") {
        Some(Json::Int(number)) => Some(number.to_string()),
        Some(Json::Str(text)) if !text.is_empty() => Some(text.clone()),
        _ => None,
    };
    let url = change
        .get("url")
        .and_then(Json::as_str)
        .filter(|url| !url.is_empty());
    let platform = change.get("platform").and_then(Json::as_str);
    let label = number.map(|number| match platform {
        Some("gitlab") => format!("MR !{number}"),
        _ => format!("PR #{number}"),
    });
    match (label, url) {
        (Some(label), Some(url)) => Some(format!("{label} ({url})")),
        (Some(label), None) => Some(label),
        (None, Some(url)) => Some(url.to_owned()),
        (None, None) => change
            .get("source_path")
            .and_then(Json::as_str)
            .map(|path| format!("a change to {path}")),
    }
}

/// `index` with the `previews` that hold up laid over it, and those that do
/// not. A preview is left out when its object fails `check`, its model check
/// ([`check_model`](super::docs::catalog::check_model)), or when, laid over
/// with the others, a reference that has to resolve (a rule's
/// `detection_model`, an objective's `threats`) no longer does: its own, or a
/// committed object's that named a signal the preview drops. The check runs
/// again after each round that leaves one out, so a preview that only held
/// up through a left-out one is left out too. A reference already broken in
/// `index` is not a preview's doing.
pub fn vet(
    index: &Index,
    previews: Vec<Preview>,
    check: &dyn Fn(&str, &Document) -> Result<(), String>,
) -> (Index, Vec<Skipped>) {
    let mut skipped = Vec::new();
    let mut kept = Vec::new();
    for preview in previews {
        match check(&preview.family, &preview.document) {
            Ok(()) => kept.push(preview),
            Err(error) => skipped.push(skip(preview, error)),
        }
    }
    let committed = broken_references(index);
    loop {
        let overlaid = apply(index, &kept);
        let mut blamed: IndexMap<String, String> = IndexMap::new();
        for reference in &overlaid.references {
            if !must_resolve(&reference.kind)
                || reference.target.is_empty()
                || resolves(&overlaid, &reference.target)
                || committed.contains(&(reference.from.clone(), reference.target.clone()))
            {
                continue;
            }
            let field = reference.field_path.join(".");
            let (culprit, error) = if kept.iter().any(|p| p.uuid == reference.from) {
                (
                    reference.from.clone(),
                    format!(
                        "{field}: {} does not exist in the catalogue",
                        reference.target
                    ),
                )
            } else if let Some(owner) = index
                .signals
                .get(&reference.target)
                .map(|signal| signal.owner.clone())
                .filter(|owner| kept.iter().any(|p| &p.uuid == owner))
            {
                (
                    owner,
                    format!(
                        "it drops the signal {}, which {} names in {field}",
                        reference.target, reference.from
                    ),
                )
            } else {
                continue;
            };
            blamed.entry(culprit).or_insert(error);
        }
        if blamed.is_empty() {
            for preview in &skipped {
                tracing::warn!(
                    path = %preview.path.display(),
                    uuid = preview.uuid.as_str(),
                    change = preview.change.as_deref().unwrap_or_default(),
                    error = preview.error.as_str(),
                    "inflight_preview_skipped"
                );
            }
            return (overlaid, skipped);
        }
        let mut still = Vec::new();
        for preview in kept {
            match blamed.get(&preview.uuid) {
                Some(error) => {
                    let error = error.clone();
                    skipped.push(skip(preview, error));
                }
                None => still.push(preview),
            }
        }
        kept = still;
    }
}

fn skip(preview: Preview, error: String) -> Skipped {
    let name = preview
        .document
        .root()
        .and_then(|root| root.get("name"))
        .and_then(|name| name.value.as_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    Skipped {
        path: preview.path,
        uuid: preview.uuid,
        name,
        change: preview.change.as_ref().and_then(change_label),
        error,
    }
}

/// `index` with `previews` laid over it, its signals and references read
/// again.
fn apply(index: &Index, previews: &[Preview]) -> Index {
    let mut overlaid = index.clone();
    let mut objectives = Vec::new();
    for preview in previews {
        if overlaid.overlay(
            &preview.family,
            &preview.uuid,
            preview.path.clone(),
            Arc::clone(&preview.document),
        ) && preview.family == "objective"
        {
            objectives.push(preview.uuid.clone());
        }
    }
    if !objectives.is_empty() {
        overlaid.reindex_signals(&objectives);
    }
    overlaid.refresh_references();
    overlaid
}

/// The references the documentation cannot render without: a rule's
/// `detection_model`, an objective's `threats`.
fn must_resolve(kind: &ReferenceKind) -> bool {
    matches!(kind, ReferenceKind::DetectionModel | ReferenceKind::Threat)
}

/// Whether `index` holds `uuid`, as an object of any family or a signal.
fn resolves(index: &Index, uuid: &str) -> bool {
    index
        .objects
        .values()
        .any(|bucket| bucket.contains_key(uuid))
        || index.signals.contains_key(uuid)
}

/// The references of `index` that already do not resolve, as (from, target).
fn broken_references(index: &Index) -> HashSet<(String, String)> {
    index
        .references
        .iter()
        .filter(|reference| must_resolve(&reference.kind) && !resolves(index, &reference.target))
        .map(|reference| (reference.from.clone(), reference.target.clone()))
        .collect()
}

/// Whether `path`, relative to the workspace with `/`, is an object file
/// the shards preview: `objects/<threats|objectives|rules>/<name>.yaml` (or
/// `.yml`).
pub fn is_object_yaml(path: &str) -> bool {
    let path = path.replace('\\', "/");
    let parts: Vec<&str> = path.split('/').collect();
    let [first, family, file] = parts.as_slice() else {
        return false;
    };
    *first == "objects"
        && ["threats", "objectives", "rules"].contains(family)
        && [".yaml", ".yml"].iter().any(|extension| {
            file.strip_suffix(extension)
                .is_some_and(|stem| !stem.is_empty())
        })
}

/// The environment, as the change metadata reads it.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

/// A variable's value, `None` when unset.
fn var(env: Env<'_>, name: &str) -> Json {
    env(name).map_or(Json::Null, Json::Str)
}

/// `os.getenv(name) or fallback`: an empty value falls through.
fn var_or(env: Env<'_>, name: &str, fallback: Option<&Json>) -> Json {
    match env(name).filter(|value| !value.is_empty()) {
        Some(value) => Json::Str(value),
        None => fallback.cloned().unwrap_or(Json::Null),
    }
}

/// A number when the value is all digits, else the value (`int(x) if
/// x.isdigit() else x`).
fn number(value: Option<String>) -> Json {
    match value {
        Some(text) if !text.is_empty() && text.chars().all(|c| c.is_ascii_digit()) => {
            text.parse().map_or(Json::Str(text), Json::Int)
        }
        Some(text) => Json::Str(text),
        None => Json::Null,
    }
}

/// The pull or merge request a shard comes from, as the CI platform
/// describes it (`collect_change_metadata`): `INFLIGHT_CHANGE_JSON` when it
/// holds a JSON object, else the platform's variables (GitHub's event file
/// for the number, link and title). `source_path` is the object file from the
/// workspace; `event` the GitHub event file's text, when there is one.
pub fn change(
    env: Env<'_>,
    ci: crate::git::Ci,
    source_path: &str,
    event: Option<&str>,
    recorded_at: &str,
) -> Json {
    if let Some(text) = env("INFLIGHT_CHANGE_JSON").filter(|text| !text.trim().is_empty())
        && let Some(document) = parse(text.trim())
        && let Some(root) = document.root()
        && let Json::Object(mut data) = Json::from_node(root)
    {
        data.entry("source_path".into())
            .or_insert_with(|| Json::from(source_path));
        data.entry("recorded_at".into())
            .or_insert_with(|| Json::from(recorded_at));
        return Json::Object(data);
    }
    let mut meta = crate::json::Object::new();
    let mut put = |key: &str, value: Json| {
        meta.insert(key.to_owned(), value);
    };
    match ci {
        crate::git::Ci::GitHub => {
            let payload = event
                .and_then(parse)
                .and_then(|document| document.root().map(|root| Json::from_node(root)))
                .unwrap_or(Json::Null);
            let pull = payload
                .get("pull_request")
                .filter(|pull| pull.as_object().is_some());
            let field = |key: &str| {
                pull.and_then(|pull| pull.get(key))
                    .cloned()
                    .unwrap_or(Json::Null)
            };
            let side = |name: &str, key: &str| {
                pull.and_then(|pull| pull.get(name))
                    .filter(|side| side.as_object().is_some())
                    .and_then(|side| side.get(key))
                    .cloned()
            };
            put("platform", Json::from("github"));
            put("number", field("number"));
            put("url", field("html_url"));
            put("title", field("title"));
            put(
                "head_ref",
                var_or(env, "GITHUB_HEAD_REF", side("head", "ref").as_ref()),
            );
            put(
                "base_ref",
                var_or(env, "GITHUB_BASE_REF", side("base", "ref").as_ref()),
            );
            put(
                "head_sha",
                var_or(env, "GITHUB_SHA", side("head", "sha").as_ref()),
            );
        }
        crate::git::Ci::GitLab => {
            let iid = env("CI_MERGE_REQUEST_IID");
            let project = env("CI_PROJECT_URL").unwrap_or_default();
            let url = match &iid {
                Some(iid) if !iid.is_empty() && !project.is_empty() => {
                    Json::Str(format!("{project}/-/merge_requests/{iid}"))
                }
                _ => Json::Null,
            };
            put("platform", Json::from("gitlab"));
            put("number", number(iid));
            put("url", url);
            put("title", var(env, "CI_MERGE_REQUEST_TITLE"));
            put("head_ref", var(env, "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"));
            put("base_ref", var(env, "CI_MERGE_REQUEST_TARGET_BRANCH_NAME"));
            put("head_sha", var(env, "CI_COMMIT_SHA"));
        }
        crate::git::Ci::Azure => {
            let number_text = env("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER")
                .filter(|value| !value.is_empty())
                .or_else(|| env("SYSTEM_PULLREQUEST_PULLREQUESTID"));
            let branch =
                |name: &str| Json::Str(env(name).unwrap_or_default().replace("refs/heads/", ""));
            put("platform", Json::from("azure"));
            put("number", number(number_text));
            put("url", var(env, "SYSTEM_PULLREQUEST_PULLREQUESTURI"));
            put("title", var(env, "SYSTEM_PULLREQUEST_PULLREQUESTTITLE"));
            put("head_ref", branch("SYSTEM_PULLREQUEST_SOURCEBRANCH"));
            put("base_ref", branch("SYSTEM_PULLREQUEST_TARGETBRANCH"));
            put("head_sha", var(env, "BUILD_SOURCEVERSION"));
        }
        crate::git::Ci::Local => {
            put("platform", Json::from("local"));
            for key in ["number", "url", "title", "head_ref", "base_ref", "head_sha"] {
                put(key, Json::Null);
            }
        }
    }
    put("source_path", Json::from(source_path));
    put("recorded_at", Json::from(recorded_at));
    Json::Object(meta)
}

/// The shard of `object` (`build_shard_payload`).
pub fn shard(object: &Node, written_at: &str, change: Json) -> Json {
    let mut shard = crate::json::Object::new();
    shard.insert("schema".into(), Json::from(SHARD_SCHEMA));
    shard.insert("written_at".into(), Json::from(written_at));
    shard.insert("object".into(), Json::from_node(object));
    shard.insert("change".into(), change);
    Json::Object(shard)
}

/// The shard files of `dir` the default branch has caught up with
/// (`prune_inflight_shards`): its object's committed version (in `index`)
/// is at least the shard's. In file name order.
pub fn superseded(dir: &Path, index: &Index) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json") && path.is_file())
        .collect();
    paths.sort();
    let mut pruned = Vec::new();
    for path in paths {
        let Some(document) = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| parse(&text))
        else {
            continue;
        };
        let shard = Shard {
            path: path.clone(),
            document: Arc::new(document),
        };
        let Some(object) = shard.object() else {
            continue;
        };
        let Some(uuid) = object_uuid(object) else {
            continue;
        };
        let committed = ["threat", "objective", "rule"].iter().find_map(|family| {
            index
                .objects
                .get(*family)
                .and_then(|objects| objects.get(&uuid))
                .and_then(opentide_workspace::Object::root)
        });
        if let Some(committed) = committed
            && object_version(committed) >= object_version(object)
        {
            pruned.push((uuid, path));
        }
    }
    pruned
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
    fn object_files_are_found_by_their_place() {
        assert!(is_object_yaml("objects/rules/a.yaml"));
        assert!(is_object_yaml("objects\\threats\\a.yml"));
        assert!(!is_object_yaml("objects/rules/.yaml"));
        assert!(!is_object_yaml("objects/rules/sub/a.yaml"));
        assert!(!is_object_yaml("objects/signals/a.yaml"));
        assert!(!is_object_yaml("x/objects/rules/a.yaml"));
        assert!(!is_object_yaml("objects/rules/a.json"));
    }

    #[test]
    fn a_change_is_described_by_its_ci_platform() {
        use crate::git::Ci;
        let vars = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            }
        };
        let line = Json::to_compact;
        let local = vars(&[]);
        assert_eq!(
            line(&change(
                &local,
                Ci::Local,
                "objects/rules/a.yaml",
                None,
                "t"
            )),
            "{\"platform\":\"local\",\"number\":null,\"url\":null,\"title\":null,\"head_ref\":null,\"base_ref\":null,\"head_sha\":null,\"source_path\":\"objects/rules/a.yaml\",\"recorded_at\":\"t\"}"
        );
        let github = vars(&[("GITHUB_HEAD_REF", ""), ("GITHUB_SHA", "abc")]);
        let event = r#"{"pull_request": {"number": 7, "html_url": "u", "title": "T", "head": {"ref": "feat", "sha": "def"}, "base": {"ref": "main"}}}"#;
        assert_eq!(
            line(&change(&github, Ci::GitHub, "p", Some(event), "t")),
            "{\"platform\":\"github\",\"number\":7,\"url\":\"u\",\"title\":\"T\",\"head_ref\":\"feat\",\"base_ref\":\"main\",\"head_sha\":\"abc\",\"source_path\":\"p\",\"recorded_at\":\"t\"}"
        );
        let gitlab = vars(&[
            ("CI_MERGE_REQUEST_IID", "12"),
            ("CI_PROJECT_URL", "https://g/p"),
        ]);
        let described = change(&gitlab, Ci::GitLab, "p", None, "t");
        assert_eq!(described.get("number"), Some(&Json::Int(12)));
        assert_eq!(
            described.get("url"),
            Some(&Json::from("https://g/p/-/merge_requests/12"))
        );
        // Without the project's URL there is no link to write.
        let unlinked = vars(&[("CI_MERGE_REQUEST_IID", "12")]);
        let described = change(&unlinked, Ci::GitLab, "p", None, "t");
        assert_eq!(described.get("number"), Some(&Json::Int(12)));
        assert_eq!(described.get("url"), Some(&Json::Null));
        let azure = vars(&[
            ("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER", ""),
            ("SYSTEM_PULLREQUEST_PULLREQUESTID", "x9"),
            ("SYSTEM_PULLREQUEST_SOURCEBRANCH", "refs/heads/feat"),
        ]);
        let described = change(&azure, Ci::Azure, "p", None, "t");
        assert_eq!(described.get("number"), Some(&Json::from("x9")));
        assert_eq!(described.get("head_ref"), Some(&Json::from("feat")));
        assert_eq!(described.get("base_ref"), Some(&Json::from("")));
        let given = vars(&[(
            "INFLIGHT_CHANGE_JSON",
            r#"{"platform": "manual", "recorded_at": "then"}"#,
        )]);
        assert_eq!(
            line(&change(&given, Ci::GitHub, "p", None, "now")),
            "{\"platform\":\"manual\",\"recorded_at\":\"then\",\"source_path\":\"p\"}"
        );
    }

    #[test]
    fn shards_the_default_branch_caught_up_with_are_superseded() {
        let dir = tempfile::tempdir().unwrap();
        let index = index_of(&[
            (
                "rule",
                "r1",
                "metadata: {uuid: r1, version: 2}\nconfigurations: {a: {}}\n",
            ),
            (
                "rule",
                "r2",
                "metadata: {uuid: r2, version: 1}\nconfigurations: {a: {}}\n",
            ),
        ]);
        write(
            dir.path(),
            "r1.json",
            r#"{"schema": "inflight.shard::1.0", "object": {"metadata": {"uuid": "r1", "version": 2}}}"#,
        );
        write(
            dir.path(),
            "r2.json",
            r#"{"metadata": {"uuid": "r2", "version": 2}}"#,
        );
        write(
            dir.path(),
            "r3.json",
            r#"{"metadata": {"uuid": "r3", "version": 1}}"#,
        );
        let pruned: Vec<String> = superseded(dir.path(), &index)
            .into_iter()
            .map(|(uuid, _)| uuid)
            .collect();
        assert_eq!(pruned, ["r1"]);
    }

    #[test]
    fn versions_read_as_integers() {
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
        // The models are not this test's: every preview passes.
        let (overlaid, skipped) = vet(&index, previews(&index, &shards), &|_, _| Ok(()));
        assert!(skipped.is_empty());
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

    /// A model check for these tests: an object with `bad` fails it.
    fn bad_fails(_family: &str, document: &Document) -> Result<(), String> {
        match document.root().and_then(|root| root.get("bad")) {
            Some(_) => Err("metadata.created: input is not a valid date".to_owned()),
            None => Ok(()),
        }
    }

    #[test]
    fn previews_that_do_not_hold_up_are_left_out_and_named() {
        let dir = tempfile::tempdir().unwrap();
        let index = index_of(&[
            (
                "threat",
                "t1",
                "metadata: {uuid: t1, version: 1}\nthreat: {a: 1}\n",
            ),
            (
                "objective",
                "o1",
                "metadata: {uuid: o1, version: 1}\nobjective: {threats: [t1], signals: [{uuid: s1}]}\n",
            ),
            (
                "rule",
                "r1",
                "name: Committed\nmetadata: {uuid: r1, version: 1}\ndetection_model: s1\nconfigurations: {a: {}}\n",
            ),
            // Broken before any preview: not a preview's doing.
            (
                "rule",
                "r0",
                "metadata: {uuid: r0, version: 1}\ndetection_model: gone\nconfigurations: {a: {}}\n",
            ),
        ]);
        // A new objective with a typo'd date, defining s9 …
        write(
            dir.path(),
            "a.json",
            r#"{"schema": "inflight.shard::1.0", "object": {"name": "Typo", "bad": 1, "metadata": {"uuid": "o9", "schema": "objective::1.0", "version": 1}, "objective": {"threats": ["t1"], "signals": [{"uuid": "s9"}]}}, "change": {"platform": "gitlab", "number": 7, "url": "https://g/p/-/merge_requests/7"}}"#,
        );
        // … a new rule on s9, fine alone, left out with it …
        write(
            dir.path(),
            "b.json",
            r#"{"schema": "inflight.shard::1.0", "object": {"name": "On s9", "metadata": {"uuid": "r9", "schema": "rule::1.1", "version": 1}, "detection_model": "s9", "configurations": {"a": {}}}, "change": {"platform": "github", "number": 12}}"#,
        );
        // … an objective that drops s1, which the committed r1 needs …
        write(
            dir.path(),
            "c.json",
            r#"{"schema": "inflight.shard::1.0", "object": {"metadata": {"uuid": "o1", "schema": "objective::1.0", "version": 2}, "objective": {"threats": ["t1"], "signals": []}}}"#,
        );
        // … and a valid newer threat, kept.
        write(
            dir.path(),
            "d.json",
            r#"{"schema": "inflight.shard::1.0", "object": {"name": "Newer", "metadata": {"uuid": "t1", "schema": "threat::1.0", "version": 2}, "threat": {"a": 2}}}"#,
        );
        let shards = load(dir.path());
        let (overlaid, skipped) = vet(&index, previews(&index, &shards), &bad_fails);
        let left: Vec<(&str, &str)> = skipped
            .iter()
            .map(|s| (s.uuid.as_str(), s.error.as_str()))
            .collect();
        assert_eq!(
            left,
            [
                ("o9", "metadata.created: input is not a valid date"),
                ("r9", "detection_model: s9 does not exist in the catalogue"),
                (
                    "o1",
                    "it drops the signal s1, which r1 names in detection_model"
                ),
            ]
        );
        // What was committed stays; the valid preview is laid over.
        assert!(!overlaid.objects["objective"].contains_key("o9"));
        assert!(!overlaid.objects["rule"].contains_key("r9"));
        assert_eq!(overlaid.signals.get("s1").unwrap().owner, "o1");
        assert_eq!(
            object_version(overlaid.objects["objective"]["o1"].root().unwrap()),
            1
        );
        assert_eq!(
            object_version(overlaid.objects["threat"]["t1"].root().unwrap()),
            2
        );
        let root = dir.path();
        assert_eq!(
            skipped[0].warning(root),
            "inflight preview a.json skipped: o9 \"Typo\" from MR !7 (https://g/p/-/merge_requests/7): \
             metadata.created: input is not a valid date; the committed object is shown instead"
        );
        assert_eq!(
            skipped[1].warning(root),
            "inflight preview b.json skipped: r9 \"On s9\" from PR #12: detection_model: s9 does \
             not exist in the catalogue; the committed object is shown instead"
        );
        assert_eq!(
            skipped[2].warning(root),
            "inflight preview c.json skipped: o1: it drops the signal s1, which r1 names in \
             detection_model; the committed object is shown instead"
        );
    }
}
