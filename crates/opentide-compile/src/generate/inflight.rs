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
        let line = |json: &Json| super::line(json);
        let local = vars(&[]);
        assert_eq!(
            line(&change(
                &local,
                Ci::Local,
                "objects/rules/a.yaml",
                None,
                "t"
            )),
            "{\"platform\": \"local\", \"number\": null, \"url\": null, \"title\": null, \"head_ref\": null, \"base_ref\": null, \"head_sha\": null, \"source_path\": \"objects/rules/a.yaml\", \"recorded_at\": \"t\"}"
        );
        let github = vars(&[("GITHUB_HEAD_REF", ""), ("GITHUB_SHA", "abc")]);
        let event = r#"{"pull_request": {"number": 7, "html_url": "u", "title": "T", "head": {"ref": "feat", "sha": "def"}, "base": {"ref": "main"}}}"#;
        assert_eq!(
            line(&change(&github, Ci::GitHub, "p", Some(event), "t")),
            "{\"platform\": \"github\", \"number\": 7, \"url\": \"u\", \"title\": \"T\", \"head_ref\": \"feat\", \"base_ref\": \"main\", \"head_sha\": \"abc\", \"source_path\": \"p\", \"recorded_at\": \"t\"}"
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
            "{\"platform\": \"manual\", \"recorded_at\": \"then\", \"source_path\": \"p\"}"
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
