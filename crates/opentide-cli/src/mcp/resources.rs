//! The `opentide://` resources (`src/opentide/mcp_server/resources.py`):
//! the index, the objects, the generated schemas and templates, the
//! vocabularies and the platforms, each an indented JSON document.

use std::path::{Path, PathBuf};

use opentide_schema::node::{Node, Value};
use opentide_schema::vocab::{KeyKind, OBJECT_TYPES, Vocabularies, Vocabulary};
use opentide_workspace::{FileSystem, OsFs, Workspace};
use serde_json::json;

use super::catalog::{PLATFORMS, get_object, node_json, require, workspace};
use super::server::Answer;
use super::tools::Context;
use crate::json::{Json, document_text};

/// The resources with a fixed URI, and whether each needs the workspace.
const FIXED: [(&str, bool); 6] = [
    ("opentide://index", true),
    ("opentide://rules", true),
    ("opentide://threats", true),
    ("opentide://objectives", true),
    ("opentide://vocabularies", false),
    ("opentide://platforms", true),
];

/// The resource templates: the URI's prefix, whether the variable is a
/// reserved expansion (`{+name}`), and whether it needs the workspace.
const TEMPLATES: [(&str, bool, bool); 6] = [
    ("opentide://rules/", false, true),
    ("opentide://threats/", false, true),
    ("opentide://objectives/", false, true),
    ("opentide://schemas/", false, false),
    ("opentide://templates/", false, false),
    ("opentide://vocabularies/", true, false),
];

/// `resources/read` of `uri`.
pub fn read(uri: &str, context: &Context<'_>) -> Answer {
    let text = if let Some((_, needs)) = FIXED.iter().find(|(fixed, _)| *fixed == uri) {
        fixed(uri, *needs, context)
    } else if let Some((prefix, value, needs)) =
        TEMPLATES.iter().find_map(|(prefix, reserved, needs)| {
            let rest = uri.strip_prefix(prefix)?;
            Some((*prefix, expand(rest, *reserved)?, *needs))
        })
    {
        templated(prefix, &value, needs, context)
    } else {
        return Answer::Error(json!({
            "code": -32602,
            "message": format!("Unknown resource: {uri}"),
            "data": {"uri": uri},
        }));
    };
    match text {
        Ok(document) => {
            let text = document_text(&document, true);
            Answer::Result(json!({
                "contents": [{"uri": uri, "mimeType": "text/plain", "text": text.trim_end_matches('\n')}],
            }))
        }
        Err(problem) => {
            tracing::error!(uri = %uri, problem = %problem, "could not read the resource");
            Answer::Error(json!({
                "code": -32603,
                "message": format!("Error reading resource {uri}"),
                "data": {"uri": uri},
            }))
        }
    }
}

/// The value of a template's variable, as the Python SDK's RFC 6570 scan
/// matches it: a simple expansion ends at `/`, `?`, `#`, `&` or `,` (a value
/// holding one does not match), a reserved one (`{+name}`) at `?` or `#`.
/// Either is percent-decoded.
fn expand(raw: &str, reserved: bool) -> Option<String> {
    let stops = if reserved { "?#" } else { "/?#&," };
    if raw.is_empty() || raw.chars().any(|c| stops.contains(c)) {
        return None;
    }
    Some(
        percent_encoding::percent_decode_str(raw)
            .decode_utf8_lossy()
            .into_owned(),
    )
}

fn fixed(uri: &str, needs: bool, context: &Context<'_>) -> Result<Json, String> {
    let open = || {
        if needs {
            require(context)
        } else {
            workspace(context)
        }
    };
    match uri {
        "opentide://index" => Ok(index(&open()?, context)),
        "opentide://rules" => Ok(bodies(&open()?, "rule")),
        "opentide://threats" => Ok(bodies(&open()?, "threat")),
        "opentide://objectives" => Ok(bodies(&open()?, "objective")),
        "opentide://vocabularies" => {
            let objects = workspace(context).ok();
            Ok(vocabularies_listing(objects.as_ref()))
        }
        _ => Ok(platforms(&open()?)),
    }
}

fn templated(
    prefix: &str,
    value: &str,
    needs: bool,
    context: &Context<'_>,
) -> Result<Json, String> {
    let open = || {
        if needs {
            require(context)
        } else {
            workspace(context)
        }
    };
    match prefix {
        "opentide://rules/" => Ok(one(&open()?, "rule", "Rule", value)),
        "opentide://threats/" => Ok(one(&open()?, "threat", "Threat", value)),
        "opentide://objectives/" => Ok(one(&open()?, "objective", "Objective", value)),
        "opentide://schemas/" => Ok(schema(&open()?, value)),
        "opentide://templates/" => Ok(template(&open()?, value)),
        _ => {
            let objects = workspace(context).ok();
            Ok(vocabulary(objects.as_ref(), value))
        }
    }
}

/// Every object of `family`, by UUID.
fn bodies(workspace: &Workspace, family: &str) -> Json {
    Json::Object(
        workspace
            .index()
            .objects
            .get(family)
            .map(|bucket| {
                bucket
                    .iter()
                    .map(|(uuid, object)| {
                        (uuid.clone(), object.root().map_or(Json::Null, node_json))
                    })
                    .collect()
            })
            .unwrap_or_default(),
    )
}

fn one(workspace: &Workspace, family: &str, noun: &str, uuid: &str) -> Json {
    match get_object(workspace.index(), uuid) {
        Some(found) if found.family == family => found.body.map_or(Json::Null, node_json),
        _ => Json::object([("error", Json::Str(format!("{noun} {uuid} not found")))]),
    }
}

fn sorted_names<'a>(names: impl IntoIterator<Item = &'a String>) -> Json {
    let mut names: Vec<&String> = names.into_iter().collect();
    names.sort();
    Json::Array(names.into_iter().map(Json::str).collect())
}

/// `rule::1.0`, `rule.1.0` or `rule` as its family and version, the family's
/// plural read as the family (`_split_schema_id`).
fn split_schema_id(identifier: &str) -> (String, Option<String>) {
    let text = identifier.trim();
    let (family, version) = text
        .split_once("::")
        .or_else(|| text.split_once('.'))
        .unwrap_or((text, ""));
    let family = family.trim().to_lowercase();
    let family = match family.as_str() {
        "rules" => "rule".to_owned(),
        "threats" => "threat".to_owned(),
        "objectives" => "objective".to_owned(),
        "visibilities" => "visibility".to_owned(),
        _ => family,
    };
    let version = version.trim();
    (family, (!version.is_empty()).then(|| version.to_owned()))
}

/// A version's sort key: numbers before words, each compared in kind.
fn version_order(version: &str) -> Vec<(u8, u64, String)> {
    version
        .split('.')
        .map(|chunk| match chunk.parse::<u64>() {
            Ok(number) if chunk.chars().all(|c| c.is_ascii_digit()) => (0, number, String::new()),
            _ => (1, 0, chunk.to_owned()),
        })
        .collect()
}

/// The key of `keys` a family alias names, the highest version first
/// (`_resolve_family_key`).
fn resolve_family_key<'k>(
    keys: impl IntoIterator<Item = &'k str>,
    requested: &str,
) -> Option<String> {
    let keys: Vec<&str> = keys.into_iter().collect();
    if keys.contains(&requested) {
        return Some(requested.to_owned());
    }
    let (family, version) = split_schema_id(requested);
    keys.iter()
        .filter_map(|key| {
            let (key_family, key_version) = split_schema_id(key);
            (key_family == family && (version.is_none() || key_version == version)).then(|| {
                (
                    version_order(key_version.as_deref().unwrap_or("0")),
                    (*key).to_owned(),
                )
            })
        })
        .max()
        .map(|(_, key)| key)
}

/// `paths.toml`'s `[paths]` value at `section`.`key`, when it is text.
fn paths_value(config: &Node, section: &str, key: &str) -> Option<String> {
    let value = config.get("paths")?.get("paths")?.get(section)?.get(key)?;
    value.value.as_str().map(str::to_owned)
}

/// `paths.toml`'s `[artifacts]` table `kind`: `(key, file name)`.
fn artifacts(config: &Node, kind: &str) -> Vec<(String, String)> {
    let Some(Value::Map(entries)) = config
        .get("paths")
        .and_then(|paths| paths.get("artifacts"))
        .and_then(|artifacts| artifacts.get(kind))
        .map(|node| &node.value)
    else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            Some((
                entry.key.value.to_string(),
                entry.value.value.as_str()?.to_owned(),
            ))
        })
        .collect()
}

fn workspace_dir(workspace: &Workspace, relative: &str) -> PathBuf {
    workspace.roots().workspace.join(relative)
}

/// `rule.1.0.schema.json` as `rule::1.0` (`parse_schema_artifact_name`).
fn schema_artifact_identifier(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".schema.json")?;
    let mut parts = stem.split('.');
    let family = parts.next()?;
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    Some(format!("{family}::{major}.{minor}"))
}

/// The generated JSON Schemas of the workspace, by identifier, with their
/// files (`_scan_framework_schemas`).
fn json_schemas(workspace: &Workspace) -> Vec<(String, PathBuf, Json)> {
    let config = &workspace.configuration().resolved.tree;
    let dir = workspace_dir(
        workspace,
        &paths_value(config, "opentide", "schemas").unwrap_or_else(|| ".opentide/schemas/".into()),
    );
    let fs = &OsFs;
    let mut found: Vec<(String, PathBuf, Json)> = Vec::new();
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.ends_with(".schema.json") && name != "opentide.schema.json")
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    let read = |path: &Path| -> Option<Json> {
        let bytes = fs.read(path).ok()?;
        Json::parse(std::str::from_utf8(&bytes).ok()?).ok()
    };
    for name in names {
        let path = dir.join(&name);
        if let (Some(identifier), Some(content)) = (schema_artifact_identifier(&name), read(&path))
        {
            found.push((identifier, path, content));
        }
    }
    for (meta, file) in artifacts(config, "schemas") {
        if meta == "router" || meta == "visibility" {
            continue;
        }
        let path = dir.join(&file);
        if !fs.is_file(&path) {
            continue;
        }
        let identifier = schema_artifact_identifier(&file).unwrap_or(meta);
        if found.iter().any(|(known, ..)| *known == identifier) {
            continue;
        }
        if let Some(content) = read(&path) {
            found.push((identifier, path, content));
        }
    }
    found
}

fn schema(workspace: &Workspace, object_type: &str) -> Json {
    let schemas = json_schemas(workspace);
    let names: Vec<String> = schemas.iter().map(|(name, ..)| name.clone()).collect();
    match resolve_family_key(names.iter().map(String::as_str), object_type) {
        Some(key) => schemas
            .into_iter()
            .find(|(name, ..)| *name == key)
            .map_or(Json::Null, |(_, _, content)| content),
        None => Json::object([
            (
                "error",
                Json::Str(format!(
                    "No JSON Schema generated for {}",
                    crate::render::codeframe::quoted(object_type)
                )),
            ),
            ("available", sorted_names(&names)),
            ("hint", Json::str("run 'opentide generate schemas'")),
        ]),
    }
}

/// The templates (`Templates.Index`): the workspace's generated object
/// templates by family, and every configured platform's block template
/// under `systems`.
fn templates(workspace: &Workspace) -> Vec<(String, Json)> {
    let config = &workspace.configuration().resolved.tree;
    let dir = workspace_dir(
        workspace,
        &paths_value(config, "opentide", "templates")
            .unwrap_or_else(|| ".opentide/templates/".into()),
    );
    let mut out: Vec<(String, Json)> = Vec::new();
    if OsFs.is_dir(&dir) {
        for (family, file) in artifacts(config, "templates") {
            let path = dir.join(&file);
            if let Ok(bytes) = OsFs.read(&path) {
                out.push((
                    family,
                    Json::Str(String::from_utf8_lossy(&bytes).into_owned()),
                ));
            }
        }
    }
    let mut systems = Vec::new();
    if let Some(Value::Map(platforms)) = config.get("platforms").map(|node| &node.value) {
        for entry in platforms {
            let name = entry.key.value.to_string();
            if !matches!(
                entry.value.get("platform").map(|node| &node.value),
                Some(Value::Map(_))
            ) {
                continue;
            }
            if let Ok(Some(text)) = opentide_schema::generate::workspace::platform_template(&name) {
                systems.push((name, Json::Str(text)));
            }
        }
    }
    match out.iter_mut().find(|(key, _)| key == "systems") {
        Some((_, existing)) => *existing = Json::Object(systems),
        None => out.push(("systems".to_owned(), Json::Object(systems))),
    }
    out
}

/// The current revision of each object family (`MetaSchemas.Index`'s keys).
fn metaschema_keys(workspace: &Workspace) -> Vec<String> {
    let families: Vec<&str> = workspace
        .configuration()
        .families
        .iter()
        .map(String::as_str)
        .collect();
    opentide_schema::generate::workspace::identifiers_for_families(&families)
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn template(workspace: &Workspace, object_type: &str) -> Json {
    let templates = templates(workspace);
    let names: Vec<String> = templates.iter().map(|(name, _)| name.clone()).collect();
    let key = resolve_family_key(names.iter().map(String::as_str), object_type).or_else(|| {
        // Templates are rendered from the current model: a versioned request
        // matches only the current version.
        let (family, version) = split_schema_id(object_type);
        let version = version?;
        if !names.contains(&family) {
            return None;
        }
        let keys = metaschema_keys(workspace);
        let current = resolve_family_key(keys.iter().map(String::as_str), &family)?;
        (split_schema_id(&current).1.as_deref() == Some(version.as_str())).then_some(family)
    });
    match key.and_then(|key| templates.into_iter().find(|(name, _)| *name == key)) {
        Some((_, text)) => text,
        None => Json::object([
            (
                "error",
                Json::Str(format!(
                    "No template available for {}",
                    crate::render::codeframe::quoted(object_type)
                )),
            ),
            ("available", sorted_names(&names)),
        ]),
    }
}

fn toml_json(value: &toml::Value) -> Json {
    match value {
        toml::Value::String(text) => Json::str(text),
        toml::Value::Integer(number) => Json::Int(*number),
        toml::Value::Float(number) => Json::Float(*number),
        toml::Value::Boolean(flag) => Json::Bool(*flag),
        toml::Value::Datetime(datetime) => Json::Str(datetime.to_string()),
        toml::Value::Array(items) => Json::Array(items.iter().map(toml_json).collect()),
        toml::Value::Table(table) => Json::Object(
            table
                .iter()
                .map(|(key, value)| (key.clone(), toml_json(value)))
                .collect(),
        ),
    }
}

/// A bundled vocabulary as the registry's index holds it
/// (`VocabularyDefinition.to_index_dict`).
fn index_vocabulary(vocabulary: &Vocabulary) -> Json {
    let metadata = &vocabulary.metadata;
    let id = metadata.key == KeyKind::Id;
    let stages: Vec<Json> = metadata
        .stages
        .iter()
        .map(|stage| {
            let mut members = Vec::new();
            for (key, value) in [
                ("id", &stage.id),
                ("name", &stage.name),
                ("description", &stage.description),
            ] {
                if let Some(value) = value {
                    members.push((key.to_owned(), Json::str(value)));
                }
            }
            Json::Object(members)
        })
        .collect();
    let mut meta = vec![
        ("name".to_owned(), Json::str(&metadata.name)),
        ("field".to_owned(), Json::str(&metadata.field)),
        ("description".to_owned(), Json::str(&metadata.description)),
        ("icon".to_owned(), Json::str(&metadata.icon)),
        ("key".to_owned(), Json::str(if id { "id" } else { "name" })),
        ("model".to_owned(), Json::Bool(id)),
        ("stages".to_owned(), Json::Array(stages)),
    ];
    for (key, value) in &metadata.extra {
        meta.push((key.clone(), toml_json(value)));
    }
    let entries = vocabulary
        .entries
        .iter()
        .map(|(key, entry)| {
            let mut members = vec![
                ("name".to_owned(), Json::str(&entry.name)),
                ("version".to_owned(), Json::Str(entry.version.to_string())),
            ];
            if let Some(removed) = entry.removed {
                members.push(("removed".to_owned(), Json::Str(removed.to_string())));
            }
            members.extend([
                ("description".to_owned(), Json::str(&entry.description)),
                ("icon".to_owned(), Json::str(&entry.icon)),
                ("link".to_owned(), Json::str(&entry.link)),
                (
                    "tide.vocab.stages".to_owned(),
                    Json::Array(entry.stages.iter().map(Json::str).collect()),
                ),
            ]);
            for (name, value) in &entry.extra {
                members.push((name.clone(), toml_json(value)));
            }
            (key.clone(), Json::Object(members))
        })
        .collect();
    Json::object([
        ("metadata", Json::Object(meta)),
        ("entries", Json::Object(entries)),
    ])
}

fn text_of(node: Option<&Node>) -> Option<Json> {
    match node.map(|node| &node.value) {
        None | Some(Value::Null) => None,
        Some(Value::Str(text)) => Some(Json::Str(text.replace("\n ", " "))),
        Some(_) => node.map(node_json),
    }
}

/// The workspace's object vocabularies as the registry's index holds them
/// (`build_object_vocabularies`), in the families' order.
fn object_vocabularies(workspace: &Workspace) -> Vec<(String, Json)> {
    let config = &workspace.configuration().resolved.tree;
    let documentation = config.get("documentation");
    let setting = |table: &str, family: &str| {
        documentation
            .and_then(|doc| doc.get(table))
            .and_then(|names| names.get(family))
            .and_then(|node| node.value.as_str().map(str::to_owned))
    };
    let index = workspace.index();
    let mut out = Vec::new();
    for family in OBJECT_TYPES {
        if !workspace
            .configuration()
            .families
            .iter()
            .any(|known| known == family)
        {
            continue;
        }
        let name = setting("object_names", family).unwrap_or_else(|| family.to_owned());
        let metadata = Json::object([
            ("field", Json::str(family)),
            (
                "icon",
                Json::Str(setting("icons", family).unwrap_or_default()),
            ),
            ("name", Json::str(&name)),
            ("description", Json::str(&name)),
            ("model", Json::Bool(true)),
        ]);
        let mut entries: Vec<(String, Json)> = Vec::new();
        for (uuid, body) in opentide_workspace::coverage::bucket(index, family) {
            let object_name = body.get("name").map(AsRef::as_ref);
            let truthy_name = match object_name.map(|node| &node.value) {
                None | Some(Value::Null | Value::Bool(false)) => false,
                Some(Value::Str(text)) => !text.is_empty(),
                Some(_) => true,
            };
            let Some(meta) = body
                .get("metadata")
                .filter(|m| matches!(m.value, Value::Map(_)))
            else {
                continue;
            };
            if !truthy_name {
                continue;
            }
            let mut entry: Vec<(String, Json)> = vec![
                (
                    "name".to_owned(),
                    text_of(object_name).unwrap_or(Json::Null),
                ),
                ("model".to_owned(), Json::Bool(true)),
                (
                    "tlp".to_owned(),
                    text_of(meta.get("tlp").map(AsRef::as_ref)).unwrap_or_else(|| Json::str("")),
                ),
            ];
            if let Some(criticality) = text_of(body.get("criticality").map(AsRef::as_ref)) {
                entry.push(("criticality".to_owned(), criticality));
            }
            if let Some(aliases) = body
                .get("actor")
                .filter(|actor| matches!(actor.value, Value::Map(_)))
                .and_then(|actor| text_of(actor.get("aliases").map(AsRef::as_ref)))
            {
                entry.push(("aliases".to_owned(), aliases));
            }
            let nested = body
                .get(family)
                .filter(|nested| matches!(nested.value, Value::Map(_)));
            let description = match family {
                "rule" => text_of(body.get("description").map(AsRef::as_ref))
                    .unwrap_or_else(|| Json::str("")),
                _ => match nested {
                    Some(nested) => {
                        text_of(nested.get("description").map(AsRef::as_ref)).unwrap_or(Json::Null)
                    }
                    None => Json::str(""),
                },
            };
            if family == "objective"
                && let Some(priority) =
                    nested.and_then(|n| text_of(n.get("priority").map(AsRef::as_ref)))
            {
                entry.push(("priority".to_owned(), priority));
            }
            if description != Json::Null {
                entry.push(("description".to_owned(), description));
            }
            entries.push((uuid.to_owned(), Json::Object(entry)));
            if family != "objective" {
                continue;
            }
            let signals = match nested.and_then(|n| n.get("signals")).map(|n| &n.value) {
                Some(Value::Seq(signals)) => signals.clone(),
                _ => Vec::new(),
            };
            for signal in signals {
                let field = |key: &str| text_of(signal.get(key).map(AsRef::as_ref));
                let (Some(Json::Str(signal_uuid)), Some(Json::Str(signal_name))) =
                    (field("uuid"), field("name"))
                else {
                    continue;
                };
                if signal_uuid.is_empty() || signal_name.is_empty() {
                    continue;
                }
                let base = match object_name.map(|node| &node.value) {
                    Some(value) => value.to_string(),
                    None => String::new(),
                };
                let mut entry = vec![
                    (
                        "name".to_owned(),
                        Json::Str(format!("{base}::{signal_name}").replace("\n ", " ")),
                    ),
                    ("model".to_owned(), Json::Bool(true)),
                    (
                        opentide_schema::keys::OBJECT_PARENT.to_owned(),
                        Json::str(uuid),
                    ),
                    (
                        "tlp".to_owned(),
                        text_of(meta.get("tlp").map(AsRef::as_ref))
                            .unwrap_or_else(|| Json::str("")),
                    ),
                ];
                for key in ["severity", "description"] {
                    if let Some(value) = field(key) {
                        entry.push((key.to_owned(), value));
                    }
                }
                entries.push((signal_uuid, Json::Object(entry)));
            }
        }
        out.push((
            family.to_owned(),
            Json::object([("metadata", metadata), ("entries", Json::Object(entries))]),
        ));
    }
    out
}

/// Every vocabulary in the index's form: the bundled ones, then the
/// workspace's object vocabularies.
fn index_vocabularies(objects: Option<&Workspace>) -> Vec<(String, Json)> {
    let bundled = Vocabularies::bundled();
    let mut out: Vec<(String, Json)> = bundled
        .fields()
        .into_iter()
        .filter_map(|field| {
            bundled
                .get(field)
                .map(|vocabulary| (field.to_owned(), index_vocabulary(&vocabulary)))
        })
        .collect();
    if let Some(workspace) = objects {
        for (field, vocabulary) in object_vocabularies(workspace) {
            out.retain(|(known, _)| *known != field);
            out.push((field, vocabulary));
        }
    }
    out
}

fn text_member(members: &[(String, Json)], key: &str) -> String {
    match members
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
    {
        Some(Json::Str(text)) => text.clone(),
        Some(Json::Null) | None => String::new(),
        Some(other) => document_text(other, false).trim_end().to_owned(),
    }
}

/// An index-form vocabulary as the registry's typed definition dumps it
/// (`VocabularyLoader.load`, then `model_dump`): the metadata's and each
/// entry's other keys under `extra`.
fn definition(vocabulary: &Json) -> Json {
    let members = |key: &str| match vocabulary.get(key) {
        Some(Json::Object(members)) => members.clone(),
        _ => Vec::new(),
    };
    let meta = members("metadata");
    let key = match meta
        .iter()
        .find(|(name, _)| name == "key")
        .map(|(_, value)| value)
    {
        Some(Json::Str(key)) if key == "id" || key == "name" => key.clone(),
        _ => {
            let model = matches!(
                meta.iter().find(|(name, _)| name == "model"),
                Some((_, Json::Bool(true)))
            );
            if model { "id" } else { "name" }.to_owned()
        }
    };
    let stages = match meta
        .iter()
        .find(|(name, _)| name == "stages")
        .map(|(_, value)| value)
    {
        Some(Json::Array(stages)) => stages
            .iter()
            .filter_map(|stage| match stage {
                Json::Object(_) => Some(stage.clone()),
                Json::Str(name) => Some(Json::object([("name", Json::str(name))])),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    const META_KNOWN: [&str; 6] = ["name", "description", "icon", "model", "key", "stages"];
    let extra: Vec<(String, Json)> = meta
        .iter()
        .filter(|(name, _)| !META_KNOWN.contains(&name.as_str()))
        .cloned()
        .collect();
    let metadata = Json::object([
        ("name", Json::Str(text_member(&meta, "name"))),
        ("field", Json::Str(text_member(&meta, "field"))),
        ("description", Json::Str(text_member(&meta, "description"))),
        ("icon", Json::Str(text_member(&meta, "icon"))),
        ("key", Json::Str(key.clone())),
        ("model", Json::Bool(key == "id")),
        ("stages", Json::Array(stages)),
        ("extra", Json::Object(extra)),
    ]);
    const ENTRY_RESERVED: [&str; 7] = [
        "name",
        "version",
        "removed",
        "description",
        "icon",
        "link",
        "tide.vocab.stages",
    ];
    let entries = members("entries")
        .into_iter()
        .map(|(key, entry)| {
            let Json::Object(fields) = entry else {
                return (key, Json::Null);
            };
            let removed = text_member(&fields, "removed");
            let version = text_member(&fields, "version");
            let stages = match fields
                .iter()
                .find(|(name, _)| name == "tide.vocab.stages")
                .map(|(_, v)| v)
            {
                Some(Json::Array(items)) => items.clone(),
                Some(Json::Str(stage)) => vec![Json::str(stage)],
                _ => Vec::new(),
            };
            let extra: Vec<(String, Json)> = fields
                .iter()
                .filter(|(name, _)| !ENTRY_RESERVED.contains(&name.as_str()))
                .cloned()
                .collect();
            (
                key,
                Json::object([
                    ("name", Json::Str(text_member(&fields, "name"))),
                    (
                        "version",
                        Json::Str(if version.is_empty() {
                            "1.0".to_owned()
                        } else {
                            version
                        }),
                    ),
                    (
                        "removed",
                        if removed.is_empty() {
                            Json::Null
                        } else {
                            Json::Str(removed)
                        },
                    ),
                    (
                        "description",
                        Json::Str(text_member(&fields, "description")),
                    ),
                    ("icon", Json::Str(text_member(&fields, "icon"))),
                    ("link", Json::Str(text_member(&fields, "link"))),
                    ("tide.vocab.stages", Json::Array(stages)),
                    ("extra", Json::Object(extra)),
                ]),
            )
        })
        .collect();
    Json::object([("metadata", metadata), ("entries", Json::Object(entries))])
}

/// `opentide://vocabularies`: each vocabulary's metadata, entry count and URI.
fn vocabularies_listing(objects: Option<&Workspace>) -> Json {
    Json::Object(
        index_vocabularies(objects)
            .into_iter()
            .map(|(field, vocabulary)| {
                let dumped = definition(&vocabulary);
                let count = match dumped.get("entries") {
                    Some(Json::Object(entries)) => entries.len(),
                    _ => 0,
                };
                let listing = Json::object([
                    (
                        "metadata",
                        dumped.get("metadata").cloned().unwrap_or(Json::Null),
                    ),
                    ("entry_count", Json::from(count)),
                    ("uri", Json::Str(format!("opentide://vocabularies/{field}"))),
                ]);
                (field, listing)
            })
            .collect(),
    )
}

fn vocabulary(objects: Option<&Workspace>, name: &str) -> Json {
    let all = index_vocabularies(objects);
    match all.iter().find(|(field, _)| field == name) {
        Some((_, vocabulary)) => definition(vocabulary),
        None => Json::object([
            (
                "error",
                Json::Str(format!(
                    "Unknown vocabulary {}",
                    crate::render::codeframe::quoted(name)
                )),
            ),
            (
                "available",
                sorted_names(all.iter().map(|(field, _)| field)),
            ),
        ]),
    }
}

/// `opentide://platforms`: what each platform can do here.
fn platforms(workspace: &Workspace) -> Json {
    let systems = workspace
        .configuration()
        .resolved
        .tree
        .get("systems")
        .cloned();
    Json::Array(
        PLATFORMS
            .iter()
            .map(|name| {
                let enabled = matches!(
                    systems
                        .as_ref()
                        .and_then(|systems| systems.get(name))
                        .and_then(|system| system.get("platform"))
                        .and_then(|platform| platform.get("enabled"))
                        .map(|node| &node.value),
                    Some(Value::Bool(true))
                );
                Json::object([
                    ("name", Json::str(*name)),
                    ("enabled", Json::Bool(enabled)),
                    ("can_deploy", Json::Bool(true)),
                    (
                        "can_validate",
                        Json::Bool(!["crowdstrike", "harfanglab", "sysdig"].contains(name)),
                    ),
                    (
                        "can_query",
                        Json::Bool(super::queries::QUERY_PLATFORMS.contains(name)),
                    ),
                ])
            })
            .collect(),
    )
}

fn path_json(path: &Path) -> Json {
    Json::Str(path.to_string_lossy().into_owned())
}

/// `opentide://index`: the registry's index (`Opentide.Index`) as far as it
/// is the workspace's: its paths, configuration, vocabularies, generated
/// schemas and templates, objects and the files they came from.
fn index(workspace: &Workspace, context: &Context<'_>) -> Json {
    let config = &workspace.configuration().resolved.tree;
    let root = workspace.roots().workspace.clone();
    let relative = |section: &str, key: &str, default: &str| {
        let value = paths_value(config, section, key).unwrap_or_else(|| default.to_owned());
        OsFs.resolve(&root.join(value))
    };
    let objects = |key: &str| {
        paths_value(config, "objects", key).map(|value| OsFs.resolve(&root.join(value)))
    };
    let mut tide = Vec::new();
    for family in OBJECT_TYPES {
        if let Some(path) = objects(family) {
            tide.push((family.to_owned(), path_json(&path)));
        }
    }
    let opentide = root.join(".opentide");
    let mut exports =
        paths_value(config, "exports", "root").unwrap_or_else(|| ".opentide/exports/".into());
    if !exports.ends_with('/') {
        exports.push('/');
    }
    tide.extend([
        (
            "json_schemas".to_owned(),
            path_json(&relative("opentide", "schemas", ".opentide/schemas/")),
        ),
        (
            "templates".to_owned(),
            path_json(&relative("opentide", "templates", ".opentide/templates/")),
        ),
        (
            "exports".to_owned(),
            path_json(&OsFs.resolve(&root.join(&exports))),
        ),
        (
            "snippet_file".to_owned(),
            path_json(
                &OsFs.resolve(
                    &root.join(
                        paths_value(config, "objects", "snippet_file")
                            .unwrap_or_else(|| ".vscode/model-templates.code-snippets".into()),
                    ),
                ),
            ),
        ),
        (
            "custom_configurations".to_owned(),
            path_json(&opentide.join("configurations")),
        ),
    ]);
    let docs = |key: &str, default: &str| path_json(&relative("docs", key, default));
    let mut paths: Vec<(String, Json)> = vec![
        ("_workspace_root".to_owned(), path_json(&root)),
        ("opentide".to_owned(), path_json(&opentide)),
    ];
    paths.extend(
        tide.iter()
            .filter(|(key, _)| key != "custom_configurations")
            .cloned(),
    );
    paths.extend([
        ("inflight".to_owned(), path_json(&opentide.join("inflight"))),
        ("docs_folder".to_owned(), docs("root", "docs/")),
        ("rules_docs_folder".to_owned(), docs("rules", "docs/rules/")),
        (
            "objectives_docs_folder".to_owned(),
            docs("objectives", "docs/objectives/"),
        ),
        (
            "threats_docs_folder".to_owned(),
            docs("threats", "docs/threats/"),
        ),
        (
            "custom_configurations".to_owned(),
            path_json(&opentide.join("configurations")),
        ),
        (
            "_artifacts".to_owned(),
            Json::Object(
                ["schemas", "templates", "exports"]
                    .into_iter()
                    .map(|kind| {
                        (
                            kind.to_owned(),
                            Json::Object(
                                artifacts(config, kind)
                                    .into_iter()
                                    .map(|(key, file)| (key, Json::Str(file)))
                                    .collect(),
                            ),
                        )
                    })
                    .collect(),
            ),
        ),
        ("tide".to_owned(), Json::Object(tide.clone())),
    ]);
    let _ = context;
    let schemas = json_schemas(workspace);
    let index = workspace.index();
    let mut families: Vec<(String, Json)> = index
        .objects
        .iter()
        .map(|(family, bucket)| {
            (
                family.clone(),
                Json::Object(
                    bucket
                        .iter()
                        .map(|(uuid, object)| {
                            (uuid.clone(), object.root().map_or(Json::Null, node_json))
                        })
                        .collect(),
                ),
            )
        })
        .collect();
    families.push((
        opentide_workspace::index::SIGNAL_FAMILY.to_owned(),
        Json::Object(
            index
                .signals
                .values()
                .map(|signal| {
                    let mut body = node_json(&signal.node);
                    if let Json::Object(members) = &mut body {
                        members.push((
                            opentide_workspace::index::SIGNAL_OWNER_FIELD.to_owned(),
                            Json::str(&signal.owner),
                        ));
                    }
                    (signal.uuid.clone(), body)
                })
                .collect(),
        ),
    ));
    let object_vocab = object_vocabularies(workspace);
    Json::object([
        ("paths", Json::Object(paths)),
        ("configurations", node_json(config)),
        ("vocabs", Json::Object(index_vocabularies(Some(workspace)))),
        (
            "framework_schemas",
            Json::Object(
                schemas
                    .iter()
                    .map(|(identifier, path, _)| (identifier.clone(), path_json(path)))
                    .collect(),
            ),
        ),
        (
            "json_schemas",
            Json::Object(
                schemas
                    .into_iter()
                    .map(|(identifier, _, content)| (identifier, content))
                    .collect(),
            ),
        ),
        ("templates", Json::Object(templates(workspace))),
        (
            "parse_errors",
            Json::Array(
                index
                    .load_errors
                    .iter()
                    .map(|error| {
                        Json::object([
                            ("path", path_json(&error.path)),
                            ("object_type", Json::str(&error.family)),
                            ("code", Json::str(error.code)),
                            ("error", Json::str(&error.error)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "duplicate_files",
            Json::Array(
                index
                    .duplicates
                    .iter()
                    .map(|duplicate| {
                        Json::object([
                            ("path", path_json(&duplicate.path)),
                            ("object_type", Json::str(&duplicate.family)),
                            ("uuid", Json::str(&duplicate.uuid)),
                            ("message", Json::str(&duplicate.message)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "nested_object_files",
            Json::Array(
                index
                    .nested
                    .iter()
                    .map(|nested| {
                        Json::object([
                            ("path", path_json(&nested.path)),
                            ("folder", path_json(&nested.folder)),
                            ("object_type", Json::str(&nested.family)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("objects", Json::Object(families)),
        (
            "files",
            Json::Object(
                index
                    .files()
                    .into_iter()
                    .map(|(uuid, name)| (uuid, Json::Str(name)))
                    .collect(),
            ),
        ),
        (
            "file_paths",
            Json::Object(
                index
                    .file_paths
                    .iter()
                    .map(|(uuid, path)| (uuid.clone(), path_json(path)))
                    .collect(),
            ),
        ),
        (
            "indexes",
            Json::object([("objects", Json::Object(object_vocab))]),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_simple_variable_takes_no_reserved_character_and_a_reserved_one_does() {
        assert_eq!(expand("att%26ck", false), Some("att&ck".to_owned()));
        assert_eq!(expand("att&ck", false), None);
        assert_eq!(
            expand("att&ck.groups", true),
            Some("att&ck.groups".to_owned())
        );
        assert_eq!(expand("a/b", false), None);
        assert_eq!(expand("rule::1.1", false), Some("rule::1.1".to_owned()));
        assert_eq!(expand("a?b", true), None);
        assert_eq!(expand("", true), None);
    }

    #[test]
    fn a_family_alias_resolves_to_its_highest_version() {
        let keys = ["rule::1.0", "rule::1.1", "threat::1.0"];
        assert_eq!(
            resolve_family_key(keys, "rules").as_deref(),
            Some("rule::1.1")
        );
        assert_eq!(
            resolve_family_key(keys, "rule.1.0").as_deref(),
            Some("rule::1.0")
        );
        assert_eq!(
            resolve_family_key(keys, "rule::1.0").as_deref(),
            Some("rule::1.0")
        );
        assert_eq!(resolve_family_key(keys, "widget"), None);
        assert_eq!(
            schema_artifact_identifier("rule.1.0.schema.json").as_deref(),
            Some("rule::1.0")
        );
        assert_eq!(schema_artifact_identifier("opentide.schema.json"), None);
    }

    #[test]
    fn a_vocabulary_dumps_its_other_keys_under_extra() {
        let vocabulary = Vocabularies::bundled().get("tlp").unwrap();
        let dumped = definition(&index_vocabulary(&vocabulary));
        let metadata = dumped.get("metadata").unwrap();
        assert_eq!(metadata.get("key"), Some(&Json::str("name")));
        assert_eq!(
            metadata.get("extra").and_then(|extra| extra.get("field")),
            Some(&Json::str("tlp"))
        );
        let Some(Json::Object(entries)) = dumped.get("entries") else {
            panic!("no entries");
        };
        let (_, first) = &entries[0];
        assert_eq!(first.get("removed"), Some(&Json::Null));
        assert!(first.get("extra").is_some());
    }
}
