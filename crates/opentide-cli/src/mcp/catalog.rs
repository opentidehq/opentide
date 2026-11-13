//! The catalogue tools (`src/opentide/mcp_server/catalog.py` and the
//! registry tools of `tools.py`): `search`, `get_chaining`, `coverage`,
//! `deployment_status` and `validate_rule`, on the workspace as it is on disk
//! at the call.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use indexmap::IndexMap;
use opentide_schema::node::{Node, Value};
use opentide_schema::objects::FieldRole;
use opentide_workspace::coverage::{match_technique, rule_technique_index, technique_covers};
use opentide_workspace::{Index, Workspace, fields};

use super::tools::{Context, next_action, validation_next_actions};
use crate::json::Json;

/// The object families the catalogue tools read, in the order they search them.
pub const FAMILIES: [&str; 3] = ["rule", "threat", "objective"];

/// The workspace `context` places, opened afresh: the tools answer for the
/// files as they are now.
pub fn workspace(context: &Context<'_>) -> Result<Workspace, String> {
    let cwd = context
        .cwd
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let (_, roots) = crate::commands::placement(context.repo, context.env, &cwd);
    crate::commands::open(roots)
        .map_err(|message| format!("{}: {message}", crate::commands::COMMAND_FAILED))
}

/// [`workspace`], refused with the reason when the launch found none
/// (`require_workspace`).
pub fn require(context: &Context<'_>) -> Result<Workspace, String> {
    if let Some(problem) = &context.workspace_problem {
        return Err(problem.clone());
    }
    workspace(context)
}

/// A YAML node as JSON, keys in the document's order.
pub fn node_json(node: &Node) -> Json {
    match &node.value {
        Value::Null => Json::Null,
        Value::Bool(flag) => Json::Bool(*flag),
        Value::Int(integer) => Json::Int(*integer),
        Value::Float(float) if float.is_finite() => Json::Float(*float),
        Value::Float(float) => Json::str(if float.is_nan() {
            "nan"
        } else if *float > 0.0 {
            "inf"
        } else {
            "-inf"
        }),
        Value::Str(text) | Value::Datetime(text) => Json::str(text),
        Value::Seq(items) => Json::Array(items.iter().map(|item| node_json(item)).collect()),
        Value::Map(entries) => Json::Object(
            entries
                .iter()
                .map(|entry| (entry.key.value.to_string(), node_json(&entry.value)))
                .collect(),
        ),
    }
}

/// One object found by UUID: its family, its key in the index, its body.
pub struct Found<'i> {
    /// `rule`, `threat` or `objective`.
    pub family: &'static str,
    /// The UUID as the index keys it.
    pub uuid: &'i str,
    /// Its document's root.
    pub body: Option<&'i Node>,
}

/// The object `uuid` names, across the families; UUIDs compare
/// case-insensitively (RFC 9562), an exact key first (`get_object`).
pub fn get_object<'i>(index: &'i Index, uuid: &str) -> Option<Found<'i>> {
    let needle = uuid.trim();
    let folded = needle.to_lowercase();
    for family in FAMILIES {
        let Some(bucket) = index.objects.get(family) else {
            continue;
        };
        let hit = bucket
            .get_key_value(needle)
            .or_else(|| bucket.iter().find(|(key, _)| key.to_lowercase() == folded));
        if let Some((key, object)) = hit {
            return Some(Found {
                family,
                uuid: key,
                body: object.root(),
            });
        }
    }
    None
}

/// The status of each platform block of a rule, sorted and once each
/// (`block_statuses`).
pub fn block_statuses(body: &Node) -> Vec<String> {
    let Some(Value::Map(blocks)) = body.get("configurations").map(|node| &node.value) else {
        return Vec::new();
    };
    blocks
        .iter()
        .filter_map(
            |entry| match entry.value.get("status").map(|node| &node.value) {
                Some(Value::Str(status)) if !status.is_empty() => Some(status.clone()),
                _ => None,
            },
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn summary(uuid: &str, family: &str, body: &Node) -> Json {
    let title = match body.get("name").map(|node| &node.value) {
        None | Some(Value::Null | Value::Bool(false)) => Json::str(uuid),
        Some(Value::Str(text)) if text.is_empty() => Json::str(uuid),
        Some(Value::Int(0)) => Json::str(uuid),
        Some(_) => body.get("name").map_or(Json::Null, |node| node_json(node)),
    };
    let statuses = if family == "rule" {
        block_statuses(body)
    } else {
        Vec::new()
    };
    Json::object([
        ("uuid", Json::str(uuid)),
        ("type", Json::str(family)),
        ("title", title),
        (
            "status",
            if statuses.is_empty() {
                Json::Null
            } else {
                Json::Str(statuses.join(", "))
            },
        ),
    ])
}

/// The filters of `search`.
pub struct Filters {
    /// `type`.
    pub family: String,
    /// `platform`.
    pub platform: String,
    /// `status`.
    pub status: String,
    /// `technique`.
    pub technique: String,
    /// `actor`.
    pub actor: String,
}

impl Filters {
    fn wanted(&self, family: &str, body: &Node) -> bool {
        (self.family.is_empty() || self.family == family)
            && (self.status.is_empty() || block_statuses(body).contains(&self.status))
            && matches_technique(body, &self.technique)
            && matches_actor(body, &self.actor)
            && matches_platform(body, &self.platform)
    }
}

fn matches_technique(body: &Node, technique: &str) -> bool {
    technique.trim().is_empty()
        || fields::role_values(body, FieldRole::Techniques)
            .iter()
            .any(|(_, value)| technique_covers(technique, value))
}

fn matches_actor(body: &Node, actor: &str) -> bool {
    let needle = actor.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    fields::role_values(body, FieldRole::Actors)
        .iter()
        .any(|(_, name)| {
            let lowered = name.to_lowercase();
            lowered == needle
                || lowered
                    .rsplit_once("::")
                    .is_some_and(|(_, suffix)| suffix == needle)
        })
}

fn matches_platform(body: &Node, platform: &str) -> bool {
    let needle = platform.trim().to_lowercase();
    needle.is_empty() || fields::platforms(body).contains(&needle)
}

static UUID: LazyLock<regex::Regex> = LazyLock::new(|| {
    #[expect(clippy::expect_used, reason = "a literal pattern")]
    regex::Regex::new("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        .expect("valid regex")
});

/// `search`: a summary of each object `query` and the filters match.
pub fn search(index: &Index, query: &str, filters: &Filters) -> Vec<Json> {
    if UUID.is_match(query.trim()) {
        let Some(found) = get_object(index, query) else {
            return Vec::new();
        };
        let Some(body) = found.body else {
            return Vec::new();
        };
        if !filters.wanted(found.family, body) {
            return Vec::new();
        }
        return vec![summary(found.uuid, found.family, body)];
    }
    let needle = query.to_lowercase();
    let mut results = Vec::new();
    for family in FAMILIES {
        if !filters.family.is_empty() && filters.family != family {
            continue;
        }
        for (uuid, body) in opentide_workspace::coverage::bucket(index, family) {
            if !filters.wanted(family, body) {
                continue;
            }
            let text = |key: &str| match body.get(key).map(|node| &node.value) {
                None => String::new(),
                Some(Value::Null) => "None".to_owned(),
                Some(value) => value.to_string(),
            };
            let haystack =
                format!("{uuid} {} {}", text("name"), text("description")).to_lowercase();
            if haystack.contains(&needle) {
                results.push(summary(uuid, family, body));
            }
        }
    }
    results
}

/// The UUIDs a field holds: a string, or a list of strings, each trimmed.
fn string_ids(node: Option<&Node>) -> Vec<String> {
    match node.map(|node| &node.value) {
        Some(Value::Str(text)) if !text.trim().is_empty() => vec![text.trim().to_owned()],
        Some(Value::Seq(items)) => items
            .iter()
            .filter_map(|item| match &item.value {
                Value::Str(text) if !text.trim().is_empty() => Some(text.trim().to_owned()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn catalogue_family(index: &Index, uuid: &str) -> Option<&'static str> {
    [
        ("threat", "threats"),
        ("objective", "objectives"),
        ("rule", "rules"),
    ]
    .into_iter()
    .find(|(family, _)| {
        index
            .objects
            .get(*family)
            .is_some_and(|bucket| bucket.contains_key(uuid))
    })
    .map(|(_, plural)| plural)
}

/// The threats, objectives and rules of one connected set.
type Lineage = [Vec<String>; 3];

fn lineage_json(lineage: &Lineage) -> Json {
    Json::object([
        (
            "threats",
            Json::Array(lineage[0].iter().map(Json::str).collect()),
        ),
        (
            "objectives",
            Json::Array(lineage[1].iter().map(Json::str).collect()),
        ),
        (
            "rules",
            Json::Array(lineage[2].iter().map(Json::str).collect()),
        ),
    ])
}

/// The connected sets reached through `objective.threats`,
/// `detection_model` and `threat.chaining` (`_lineage_by_uuid`): each
/// member's set, in the order members were first linked.
fn lineage_by_uuid(index: &Index) -> IndexMap<String, Lineage> {
    let mut parent: HashMap<String, String> = HashMap::new();
    let mut families: IndexMap<String, &'static str> = IndexMap::new();
    fn find(parent: &mut HashMap<String, String>, node: &str) -> String {
        let mut current = node.to_owned();
        parent
            .entry(current.clone())
            .or_insert_with(|| current.clone());
        loop {
            let next = parent
                .get(&current)
                .cloned()
                .unwrap_or_else(|| current.clone());
            if next == current {
                return current;
            }
            let grand = parent.get(&next).cloned().unwrap_or_else(|| next.clone());
            parent.insert(current.clone(), grand.clone());
            current = grand;
        }
    }
    let mut unite =
        |left: &str, left_family: &'static str, right: &str, right_family: &'static str| {
            let left_known = catalogue_family(index, left).unwrap_or(left_family);
            let right_known = catalogue_family(index, right).unwrap_or(right_family);
            families.insert(left.to_owned(), left_known);
            families.insert(right.to_owned(), right_known);
            let left_root = find(&mut parent, left);
            let right_root = find(&mut parent, right);
            if left_root != right_root {
                parent.insert(right_root, left_root);
            }
        };
    for (uuid, body) in opentide_workspace::coverage::bucket(index, "objective") {
        let threats = match body.get("objective") {
            Some(nested) if matches!(nested.value, Value::Map(_)) => {
                string_ids(nested.get("threats").map(AsRef::as_ref))
            }
            _ => Vec::new(),
        };
        for threat in threats {
            unite(uuid, "objectives", &threat, "threats");
        }
    }
    for (uuid, body) in opentide_workspace::coverage::bucket(index, "rule") {
        for objective in string_ids(body.get("detection_model").map(AsRef::as_ref)) {
            unite(uuid, "rules", &objective, "objectives");
        }
    }
    for (uuid, relation) in &index.chaining {
        for vectors in relation.values() {
            for vector in vectors {
                let vector = vector.trim();
                if !vector.is_empty() {
                    unite(uuid, "threats", vector, "threats");
                }
            }
        }
    }
    let mut groups: IndexMap<String, Vec<String>> = IndexMap::new();
    let members: Vec<String> = families.keys().cloned().collect();
    for node in members {
        let root = find(&mut parent, &node);
        groups.entry(root).or_default().push(node);
    }
    let mut lineage = IndexMap::new();
    for members in groups.values() {
        let mut block: Lineage = Default::default();
        for (slot, family) in ["threats", "objectives", "rules"].into_iter().enumerate() {
            let mut picked: Vec<String> = members
                .iter()
                .filter(|uuid| families.get(*uuid) == Some(&family))
                .cloned()
                .collect();
            picked.sort();
            block[slot] = picked;
        }
        if block.iter().all(Vec::is_empty) {
            continue;
        }
        for uuid in members {
            lineage.insert(uuid.clone(), block.clone());
        }
    }
    lineage
}

fn relation_json(relation: &IndexMap<String, Vec<String>>) -> Json {
    Json::Object(
        relation
            .iter()
            .map(|(name, vectors)| {
                (
                    name.clone(),
                    Json::Array(vectors.iter().map(Json::str).collect()),
                )
            })
            .collect(),
    )
}

/// `get_chaining`: the lineage of the object `uuid` names.
pub fn get_chaining(index: &Index, uuid: &str) -> Json {
    let Some(node) = get_object(index, uuid) else {
        return Json::object([
            ("uuid", Json::str(uuid)),
            ("found", Json::Bool(false)),
            ("graph", Json::object::<&str>([])),
        ]);
    };
    let lineages = lineage_by_uuid(index);
    let relation = index.chaining.get(node.uuid).filter(|r| !r.is_empty());
    let lineage = lineages.get(node.uuid);
    let graph = match (relation, lineage) {
        (Some(relation), _) => relation_json(relation),
        (None, Some(lineage)) => lineage_json(lineage),
        (None, None) => Json::object::<&str>([]),
    };
    let mut chaining_index: Vec<(String, Json)> = index
        .chaining
        .iter()
        .filter(|(_, relation)| !relation.is_empty())
        .map(|(uuid, relation)| (uuid.clone(), relation_json(relation)))
        .collect();
    for (uuid, lineage) in &lineages {
        if !chaining_index.iter().any(|(key, _)| key == uuid) {
            chaining_index.push((uuid.clone(), lineage_json(lineage)));
        }
    }
    let mut payload = vec![
        ("uuid".to_owned(), Json::str(node.uuid)),
        ("found".to_owned(), Json::Bool(true)),
        ("type".to_owned(), Json::str(node.family)),
        ("graph".to_owned(), graph),
        ("chaining_index".to_owned(), Json::Object(chaining_index)),
    ];
    if let Some(lineage) = lineage {
        payload.push(("lineage".to_owned(), lineage_json(lineage)));
    }
    Json::Object(payload)
}

fn strings(items: impl IntoIterator<Item = String>) -> Json {
    Json::Array(items.into_iter().map(Json::Str).collect())
}

fn sorted(items: &[String]) -> Json {
    let mut items = items.to_vec();
    items.sort();
    strings(items)
}

/// `coverage`: the rules that cover `technique`, or the whole matrix.
pub fn coverage(index: &Index, technique: &str, tactic: &str) -> Json {
    let techniques = rule_technique_index(index);
    if !technique.is_empty() {
        let found = match_technique(technique, &techniques);
        return Json::object([
            ("technique", Json::str(&found.technique)),
            ("covered", Json::Bool(!found.rules.is_empty())),
            (
                "matched_techniques",
                strings(found.matched_techniques.clone()),
            ),
            ("rules", sorted(&found.rules)),
            ("own_rules", sorted(&found.own)),
            ("inherited_rules", sorted(&found.inherited)),
        ]);
    }
    let mut covered: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut own: IndexMap<String, Vec<String>> = IndexMap::new();
    for (uuid, rule) in &techniques {
        let all: BTreeSet<&String> = rule.own.iter().chain(&rule.inherited).collect();
        for tech in all {
            covered.entry(tech.clone()).or_default().push(uuid.clone());
            if rule.own.contains(tech) {
                own.entry(tech.clone()).or_default().push(uuid.clone());
            }
        }
    }
    let matrix = |map: IndexMap<String, Vec<String>>| {
        Json::Object(
            map.into_iter()
                .map(|(tech, uuids)| (tech, strings(uuids)))
                .collect(),
        )
    };
    Json::object([
        ("technique_count", Json::from(covered.len())),
        ("matrix", matrix(covered)),
        ("own_matrix", matrix(own)),
        (
            "tactic_filter",
            if tactic.is_empty() {
                Json::Null
            } else {
                Json::str(tactic)
            },
        ),
    ])
}

fn platform_state(block: Option<&Node>, external_ids: Option<&IndexMap<String, String>>) -> Json {
    let ids: Vec<(String, Json)> = external_ids
        .map(|ids| {
            ids.iter()
                .map(|(tenant, id)| (tenant.clone(), Json::str(id)))
                .collect()
        })
        .unwrap_or_default();
    let tenants: Vec<Json> = match block
        .and_then(|block| block.get("tenants"))
        .map(|n| &n.value)
    {
        Some(Value::Seq(items)) => items.iter().map(|item| node_json(item)).collect(),
        _ => Vec::new(),
    };
    let rule_id = if ids.len() == 1 {
        ids[0].1.clone()
    } else {
        Json::Null
    };
    Json::object([
        (
            "deployed",
            Json::Bool(!ids.is_empty() || !tenants.is_empty()),
        ),
        ("rule_id", rule_id),
        ("external_ids", Json::Object(ids)),
        ("tenants", Json::Array(tenants)),
    ])
}

/// `deployment_status`: where the rule `uuid` is deployed.
pub fn deployment_status(workspace: &Workspace, uuid: &str) -> Json {
    let index = workspace.index();
    let Some(body) = index
        .objects
        .get("rule")
        .and_then(|bucket| bucket.get(uuid))
        .map(|object| object.root())
    else {
        return Json::object([
            ("platforms", Json::object::<&str>([])),
            ("uuid", Json::str(uuid)),
            ("found", Json::Bool(false)),
        ]);
    };
    let (recorded, state_error) =
        match crate::commands::deploy_state::Shard::load(workspace.root(), uuid) {
            Ok(shard) => (shard.platforms, None),
            Err(error) => (
                IndexMap::new(),
                Some(Json::object([
                    ("code", Json::str(error.code)),
                    ("message", Json::str(&error.message)),
                ])),
            ),
        };
    let mut platforms: Vec<(String, Json)> = Vec::new();
    let configurations = body.and_then(|body| {
        ["configurations", "platforms"]
            .into_iter()
            .filter_map(|key| body.get(key))
            .find(|node| !matches!(&node.value, Value::Null) && truthy(node))
    });
    if let Some(Value::Map(blocks)) = configurations.map(|node| &node.value) {
        for entry in blocks {
            let name = entry.key.value.to_string();
            let block = matches!(entry.value.value, Value::Map(_)).then_some(entry.value.as_ref());
            platforms.push((name.clone(), platform_state(block, recorded.get(&name))));
        }
    }
    for (name, ids) in &recorded {
        if !platforms.iter().any(|(key, _)| key == name) {
            platforms.push((name.clone(), platform_state(None, Some(ids))));
        }
    }
    let mut payload = vec![
        ("platforms".to_owned(), Json::Object(platforms)),
        ("uuid".to_owned(), Json::str(uuid)),
        ("found".to_owned(), Json::Bool(true)),
    ];
    if let Some(error) = state_error {
        payload.push(("state_error".to_owned(), error));
    }
    Json::Object(payload)
}

/// Python's truthiness of a YAML value.
fn truthy(node: &Node) -> bool {
    match &node.value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Int(number) => *number != 0,
        Value::Float(number) => *number != 0.0,
        Value::Str(text) | Value::Datetime(text) => !text.is_empty(),
        Value::Seq(items) => !items.is_empty(),
        Value::Map(entries) => !entries.is_empty(),
    }
}

/// The platforms opentide knows (`Opentide.Platforms`), in name order.
pub const PLATFORMS: [&str; opentide_schema::platforms::COUNT] =
    opentide_schema::platforms::ordered(opentide_schema::platforms::Order::Name);

/// Whether `platform` is one opentide deploys to: built in, or an installed
/// platform plugin's.
pub fn known_platform(platform: &str) -> bool {
    PLATFORMS.contains(&platform)
        || crate::plugins::configurations()
            .is_some_and(|plugins| plugins.platforms().iter().any(|name| name == platform))
}

/// The `--strategy` values whose run deploys the rule's `platform` block;
/// none for `INERT`. A status the deployment configuration does not define
/// runs `PREVIEW` (`_run_strategies`).
fn run_strategies(workspace: &Workspace, body: &Node, platform: &str) -> Vec<&'static str> {
    use opentide_compile::strategy::{Statuses, deployed_by};
    let block_status = body
        .get("configurations")
        .and_then(|blocks| blocks.get(platform))
        .and_then(|block| block.get("status"))
        .and_then(|status| fields::text(Some(status)));
    let status = block_status
        .or_else(|| fields::text(body.get("status").map(AsRef::as_ref)))
        .unwrap_or_default();
    let statuses = Statuses::from_resolved(&workspace.configuration().resolved);
    match statuses.strategy(&status) {
        Ok(strategy) => deployed_by(strategy)
            .into_iter()
            .map(|run| run.name())
            .collect(),
        Err(_) => vec!["PREVIEW"],
    }
}

/// An issue as `ValidationIssue.to_legacy_string` writes it, from its JSON.
fn legacy(entry: &Json) -> String {
    let location = match entry.get("field_path") {
        Some(Json::Array(parts)) => parts
            .iter()
            .map(|part| match part {
                Json::Str(text) => text.clone(),
                other => crate::json::document_text(other, false)
                    .trim_end()
                    .to_owned(),
            })
            .collect::<Vec<_>>()
            .join("."),
        _ => String::new(),
    };
    let message = entry
        .get("message")
        .and_then(Json::as_str)
        .unwrap_or_default();
    if location.is_empty() {
        message.to_owned()
    } else {
        format!("{location}: {message}")
    }
}

/// `validate_rule`: one rule's report, with its next steps.
pub fn validate_rule(context: &Context<'_>, uuid: &str) -> Result<Json, String> {
    let workspace = require(context)?;
    let Some(body) = workspace
        .index()
        .objects
        .get("rule")
        .and_then(|bucket| bucket.get(uuid))
        .map(|object| object.root())
    else {
        return Ok(Json::object([
            ("valid", Json::Bool(false)),
            ("errors", strings([format!("Rule {uuid} not found")])),
            ("warnings", Json::Array(Vec::new())),
            ("issues", Json::Array(Vec::new())),
            (
                "next_actions",
                Json::Array(vec![next_action(
                    "search",
                    Json::object([("query", Json::str("")), ("type", Json::str("rule"))]),
                    "opentide --json info rules",
                    "list the catalogue's rules to find the UUID: search returns each rule's \
                     title, the command only the UUIDs",
                )]),
            ),
        ]));
    };
    let request = crate::embed::ValidateRequest {
        uuids: vec![uuid.to_owned()],
        queries: "error".to_owned(),
        repo: context.repo.map(str::to_owned),
        ..crate::embed::ValidateRequest::default()
    };
    let cwd = context
        .cwd
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let report = super::tools::report(&request, context.env, &cwd)?;
    let ok = matches!(report.get("ok"), Some(Json::Bool(true)));
    let list = |key: &str| match report.get(key) {
        Some(Json::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    let issues = list("issues");
    let errors: Vec<String> = issues
        .iter()
        .filter(|entry| entry.get("severity").and_then(Json::as_str) == Some("error"))
        .map(legacy)
        .collect();
    let warnings: Vec<String> = list("warnings").iter().map(legacy).collect();
    let again = next_action(
        "validate_rule",
        Json::object([("uuid", Json::str(uuid))]),
        &format!(
            "opentide --json validate --uuid {}",
            super::tools::quote(uuid)
        ),
        "",
    );
    let mut actions = validation_next_actions(&issues, again);
    if ok && let Some(body) = body {
        let platforms: Vec<String> = match body.get("configurations").map(|node| &node.value) {
            Some(Value::Map(blocks)) => blocks
                .iter()
                .map(|entry| entry.key.value.to_string())
                .filter(|name| known_platform(name))
                .collect(),
            _ => Vec::new(),
        };
        for platform in platforms {
            let runs = run_strategies(&workspace, body, &platform);
            if runs.is_empty() {
                continue;
            }
            let flags = runs
                .iter()
                .map(|name| format!("--strategy {name}"))
                .collect::<Vec<_>>()
                .join(" ");
            actions.push(next_action(
                "deploy_rule",
                Json::object([
                    ("uuid", Json::str(uuid)),
                    ("platform", Json::str(&platform)),
                    ("dry_run", Json::Bool(true)),
                ]),
                &format!("opentide --json deploy --dry-run {flags} --all --platform {platform}"),
                &format!("preview the {platform} deployment; nothing is sent"),
            ));
        }
    }
    Ok(Json::object([
        ("valid", Json::Bool(ok)),
        ("errors", strings(errors)),
        ("warnings", strings(warnings)),
        ("issues", Json::Array(issues)),
        ("next_actions", Json::Array(actions)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(files: &[(&str, &str)]) -> Workspace {
        let mut all = vec![(".opentide/configurations/.keep", "")];
        all.extend_from_slice(files);
        let fs = opentide_workspace::MemoryFs::new();
        for (path, text) in &all {
            fs.write(format!("/ws/{path}"), text.as_bytes().to_vec());
        }
        Workspace::open(
            std::sync::Arc::new(fs),
            opentide_workspace::Options {
                roots: opentide_workspace::RootOptions {
                    repo: Some("/ws".into()),
                    repo_root_env: None,
                    tide_workspace_env: None,
                    cwd: "/ws".into(),
                },
            },
        )
        .unwrap()
    }

    const THREAT: &str = "name: Actor\nmetadata: {uuid: 11111111-1111-4111-8111-111111111111, schema: threat::1.0}\nthreat:\n  actors: [{name: 'att&ck::G0006'}]\n  mitre_attack: [T1003]\n";
    const OBJECTIVE: &str = "name: Goal\nmetadata: {uuid: 22222222-2222-4222-8222-222222222222, schema: objective::1.0}\nobjective:\n  threats: [11111111-1111-4111-8111-111111111111]\n";
    const RULE: &str = "name: Watch\nmetadata: {uuid: 33333333-3333-4333-8333-333333333333, schema: rule::1.0}\ndescription: Looks for logons\ntechniques: [T1059.001]\ndetection_model: 22222222-2222-4222-8222-222222222222\nconfigurations:\n  sentinel: {status: STAGING, tenants: [a]}\n  splunk: {status: DESIGN}\n";

    fn ws() -> Workspace {
        index(&[
            ("objects/threats/t.yaml", THREAT),
            ("objects/objectives/o.yaml", OBJECTIVE),
            ("objects/rules/r.yaml", RULE),
        ])
    }

    fn none() -> Filters {
        Filters {
            family: String::new(),
            platform: String::new(),
            status: String::new(),
            technique: String::new(),
            actor: String::new(),
        }
    }

    fn uuids(hits: &[Json]) -> Vec<String> {
        hits.iter()
            .map(|hit| hit.get("uuid").and_then(Json::as_str).unwrap().to_owned())
            .collect()
    }

    #[test]
    fn search_matches_text_uuids_and_filters() {
        let ws = ws();
        let index = ws.index();
        assert_eq!(uuids(&search(index, "LOGONS", &none())).len(), 1);
        let hit = search(index, "33333333-3333-4333-8333-333333333333", &none());
        assert_eq!(
            hit[0].get("status"),
            Some(&Json::str("DESIGN, STAGING")),
            "the statuses of the blocks, sorted"
        );
        let upper = search(
            index,
            "33333333-3333-4333-8333-33333333333A"
                .to_lowercase()
                .as_str(),
            &none(),
        );
        assert!(upper.is_empty(), "another UUID");
        let filtered = |filters: Filters| uuids(&search(index, "", &filters));
        assert_eq!(
            filtered(Filters {
                technique: "t1059".into(),
                ..none()
            }),
            ["33333333-3333-4333-8333-333333333333"]
        );
        assert_eq!(
            filtered(Filters {
                actor: "G0006".into(),
                ..none()
            }),
            ["11111111-1111-4111-8111-111111111111"]
        );
        assert!(
            filtered(Filters {
                platform: "sentinel_one".into(),
                ..none()
            })
            .is_empty()
        );
        assert_eq!(
            filtered(Filters {
                status: "STAGING".into(),
                ..none()
            })
            .len(),
            1
        );
        assert_eq!(
            filtered(Filters {
                family: "objective".into(),
                ..none()
            })
            .len(),
            1
        );
        assert_eq!(
            filtered(none()).len(),
            3,
            "rules, then threats, then objectives"
        );
    }

    #[test]
    fn chaining_links_threats_objectives_and_rules() {
        let ws = ws();
        let graph = get_chaining(ws.index(), "33333333-3333-4333-8333-333333333333");
        assert_eq!(graph.get("type"), Some(&Json::str("rule")));
        let lineage = graph.get("lineage").unwrap();
        assert_eq!(
            lineage.get("threats"),
            Some(&strings(
                ["11111111-1111-4111-8111-111111111111".to_owned()]
            ))
        );
        assert_eq!(graph.get("graph"), Some(lineage));
        let unknown = get_chaining(ws.index(), "nope");
        assert_eq!(unknown.get("found"), Some(&Json::Bool(false)));
    }

    #[test]
    fn coverage_counts_a_parent_and_lists_the_matrix() {
        let ws = ws();
        let found = coverage(ws.index(), "T1059", "");
        assert_eq!(found.get("covered"), Some(&Json::Bool(true)));
        assert_eq!(
            found.get("matched_techniques"),
            Some(&strings(["T1059.001".to_owned()]))
        );
        let matrix = coverage(ws.index(), "", "execution");
        assert_eq!(matrix.get("tactic_filter"), Some(&Json::str("execution")));
        assert!(
            matrix.get("matrix").unwrap().get("T1003").is_some(),
            "inherited"
        );
        assert!(matrix.get("own_matrix").unwrap().get("T1003").is_none());
    }

    #[test]
    fn a_legacy_string_leads_with_the_field_path() {
        let entry = Json::object([
            (
                "field_path",
                Json::Array(vec![Json::str("a"), Json::Int(0)]),
            ),
            ("message", Json::str("bad")),
        ]);
        assert_eq!(legacy(&entry), "a.0: bad");
        assert_eq!(legacy(&Json::object([("message", Json::str("m"))])), "m");
    }

    #[test]
    fn truthiness_is_pythons() {
        let node = |text: &str| {
            opentide_schema::node::load(text)
                .unwrap()
                .root()
                .unwrap()
                .as_ref()
                .clone()
        };
        assert!(!truthy(&node("[]")) && truthy(&node("[1]")) && !truthy(&node("0")));
        assert!(!truthy(&node("''")) && truthy(&node("{a: 1}")) && !truthy(&node("false")));
    }
}
