//! The catalogue tools (`src/opentide/mcp_server/catalog.py` and the
//! registry tools of `tools.py`): `search`, `get_chaining`, `coverage`,
//! `deployment_status` and `validate_rule`, on the workspace as it is on disk
//! at the call.

use std::collections::{BTreeSet, HashMap, HashSet};
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

/// The workspace `context` places, as its files are now: under a call
/// ([`super::tools::call`]) the process's warm one, brought up to date with
/// what changed on disk since the last call.
pub fn workspace(context: &Context<'_>) -> Result<Workspace, String> {
    let cwd = context
        .cwd
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let (_, roots) = crate::commands::placement(context.repo, context.env, &cwd);
    // A configuration file that does not parse keeps `config_parse` and its
    // place, as on the command line (D9, B10).
    crate::commands::open_for("mcp", roots).map_err(|refused| {
        let (code, message, _) = crate::commands::refusal_parts(&refused);
        format!("{code}: {message}")
    })
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
        Value::Str(text) | Value::Datetime(text) => Json::str(text.as_str()),
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
                Some(Value::Str(status)) if !status.is_empty() => Some(status.to_string()),
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
                Some(Value::Null) => String::new(),
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

/// An edge of the lineage: two objects, each with the family it is taken to
/// be when the catalogue does not know it.
type Edge = (String, &'static str, String, &'static str);

/// The references the lineage follows, in the order they are read:
/// `objective.threats`, `detection_model` (a signal belongs to its
/// objective) and `threat.chaining`.
fn lineage_edges(index: &Index) -> Vec<Edge> {
    let mut edges: Vec<Edge> = Vec::new();
    for (uuid, body) in opentide_workspace::coverage::bucket(index, "objective") {
        let threats = match body.get("objective") {
            Some(nested) if matches!(nested.value, Value::Map(_)) => {
                string_ids(nested.get("threats").map(AsRef::as_ref))
            }
            _ => Vec::new(),
        };
        for threat in threats {
            edges.push((uuid.to_owned(), "objectives", threat, "threats"));
        }
    }
    for (uuid, body) in opentide_workspace::coverage::bucket(index, "rule") {
        for target in string_ids(body.get("detection_model").map(AsRef::as_ref)) {
            // A signal belongs to its objective: the rule joins that lineage.
            let objective = if catalogue_family(index, &target).is_some() {
                target
            } else {
                index
                    .signal(&target)
                    .map_or(target, |signal| signal.owner.clone())
            };
            edges.push((uuid.to_owned(), "rules", objective, "objectives"));
        }
    }
    for (uuid, relation) in &index.chaining {
        for vectors in relation.values() {
            for vector in vectors {
                let vector = vector.trim();
                if !vector.is_empty() {
                    edges.push((uuid.clone(), "threats", vector.to_owned(), "threats"));
                }
            }
        }
    }
    edges
}

/// The connected sets reached through `objective.threats`,
/// `detection_model` and `threat.chaining` (`_lineage_by_uuid`): each
/// member's set, in the order members were first linked.
fn lineage_by_uuid(index: &Index, edges: &[Edge]) -> IndexMap<String, Lineage> {
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
    for (left, left_family, right, right_family) in edges {
        unite(left, left_family, right, right_family);
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

/// The UUIDs within `depth` hops of `start`, over the lineage's references
/// followed in either direction: threat <-> objective <-> rule, and the
/// links of `threat.chaining`.
fn within_hops(edges: &[Edge], start: &str, depth: usize) -> HashSet<String> {
    let mut neighbours: HashMap<String, Vec<String>> = HashMap::new();
    for (left, _, right, _) in edges {
        neighbours
            .entry(left.clone())
            .or_default()
            .push(right.clone());
        neighbours
            .entry(right.clone())
            .or_default()
            .push(left.clone());
    }
    let mut reached: HashSet<String> = HashSet::from([start.to_owned()]);
    let mut frontier = vec![start.to_owned()];
    for _ in 0..depth {
        let mut next = Vec::new();
        for uuid in &frontier {
            for neighbour in neighbours.get(uuid).into_iter().flatten() {
                if reached.insert(neighbour.clone()) {
                    next.push(neighbour.clone());
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    reached
}

/// The hops `get_chaining` follows when the call names no `depth`: the
/// object's direct neighbours. A whole lineage can hold most of a large
/// catalogue, so it is fetched only by asking for a larger depth.
pub const DEFAULT_CHAINING_DEPTH: usize = 1;

/// `get_chaining`: the lineage of the object `uuid` names; a signal's UUID
/// names its objective (`resolved_from`). Only the objects within `depth`
/// hops of it, in either direction, are returned (`0`: the object alone);
/// when the lineage reaches further, the answer says so with `truncated` and
/// a `hint`. `chaining_index` holds the `threat.chaining` relation of each
/// returned threat that has one, narrowed to the returned objects; every
/// other returned object's graph is `lineage`, which is not repeated per
/// object.
pub fn get_chaining(index: &Index, uuid: &str, depth: usize) -> Json {
    let (found, resolved_from) = match get_object(index, uuid) {
        Some(found) => (Some(found), None),
        None => match index.signal(uuid) {
            Some(signal) => (get_object(index, &signal.owner), Some(signal.uuid.as_str())),
            None => (None, None),
        },
    };
    let Some(node) = found else {
        return Json::object([
            ("uuid", Json::str(uuid)),
            ("found", Json::Bool(false)),
            ("graph", Json::object::<&str>([])),
        ]);
    };
    let edges = lineage_edges(index);
    let lineages = lineage_by_uuid(index, &edges);
    let allowed = within_hops(&edges, node.uuid, depth);
    // Cut when the walk could still go on: an object `depth` hops away has
    // a neighbour that was not reached.
    let truncated = within_hops(&edges, node.uuid, depth.saturating_add(1)).len() > allowed.len();
    let keeps = |uuid: &str| allowed.contains(uuid.trim());
    let narrow_relation = |relation: &IndexMap<String, Vec<String>>| {
        let kept: IndexMap<String, Vec<String>> = relation
            .iter()
            .map(|(name, vectors)| {
                let vectors: Vec<String> = vectors.iter().filter(|v| keeps(v)).cloned().collect();
                (name.clone(), vectors)
            })
            .filter(|(_, vectors)| !vectors.is_empty())
            .collect();
        relation_json(&kept)
    };
    let narrow_lineage = |lineage: &Lineage| -> Lineage {
        [0, 1, 2].map(|slot| lineage[slot].iter().filter(|u| keeps(u)).cloned().collect())
    };
    let relation = index.chaining.get(node.uuid).filter(|r| !r.is_empty());
    let lineage = lineages.get(node.uuid).map(narrow_lineage);
    // An object alone has no lineage to show: its graph is empty.
    let alone = |lineage: &Lineage| lineage.iter().map(Vec::len).sum::<usize>() <= 1;
    let graph = match (relation, &lineage) {
        (Some(relation), _) => narrow_relation(relation),
        (None, Some(lineage)) if !alone(lineage) => lineage_json(lineage),
        _ => Json::object::<&str>([]),
    };
    // Every UUID the response names: the object, the vectors of its
    // relation, and its lineage (which `lineage` carries beside `graph`).
    let mut present: HashSet<String> = HashSet::from([node.uuid.to_owned()]);
    if let Some(relation) = relation {
        present.extend(
            relation
                .values()
                .flatten()
                .map(|vector| vector.trim().to_owned())
                .filter(|vector| keeps(vector)),
        );
    }
    if let Some(lineage) = &lineage {
        present.extend(lineage.iter().flatten().cloned());
    }
    // Only the chaining relations: an object without one has `lineage` for
    // its graph, and repeating it under every member made the answer grow
    // with the square of the lineage.
    let chaining_index: Vec<(String, Json)> = index
        .chaining
        .iter()
        .filter(|(uuid, relation)| !relation.is_empty() && present.contains(*uuid))
        .map(|(uuid, relation)| (uuid.clone(), narrow_relation(relation)))
        .collect();
    let mut payload = vec![
        ("uuid".to_owned(), Json::str(node.uuid)),
        ("found".to_owned(), Json::Bool(true)),
        ("type".to_owned(), Json::str(node.family)),
        ("graph".to_owned(), graph),
        ("chaining_index".to_owned(), Json::object(chaining_index)),
    ];
    if let Some(signal) = resolved_from {
        payload.push((
            "resolved_from".to_owned(),
            Json::object([("type", Json::str("signal")), ("uuid", Json::str(signal))]),
        ));
    }
    if let Some(lineage) = &lineage {
        payload.push(("lineage".to_owned(), lineage_json(lineage)));
    }
    if truncated {
        payload.push(("truncated".to_owned(), Json::Bool(true)));
        payload.push((
            "hint".to_owned(),
            Json::str(format!(
                "The lineage goes on beyond {depth} hop(s): call get_chaining again with a larger depth to follow it."
            )),
        ));
    }
    Json::object(payload)
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

fn platform_state(
    name: &str,
    block: Option<&Node>,
    external_ids: Option<&IndexMap<String, String>>,
) -> Json {
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
    let mut state = vec![
        (
            "deployed".to_owned(),
            Json::Bool(!ids.is_empty() || !tenants.is_empty()),
        ),
        ("rule_id".to_owned(), rule_id),
        ("external_ids".to_owned(), Json::object(ids)),
        ("tenants".to_owned(), Json::Array(tenants)),
    ];
    // A platform that addresses its rules without a vendor id has no state to
    // read: a deploy leaves no trace here, and `deployed` only says the rule's
    // block names tenants.
    if opentide_schema::platforms::external_id_kind(name)
        == opentide_schema::platforms::ExternalId::None
    {
        state.push(("note".to_owned(), Json::Str(format!(
            "opentide records no deployment state for {name}: it addresses its rules without a vendor id, \
             so a deploy leaves nothing here and deployed only says the rule's block names tenants. \
             Ask the tenant: validate_query or run_query with live true; deploy_rule with dry_run true \
             previews what a deploy sends."
        ))));
    }
    Json::object(state)
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
    // The platform blocks: `configurations`, else the legacy `platforms`,
    // whichever is a table with a block in it. A value of any other type
    // holds no block, so it does not hide the other key.
    let blocks = body.and_then(|body| {
        ["configurations", "platforms"]
            .into_iter()
            .filter_map(|key| body.get(key))
            .find_map(|node| match &node.value {
                Value::Map(blocks) if !blocks.is_empty() => Some(blocks),
                _ => None,
            })
    });
    if let Some(blocks) = blocks {
        for entry in blocks {
            let name = entry.key.value.to_string();
            let block = matches!(entry.value.value, Value::Map(_)).then_some(entry.value.as_ref());
            platforms.push((
                name.clone(),
                platform_state(&name, block, recorded.get(&name)),
            ));
        }
    }
    for (name, ids) in &recorded {
        if !platforms.iter().any(|(key, _)| key == name) {
            platforms.push((name.clone(), platform_state(name, None, Some(ids))));
        }
    }
    let mut payload = vec![
        ("platforms".to_owned(), Json::object(platforms)),
        ("uuid".to_owned(), Json::str(uuid)),
        ("found".to_owned(), Json::Bool(true)),
    ];
    if let Some(error) = state_error {
        payload.push(("state_error".to_owned(), error));
    }
    Json::object(payload)
}

/// The platforms opentide knows (`Opentide.Platforms`), in the platform table's order.
pub const PLATFORMS: [&str; opentide_schema::platforms::COUNT] = opentide_schema::platforms::IDS;

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
        let graph = get_chaining(
            ws.index(),
            "33333333-3333-4333-8333-333333333333",
            usize::MAX,
        );
        assert_eq!(graph.get("type"), Some(&Json::str("rule")));
        let lineage = graph.get("lineage").unwrap();
        assert_eq!(
            lineage.get("threats"),
            Some(&strings(
                ["11111111-1111-4111-8111-111111111111".to_owned()]
            ))
        );
        assert_eq!(graph.get("graph"), Some(lineage));
        let unknown = get_chaining(ws.index(), "nope", usize::MAX);
        assert_eq!(unknown.get("found"), Some(&Json::Bool(false)));
    }

    const SIGNAL: &str = "44444444-4444-4444-8444-444444444444";
    const SIGNAL_RULE: &str = "55555555-5555-4555-8555-555555555555";
    const OTHER_THREAT: &str = "66666666-6666-4666-8666-666666666666";

    /// An objective that defines a signal, a rule that targets the signal and
    /// a threat of no relation to either.
    fn signal_ws() -> Workspace {
        let objective = format!(
            "name: Goal\nmetadata: {{uuid: 22222222-2222-4222-8222-222222222222, schema: objective::1.0}}\nobjective:\n  threats: [11111111-1111-4111-8111-111111111111]\n  signals:\n    - {{name: S, uuid: {SIGNAL}}}\n"
        );
        let rule = format!(
            "name: By signal\nmetadata: {{uuid: {SIGNAL_RULE}, schema: rule::1.0}}\ndetection_model: {SIGNAL}\n"
        );
        let other = format!(
            "name: Other\nmetadata: {{uuid: {OTHER_THREAT}, schema: threat::1.0}}\nthreat:\n  mitre_attack: [T1003]\n"
        );
        // The other threat has an objective, so a lineage, of its own.
        let other_objective = format!(
            "name: Other goal\nmetadata: {{uuid: 77777777-7777-4777-8777-777777777777, schema: objective::1.0}}\nobjective:\n  threats: [{OTHER_THREAT}]\n"
        );
        index(&[
            ("objects/threats/t.yaml", THREAT),
            ("objects/threats/other.yaml", &other),
            ("objects/objectives/o.yaml", &objective),
            ("objects/objectives/other.yaml", &other_objective),
            ("objects/rules/r.yaml", &rule),
        ])
    }

    fn ids(json: Option<&Json>) -> Vec<String> {
        match json {
            Some(Json::Array(items)) => items
                .iter()
                .map(|item| item.as_str().unwrap().to_owned())
                .collect(),
            other => panic!("not a list: {other:?}"),
        }
    }

    #[test]
    fn a_rule_on_a_signal_stays_in_its_objectives_lineage() {
        let ws = signal_ws();
        let rule = get_chaining(ws.index(), SIGNAL_RULE, usize::MAX);
        let graph = rule.get("graph").unwrap();
        assert_eq!(
            ids(graph.get("objectives")),
            ["22222222-2222-4222-8222-222222222222"],
            "the owner, not the signal"
        );
        assert_eq!(
            ids(graph.get("threats")),
            ["11111111-1111-4111-8111-111111111111"]
        );
        // The objective sees its rule.
        let objective = get_chaining(
            ws.index(),
            "22222222-2222-4222-8222-222222222222",
            usize::MAX,
        );
        assert_eq!(
            ids(objective.get("graph").unwrap().get("rules")),
            [SIGNAL_RULE]
        );
        assert_eq!(objective.get("resolved_from"), None);
    }

    #[test]
    fn a_signal_uuid_resolves_to_its_objective() {
        let ws = signal_ws();
        let chained = get_chaining(ws.index(), SIGNAL, usize::MAX);
        assert_eq!(chained.get("found"), Some(&Json::Bool(true)));
        assert_eq!(chained.get("type"), Some(&Json::str("objective")));
        assert_eq!(
            chained.get("uuid"),
            Some(&Json::str("22222222-2222-4222-8222-222222222222"))
        );
        assert_eq!(
            chained.get("resolved_from").and_then(|r| r.get("uuid")),
            Some(&Json::str(SIGNAL))
        );
        assert_eq!(
            ids(chained.get("graph").unwrap().get("rules")),
            [SIGNAL_RULE]
        );
    }

    #[test]
    fn the_answer_holds_only_the_returned_lineage() {
        let ws = signal_ws();
        let chained = get_chaining(ws.index(), SIGNAL_RULE, usize::MAX);
        let members = lineage_ids(&chained);
        assert!(members.contains(&SIGNAL_RULE.to_owned()), "{members:?}");
        assert!(
            !members.contains(&OTHER_THREAT.to_owned())
                && !members.contains(&"77777777-7777-4777-8777-777777777777".to_owned()),
            "an unrelated threat stays out: {members:?}"
        );
        // No threat here has a chaining relation: `lineage` is every
        // object's graph, and it is not repeated per object.
        assert!(index_keys(&chained).is_empty(), "{chained:?}");
    }

    const OBJECTIVE_ID: &str = "22222222-2222-4222-8222-222222222222";
    const THREAT_ID: &str = "11111111-1111-4111-8111-111111111111";

    /// Every UUID of the answer's `lineage`, sorted.
    fn lineage_ids(chained: &Json) -> Vec<String> {
        let lineage = chained.get("lineage").expect("a lineage");
        let mut members: Vec<String> = ["threats", "objectives", "rules"]
            .into_iter()
            .flat_map(|family| ids(lineage.get(family)))
            .collect();
        members.sort();
        members
    }

    fn index_keys(chained: &Json) -> Vec<String> {
        let Some(Json::Object(entries)) = chained.get("chaining_index") else {
            panic!("no chaining_index");
        };
        let mut keys: Vec<String> = entries.iter().map(|(key, _)| key.clone()).collect();
        keys.sort();
        keys
    }

    #[test]
    fn depth_zero_is_the_object_alone() {
        let ws = signal_ws();
        let chained = get_chaining(ws.index(), SIGNAL_RULE, 0);
        assert_eq!(chained.get("found"), Some(&Json::Bool(true)));
        assert_eq!(chained.get("graph"), Some(&Json::object::<&str>([])));
        assert!(index_keys(&chained).is_empty(), "{chained:?}");
        assert_eq!(chained.get("truncated"), Some(&Json::Bool(true)));
        let lineage = chained.get("lineage").unwrap();
        assert_eq!(ids(lineage.get("rules")), [SIGNAL_RULE]);
        assert!(ids(lineage.get("objectives")).is_empty());
        assert!(ids(lineage.get("threats")).is_empty());
    }

    #[test]
    fn depth_one_is_the_neighbours_in_both_directions() {
        let ws = signal_ws();
        // From the rule: its objective, not the threat behind it.
        let rule = get_chaining(ws.index(), SIGNAL_RULE, 1);
        let graph = rule.get("graph").unwrap();
        assert_eq!(ids(graph.get("objectives")), [OBJECTIVE_ID]);
        assert_eq!(ids(graph.get("rules")), [SIGNAL_RULE]);
        assert!(ids(graph.get("threats")).is_empty(), "{graph:?}");
        let mut expected = vec![SIGNAL_RULE.to_owned(), OBJECTIVE_ID.to_owned()];
        expected.sort();
        assert_eq!(lineage_ids(&rule), expected);
        assert_eq!(rule.get("truncated"), Some(&Json::Bool(true)), "the threat");
        // From the objective: the threat above it and the rule below it.
        let objective = get_chaining(ws.index(), OBJECTIVE_ID, 1);
        let graph = objective.get("graph").unwrap();
        assert_eq!(ids(graph.get("threats")), [THREAT_ID]);
        assert_eq!(ids(graph.get("rules")), [SIGNAL_RULE]);
        assert_eq!(lineage_ids(&objective).len(), 3);
        assert_eq!(objective.get("truncated"), None, "{objective:?}");
    }

    #[test]
    fn a_depth_that_reaches_the_whole_lineage_is_the_whole_lineage() {
        let ws = signal_ws();
        let full = get_chaining(ws.index(), SIGNAL_RULE, usize::MAX);
        assert_eq!(get_chaining(ws.index(), SIGNAL_RULE, 2), full);
        assert_eq!(get_chaining(ws.index(), SIGNAL_RULE, 50), full);
        assert_eq!(ids(full.get("graph").unwrap().get("threats")), [THREAT_ID]);
    }

    const TA: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const TB: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const R1: &str = "c1c1c1c1-c1c1-4c1c-8c1c-c1c1c1c1c1c1";
    const R2: &str = "c2c2c2c2-c2c2-4c2c-8c2c-c2c2c2c2c2c2";

    fn threat_yaml(uuid: &str, links: &[&str]) -> String {
        let mut chaining = String::new();
        for to in links {
            chaining.push_str(&format!("    - {{vector: {to}, relation: preceeds}}\n"));
        }
        let chaining = if chaining.is_empty() {
            String::new()
        } else {
            format!("  chaining:\n{chaining}")
        };
        format!(
            "name: T\nmetadata: {{uuid: {uuid}, schema: threat::1.0}}\nthreat:\n  mitre_attack: [T1003]\n{chaining}"
        )
    }

    fn rule_yaml(uuid: &str, target: &str) -> String {
        format!(
            "name: R\nmetadata: {{uuid: {uuid}, schema: rule::1.0}}\ndetection_model: {target}\n"
        )
    }

    fn sorted(mut keys: Vec<String>) -> Vec<String> {
        keys.sort();
        keys
    }

    #[test]
    fn depth_two_from_a_rule_reaches_the_sibling_rules_of_its_objective() {
        let objective = format!(
            "name: Goal\nmetadata: {{uuid: {OBJECTIVE_ID}, schema: objective::1.0}}\nobjective:\n  threats: [{THREAT_ID}]\n"
        );
        let (r1, r2) = (rule_yaml(R1, OBJECTIVE_ID), rule_yaml(R2, OBJECTIVE_ID));
        let t = threat_yaml(THREAT_ID, &[]);
        let ws = index(&[
            ("objects/threats/t.yaml", &t),
            ("objects/objectives/o.yaml", &objective),
            ("objects/rules/r1.yaml", &r1),
            ("objects/rules/r2.yaml", &r2),
        ]);
        let one = get_chaining(ws.index(), R1, 1);
        assert_eq!(
            lineage_ids(&one),
            sorted(vec![R1.into(), OBJECTIVE_ID.into()])
        );
        let two = get_chaining(ws.index(), R1, 2);
        assert_eq!(ids(two.get("graph").unwrap().get("rules")), [R1, R2]);
        assert_eq!(ids(two.get("graph").unwrap().get("threats")), [THREAT_ID]);
        assert_eq!(lineage_ids(&two).len(), 4);
        assert_eq!(two.get("truncated"), None);
    }

    #[test]
    fn a_chaining_cycle_ends_at_any_depth() {
        let (a, b) = (threat_yaml(TA, &[TB]), threat_yaml(TB, &[TA]));
        let ws = index(&[
            ("objects/threats/a.yaml", &a),
            ("objects/threats/b.yaml", &b),
        ]);
        let full = get_chaining(ws.index(), TA, usize::MAX);
        for depth in [1, 2, 9] {
            let chained = get_chaining(ws.index(), TA, depth);
            assert_eq!(index_keys(&chained), [TA, TB], "depth {depth}");
            assert_eq!(chained, full, "depth {depth}");
        }
        let alone = get_chaining(ws.index(), TA, 0);
        assert_eq!(index_keys(&alone), [TA]);
        assert_eq!(alone.get("truncated"), Some(&Json::Bool(true)));
        assert_eq!(alone.get("graph"), Some(&Json::object::<&str>([])));
    }

    #[test]
    fn a_signal_uuid_combines_with_depth() {
        let ws = signal_ws();
        let alone = get_chaining(ws.index(), SIGNAL, 0);
        assert_eq!(alone.get("uuid"), Some(&Json::str(OBJECTIVE_ID)));
        assert_eq!(
            alone.get("resolved_from").and_then(|r| r.get("uuid")),
            Some(&Json::str(SIGNAL))
        );
        assert_eq!(alone.get("graph"), Some(&Json::object::<&str>([])));
        assert_eq!(lineage_ids(&alone), [OBJECTIVE_ID]);
        let one = get_chaining(ws.index(), SIGNAL, 1);
        assert_eq!(one.get("resolved_from"), alone.get("resolved_from"));
        assert_eq!(ids(one.get("graph").unwrap().get("threats")), [THREAT_ID]);
        assert_eq!(ids(one.get("graph").unwrap().get("rules")), [SIGNAL_RULE]);
    }

    #[test]
    fn a_threat_with_chaining_and_objectives_is_cut_by_depth() {
        let objective = format!(
            "name: Goal\nmetadata: {{uuid: {OBJECTIVE_ID}, schema: objective::1.0}}\nobjective:\n  threats: [{THREAT_ID}]\n"
        );
        let (t1, t2) = (threat_yaml(THREAT_ID, &[TB]), threat_yaml(TB, &[]));
        let rule = rule_yaml(R1, OBJECTIVE_ID);
        let ws = index(&[
            ("objects/threats/t1.yaml", &t1),
            ("objects/threats/t2.yaml", &t2),
            ("objects/objectives/o.yaml", &objective),
            ("objects/rules/r.yaml", &rule),
        ]);
        let one = get_chaining(ws.index(), THREAT_ID, 1);
        // graph stays the chaining relation; lineage is cut at one hop.
        assert_eq!(
            one.get("graph"),
            Some(&Json::object([(
                "preceeds",
                Json::Array(vec![Json::str(TB)])
            )]))
        );
        let lineage = one.get("lineage").unwrap();
        assert_eq!(ids(lineage.get("threats")), [THREAT_ID, TB]);
        assert_eq!(ids(lineage.get("objectives")), [OBJECTIVE_ID]);
        assert!(ids(lineage.get("rules")).is_empty());
        assert_eq!(
            lineage_ids(&one),
            sorted(vec![THREAT_ID.into(), TB.into(), OBJECTIVE_ID.into()])
        );
        // Only the chaining relation is indexed: the objective's graph is
        // `lineage`.
        assert_eq!(index_keys(&one), [THREAT_ID]);
        assert_eq!(one.get("truncated"), Some(&Json::Bool(true)), "the rule");
        let two = get_chaining(ws.index(), THREAT_ID, 2);
        assert_eq!(ids(two.get("lineage").unwrap().get("rules")), [R1]);
        assert_eq!(two, get_chaining(ws.index(), THREAT_ID, usize::MAX));
    }

    #[test]
    fn depth_follows_threat_chaining_links() {
        let threat = |n: u8, link: Option<u8>| {
            let chaining = link.map_or(String::new(), |to| {
                format!("  chaining:\n    - {{vector: {to}{to}{to}{to}{to}{to}{to}{to}-{to}{to}{to}{to}-4{to}{to}{to}-8{to}{to}{to}-{to}{to}{to}{to}{to}{to}{to}{to}{to}{to}{to}{to}, relation: preceeds}}\n")
            });
            format!(
                "name: T{n}\nmetadata: {{uuid: {n}{n}{n}{n}{n}{n}{n}{n}-{n}{n}{n}{n}-4{n}{n}{n}-8{n}{n}{n}-{n}{n}{n}{n}{n}{n}{n}{n}{n}{n}{n}{n}, schema: threat::1.0}}\nthreat:\n  mitre_attack: [T1003]\n{chaining}"
            )
        };
        let (a, b, c) = (threat(1, Some(2)), threat(2, Some(3)), threat(3, None));
        let ws = index(&[
            ("objects/threats/a.yaml", &a),
            ("objects/threats/b.yaml", &b),
            ("objects/threats/c.yaml", &c),
        ]);
        let first = "11111111-1111-4111-8111-111111111111";
        let second = "22222222-2222-4222-8222-222222222222";
        let third = "33333333-3333-4333-8333-333333333333";
        let near = get_chaining(ws.index(), first, 1);
        assert_eq!(
            near.get("graph"),
            Some(&Json::object([(
                "preceeds",
                Json::Array(vec![Json::str(second)])
            )]))
        );
        assert_eq!(lineage_ids(&near), [first, second]);
        assert_eq!(index_keys(&near), [first, second]);
        assert_eq!(near.get("truncated"), Some(&Json::Bool(true)), "{near:?}");
        // Backwards too: the threat that chains into this one, whose
        // relation is indexed; the third threat has none.
        let back = get_chaining(ws.index(), third, 1);
        assert_eq!(lineage_ids(&back), [second, third]);
        assert_eq!(index_keys(&back), [second]);
        // A depth as long as the chain returns all of it, uncut.
        let whole = get_chaining(ws.index(), first, 2);
        assert_eq!(lineage_ids(&whole).len(), 3);
        assert_eq!(whole.get("truncated"), None, "{whole:?}");
        assert_eq!(whole, get_chaining(ws.index(), first, usize::MAX));
        let alone = get_chaining(ws.index(), first, 0);
        assert_eq!(alone.get("graph"), Some(&Json::object::<&str>([])));
        assert_eq!(index_keys(&alone), [first]);
    }

    #[test]
    fn chaining_index_follows_a_chain_and_the_lineage_it_returns() {
        let threat = |n: u8, link: Option<u8>| {
            let chaining = link.map_or(String::new(), |to| {
                format!("  chaining:\n    - {{vector: {to}{to}{to}{to}{to}{to}{to}{to}-{to}{to}{to}{to}-4{to}{to}{to}-8{to}{to}{to}-{to}{to}{to}{to}{to}{to}{to}{to}{to}{to}{to}{to}, relation: preceeds}}\n")
            });
            format!(
                "name: T{n}\nmetadata: {{uuid: {n}{n}{n}{n}{n}{n}{n}{n}-{n}{n}{n}{n}-4{n}{n}{n}-8{n}{n}{n}-{n}{n}{n}{n}{n}{n}{n}{n}{n}{n}{n}{n}, schema: threat::1.0}}\nthreat:\n  mitre_attack: [T1003]\n{chaining}"
            )
        };
        let objective = "name: Goal\nmetadata: {uuid: 22222222-2222-4222-8222-222222222222, schema: objective::1.0}\nobjective:\n  threats: [33333333-3333-4333-8333-333333333333]\n";
        let (a, b, c) = (threat(1, Some(2)), threat(2, Some(3)), threat(3, None));
        let ws = index(&[
            ("objects/threats/a.yaml", &a),
            ("objects/threats/b.yaml", &b),
            ("objects/threats/c.yaml", &c),
            ("objects/objectives/o.yaml", objective),
        ]);
        let chained = get_chaining(
            ws.index(),
            "11111111-1111-4111-8111-111111111111",
            usize::MAX,
        );
        let Some(Json::Object(entries)) = chained.get("chaining_index") else {
            panic!("no chaining_index");
        };
        let keys: Vec<&str> = entries.iter().map(|(key, _)| key.as_str()).collect();
        // The two threats that chain; the third has `lineage` for its graph.
        assert_eq!(
            keys,
            [
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
            ]
        );
        assert_eq!(lineage_ids(&chained).len(), 3, "{chained:?}");
    }

    /// The answer no longer repeats the lineage under each of its objects:
    /// on one objective with many rules it grows with the rules, not with
    /// their square (2.1 MB on a user's catalogue in 1.0.0-rc.5).
    #[test]
    fn a_large_lineage_is_not_repeated_per_object() {
        let objective = format!(
            "name: Goal\nmetadata: {{uuid: {OBJECTIVE_ID}, schema: objective::1.0}}\nobjective:\n  threats: [{THREAT_ID}]\n"
        );
        let threat = threat_yaml(THREAT_ID, &[]);
        let rules: Vec<(String, String)> = (0..200)
            .map(|n| {
                let uuid = format!("c0c0c0c0-c0c0-4c0c-8c0c-{n:012}");
                (
                    format!("objects/rules/r{n}.yaml"),
                    rule_yaml(&uuid, OBJECTIVE_ID),
                )
            })
            .collect();
        let mut files: Vec<(&str, &str)> = vec![
            ("objects/threats/t.yaml", &threat),
            ("objects/objectives/o.yaml", &objective),
        ];
        files.extend(
            rules
                .iter()
                .map(|(path, text)| (path.as_str(), text.as_str())),
        );
        let ws = index(&files);
        let whole = get_chaining(ws.index(), THREAT_ID, usize::MAX);
        assert_eq!(lineage_ids(&whole).len(), 202);
        assert!(index_keys(&whole).is_empty());
        // One lineage (~200 UUIDs of 36 characters) and the graph beside it.
        let size = whole.to_compact().len();
        assert!(size < 25_000, "{size} bytes");
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
}
