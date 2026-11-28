//! The `graph` tool: the catalogue's threat -> objective -> rule funnel as
//! counts, and where it is blind, small whatever the catalogue's size.
//!
//! `coverage` answers per ATT&CK technique and `get_chaining` per object;
//! neither says which threats nothing covers, so this is its own tool.

use std::collections::{BTreeMap, HashMap, HashSet};

use opentide_compile::strategy::{StatusStrategy, Statuses};
use opentide_schema::node::{Node, Value};
use opentide_schema::objects::FieldRole;
use opentide_workspace::coverage::{bucket, rule_objective_uuid};
use opentide_workspace::index::ReferenceKind;
use opentide_workspace::{Workspace, fields};

use super::args::Args;
use super::catalog::{block_statuses, summary};
use super::tools::Context;
use crate::json::Json;

/// The levels of detail `graph` answers.
pub const DETAILS: [&str; 1] = ["summary"];

/// How many objects each gap lists; its `count` is the full number.
pub const GAP_LIMIT: usize = 25;

/// The `detail` argument, refused unless it is one of [`DETAILS`].
pub fn detail(value: &str) -> Result<(), String> {
    if DETAILS.contains(&value) {
        return Ok(());
    }
    Err(format!(
        "argument detail must be one of {}, not {value:?}",
        DETAILS.join(", ")
    ))
}

/// The statuses whose rules are in production, in `[[statuses]]` order:
/// those `deployment.toml` maps to `RELEASE`, or to `UNIVERSAL`, which a
/// release run deploys as well (`PRODUCTION` in the bundled lifecycle).
/// `DISABLEMENT` and `DELETION` are deployed by a release run too, but to
/// take the rule away: not production.
///
/// A `deployment.toml` that does not match its model is the error
/// (`deployment.toml is invalid: ...`), as `deploy_rule` reports it: no
/// rule deploys under it, so none is in production.
fn release_statuses(workspace: &Workspace) -> Result<Vec<String>, String> {
    let Statuses(statuses, invalid) = Statuses::from_resolved(&workspace.configuration().resolved);
    if let Some(invalid) = invalid {
        return Err(invalid);
    }
    Ok(statuses
        .into_iter()
        .filter(|(_, strategy)| {
            matches!(
                strategy,
                StatusStrategy::Release | StatusStrategy::Universal
            )
        })
        .map(|(name, _)| name)
        .collect())
}

/// `{count, items}`: the first [`GAP_LIMIT`] objects as `search` lists them.
fn gap(family: &str, items: &[(&str, &Node)], limit: usize) -> Json {
    Json::object([
        ("count", Json::from(items.len())),
        (
            "items",
            Json::Array(
                items
                    .iter()
                    .take(limit)
                    .map(|(uuid, body)| summary(uuid, family, body))
                    .collect(),
            ),
        ),
    ])
}

fn counted(counts: BTreeMap<String, usize>) -> Json {
    Json::Object(
        counts
            .into_iter()
            .map(|(key, count)| (key, Json::from(count)))
            .collect(),
    )
}

/// Rules' platform blocks counted by status, overall and per platform; a
/// block without a status counts as `unset`.
#[derive(Default)]
struct BlockCounts {
    by_status: BTreeMap<String, usize>,
    by_platform: BTreeMap<String, BTreeMap<String, usize>>,
}

impl BlockCounts {
    fn add(&mut self, rule: &Node) {
        let Some(Value::Map(blocks)) = rule.get("configurations").map(|node| &node.value) else {
            return;
        };
        for block in blocks {
            if !matches!(block.value.value, Value::Map(_)) {
                continue;
            }
            let status = fields::text(block.value.get("status").map(AsRef::as_ref))
                .filter(|status| !status.is_empty())
                .unwrap_or_else(|| "unset".to_owned());
            *self.by_status.entry(status.clone()).or_default() += 1;
            *self
                .by_platform
                .entry(block.key.value.to_string())
                .or_default()
                .entry(status)
                .or_default() += 1;
        }
    }
}

/// `graph`: the `detail` argument checked, then [`summarise`].
pub fn tool(args: &Args<'_>, context: &Context<'_>) -> Result<Json, String> {
    detail(&args.string("detail", "summary")?)?;
    let workspace = super::catalog::require(context)?;
    summarise(&workspace)
}

/// `graph` with `detail: "summary"`; the error is why `deployment.toml`
/// does not read ([`release_statuses`]).
pub fn summarise(workspace: &Workspace) -> Result<Json, String> {
    let limit = GAP_LIMIT;
    let index = workspace.index();
    let threats = bucket(index, "threat");
    let objectives = bucket(index, "objective");
    let rules = bucket(index, "rule");
    let release = release_statuses(workspace)?;

    // objective.threats, as the index read the references.
    let mut objectives_of: HashMap<&str, Vec<&str>> = HashMap::new();
    for reference in &index.references {
        if reference.kind == ReferenceKind::Threat {
            objectives_of
                .entry(reference.target.trim())
                .or_default()
                .push(reference.from.as_str());
        }
    }
    // Each objective's rules, a signal's rules counted for its objective;
    // and whether one of them is in production.
    let mut rules_of: HashMap<&str, usize> = HashMap::new();
    let mut released: HashSet<&str> = HashSet::new();
    let mut blocks = BlockCounts::default();
    for (_, rule) in &rules {
        let statuses = block_statuses(rule);
        if let Some(objective) = rule_objective_uuid(rule, index) {
            *rules_of.entry(objective).or_default() += 1;
            if statuses.iter().any(|status| release.contains(status)) {
                released.insert(objective);
            }
        }
        blocks.add(rule);
    }

    let mut no_objective = Vec::new();
    let mut no_rule = Vec::new();
    let mut no_production = Vec::new();
    for &(uuid, body) in &threats {
        let covering = objectives_of.get(uuid).map_or(&[][..], Vec::as_slice);
        if covering.is_empty() {
            no_objective.push((uuid, body));
        } else if !covering.iter().any(|o| rules_of.contains_key(o)) {
            no_rule.push((uuid, body));
        } else if !covering.iter().any(|o| released.contains(o)) {
            no_production.push((uuid, body));
        }
    }
    let idle: Vec<_> = objectives
        .iter()
        .copied()
        .filter(|(uuid, _)| !rules_of.contains_key(uuid))
        .collect();

    // The threats on either end of a chaining vector; a vector naming no
    // threat of the catalogue (dangling, or another kind) counts neither.
    let known: HashSet<&str> = threats.iter().map(|&(uuid, _)| uuid).collect();
    let mut chained: HashSet<&str> = HashSet::new();
    for (uuid, relation) in &index.chaining {
        for vector in relation.values().flatten() {
            let vector = vector.trim();
            if known.contains(uuid.as_str()) && known.contains(vector) {
                chained.insert(uuid);
                chained.insert(vector);
            }
        }
    }
    let actors: HashSet<String> = threats
        .iter()
        .flat_map(|(_, body)| fields::role_values(body, FieldRole::Actors))
        .map(|(_, actor)| actor)
        .collect();

    Ok(Json::object([
        (
            "counts",
            Json::object([
                ("threats", Json::from(threats.len())),
                ("objectives", Json::from(objectives.len())),
                ("rules", Json::from(rules.len())),
                ("signals", Json::from(index.signals.len())),
                ("chained_threats", Json::from(chained.len())),
                ("actors", Json::from(actors.len())),
            ]),
        ),
        (
            "release_statuses",
            Json::Array(release.iter().map(Json::str).collect()),
        ),
        ("rule_blocks_by_status", counted(blocks.by_status)),
        (
            "rule_blocks_by_platform",
            Json::Object(
                blocks
                    .by_platform
                    .into_iter()
                    .map(|(platform, counts)| (platform, counted(counts)))
                    .collect(),
            ),
        ),
        (
            "threats_without_objectives",
            gap("threat", &no_objective, limit),
        ),
        ("threats_without_rules", gap("threat", &no_rule, limit)),
        (
            "threats_without_production_rules",
            gap("threat", &no_production, limit),
        ),
        ("objectives_without_rules", gap("objective", &idle, limit)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_summary_is_a_detail() {
        assert_eq!(detail("summary"), Ok(()));
        assert_eq!(
            detail("full"),
            Err("argument detail must be one of summary, not \"full\"".to_owned())
        );
    }
}
