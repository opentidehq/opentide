//! Threat chaining as `opentide tui` draws it: a path to read and follow
//! (`cli/services/chains_view.py`, #776).
//!
//! `threat.chaining` links two threats with a relation from the
//! `chaining_relations` vocabulary. Each stage has a pair of inverse
//! relations (`sequence::preceeds` and `sequence::succeeds`,
//! `atomicity::implemented` and `atomicity::implements`, `support::enabled`
//! and `support::enabling`), and `support::synergize` goes both ways, so the
//! same link can be written from either end. [`chain_edges`] reads every link
//! once, as its `from` form (`A preceeds B` for `B succeeds A`), with the
//! description each end gives.
//!
//! [`neighbourhood`] is what the tab shows: the threats within some hops of
//! the focused one, sequence links laid out left to right as attack flow
//! ([`flow_layers`]), supporting and atomicity links beside them, and per
//! threat the rules under its objectives and how many of its techniques some
//! rule covers.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use indexmap::IndexMap;
use opentide_schema::node::{Node, Value};

/// The relation stages, in the order the filter cycles through them.
pub const STAGES: [&str; 3] = ["sequence", "atomicity", "support"];

/// One chaining link, read once whichever end wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEdge {
    /// The threat the link reads from.
    pub source: String,
    /// The threat it reads to.
    pub target: String,
    /// `sequence`, `atomicity` or `support`.
    pub stage: String,
    /// How it reads from source to target: `then`, `enables`, `implemented by`…
    pub label: &'static str,
    /// The relation each end wrote, as written (`sequence::preceeds`).
    pub relations: Vec<String>,
    /// Each end's `description`, when it gives one, each once.
    pub descriptions: Vec<String>,
    /// Whether both ends wrote it (so it was merged).
    pub merged: bool,
    /// Whether an end is no threat of the catalogue.
    pub missing: bool,
    /// `false` for `support::synergize`, which reads both ways.
    pub directed: bool,
}

/// One threat of a [`Neighbourhood`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainNode {
    /// Its UUID.
    pub uuid: String,
    /// Its name, or the UUID when the catalogue has no such threat.
    pub name: String,
    /// Hops from the focused threat.
    pub distance: usize,
    /// Rules under the threat's objectives.
    pub rules: usize,
    /// `(covered, total)` of the threat's techniques that some rule covers.
    pub techniques: (usize, usize),
    /// Whether the catalogue has no such threat.
    pub missing: bool,
}

/// The threats around one, and the links between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbourhood {
    /// The threat it is drawn around.
    pub focus: String,
    /// The threats within the hops, by UUID.
    pub nodes: BTreeMap<String, ChainNode>,
    /// The links between them.
    pub edges: Vec<ChainEdge>,
    /// Sequence links' threats in flow order: each layer after the one before.
    pub layers: Vec<Vec<String>>,
    /// The stage shown, or `None` for all.
    pub stage: Option<String>,
    /// The hop limit.
    pub hops: usize,
    /// Threats the hop limit left out.
    pub hidden: usize,
    /// Links shown, by stage.
    pub totals: BTreeMap<String, usize>,
}

/// `(stage, name)` of a relation as written, lowercased; `None` without `::`.
fn relation(raw: &str) -> Option<(String, String)> {
    let (stage, name) = raw.split_once("::")?;
    let name = name.trim().to_lowercase();
    if name.is_empty() {
        return None;
    }
    Some((stage.trim().to_lowercase(), name))
}

/// How a relation's `from` form reads, source to target.
fn from_label(stage: &str, name: &str) -> Option<&'static str> {
    match (stage, name) {
        ("sequence", "preceeds") => Some("then"),
        ("atomicity", "implemented") => Some("implemented by"),
        ("support", "enabled") => Some("enables"),
        _ => None,
    }
}

/// The `from` form a `to` form is the inverse of.
fn inverse(stage: &str, name: &str) -> Option<(&'static str, &'static str)> {
    match (stage, name) {
        ("sequence", "succeeds") => Some(("sequence", "preceeds")),
        ("atomicity", "implements") => Some(("atomicity", "implemented")),
        ("support", "enabling") => Some(("support", "enabled")),
        _ => None,
    }
}

fn str_of(node: Option<&std::sync::Arc<Node>>) -> Option<&str> {
    node.and_then(|node| node.value.as_str())
}

struct Merging {
    label: &'static str,
    relations: Vec<String>,
    descriptions: Vec<String>,
    ends: BTreeSet<String>,
    directed: bool,
}

/// Every chaining link of `threats` (each threat's document root, by UUID),
/// each once, inverses merged, sorted by source, target, stage and relation.
pub fn chain_edges(threats: &IndexMap<String, &Node>) -> Vec<ChainEdge> {
    let mut found: BTreeMap<(String, String, String, String), Merging> = BTreeMap::new();
    for (uuid, root) in threats {
        let Some(section) = root.get("threat") else {
            continue;
        };
        let Some(chaining) = section.get("chaining") else {
            continue;
        };
        let Value::Seq(links) = &chaining.value else {
            continue;
        };
        for link in links {
            let (Some(raw), Some(vector)) =
                (str_of(link.get("relation")), str_of(link.get("vector")))
            else {
                continue;
            };
            let Some((stage, name)) = relation(raw) else {
                continue;
            };
            let (key, source, target, label, directed) =
                if let Some(label) = from_label(&stage, &name) {
                    ((stage, name), uuid.clone(), vector.to_owned(), label, true)
                } else if let Some((stage, name)) = inverse(&stage, &name) {
                    let label = from_label(stage, name).unwrap_or_default();
                    (
                        (stage.to_owned(), name.to_owned()),
                        vector.to_owned(),
                        uuid.clone(),
                        label,
                        true,
                    )
                } else if (stage.as_str(), name.as_str()) == ("support", "synergize") {
                    let (source, target) = if uuid.as_str() <= vector {
                        (uuid.clone(), vector.to_owned())
                    } else {
                        (vector.to_owned(), uuid.clone())
                    };
                    ((stage, name), source, target, "synergizes with", false)
                } else {
                    continue;
                };
            let entry = found
                .entry((source, target, key.0, key.1))
                .or_insert_with(|| Merging {
                    label,
                    relations: Vec::new(),
                    descriptions: Vec::new(),
                    ends: BTreeSet::new(),
                    directed,
                });
            entry.relations.push(raw.to_owned());
            entry.ends.insert(uuid.clone());
            if let Some(description) = str_of(link.get("description")) {
                let words = description.split_whitespace().collect::<Vec<_>>().join(" ");
                if !words.is_empty() && !entry.descriptions.contains(&words) {
                    entry.descriptions.push(words);
                }
            }
        }
    }
    found
        .into_iter()
        .map(|((source, target, stage, _), entry)| ChainEdge {
            missing: !threats.contains_key(&source) || !threats.contains_key(&target),
            source,
            target,
            stage,
            label: entry.label,
            relations: entry.relations,
            descriptions: entry.descriptions,
            merged: entry.ends.len() > 1,
            directed: entry.directed,
        })
        .collect()
}

/// The threats sequence links connect, in layers: each after the layer
/// before it.
///
/// A threat's layer is the longest run of `then` links that leads to it, so
/// a chain reads left to right as the attack unfolds. A cycle (`A then B
/// then A`) is cut where it closes. Threats no sequence link touches are
/// left out.
pub fn flow_layers<'a>(
    nodes: impl IntoIterator<Item = &'a String>,
    edges: &[ChainEdge],
) -> Vec<Vec<String>> {
    let members: BTreeSet<&String> = nodes.into_iter().collect();
    let mut after: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut incoming: HashMap<&str, usize> = HashMap::new();
    let mut touched: BTreeSet<&str> = BTreeSet::new();
    for edge in edges
        .iter()
        .filter(|edge| edge.stage == "sequence" && edge.directed)
    {
        if members.contains(&edge.source)
            && members.contains(&edge.target)
            && edge.source != edge.target
        {
            after.entry(&edge.source).or_default().push(&edge.target);
            *incoming.entry(&edge.target).or_default() += 1;
            touched.insert(&edge.source);
            touched.insert(&edge.target);
        }
    }
    let mut layer: HashMap<&str, usize> = touched.iter().map(|uuid| (*uuid, 0)).collect();
    let mut queue: VecDeque<&str> = touched
        .iter()
        .filter(|uuid| incoming.get(*uuid).copied().unwrap_or(0) == 0)
        .copied()
        .collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut remaining = incoming.clone();
    while !queue.is_empty() || seen.len() < touched.len() {
        if queue.is_empty() {
            // A cycle: start again from the earliest threat not yet placed.
            if let Some(first) = touched.iter().find(|uuid| !seen.contains(*uuid)) {
                queue.push_back(first);
            }
        }
        let Some(uuid) = queue.pop_front() else {
            break;
        };
        if !seen.insert(uuid) {
            continue;
        }
        let here = layer.get(uuid).copied().unwrap_or(0);
        for target in after.get(uuid).map(Vec::as_slice).unwrap_or_default() {
            if seen.contains(target) {
                continue;
            }
            let at = layer.entry(target).or_insert(0);
            *at = (*at).max(here + 1);
            let left = remaining.entry(target).or_insert(0);
            *left = left.saturating_sub(1);
            if *left == 0 {
                queue.push_back(target);
            }
        }
    }
    let depth = layer.values().max().map_or(0, |deepest| deepest + 1);
    (0..depth)
        .map(|index| {
            let mut at: Vec<String> = layer
                .iter()
                .filter(|(_, n)| **n == index)
                .map(|(uuid, _)| (*uuid).to_owned())
                .collect();
            at.sort();
            at
        })
        .collect()
}

/// What a [`neighbourhood`] reads about the catalogue's threats.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    /// Each threat's name, by UUID.
    pub names: &'a HashMap<String, String>,
    /// Rules under each threat's objectives, by UUID.
    pub rules: &'a HashMap<String, usize>,
    /// `(covered, total)` techniques of each threat, by UUID.
    pub techniques: &'a HashMap<String, (usize, usize)>,
}

/// The threats within `hops` links of `focus`, by links of `stage` (all
/// when `None`).
pub fn neighbourhood(
    focus: &str,
    edges: &[ChainEdge],
    facts: Facts<'_>,
    hops: usize,
    stage: Option<&str>,
) -> Neighbourhood {
    let chosen: Vec<&ChainEdge> = edges
        .iter()
        .filter(|edge| stage.is_none_or(|stage| edge.stage == stage))
        .collect();
    let mut adjacent: HashMap<&str, BTreeSet<&str>> = HashMap::new();
    for edge in &chosen {
        adjacent
            .entry(&edge.source)
            .or_default()
            .insert(&edge.target);
        adjacent
            .entry(&edge.target)
            .or_default()
            .insert(&edge.source);
    }
    let mut distance: HashMap<String, usize> = HashMap::from([(focus.to_owned(), 0)]);
    let mut queue = VecDeque::from([focus.to_owned()]);
    while let Some(uuid) = queue.pop_front() {
        let here = distance.get(&uuid).copied().unwrap_or(0);
        for other in adjacent.get(uuid.as_str()).into_iter().flatten() {
            if !distance.contains_key(*other) {
                distance.insert((*other).to_owned(), here + 1);
                queue.push_back((*other).to_owned());
            }
        }
    }
    let reachable = distance.len();
    let within: BTreeMap<String, usize> =
        distance.into_iter().filter(|(_, n)| *n <= hops).collect();
    let shown: Vec<ChainEdge> = chosen
        .into_iter()
        .filter(|edge| within.contains_key(&edge.source) && within.contains_key(&edge.target))
        .cloned()
        .collect();
    let nodes: BTreeMap<String, ChainNode> = within
        .iter()
        .map(|(uuid, n)| {
            (
                uuid.clone(),
                ChainNode {
                    uuid: uuid.clone(),
                    name: facts
                        .names
                        .get(uuid)
                        .cloned()
                        .unwrap_or_else(|| uuid.clone()),
                    distance: *n,
                    rules: facts.rules.get(uuid).copied().unwrap_or(0),
                    techniques: facts.techniques.get(uuid).copied().unwrap_or((0, 0)),
                    missing: !facts.names.contains_key(uuid),
                },
            )
        })
        .collect();
    let totals = STAGES
        .iter()
        .map(|name| {
            (
                (*name).to_owned(),
                shown.iter().filter(|edge| edge.stage == *name).count(),
            )
        })
        .collect();
    Neighbourhood {
        focus: focus.to_owned(),
        layers: flow_layers(within.keys(), &shown),
        nodes,
        edges: shown,
        stage: stage.map(str::to_owned),
        hops,
        hidden: reachable - within.len(),
        totals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn threats(texts: &[(&str, &str)]) -> Vec<(String, opentide_schema::node::Document)> {
        texts
            .iter()
            .map(|(uuid, text)| {
                (
                    (*uuid).to_owned(),
                    opentide_schema::node::load(text).unwrap(),
                )
            })
            .collect()
    }

    fn edges_of(docs: &[(String, opentide_schema::node::Document)]) -> Vec<ChainEdge> {
        let map: IndexMap<String, &Node> = docs
            .iter()
            .map(|(uuid, doc)| (uuid.clone(), doc.root().unwrap().as_ref()))
            .collect();
        chain_edges(&map)
    }

    fn link(relation: &str, vector: &str, description: &str) -> String {
        format!(
            "threat:\n  chaining:\n    - relation: {relation}\n      vector: {vector}\n      description: {description}\n"
        )
    }

    #[test]
    fn a_link_written_from_both_ends_is_read_once_with_both_descriptions() {
        let docs = threats(&[
            ("a", &link("sequence::preceeds", "b", "A  first")),
            ("b", &link("sequence::succeeds", "a", "then B")),
        ]);
        let edges = edges_of(&docs);
        assert_eq!(edges.len(), 1);
        let edge = &edges[0];
        assert_eq!((edge.source.as_str(), edge.target.as_str()), ("a", "b"));
        assert_eq!(edge.label, "then");
        assert!(edge.merged && edge.directed && !edge.missing);
        assert_eq!(edge.descriptions, ["A first", "then B"]);
        assert_eq!(edge.relations, ["sequence::preceeds", "sequence::succeeds"]);
    }

    #[test]
    fn inverse_forms_read_from_their_source_and_unknown_relations_are_skipped() {
        let docs = threats(&[
            ("a", &link("atomicity::implements", "b", "x")),
            ("c", &link("Support::Synergize", "a", "y")),
            ("d", &link("sequence::sideways", "a", "z")),
            ("e", &link("support::enabled", "nowhere", "w")),
        ]);
        let edges = edges_of(&docs);
        let read: Vec<(&str, &str, &str, bool, bool)> = edges
            .iter()
            .map(|e| {
                (
                    e.source.as_str(),
                    e.target.as_str(),
                    e.label,
                    e.directed,
                    e.missing,
                )
            })
            .collect();
        assert_eq!(
            read,
            [
                ("a", "c", "synergizes with", false, false),
                ("b", "a", "implemented by", true, true),
                ("e", "nowhere", "enables", true, true),
            ]
        );
    }

    fn sequence(source: &str, target: &str) -> ChainEdge {
        ChainEdge {
            source: source.into(),
            target: target.into(),
            stage: "sequence".into(),
            label: "then",
            relations: Vec::new(),
            descriptions: Vec::new(),
            merged: false,
            missing: false,
            directed: true,
        }
    }

    #[test]
    fn flow_layers_place_each_threat_after_its_longest_run_and_cut_cycles() {
        let names: Vec<String> = ["a", "b", "c", "d"].map(String::from).to_vec();
        let edges = [sequence("a", "b"), sequence("b", "c"), sequence("a", "c")];
        assert_eq!(
            flow_layers(&names, &edges),
            [
                vec!["a".to_owned()],
                vec!["b".to_owned()],
                vec!["c".to_owned()]
            ]
        );
        let cycle = [sequence("a", "b"), sequence("b", "a")];
        assert_eq!(
            flow_layers(&names, &cycle),
            [vec!["a".to_owned()], vec!["b".to_owned()]]
        );
    }

    #[test]
    fn the_neighbourhood_keeps_the_threats_within_the_hops_and_counts_the_rest() {
        let edges = [sequence("a", "b"), sequence("b", "c"), sequence("c", "d")];
        let names: HashMap<String, String> = [("a", "A"), ("b", "B"), ("c", "C")]
            .map(|(k, v)| (k.into(), v.into()))
            .into();
        let rules = HashMap::from([("b".to_owned(), 2)]);
        let techniques = HashMap::from([("b".to_owned(), (1, 3))]);
        let facts = Facts {
            names: &names,
            rules: &rules,
            techniques: &techniques,
        };
        let view = neighbourhood("b", &edges, facts, 1, None);
        assert_eq!(view.nodes.keys().collect::<Vec<_>>(), ["a", "b", "c"]);
        assert_eq!(view.hidden, 1);
        assert_eq!(view.edges.len(), 2);
        assert_eq!(view.totals["sequence"], 2);
        assert_eq!(view.nodes["b"].rules, 2);
        assert_eq!(view.nodes["b"].techniques, (1, 3));
        let wide = neighbourhood("b", &edges, facts, 2, None);
        assert!(wide.nodes["d"].missing);
        assert_eq!(wide.nodes["d"].name, "d");
        assert_eq!(wide.hidden, 0);
        let none = neighbourhood("b", &edges, facts, 4, Some("support"));
        assert_eq!(none.nodes.len(), 1);
        assert!(none.edges.is_empty());
    }
}
