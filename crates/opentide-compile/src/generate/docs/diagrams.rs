//! The diagrams pages show (`documentation/diagram/builders.py`), each
//! answering one question:
//!
//! - **Detection coverage** (every page): how a threat is detected; lanes
//!   of threat vectors, objectives, signals and rules.
//! - **Deployment map** (rule pages): the platforms a rule deploys to, at
//!   their status, and the tenants each run reaches.
//! - **Threat chaining** (threat pages): lanes of kill-chain phases; every
//!   relation drawn its `from` way, the line style telling its family.
//! - **Kill-chain position** (threat pages) and **kill-chain coverage**
//!   (the catalogue overview): the Unified Kill Chain, stage by stage.
//! - **Threat landscape** (the catalogue overview): every threat by phase.
//! - **Relations** (fallback): an object's direct neighbours.

use std::collections::HashSet;

use super::catalog::{Catalog, Direction, Graph};
use super::facts::PlatformDeployment;
use super::flavor::Flavor;
use super::mermaid::{Diagram, Lane, Link, LinkStyle, Node, NodeKind, Tone, legend, render};
use super::vocab::Vocab;

/// `diagram` in the flavour's fence, followed by its legend; empty when
/// there is nothing to draw.
pub fn fenced(flavor: Flavor, diagram: Option<&Diagram>) -> String {
    let Some(diagram) = diagram.filter(|diagram| !diagram.is_trivial()) else {
        return String::new();
    };
    let dialect = flavor.dialect();
    let fence = flavor.mermaid_fence(&render(diagram, dialect));
    format!("{}\n\n{}\n", fence.trim_end(), legend(diagram, dialect))
}

/// The lane title of each kind.
fn lane_title(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Threat => "Threat vectors",
        NodeKind::Objective => "Detection objectives",
        NodeKind::Signal => "Signals",
        NodeKind::Rule => "Detection rules",
        NodeKind::Platform => "Platforms",
        NodeKind::Tenant => "Tenants",
        NodeKind::Phase => "Kill-chain phases",
    }
}

/// One lane per kind present, in kind order.
fn kind_lanes(diagram: &Diagram) -> Vec<Lane> {
    NodeKind::ALL
        .into_iter()
        .filter_map(|kind| {
            let members: Vec<String> = diagram
                .nodes
                .values()
                .filter(|node| node.kind == kind)
                .map(|node| node.key.clone())
                .collect();
            (!members.is_empty()).then(|| Lane::new(lane_title(kind), members))
        })
        .collect()
}

/// One lane per kill-chain phase, in the vocabulary's order, the nodes
/// without one left out of every lane.
fn phase_lanes(phases: &[(String, String)], vocab: &Vocab<'_>) -> Vec<Lane> {
    let order = vocab.order("killchain");
    let mut named: Vec<&str> = Vec::new();
    for (_, phase) in phases {
        if !phase.is_empty() && !named.contains(&phase.as_str()) {
            named.push(phase);
        }
    }
    named.sort_by_key(|phase| {
        (
            order
                .iter()
                .position(|known| known == phase)
                .unwrap_or(order.len()),
            (*phase).to_owned(),
        )
    });
    named
        .into_iter()
        .map(|phase| Lane {
            caption_fallback: true,
            ..Lane::new(
                phase,
                phases
                    .iter()
                    .filter(|(_, value)| value == phase)
                    .map(|(uuid, _)| uuid.clone())
                    .collect(),
            )
        })
        .collect()
}

/// Threat-to-rule coverage around `uuid`; `None` without a coverage graph.
pub fn coverage(catalog: &Catalog<'_>, uuid: &str, name: &str) -> Option<Diagram> {
    let graph = catalog.coverage_graph(uuid);
    if graph.nodes.is_empty() {
        return None;
    }
    let mut diagram = Diagram::new(
        &format!("Detection coverage of {name}"),
        "Threat vectors on the left are detected by the objectives, signals and rules to their \
         right.",
    );
    for node in &graph.nodes {
        if let Some(kind) = NodeKind::of(node.object_type) {
            diagram.add_node(Node::new(&node.uuid, &node.name, kind).focused(node.uuid == uuid));
        }
    }
    for edge in &graph.edges {
        diagram.add_link(Link::new(&edge.source, &edge.target));
    }
    diagram.lanes = kind_lanes(&diagram);
    Some(diagram)
}

/// `uuid` and its direct neighbours, when there is no coverage path.
pub fn relations(
    catalog: &Catalog<'_>,
    uuid: &str,
    name: &str,
    kind: NodeKind,
    direction: Direction,
) -> Option<Diagram> {
    let related = catalog.related(uuid, direction);
    if related.is_empty() {
        return None;
    }
    let mut diagram = Diagram::new(
        &format!("Relations of {name}"),
        "Objects this one references, and objects that reference it.",
    );
    diagram.add_node(Node::new(uuid, name, kind).focused(true));
    for entry in &related {
        let Some(entry_kind) = NodeKind::of(&entry.object_type) else {
            continue;
        };
        diagram.add_node(Node::new(&entry.uuid, &entry.name, entry_kind));
        if entry.direction == Direction::Upstream {
            diagram.add_link(Link::new(&entry.uuid, uuid));
        } else {
            diagram.add_link(Link::new(uuid, &entry.uuid));
        }
    }
    diagram.lanes = kind_lanes(&diagram);
    Some(diagram)
}

/// Where a rule goes: each platform at its status, and the tenants each run
/// reaches. A solid link is one a run takes, labelled with the runs; a
/// dotted one is a status or a tenant no run deploys to.
pub fn deployment(uuid: &str, name: &str, deployments: &[PlatformDeployment]) -> Option<Diagram> {
    if deployments.is_empty() {
        return None;
    }
    let mut diagram = Diagram::new(
        &format!("Deployment map of {name}"),
        "The platforms the rule deploys to, at their status, and the tenants each run reaches.",
    );
    diagram.add_node(Node::new(uuid, name, NodeKind::Rule).focused(true));
    let style = |deployed: bool| {
        if deployed {
            LinkStyle::Solid
        } else {
            LinkStyle::Dotted
        }
    };
    for deployment in deployments {
        let platform_key = format!("{uuid}::{}", deployment.platform);
        diagram.add_node(
            Node::new(&platform_key, &deployment.label, NodeKind::Platform)
                .captioned(&deployment.status),
        );
        diagram.add_link(Link {
            style: style(!deployment.runs.is_empty()),
            ..Link::new(uuid, &platform_key)
        });
        for target in &deployment.targets {
            let tenant_key = format!("{platform_key}::{}", target.name);
            let caption = if target.remote_id.is_empty() {
                String::new()
            } else {
                format!("id {}", target.remote_id)
            };
            diagram.add_node(
                Node::new(&tenant_key, &target.name, NodeKind::Tenant).captioned(&caption),
            );
            diagram.add_link(Link {
                label: target
                    .runs
                    .iter()
                    .map(|run| run.name())
                    .collect::<Vec<_>>()
                    .join(" + "),
                style: style(!target.runs.is_empty()),
                ..Link::new(&platform_key, &tenant_key)
            });
        }
    }
    diagram.link_legend = vec![
        (
            LinkStyle::Solid,
            "deployed, by the runs named on the line".to_owned(),
        ),
        (
            LinkStyle::Dotted,
            "not deployed: no run takes this status or tenant".to_owned(),
        ),
    ];
    let of_kind = |kind: NodeKind| -> Vec<String> {
        diagram
            .nodes
            .values()
            .filter(|node| node.kind == kind)
            .map(|node| node.key.clone())
            .collect()
    };
    let lanes = [
        ("Detection rule", vec![uuid.to_owned()]),
        ("Platforms", of_kind(NodeKind::Platform)),
        ("Tenants", of_kind(NodeKind::Tenant)),
    ];
    diagram.lanes = lanes
        .into_iter()
        .filter(|(_, members)| !members.is_empty())
        .map(|(title, members)| Lane::new(title, members))
        .collect();
    Some(diagram)
}

/// A chaining link: the relation's family sets the line, a `to` relation
/// is drawn from the target under its family's `from` name.
fn add_chaining_link(
    diagram: &mut Diagram,
    vocab: &Vocab<'_>,
    source: &str,
    target: &str,
    relation: &str,
) {
    if relation.is_empty() {
        diagram.add_link(Link::new(source, target));
        return;
    }
    let relation = vocab.chaining_relation(relation);
    let (style, family) = match relation.family.as_str() {
        "sequence" => (LinkStyle::Solid, "sequence"),
        "atomicity" => (LinkStyle::Thick, "composition"),
        "support" => (LinkStyle::Dotted, "support"),
        other => (LinkStyle::Solid, other),
    };
    if !family.is_empty() {
        diagram.set_link_legend(style, family);
    }
    let (source, target) = if relation.reversed {
        (target, source)
    } else {
        (source, target)
    };
    diagram.add_link(Link {
        label: relation.drawn_label().to_owned(),
        style,
        bidirectional: relation.bidirectional,
        ..Link::new(source, target)
    });
}

/// The chaining network of threat `uuid`, laned by kill-chain phase; the
/// threat's own entries when the network has no link.
pub fn chaining(
    catalog: &Catalog<'_>,
    vocab: &Vocab<'_>,
    uuid: &str,
    name: &str,
) -> Option<Diagram> {
    let network: Graph = catalog.chaining_network(uuid, vocab);
    if network.edges.is_empty() {
        let entries = catalog.chaining_entries(uuid, vocab);
        if entries.is_empty() {
            return None;
        }
        let mut diagram = Diagram::new(
            &format!("Threat chaining of {name}"),
            "Threat vectors this threat declares chaining relations to.",
        );
        diagram.add_node(Node::new(uuid, name, NodeKind::Threat).focused(true));
        for entry in &entries {
            diagram.add_node(Node::new(&entry.uuid, &entry.name, NodeKind::Threat));
            add_chaining_link(
                &mut diagram,
                vocab,
                uuid,
                &entry.uuid,
                entry.relation.as_deref().unwrap_or_default(),
            );
        }
        return Some(diagram);
    }
    let mut diagram = Diagram::new(
        &format!("Threat chaining of {name}"),
        "Threat vectors linked by chaining relations, grouped by kill-chain phase.",
    );
    for node in &network.nodes {
        diagram.add_node(
            Node::new(&node.uuid, &node.name, NodeKind::Threat).focused(node.uuid == uuid),
        );
    }
    for edge in &network.edges {
        add_chaining_link(
            &mut diagram,
            vocab,
            &edge.source,
            &edge.target,
            edge.label.as_deref().unwrap_or_default(),
        );
    }
    let phases: Vec<(String, String)> = network
        .nodes
        .iter()
        .map(|node| {
            (
                node.uuid.clone(),
                node.killchain.clone().unwrap_or_default(),
            )
        })
        .collect();
    diagram.lanes = phase_lanes(&phases, vocab);
    Some(diagram)
}

/// Every phase in its stage's lane, linked in order; the stages follow one
/// another.
fn killchain_frame(stages: &[(String, Vec<String>)], title: &str, description: &str) -> Diagram {
    let mut diagram = Diagram::new(title, description);
    diagram.direction = "TB";
    diagram.chain_lanes = true;
    for (stage, phases) in stages {
        let keys: Vec<String> = phases
            .iter()
            .map(|phase| format!("phase::{phase}"))
            .collect();
        for (key, phase) in keys.iter().zip(phases) {
            diagram.add_node(Node::new(key, phase, NodeKind::Phase));
        }
        for pair in keys.windows(2) {
            diagram.add_link(Link::new(&pair[0], &pair[1]));
        }
        diagram.lanes.push(Lane {
            direction: Some("LR"),
            ..Lane::new(stage, keys)
        });
    }
    diagram
}

/// Where a threat sits on the kill chain, and where the threats chained to
/// it sit (`related`: a phase and the names of the chained threats in it).
pub fn threat_killchain(
    vocab: &Vocab<'_>,
    phases: &[String],
    related: &[(String, Vec<String>)],
) -> Option<Diagram> {
    let stages = vocab.killchain_stages();
    let placed = stages
        .iter()
        .any(|(_, members)| phases.iter().any(|phase| members.contains(phase)));
    if !placed {
        return None;
    }
    let mut diagram = killchain_frame(
        &stages,
        "Kill-chain position",
        "The threat's own phase, and the phases of the threats chained to it.",
    );
    for node in diagram.nodes.values_mut() {
        if phases.contains(&node.label) {
            node.tone = Some(Tone::Current);
            "this threat".clone_into(&mut node.caption);
            node.focus = true;
        } else if let Some((_, names)) = related
            .iter()
            .find(|(phase, names)| *phase == node.label && !names.is_empty())
        {
            node.tone = Some(Tone::Related);
            node.caption = if names.len() == 1 {
                names[0].clone()
            } else {
                format!("{} +{}", names[0], names.len() - 1)
            };
        }
    }
    diagram.tone_legend = vec![
        (Tone::Current, "this threat vector".to_owned()),
        (Tone::Related, "a threat vector chained to it".to_owned()),
    ];
    Some(diagram)
}

/// The kill chain stage by stage, each phase coloured by how many of its
/// threat vectors an objective addresses (`phases`: a phase and one flag
/// per threat in it).
pub fn killchain_coverage(vocab: &Vocab<'_>, phases: &[(String, Vec<bool>)]) -> Option<Diagram> {
    let stages = vocab.killchain_stages();
    if stages.is_empty() || phases.iter().all(|(_, flags)| flags.is_empty()) {
        return None;
    }
    let mut diagram = killchain_frame(
        &stages,
        "Kill-chain coverage",
        "The Unified Kill Chain stage by stage; each phase is coloured by how many of its threat \
         vectors a detection objective addresses.",
    );
    for node in diagram.nodes.values_mut() {
        let flags = phases
            .iter()
            .find(|(phase, _)| *phase == node.label)
            .map(|(_, flags)| flags.as_slice())
            .unwrap_or_default();
        let covered = flags.iter().filter(|flag| **flag).count();
        let (tone, caption) = if flags.is_empty() {
            (Tone::Idle, String::new())
        } else if covered == flags.len() {
            (
                Tone::Covered,
                format!("{covered} of {} covered", flags.len()),
            )
        } else if covered > 0 {
            (
                Tone::Partial,
                format!("{covered} of {} covered", flags.len()),
            )
        } else {
            (Tone::Uncovered, format!("0 of {} covered", flags.len()))
        };
        node.tone = Some(tone);
        node.caption = caption;
    }
    diagram.tone_legend = vec![
        (Tone::Covered, "every threat vector addressed".to_owned()),
        (Tone::Partial, "some addressed".to_owned()),
        (Tone::Uncovered, "none addressed".to_owned()),
        (Tone::Idle, "no threat vector".to_owned()),
    ];
    Some(diagram)
}

/// Above this many threat vectors the landscape is too dense to read.
pub const LANDSCAPE_LIMIT: usize = 60;

/// A threat vector as the landscape draws it.
pub struct LandscapeThreat<'t> {
    /// Its UUID.
    pub uuid: &'t str,
    /// Its name.
    pub name: &'t str,
    /// Its first kill-chain phase, if any.
    pub phase: &'t str,
    /// Its chaining entries: `(target, relation)`.
    pub chaining: Vec<(&'t str, String)>,
}

/// Every threat vector of the catalogue by kill-chain phase, linked by
/// chaining, those no objective addresses drawn as gaps; `None` for fewer
/// than two threats or more than [`LANDSCAPE_LIMIT`].
pub fn landscape<S: std::hash::BuildHasher>(
    vocab: &Vocab<'_>,
    threats: &[LandscapeThreat<'_>],
    addressed: &HashSet<String, S>,
) -> Option<Diagram> {
    if !(2..=LANDSCAPE_LIMIT).contains(&threats.len()) {
        return None;
    }
    let mut diagram = Diagram::new(
        "Threat landscape",
        "Every threat vector by kill-chain phase, linked by chaining relations; dashed ones have \
         no detection objective.",
    );
    let mut phases = Vec::new();
    for threat in threats {
        let gap = !addressed.contains(threat.uuid);
        let mut node = Node::new(threat.uuid, threat.name, NodeKind::Threat).captioned(if gap {
            "not covered"
        } else {
            ""
        });
        node.gap = gap;
        diagram.add_node(node);
        phases.push((threat.uuid.to_owned(), threat.phase.to_owned()));
    }
    for threat in threats {
        for (target, relation) in &threat.chaining {
            add_chaining_link(&mut diagram, vocab, threat.uuid, target, relation);
        }
    }
    diagram.lanes = phase_lanes(&phases, vocab);
    Some(diagram)
}

#[cfg(test)]
mod tests;
