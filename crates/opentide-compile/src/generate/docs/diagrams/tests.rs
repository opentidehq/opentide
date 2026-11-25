use indexmap::IndexMap;
use opentide_schema::vocab::Vocabularies;

use super::super::facts::{PlatformDeployment, StatusDefinition, TenantScope, TenantTarget};
use super::super::mermaid::Dialect;
use super::*;
use crate::strategy::StatusStrategy::{Preview, Release};

fn block(
    platform: &str,
    status: &str,
    runs: Vec<crate::strategy::StatusStrategy>,
) -> PlatformDeployment {
    PlatformDeployment {
        platform: platform.to_owned(),
        label: super::super::platforms::platform_label(platform),
        enabled: true,
        status: status.to_owned(),
        definition: Some(StatusDefinition {
            name: status.to_owned(),
            description: String::new(),
            strategy: Preview,
        }),
        runs,
        scope: TenantScope::All,
        targets: Vec::new(),
        unknown_tenants: Vec::new(),
        platform_enabled: Some(true),
        orphaned_ids: IndexMap::new(),
    }
}

#[test]
fn a_deployment_map_draws_runs_and_tenants() {
    assert!(deployment_map_of(&[]).is_none());
    let mut sentinel = block("sentinel", "STAGING", vec![Preview]);
    sentinel.targets = vec![
        TenantTarget {
            name: "lab".into(),
            runs: vec![Preview, Release],
            remote_id: "42".into(),
            ..TenantTarget::default()
        },
        TenantTarget {
            name: "prod".into(),
            ..TenantTarget::default()
        },
    ];
    let splunk = block("splunk", "DRAFT", Vec::new());
    let diagram = deployment_map_of(&[sentinel, splunk]).unwrap();
    let text = render(&diagram, Dialect::FULL);
    assert!(
        text.contains("    accTitle: Deployment map of R\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "    subgraph lane3[\"Tenants\"]\n        ten1[[\"lab<br>id 42\"]]\n        \
             ten2[[\"prod\"]]\n    end\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "    rul1 --> plt1\n    plt1 -->|\"PREVIEW + RELEASE\"| ten1\n    plt1 -.-> ten2\n    \
             rul1 -.-> plt2\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("plt2[(\"Splunk Enterprise Security<br>DRAFT\")]"),
        "{text}"
    );
    assert_eq!(
        legend(&diagram, Dialect::FULL),
        "*Shapes:* rectangle = detection rule; cylinder = platform; subroutine box = tenant; \
         bold outline = this page. *Lines:* solid line = deployed, by the runs named on the \
         line; dotted line = not deployed: no run takes this status or tenant."
    );
    // Without a tenant, no tenant lane.
    let only = deployment_map_of(&[block("sentinel", "S", vec![Preview])]).unwrap();
    assert_eq!(only.lanes.len(), 2);
}

fn deployment_map_of(deployments: &[PlatformDeployment]) -> Option<Diagram> {
    super::deployment("u", "R", deployments)
}

#[test]
fn fenced_diagrams_end_with_their_legend() {
    let mut diagram = Diagram::new("T", "");
    assert_eq!(fenced(Flavor::Github, Some(&diagram)), "");
    assert_eq!(fenced(Flavor::Github, None), "");
    diagram.add_node(Node::new("a", "A", NodeKind::Rule));
    diagram.add_node(Node::new("b", "B", NodeKind::Rule));
    diagram.add_link(Link::new("a", "b"));
    assert_eq!(
        fenced(Flavor::AzureDevops, Some(&diagram)),
        "::: mermaid\ngraph LR\n    rul1[\"A\"]\n    rul2[\"B\"]\n    rul1 --> rul2\n:::\n\n\
         *Shapes:* rectangle = detection rule.\n"
    );
}

#[test]
fn the_kill_chain_maps() {
    let vocabularies = Vocabularies::bundled();
    let vocab = Vocab::new(&vocabularies);
    let stages = vocab.killchain_stages();
    assert!(stages.len() >= 3, "{stages:?}");
    assert!(threat_killchain(&vocab, &["Nowhere".into()], &[]).is_none());
    let related = vec![
        ("Execution".to_owned(), vec!["A".to_owned()]),
        ("Discovery".to_owned(), vec!["B".to_owned(), "C".to_owned()]),
    ];
    let diagram = threat_killchain(&vocab, &["Credential Access".into()], &related).unwrap();
    let text = render(&diagram, Dialect::FULL);
    assert!(
        text.starts_with("flowchart TB\n    accTitle: Kill-chain position\n"),
        "{text}"
    );
    assert!(text.contains("        direction LR\n"), "{text}");
    assert!(
        text.contains("([\"Credential Access<br>this threat\"])"),
        "{text}"
    );
    assert!(text.contains("([\"Execution<br>A\"])"), "{text}");
    assert!(text.contains("([\"Discovery<br>B +1\"])"), "{text}");
    assert!(text.contains("    lane1 --> lane2 --> lane3\n"), "{text}");
    assert!(legend(&diagram, Dialect::FULL).ends_with(
        "*Colours:* blue = this threat vector; light blue = a threat vector chained to it."
    ));

    assert!(killchain_coverage(&vocab, &[]).is_none());
    assert!(killchain_coverage(&vocab, &[("Execution".into(), Vec::new())]).is_none());
    let coverage = killchain_coverage(
        &vocab,
        &[
            ("Execution".into(), vec![true, true]),
            ("Discovery".into(), vec![true, false]),
            ("Collection".into(), vec![false]),
        ],
    )
    .unwrap();
    let text = render(&coverage, Dialect::FULL);
    assert!(
        text.contains("([\"Execution<br>2 of 2 covered\"])"),
        "{text}"
    );
    assert!(
        text.contains("([\"Discovery<br>1 of 2 covered\"])"),
        "{text}"
    );
    assert!(
        text.contains("([\"Collection<br>0 of 1 covered\"])"),
        "{text}"
    );
    for tone in ["covered", "partial", "uncovered", "idle"] {
        assert!(
            text.contains(&format!("    classDef {tone} ")),
            "{tone}: {text}"
        );
    }
    // Azure DevOps: no lanes, so each stage's last phase leads to the next
    // stage's first.
    let plain = render(&coverage, Dialect::AZURE_DEVOPS);
    assert!(!plain.contains("lane"), "{plain}");
    assert_eq!(
        plain.matches(" --> ").count(),
        coverage.links.len() + stages.len() - 1,
        "{plain}"
    );
}

#[test]
fn the_landscape_lanes_threats_by_phase_and_marks_gaps() {
    let vocabularies = Vocabularies::bundled();
    let vocab = Vocab::new(&vocabularies);
    let one = LandscapeThreat {
        uuid: "a",
        name: "Alpha",
        phase: "Lateral Movement",
        chaining: vec![("b", "preceeds".to_owned()), ("z", String::new())],
    };
    assert!(landscape(&vocab, std::slice::from_ref(&one), &HashSet::new()).is_none());
    let two = LandscapeThreat {
        uuid: "b",
        name: "Beta",
        phase: "Credential Access",
        chaining: vec![("a", "succeeds".to_owned())],
    };
    let three = LandscapeThreat {
        uuid: "c",
        name: "Gamma",
        phase: "",
        chaining: Vec::new(),
    };
    let addressed: HashSet<String> = ["a".to_owned()].into();
    let diagram = landscape(&vocab, &[one, two, three], &addressed).unwrap();
    let titles: Vec<&str> = diagram
        .lanes
        .iter()
        .map(|lane| lane.title.as_str())
        .collect();
    assert_eq!(titles, ["Credential Access", "Lateral Movement"]);
    assert!(diagram.lanes.iter().all(|lane| lane.caption_fallback));
    assert!(diagram.nodes["b"].gap && diagram.nodes["c"].gap && !diagram.nodes["a"].gap);
    assert_eq!(diagram.nodes["b"].caption, "not covered");
    // `succeeds` is drawn the `preceeds` way, so the two declarations are
    // one link; a target outside the catalogue is not drawn.
    let links: Vec<(&str, &str, &str)> = diagram
        .links
        .iter()
        .map(|link| {
            (
                link.source.as_str(),
                link.target.as_str(),
                link.label.as_str(),
            )
        })
        .collect();
    assert_eq!(links.len(), 1, "{links:?}");
    assert_eq!(links[0].0, "a");
    assert_eq!(links[0].1, "b");
    let text = legend(&diagram, Dialect::FULL);
    assert!(
        text.contains("dashed outline = no detection objective"),
        "{text}"
    );
}

#[test]
fn chaining_links_follow_their_family() {
    let vocabularies = Vocabularies::bundled();
    let vocab = Vocab::new(&vocabularies);
    let mut diagram = Diagram::new("T", "");
    for key in ["a", "b", "c"] {
        diagram.add_node(Node::new(key, key, NodeKind::Threat));
    }
    add_chaining_link(&mut diagram, &vocab, "a", "b", "");
    add_chaining_link(&mut diagram, &vocab, "a", "c", "no-such-relation");
    assert_eq!(diagram.links[0].label, "");
    assert_eq!(diagram.links[1].label, "no-such-relation");
    assert_eq!(diagram.links[1].style, LinkStyle::Solid);
    assert!(diagram.link_legend.is_empty());
}

#[test]
fn lane_titles_name_each_kind() {
    for kind in NodeKind::ALL {
        assert!(!lane_title(kind).is_empty());
    }
}
