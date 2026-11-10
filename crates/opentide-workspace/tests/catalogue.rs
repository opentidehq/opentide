//! `info catalog`'s catalogue over a loaded workspace: edges and whether
//! they name an object, signals an objective owns, platform blocks and their
//! strategies, deployment bindings, tactics in matrix order, and the
//! summary.

mod catalogue {
    use std::path::PathBuf;
    use std::sync::Arc;

    use opentide_workspace::catalogue::{Catalogue, Edge, Row, build};
    use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

    const RULE: &str = "0b4d0e4e-1c33-4f53-8a6b-4c5b6e7f8a9b";

    fn options() -> Options {
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from("/ws")),
                cwd: PathBuf::from("/ws"),
                ..RootOptions::default()
            },
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "a test helper: the workspace it writes resolves"
    )]
    fn catalogue() -> Catalogue {
        let fs = Arc::new(MemoryFs::new());
        fs.create_dir("/ws/.opentide/configurations");
        fs.write(
            "/ws/.opentide/configurations/deployment.toml",
            "[[statuses]]\nname = \"production\"\nstrategy = \"release\"\n\n[[statuses]]\nname = \"draft\"\nstrategy = \"someday\"\n",
        );
        fs.write(
            format!("/ws/.opentide/states/deployment/{RULE}.json"),
            format!(
                r#"{{"schema": "deployment.state::1.0", "object_uuid": "{RULE}", "platforms": {{"sentinel_one": {{"prod": "17"}}}}}}"#
            ),
        );
        fs.write(
            "/ws/objects/threats/t1.yaml",
            "metadata:\n  uuid: t-1\nname: Threat\nthreat:\n  mitre_attack: [T1059]\n  actors: [APT1]\n  chaining:\n    - {relation: precedes, vector: t-gone}\n",
        );
        fs.write(
            "/ws/objects/objectives/o1.yaml",
            "metadata:\n  uuid: o-1\nname: Objective\nobjective:\n  threats: [t-1, t-gone]\n  signals:\n    - uuid: s-1\n      name: First\n      parent: s-none\n      data: {logsources: [winlog]}\n    - uuid: s-2\n      parent: s-1\n",
        );
        // Defines s-1 again: indexed under o-1, so no edge comes from here.
        fs.write(
            "/ws/objects/objectives/o2.yaml",
            "metadata:\n  uuid: o-2\nobjective:\n  signals:\n    - uuid: s-1\n      parent: s-2\n",
        );
        fs.write(
            "/ws/objects/rules/r1.yaml",
            format!(
                "metadata:\n  uuid: {RULE}\nname: Rule\ndetection_model: s-1\ntechniques: [T1105]\nconfigurations:\n  sentinel: {{enabled: true, status: production}}\n  splunk: {{enabled: \"yes\", status: draft}}\n  elastic: 5\n"
            ),
        );
        fs.write(
            "/ws/objects/rules/r2.yaml",
            "metadata:\n  uuid: r-2\nname: Other\ndetection_model: o-missing\n",
        );
        fs.write(
            "/ws/objects/rules/broken.yaml",
            "name: Broken\nmetadata:\n  uuid: 1b4d0e4e-1c33-4f53-8a6b-4c5b6e7f8a9b\n  tags: [unclosed\n",
        );
        let workspace =
            Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, options()).expect("opens");
        build(&workspace)
    }

    fn edge(
        from: &str,
        to: &str,
        kind: &str,
        field_path: &str,
        relation: Option<&str>,
        missing: bool,
    ) -> (String, String, String, String, Option<String>, bool) {
        (
            from.into(),
            to.into(),
            kind.into(),
            field_path.into(),
            relation.map(Into::into),
            missing,
        )
    }

    fn plain(edge: &Edge) -> (String, String, String, String, Option<String>, bool) {
        (
            edge.from.clone(),
            edge.to.clone(),
            edge.kind.to_owned(),
            edge.field_path.clone(),
            edge.relation.clone(),
            edge.missing,
        )
    }

    #[expect(
        clippy::expect_used,
        reason = "a test helper: it looks up objects the fixture writes"
    )]
    fn object<'c>(
        catalogue: &'c Catalogue,
        uuid: &str,
    ) -> &'c opentide_workspace::catalogue::ObjectRow {
        catalogue
            .objects
            .iter()
            .find_map(|row| match row {
                Row::Object(row) if row.uuid == uuid => Some(row.as_ref()),
                _ => None,
            })
            .expect("the object is listed")
    }

    #[test]
    fn edges_say_whether_they_name_an_object() {
        let catalogue = catalogue();
        let edges: Vec<_> = catalogue.edges.iter().map(plain).collect();
        assert_eq!(
            edges,
            [
                edge(
                    "t-1",
                    "T1059",
                    "technique",
                    "threat.mitre_attack",
                    None,
                    false
                ),
                edge(
                    "t-1",
                    "t-gone",
                    "chains",
                    "threat.chaining",
                    Some("precedes"),
                    true
                ),
                edge("o-1", "t-1", "covers", "objective.threats", None, false),
                edge("o-1", "t-gone", "covers", "objective.threats", None, true),
                edge(
                    "s-1",
                    "s-none",
                    "parent",
                    "objective.signals.0.parent",
                    None,
                    true
                ),
                edge(
                    "s-1",
                    "winlog",
                    "logsource",
                    "objective.signals.0.data.logsources",
                    None,
                    false
                ),
                edge(
                    "s-2",
                    "s-1",
                    "parent",
                    "objective.signals.1.parent",
                    None,
                    false
                ),
                edge(RULE, "T1105", "technique", "techniques", None, false),
                edge(RULE, "s-1", "implements", "detection_model", None, false),
                edge(
                    "r-2",
                    "o-missing",
                    "implements",
                    "detection_model",
                    None,
                    true
                ),
            ]
        );
        // A signal UUID o-2 defines again belongs to o-1: one row each.
        let signals: Vec<_> = catalogue
            .signals
            .iter()
            .map(|s| {
                (
                    s.uuid.as_str(),
                    s.name.as_str(),
                    s.objective.as_deref(),
                    s.parent.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            signals,
            [
                ("s-1", "First", Some("o-1"), Some("s-none")),
                ("s-2", "", Some("o-1"), Some("s-1")),
            ]
        );
    }

    #[test]
    fn rows_carry_techniques_tactics_platforms_and_bindings() {
        let catalogue = catalogue();
        let rule = object(&catalogue, RULE);
        assert_eq!(rule.techniques.own, ["T1105"]);
        assert_eq!(rule.techniques.inherited, ["T1059"]);
        // Matrix order, not alphabetical.
        assert_eq!(rule.tactics, ["execution", "command-and-control"]);
        assert_eq!(rule.actors, ["APT1"]);
        assert_eq!(rule.line, 3);
        assert_eq!(rule.path.as_deref(), Some("objects/rules/r1.yaml"));
        // `elastic: 5` is no block; `enabled: "yes"` is text, so not enabled;
        // a status mapped to no known strategy has none.
        let blocks: Vec<_> = rule
            .platforms
            .iter()
            .map(|b| {
                (
                    b.id.as_str(),
                    b.enabled,
                    b.status.as_deref(),
                    b.strategy.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            blocks,
            [
                ("sentinel", true, Some("production"), Some("RELEASE")),
                ("splunk", false, Some("draft"), None),
            ]
        );
        let bindings: Vec<_> = rule
            .deployment
            .iter()
            .map(|b| {
                (
                    b.platform.as_str(),
                    b.tenant.as_str(),
                    b.rule_id.as_str(),
                    b.deployed,
                )
            })
            .collect();
        assert_eq!(bindings, [("sentinel_one", "prod", "17", true)]);
        assert!(object(&catalogue, "r-2").deployment.is_empty());
        assert!(object(&catalogue, "r-2").platforms.is_empty());
        let objective = object(&catalogue, "o-1");
        assert_eq!(objective.techniques.inherited, ["T1059"]);
        assert_eq!(objective.actors, ["APT1"]);
        assert!(object(&catalogue, "t-1").platforms.is_empty());
    }

    #[test]
    fn families_in_order_then_load_errors_and_the_summary() {
        let catalogue = catalogue();
        let order: Vec<Option<&str>> = catalogue.objects.iter().map(Row::loaded_family).collect();
        assert_eq!(
            order,
            [
                Some("threat"),
                Some("objective"),
                Some("objective"),
                Some("rule"),
                Some("rule"),
                None,
            ]
        );
        let Some(Row::LoadError(broken)) = catalogue.objects.last() else {
            panic!("the last row is the load error");
        };
        assert_eq!(broken.name, "Broken");
        assert_eq!(
            broken.uuid.as_deref(),
            Some("1b4d0e4e-1c33-4f53-8a6b-4c5b6e7f8a9b")
        );
        assert_eq!(broken.path.as_deref(), Some("objects/rules/broken.yaml"));
        let summary = &catalogue.summary;
        assert_eq!(
            (
                summary.objects,
                summary.threats,
                summary.objectives,
                summary.rules,
                summary.signals,
                summary.edges,
                summary.load_errors,
            ),
            (6, 1, 2, 2, 2, 10, 1)
        );
    }
}
