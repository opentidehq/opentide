//! Technique coverage over a loaded workspace: what a rule lists, and what
//! it inherits from its objective (named directly or through a signal) and
//! that objective's threats, each once.

mod coverage {
    use std::path::PathBuf;
    use std::sync::Arc;

    use opentide_workspace::coverage::{
        RuleTechniques, inherited_techniques, rule_technique_index,
    };
    use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

    fn options() -> Options {
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from("/ws")),
                cwd: PathBuf::from("/ws"),
                ..RootOptions::default()
            },
        }
    }

    fn techniques(own: &[&str], inherited: &[&str]) -> RuleTechniques {
        RuleTechniques {
            own: own.iter().map(|t| (*t).to_owned()).collect(),
            inherited: inherited.iter().map(|t| (*t).to_owned()).collect(),
        }
    }

    #[test]
    fn rules_inherit_through_objectives_signals_and_threats() {
        let fs = Arc::new(MemoryFs::new());
        fs.create_dir("/ws/.opentide/configurations");
        fs.write(
            "/ws/objects/threats/t1.yaml",
            "metadata:\n  uuid: t-1\nthreat:\n  mitre_attack: [T1059, T1105]\n",
        );
        fs.write(
            "/ws/objects/threats/t2.yaml",
            "metadata:\n  uuid: t-2\nthreat:\n  mitre_attack: [T1105, T1566]\n",
        );
        // Inherits from its threats (a missing one skipped), each once.
        fs.write(
            "/ws/objects/objectives/o1.yaml",
            "metadata:\n  uuid: o-1\nobjective:\n  threats: [t-1, t-missing, t-2]\n  signals:\n    - uuid: s-1\n",
        );
        // Lists its own: its threats' are not read.
        fs.write(
            "/ws/objects/objectives/o2.yaml",
            "metadata:\n  uuid: o-2\nobjective:\n  mitre_attack: [T1003]\n  threats: [t-1]\n",
        );
        // Through a signal of o-1, listing one of the inherited itself.
        fs.write(
            "/ws/objects/rules/r1.yaml",
            "metadata:\n  uuid: r-1\ndetection_model: s-1\ntechniques: [T1105, T1027]\n",
        );
        // Names o-2 directly.
        fs.write(
            "/ws/objects/rules/r2.yaml",
            "metadata:\n  uuid: r-2\ndetection_model: o-2\n",
        );
        // Names nothing that exists.
        fs.write(
            "/ws/objects/rules/r3.yaml",
            "metadata:\n  uuid: r-3\ndetection_model: s-none\ntechniques: [T1027]\n",
        );
        let workspace =
            Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, options()).expect("opens");
        let index = workspace.index();

        let rules = rule_technique_index(index);
        assert_eq!(
            rules["r-1"],
            techniques(&["T1105", "T1027"], &["T1059", "T1566"])
        );
        assert_eq!(rules["r-2"], techniques(&[], &["T1003"]));
        assert_eq!(rules["r-3"], techniques(&["T1027"], &[]));

        let objective = |uuid: &str| {
            index.objects["objective"][uuid]
                .root()
                .expect("the objective loads")
        };
        assert_eq!(
            inherited_techniques("objective", objective("o-1"), index),
            ["T1059", "T1105", "T1566"]
        );
        assert_eq!(
            inherited_techniques("objective", objective("o-2"), index),
            ["T1003"]
        );
        let threat = index.objects["threat"]["t-1"].root().expect("loads");
        assert!(inherited_techniques("threat", threat, index).is_empty());
    }
}
