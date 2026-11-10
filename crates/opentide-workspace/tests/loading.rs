//! Loading a workspace: discovery, the configuration resolved once, each
//! file read and parsed once, load errors, duplicates, signals, references,
//! the SDK lifecycle and invalidation.

mod loading {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use opentide_workspace::index::{MISSING_UUID, ReferenceKind, YAML_PARSE};
    use opentide_workspace::{
        Change, ConfigError, FileSystem, MemoryFs, Options, Registry, RootOptions, Workspace,
    };

    const ROOT: &str = "/ws";

    fn options() -> Options {
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from(ROOT)),
                cwd: PathBuf::from(ROOT),
                ..RootOptions::default()
            },
        }
    }

    fn object(uuid: &str) -> String {
        format!("metadata:\n  uuid: {uuid}\n  name: n\n")
    }

    #[expect(
        clippy::unwrap_used,
        reason = "a test helper: every workspace it opens resolves"
    )]
    fn open(fs: &Arc<MemoryFs>) -> Workspace {
        Workspace::open(Arc::clone(fs) as Arc<dyn FileSystem>, options()).unwrap()
    }

    fn sample() -> Arc<MemoryFs> {
        let fs = Arc::new(MemoryFs::new());
        fs.create_dir("/ws/.opentide/configurations");
        fs.write(
            "/ws/.opentide/configurations/deployment.toml",
            "default_responders = \"soc\"\n",
        );
        fs.write("/ws/objects/threats/t1.yaml", object("t-1"));
        fs.write(
            "/ws/objects/objectives/o1.yaml",
            "metadata:\n  uuid: o-1\nobjective:\n  threats: [t-1, t-x]\n  signals:\n    - uuid: s-1\n    - uuid: s-2\n",
        );
        fs.write(
            "/ws/objects/rules/r1.yaml",
            "metadata:\n  uuid: r-1\ndetection_model: s-1\n",
        );
        fs.write("/ws/objects/rules/r2.yml", object("r-2"));
        fs.write("/ws/objects/rules/r3.debug.yaml", object("r-3"));
        fs.write("/ws/objects/rules/team/r4.yaml", object("r-4"));
        fs.write("/ws/objects/rules/README.md", "# rules\n");
        fs
    }

    #[test]
    fn each_file_is_read_and_parsed_once_and_the_configuration_resolved_once() {
        let fs = sample();
        let workspace = open(&fs);
        let stats = workspace.stats();
        assert_eq!(stats.file_reads, 4, "{stats:?}");
        assert_eq!(stats.parses, 4);
        assert_eq!(stats.config_resolutions, 1);
        assert_eq!(stats.config_files_read, 1);
        let reads = fs.reads();
        for (path, count) in &reads {
            assert_eq!(*count, 1, "{} read {count} times", path.display());
        }
        let mut read: Vec<&PathBuf> = reads.keys().collect();
        read.sort();
        assert_eq!(
            read,
            [
                Path::new("/ws/.opentide/configurations/deployment.toml"),
                Path::new("/ws/objects/objectives/o1.yaml"),
                Path::new("/ws/objects/rules/r1.yaml"),
                Path::new("/ws/objects/rules/r2.yml"),
                Path::new("/ws/objects/threats/t1.yaml"),
            ]
        );
        let index = workspace.index();
        assert_eq!(index.len(), 4);
        assert_eq!(index.nested.len(), 1);
        assert_eq!(
            index.nested[0].path,
            Path::new("/ws/objects/rules/team/r4.yaml")
        );
        assert_eq!(
            workspace
                .configuration()
                .resolved
                .get("deployment")
                .and_then(|d| d.get("default_responders"))
                .and_then(|v| v.value.as_str()),
            Some("soc")
        );
    }

    #[test]
    fn references_signals_and_lookups() {
        let fs = sample();
        // An empty `detection_model` names nothing.
        fs.write(
            "/ws/objects/rules/r5.yaml",
            "metadata:\n  uuid: r-5\ndetection_model: ''\n",
        );
        let workspace = open(&fs);
        let index = workspace.index();
        let refs: Vec<(&str, &str, &str)> = index
            .references
            .iter()
            .map(|r| (r.from.as_str(), r.kind.name(), r.target.as_str()))
            .collect();
        assert_eq!(
            refs,
            [
                ("o-1", "threat", "t-1"),
                ("o-1", "threat", "t-x"),
                ("o-1", "signal", "s-1"),
                ("o-1", "signal", "s-2"),
                ("r-1", "detection_model", "s-1"),
            ]
        );
        assert_eq!(index.referrers("s-1").count(), 2);
        assert_eq!(index.signals["s-1"].owner, "o-1");
        assert_eq!(index.lookup("r-2").unwrap().family, "rule");
        assert_eq!(index.lookup("t-1").unwrap().file_name(), "t1.yaml");
        assert!(index.lookup("s-1").is_none());
        assert_eq!(index.rules().count(), 3);
        assert_eq!(index.threats().count(), 1);
        assert_eq!(index.objectives().count(), 1);
        assert_eq!(index.files()["r-2"], "r2.yml");
        assert!(!index.is_empty());
    }

    #[test]
    fn load_errors_keep_the_file_its_family_and_code() {
        let fs = Arc::new(MemoryFs::new());
        fs.write("/ws/objects/rules/a-empty.yaml", "");
        fs.write(
            "/ws/objects/rules/b-latin1.yaml",
            b"name: caf\xe9\n".to_vec(),
        );
        fs.write("/ws/objects/rules/c-no-uuid.yaml", "metadata:\n  name: x\n");
        fs.write("/ws/objects/rules/d-list-uuid.yaml", "uuid: [a]\n");
        fs.write("/ws/objects/rules/e-syntax.yaml", "a: [1\n");
        fs.write(
            "/ws/objects/rules/f-empty-uuid.yaml",
            "metadata:\n  uuid: ''\n",
        );
        let workspace = open(&fs);
        let errors: Vec<(&str, &str, String)> = workspace
            .index()
            .load_errors
            .iter()
            .map(|e| {
                (
                    e.path.file_name().unwrap().to_str().unwrap(),
                    e.code,
                    e.message(),
                )
            })
            .collect();
        assert_eq!(errors[0], (
            "a-empty.yaml",
            YAML_PARSE,
            "Could not parse object YAML: expected a mapping at the top of the file, found an empty file".to_owned()
        ));
        assert_eq!(errors[1], (
            "b-latin1.yaml",
            YAML_PARSE,
            "Could not parse object YAML: the file is not UTF-8 text (byte 0xe9 at offset 9); save it as UTF-8".to_owned()
        ));
        assert_eq!(
            errors[2],
            (
                "c-no-uuid.yaml",
                MISSING_UUID,
                "Object YAML has no uuid: c-no-uuid.yaml".to_owned()
            )
        );
        assert_eq!(errors[3].1, MISSING_UUID);
        assert_eq!(
            workspace.index().load_errors[3].error,
            "object YAML uuid is a sequence, not text"
        );
        assert_eq!(errors[4].1, YAML_PARSE);
        assert!(errors[4].2.contains("at line 2"), "{}", errors[4].2);
        // An empty UUID is no UUID: nothing is indexed under "".
        assert_eq!(
            errors[5],
            (
                "f-empty-uuid.yaml",
                MISSING_UUID,
                "Object YAML has no uuid: f-empty-uuid.yaml".to_owned()
            )
        );
        assert_eq!(errors.len(), 6);
        assert!(workspace.index().is_empty());
    }

    #[test]
    fn a_later_file_replaces_an_earlier_one_with_the_same_uuid() {
        let fs = Arc::new(MemoryFs::new());
        fs.write("/ws/objects/rules/a.yaml", object("same"));
        fs.write("/ws/objects/rules/b.yaml", object("same"));
        fs.write("/ws/objects/threats/c.yaml", object("same"));
        let mut opts = options();
        let workspace = open(&fs);
        let index = workspace.index();
        assert_eq!(index.duplicates.len(), 1);
        let duplicate = &index.duplicates[0];
        assert_eq!(duplicate.path, Path::new("/ws/objects/rules/a.yaml"));
        assert_eq!(
            duplicate.message,
            "UUID same is also used by objects/rules/b.yaml"
        );
        assert_eq!(index.get("rule", "same").unwrap().file_name(), "b.yaml");
        // Another family keeps its own: id_uniqueness reports that one.
        assert!(index.get("threat", "same").is_some());
        // The working directory is resolved before it is compared, as
        // `_shown_path` resolves it (a link, `\\?\` on Windows).
        let mut indirect = options();
        indirect.roots.cwd = PathBuf::from("/ws/sub/..");
        let workspace = Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, indirect).unwrap();
        assert_eq!(
            workspace.index().duplicates[0].message,
            "UUID same is also used by objects/rules/b.yaml"
        );
        // Outside the working directory the path is shown whole.
        opts.roots.cwd = PathBuf::from("/elsewhere");
        let workspace = Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, opts).unwrap();
        let later = &workspace.index().get("rule", "same").unwrap().path;
        assert_eq!(
            workspace.index().duplicates[0].message,
            format!("UUID same is also used by {}", later.display())
        );
    }

    #[test]
    fn a_signal_keeps_its_first_objective_and_a_reread_objective_its_own() {
        let fs = Arc::new(MemoryFs::new());
        fs.write(
            "/ws/objects/objectives/a.yaml",
            "metadata:\n  uuid: o-a\nobjective:\n  signals:\n    - uuid: s\n      name: first\n    - uuid: s\n      name: repeated\n",
        );
        fs.write(
            "/ws/objects/objectives/b.yaml",
            "metadata:\n  uuid: o-b\nobjective:\n  signals:\n    - uuid: s\n      name: other\n    - uuid: t\n",
        );
        fs.write(
            "/ws/objects/objectives/c.yaml",
            "metadata:\n  uuid: o-a\nobjective:\n  signals:\n    - uuid: s\n      name: replaced\n",
        );
        let workspace = open(&fs);
        let signals = &workspace.index().signals;
        assert_eq!(signals["s"].owner, "o-a");
        assert_eq!(
            signals["s"].node.get("name").unwrap().value.as_str(),
            Some("replaced")
        );
        assert_eq!(signals["t"].owner, "o-b");
    }

    #[test]
    fn a_signal_repeated_in_one_objective_keeps_its_first_definition() {
        let fs = Arc::new(MemoryFs::new());
        fs.write(
            "/ws/objects/objectives/a.yaml",
            "metadata:\n  uuid: o-a\nobjective:\n  signals:\n    - uuid: s\n      name: first\n    - uuid: s\n      name: repeated\n",
        );
        let workspace = open(&fs);
        let signals = &workspace.index().signals;
        assert_eq!(signals["s"].owner, "o-a");
        assert_eq!(
            signals["s"].node.get("name").unwrap().value.as_str(),
            Some("first")
        );
    }

    #[test]
    fn a_signal_another_objective_owns_is_not_taken_over() {
        let fs = Arc::new(MemoryFs::new());
        fs.write(
            "/ws/objects/objectives/a.yaml",
            "metadata:\n  uuid: o-a\nobjective:\n  signals:\n    - uuid: s\n      name: own\n",
        );
        fs.write(
            "/ws/objects/objectives/b.yaml",
            "metadata:\n  uuid: o-b\nobjective:\n  signals:\n    - uuid: s\n      name: other\n",
        );
        let workspace = open(&fs);
        let signals = &workspace.index().signals;
        assert_eq!(signals["s"].owner, "o-a");
        assert_eq!(
            signals["s"].node.get("name").unwrap().value.as_str(),
            Some("own")
        );
    }

    #[test]
    fn chaining_groups_vectors_by_relation() {
        let fs = Arc::new(MemoryFs::new());
        fs.write(
            "/ws/objects/threats/t.yaml",
            "metadata:\n  uuid: t\nthreat:\n  chaining:\n    - {relation: precedes, vector: a}\n    - {relation: precedes, vector: a}\n    - {relation: follows, vector: b}\n    - {vector: c}\n    - text\n",
        );
        fs.write(
            "/ws/objects/threats/u.yaml",
            "metadata:\n  uuid: u\nthreat:\n  chaining:\n    - {relation: ''}\n    - {relation: '', vector: x}\n",
        );
        let workspace = open(&fs);
        let index = workspace.index();
        assert_eq!(index.chaining["t"]["precedes"], ["a"]);
        assert_eq!(index.chaining["t"]["follows"], ["b"]);
        // An empty relation groups nothing: the vector is referenced without one.
        assert!(index.chaining["u"].is_empty(), "{:?}", index.chaining["u"]);
        let kinds: Vec<&ReferenceKind> = index.references.iter().map(|r| &r.kind).collect();
        assert_eq!(kinds.len(), 5);
        assert_eq!(kinds[3], &ReferenceKind::Chaining { relation: None });
        let from_u: Vec<_> = index.references.iter().filter(|r| r.from == "u").collect();
        assert_eq!(from_u.len(), 1);
        assert_eq!(from_u[0].target, "x");
        assert_eq!(from_u[0].kind, ReferenceKind::Chaining { relation: None });
    }

    #[test]
    fn paths_toml_moves_the_folders_and_a_bad_one_stops_the_load() {
        let fs = Arc::new(MemoryFs::new());
        fs.write(
            "/ws/.opentide/configurations/paths.toml",
            "[paths.objects]\nrule = \"detections/\"\n",
        );
        fs.write("/ws/detections/r.yaml", object("r"));
        fs.write("/ws/objects/rules/ignored.yaml", object("x"));
        let workspace = open(&fs);
        assert_eq!(workspace.index().rules().count(), 1);
        assert_eq!(
            workspace.configuration().folder("rule"),
            Some(Path::new("/ws/detections"))
        );
        assert_eq!(
            workspace.index().skipped_folders.len(),
            2,
            "threats and objectives are missing"
        );

        // An empty folder names none, as the oracle's `if rel:` skips it: the
        // workspace root is never scanned as the rule folder.
        fs.write("/ws/root-level.yaml", object("root"));
        fs.write(
            "/ws/.opentide/configurations/paths.toml",
            "[paths.objects]\nrule = \"\"\n",
        );
        let workspace = open(&fs);
        assert_eq!(workspace.configuration().folder("rule"), None);
        assert_eq!(workspace.index().rules().count(), 0);
        assert!(workspace.index().skipped_folders.iter().any(|folder| {
            folder.family == "rule"
                && folder.path.is_none()
                && folder.problem == opentide_workspace::discover::FolderProblem::Missing
        }));

        fs.write(
            "/ws/.opentide/configurations/paths.toml",
            "[paths.objects]\nrule = 5\n",
        );
        let error = Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, options()).unwrap_err();
        assert!(matches!(error, ConfigError::Paths(_)), "{error:?}");
        assert_eq!(error.code(), None);
        fs.write("/ws/.opentide/configurations/paths.toml", "[paths\n");
        let error = Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, options()).unwrap_err();
        assert_eq!(error.code(), Some("config_parse"));
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn the_parent_instance_is_merged_unless_tide_workspace_is_set() {
        let fs = Arc::new(MemoryFs::new());
        fs.write(
            "/.opentide/configurations/paths.toml",
            "[paths.objects]\nrule = \"parent-rules/\"\n",
        );
        fs.write("/ws/parent-rules/r.yaml", object("r"));
        fs.create_dir("/ws/objects");
        let workspace = open(&fs);
        assert_eq!(workspace.index().rules().count(), 1);
        let mut opts = options();
        opts.roots.tide_workspace_env = Some(PathBuf::from(ROOT));
        let workspace = Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, opts).unwrap();
        assert!(workspace.roots().tide_workspace);
        assert_eq!(workspace.index().rules().count(), 0);
    }

    #[test]
    fn the_registry_loads_once_and_reloads_on_request() {
        let fs = sample();
        let mut registry = Registry::new(Arc::clone(&fs) as Arc<dyn FileSystem>, options());
        assert!(!registry.is_initialised());
        assert_eq!(registry.rules().unwrap().len(), 2);
        assert!(registry.is_initialised());
        let reads = fs.reads().values().sum::<usize>();
        registry.initialise().unwrap();
        assert_eq!(registry.threats().unwrap().len(), 1);
        assert_eq!(registry.objectives().unwrap().len(), 1);
        assert_eq!(registry.signals().unwrap().len(), 2);
        assert_eq!(registry.lookup("t-1").unwrap().unwrap().family, "threat");
        assert!(registry.lookup("nothing").unwrap().is_none());
        assert!(
            registry
                .configuration()
                .unwrap()
                .resolved
                .get("paths")
                .is_some()
        );
        assert_eq!(
            fs.reads().values().sum::<usize>(),
            reads,
            "initialise reads nothing again"
        );
        fs.write("/ws/objects/rules/r9.yaml", object("r-9"));
        assert_eq!(registry.rules().unwrap().len(), 2, "the snapshot holds");
        registry.reload().unwrap();
        assert_eq!(registry.rules().unwrap().len(), 3);
        assert_eq!(registry.index().unwrap().len(), 5);
    }

    #[test]
    fn invalidation_rereads_only_what_changed() {
        let fs = sample();
        let mut workspace = open(&fs);
        fs.reset_reads();
        fs.write("/ws/objects/rules/r1.yaml", object("r-1"));
        let done = workspace
            .invalidate(&[Change::changed("objects/rules/r1.yaml")])
            .unwrap();
        assert!(!done.full && !done.configuration);
        assert_eq!(done.reparsed, [PathBuf::from("/ws/objects/rules/r1.yaml")]);
        assert_eq!(fs.reads().len(), 1);
        assert!(done.affected.contains("r-1"), "{:?}", done.affected);
        assert!(done.affected.contains("s-1"), "the reference it dropped");
        assert_eq!(workspace.stats().config_resolutions, 1);

        // A duplicate gained or lost names its UUID, though the object that
        // wins (r2.yml, the later file) stays the same.
        fs.write("/ws/objects/rules/0.yaml", object("r-2"));
        let done = workspace
            .invalidate(&[Change::created("/ws/objects/rules/0.yaml")])
            .unwrap();
        assert_eq!(workspace.index().duplicates.len(), 1);
        assert_eq!(done.affected.iter().collect::<Vec<_>>(), ["r-2"]);
        fs.remove("/ws/objects/rules/0.yaml");
        let done = workspace
            .invalidate(&[Change::deleted("/ws/objects/rules/0.yaml")])
            .unwrap();
        assert!(workspace.index().duplicates.is_empty());
        assert_eq!(done.affected.iter().collect::<Vec<_>>(), ["r-2"]);

        // A rename is a deletion and a creation.
        fs.rename("/ws/objects/rules/r2.yml", "/ws/objects/rules/team/r2.yml");
        let done = workspace
            .invalidate(&Change::renamed(
                "/ws/objects/rules/r2.yml",
                "/ws/objects/rules/team/r2.yml",
            ))
            .unwrap();
        assert!(done.reparsed.is_empty(), "a nested file is never read");
        assert!(done.affected.contains("r-2"));
        assert_eq!(workspace.index().nested.len(), 2);

        // A configuration file resolves the configuration again.
        fs.write(
            "/ws/.opentide/configurations/paths.toml",
            "[paths.objects]\nrule = \"objects/rules/team/\"\n",
        );
        let done = workspace
            .invalidate(&[Change::created("/ws/.opentide/configurations/paths.toml")])
            .unwrap();
        assert!(done.configuration && !done.full);
        assert_eq!(workspace.stats().config_resolutions, 2);
        assert_eq!(workspace.index().rules().count(), 2);

        // A path outside the workspace loads everything again.
        let done = workspace
            .invalidate(&[Change::changed("/other/file.toml")])
            .unwrap();
        assert!(done.full);
        assert_eq!(
            workspace.invalidate(&[]).unwrap(),
            opentide_workspace::Invalidation::default()
        );

        // Deleting a folder drops what was under it.
        fs.remove("/ws/objects/threats");
        let done = workspace
            .invalidate(&[Change::deleted("/ws/objects/threats")])
            .unwrap();
        assert!(done.affected.contains("t-1"));
        assert_eq!(workspace.index().threats().count(), 0);
        assert!(format!("{workspace:?}").contains("Workspace"));
    }

    #[expect(
        clippy::unwrap_used,
        reason = "a test helper: every workspace it opens resolves"
    )]
    fn fresh(fs: &Arc<MemoryFs>, options: Options) -> serde_json::Value {
        let workspace = Workspace::open(Arc::clone(fs) as Arc<dyn FileSystem>, options).unwrap();
        workspace.index().to_json(workspace.root())
    }

    #[test]
    fn removing_the_configuration_folder_resolves_the_configuration_again() {
        for removed in ["/ws/.opentide", "/ws/.opentide/configurations"] {
            let fs = Arc::new(MemoryFs::new());
            fs.write(
                "/ws/.opentide/configurations/paths.toml",
                "[paths.objects]\nrule = \"detections/\"\n",
            );
            fs.write("/ws/detections/d.yaml", object("d"));
            fs.write("/ws/objects/rules/r.yaml", object("r"));
            let mut workspace = open(&fs);
            assert!(workspace.index().get("rule", "d").is_some());
            fs.remove(removed);
            // Only the folder is reported, as a watcher reports a deleted tree.
            let done = workspace.invalidate(&[Change::deleted(removed)]).unwrap();
            assert!(done.configuration && !done.full, "{removed}: {done:?}");
            assert_eq!(
                workspace.configuration().folder("rule"),
                Some(Path::new("/ws/objects/rules"))
            );
            assert!(workspace.index().get("rule", "r").is_some());
            assert_eq!(
                workspace.index().to_json(workspace.root()),
                fresh(&fs, options())
            );
        }
        // A rename of the folder, reported as the folder alone.
        let fs = Arc::new(MemoryFs::new());
        fs.write(
            "/ws/.opentide/configurations/paths.toml",
            "[paths.objects]\nrule = \"detections/\"\n",
        );
        fs.write("/ws/detections/d.yaml", object("d"));
        fs.write("/ws/objects/rules/r.yaml", object("r"));
        let mut workspace = open(&fs);
        fs.rename("/ws/.opentide", "/ws/.retired");
        let done = workspace
            .invalidate(&Change::renamed("/ws/.opentide", "/ws/.retired"))
            .unwrap();
        assert!(done.configuration && !done.full, "{done:?}");
        assert_eq!(
            workspace.index().to_json(workspace.root()),
            fresh(&fs, options())
        );
    }

    #[test]
    fn the_workspace_root_itself_and_the_parent_configuration() {
        let fs = sample();
        let mut workspace = open(&fs);
        // A change that names the workspace itself loads everything again.
        let done = workspace.invalidate(&[Change::changed(ROOT)]).unwrap();
        assert!(done.full, "{done:?}");

        // The parent instance's configuration, outside the workspace, is
        // resolved again without a full load.
        fs.write(
            "/.opentide/configurations/paths.toml",
            "[paths.objects]\nrule = \"objects/rules/team/\"\n",
        );
        let done = workspace
            .invalidate(&[Change::created("/.opentide/configurations/paths.toml")])
            .unwrap();
        assert!(done.configuration && !done.full, "{done:?}");
        assert_eq!(
            workspace.configuration().folder("rule"),
            Some(Path::new("/ws/objects/rules/team"))
        );
        assert!(workspace.index().get("rule", "r-4").is_some());
        assert_eq!(
            workspace.index().to_json(workspace.root()),
            fresh(&fs, options())
        );
    }

    fn discovered() -> Options {
        Options {
            roots: RootOptions {
                cwd: PathBuf::from("/repo/ws/sub"),
                ..RootOptions::default()
            },
        }
    }

    #[test]
    fn a_root_marker_created_or_deleted_moves_the_workspace() {
        for marker in ["objects", ".opentide"] {
            let fs = Arc::new(MemoryFs::new());
            fs.create_dir("/repo/.git");
            fs.create_dir("/repo/ws/sub");
            fs.write("/repo/ws/objects/rules/a.yaml", object("r-a"));
            fs.write("/repo/ws/sub/objects/rules/b.yaml", object("r-b"));
            fs.remove("/repo/ws/sub/objects");
            let mut workspace =
                Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, discovered()).unwrap();
            assert_eq!(workspace.root(), Path::new("/repo/ws"));

            // Created: the nearer marker wins.
            let created = format!("/repo/ws/sub/{marker}");
            if marker == "objects" {
                fs.write("/repo/ws/sub/objects/rules/b.yaml", object("r-b"));
            } else {
                fs.create_dir(&created);
            }
            let done = workspace
                .invalidate(&[Change::created(created.as_str())])
                .unwrap();
            assert!(done.full, "{marker}: {done:?}");
            assert_eq!(workspace.root(), Path::new("/repo/ws/sub"), "{marker}");
            assert_eq!(
                workspace.index().to_json(workspace.root()),
                fresh(&fs, discovered()),
                "{marker}"
            );

            // Deleted: back to the outer workspace.
            fs.remove(&created);
            let done = workspace
                .invalidate(&[Change::deleted(created.as_str())])
                .unwrap();
            assert!(done.full, "{marker}: {done:?}");
            assert_eq!(workspace.root(), Path::new("/repo/ws"), "{marker}");
            assert!(workspace.index().get("rule", "r-a").is_some());
            assert_eq!(
                workspace.index().to_json(workspace.root()),
                fresh(&fs, discovered()),
                "{marker}"
            );
        }
    }

    #[test]
    fn a_configuration_that_stops_leaves_the_workspace_as_it_was() {
        let fs = sample();
        let mut workspace = open(&fs);
        fs.write("/ws/.opentide/configurations/paths.toml", "[broken\n");
        assert!(
            workspace
                .invalidate(&[Change::changed("/ws/.opentide/configurations/paths.toml")])
                .is_err()
        );
        assert_eq!(workspace.index().len(), 4);
    }

    #[test]
    fn the_disk() {
        let dir = std::env::temp_dir().join(format!("opentide-ws-loading-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("objects/rules/team")).unwrap();
        std::fs::create_dir_all(dir.join("elsewhere")).unwrap();
        std::fs::write(dir.join("objects/rules/r.yaml"), object("r")).unwrap();
        std::fs::write(dir.join("objects/rules/team/n.yaml"), object("n")).unwrap();
        std::fs::write(dir.join("elsewhere/linked.yaml"), object("l")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join("objects/rules/link")).unwrap();
        let workspace = Workspace::open_os(Some(dir.clone())).unwrap();
        assert_eq!(workspace.index().rules().count(), 1);
        // A linked folder is not entered, as rglob does not enter it.
        assert_eq!(workspace.index().nested.len(), 1);
        let json = workspace.index().to_json(workspace.root());
        assert_eq!(json["file_paths"]["r"], "objects/rules/r.yaml");
        assert_eq!(json["nested"][0]["folder"], "objects/rules");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A fresh folder under the system's temporary directory.
    #[cfg(unix)]
    #[expect(
        clippy::unwrap_used,
        reason = "a test helper: the scratch folder is writable"
    )]
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("opentide-ws-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("objects/rules")).unwrap();
        dir
    }

    #[cfg(unix)]
    #[expect(
        clippy::unwrap_used,
        reason = "a test helper: the scratch folder is writable"
    )]
    fn on_disk(dir: &Path) -> serde_json::Value {
        let workspace = Workspace::open_os(Some(dir.to_path_buf())).unwrap();
        workspace.index().to_json(workspace.root())
    }

    #[cfg(unix)]
    fn rule_name(workspace: &Workspace) -> Option<String> {
        let rule = workspace.index().get("rule", "r-1")?;
        let root = rule.root()?;
        let name = root.get("metadata")?.get("name")?.value.as_str()?;
        Some(name.to_owned())
    }

    /// An object file that is a symbolic link to a file in the workspace is
    /// read again when a change is reported through the link or its target.
    #[cfg(unix)]
    #[test]
    fn a_linked_object_is_read_again_through_the_link_or_its_target() {
        let dir = scratch("link");
        std::fs::create_dir_all(dir.join("shared")).unwrap();
        let target = dir.join("shared/x.yaml");
        let body = |name: &str| format!("metadata:\n  uuid: r-1\n  name: {name}\n");
        std::fs::write(&target, body("old")).unwrap();
        std::os::unix::fs::symlink(&target, dir.join("objects/rules/link.yaml")).unwrap();
        let mut workspace = Workspace::open_os(Some(dir.clone())).unwrap();
        assert_eq!(rule_name(&workspace).as_deref(), Some("old"));

        for (round, reported) in [
            dir.join("objects/rules/link.yaml"),
            target.clone(),
            PathBuf::from("objects/rules/../rules/link.yaml"),
        ]
        .into_iter()
        .enumerate()
        {
            let name = format!("new-{round}");
            std::fs::write(&target, body(&name)).unwrap();
            let reported = if reported.is_absolute() {
                reported
            } else {
                dir.join(reported)
            };
            let done = workspace.invalidate(&[Change::changed(&reported)]).unwrap();
            assert!(!done.full, "{}: {done:?}", reported.display());
            assert_eq!(
                done.reparsed,
                [dir.canonicalize().unwrap().join("objects/rules/link.yaml")],
                "{}",
                reported.display()
            );
            assert_eq!(rule_name(&workspace).as_deref(), Some(name.as_str()));
            assert_eq!(workspace.index().to_json(workspace.root()), on_disk(&dir));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A file name that is not UTF-8, valid on Linux, still names its file.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_object_file_name_that_is_not_utf8_is_loaded() {
        use std::os::unix::ffi::OsStrExt;
        let dir = scratch("bytes");
        let name = std::ffi::OsStr::from_bytes(b"r\xff.yaml");
        std::fs::write(dir.join("objects/rules").join(name), object("r-1")).unwrap();
        let workspace = Workspace::open_os(Some(dir.clone())).unwrap();
        assert!(
            workspace.index().load_errors.is_empty(),
            "{:?}",
            workspace.index().load_errors
        );
        let rule = workspace.index().get("rule", "r-1").unwrap();
        assert_eq!(rule.path.file_name(), Some(name));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A filesystem in memory where one path cannot be read or listed.
    struct Faulty {
        inner: MemoryFs,
        broken: PathBuf,
    }

    impl FileSystem for Faulty {
        fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            if path == self.broken {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Permission denied (os error 13)",
                ));
            }
            self.inner.read(path)
        }

        fn kind(&self, path: &Path) -> std::io::Result<opentide_workspace::fs::EntryKind> {
            self.inner.kind(path)
        }

        fn read_dir(&self, path: &Path) -> std::io::Result<Vec<opentide_workspace::fs::DirEntry>> {
            if path == self.broken {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Permission denied (os error 13)",
                ));
            }
            self.inner.read_dir(path)
        }

        fn resolve(&self, path: &Path) -> PathBuf {
            self.inner.resolve(path)
        }
    }

    fn faulty(broken: &str) -> Arc<Faulty> {
        let inner = MemoryFs::new();
        inner.write("/ws/objects/rules/a.yaml", object("a"));
        inner.write("/ws/objects/rules/b.yaml", object("b"));
        inner.write("/ws/objects/threats/t.yaml", object("t"));
        Arc::new(Faulty {
            inner,
            broken: PathBuf::from(broken),
        })
    }

    #[test]
    fn an_unreadable_file_is_a_load_error_and_an_unreadable_folder_is_skipped() {
        let fs = faulty("/ws/objects/rules/a.yaml");
        let workspace = Workspace::open(fs as Arc<dyn FileSystem>, options()).unwrap();
        let errors = &workspace.index().load_errors;
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, YAML_PARSE);
        assert_eq!(
            errors[0].failure,
            Some(opentide_workspace::load::FailureKind::Unreadable)
        );
        assert_eq!(
            errors[0].message(),
            "Could not parse object YAML: Permission denied (os error 13)"
        );
        assert_eq!(workspace.index().rules().count(), 1);

        let fs = faulty("/ws/objects/rules");
        let workspace = Workspace::open(fs as Arc<dyn FileSystem>, options()).unwrap();
        let skipped = &workspace.index().skipped_folders;
        assert_eq!(skipped.len(), 2, "{skipped:?}");
        assert!(skipped.iter().any(|folder| folder.family == "rule"
            && matches!(
                folder.problem,
                opentide_workspace::discover::FolderProblem::Unreadable(_)
            )));
        assert_eq!(workspace.index().threats().count(), 1);
    }

    #[test]
    fn a_configuration_file_that_cannot_be_read_stops_the_load() {
        let fs = faulty("/ws/.opentide/configurations/deployment.toml");
        fs.inner
            .write("/ws/.opentide/configurations/deployment.toml", "x = 1\n");
        let error = Workspace::open(fs as Arc<dyn FileSystem>, options()).unwrap_err();
        assert!(matches!(error, ConfigError::Unreadable { .. }), "{error:?}");
        assert_eq!(error.code(), Some("config_parse"));
        assert!(error.to_string().contains("deployment.toml"));

        let fs = Arc::new(MemoryFs::new());
        fs.write(
            "/ws/.opentide/configurations/deployment.toml",
            b"x = \"caf\xe9\"\n".to_vec(),
        );
        let error = Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, options()).unwrap_err();
        assert!(error.to_string().contains("not UTF-8"), "{error}");
    }

    #[test]
    fn hidden_configuration_folders_and_other_files_are_never_read() {
        let fs = Arc::new(MemoryFs::new());
        fs.write("/ws/.opentide/configurations/.cache/x.toml", "broken [\n");
        fs.write(
            "/ws/.opentide/configurations/__pycache__/y.toml",
            "broken [\n",
        );
        fs.write("/ws/.opentide/configurations/notes.md", "# notes\n");
        fs.write("/ws/.opentide/configurations/platforms/notes.txt", "x\n");
        fs.write(
            "/ws/.opentide/configurations/platforms/splunk.toml",
            "[platform]\nenabled = true\n",
        );
        fs.create_dir("/ws/objects");
        let workspace = open(&fs);
        assert_eq!(workspace.stats().config_files_read, 1);
        assert_eq!(workspace.roots().workspace, PathBuf::from(ROOT));
        assert_eq!(workspace.root(), Path::new(ROOT));
        assert!(workspace.fs().is_dir(Path::new("/ws/objects")));
        assert_eq!(
            workspace.configuration().folders[0],
            PathBuf::from("/ws/.opentide/configurations")
        );
    }
}
