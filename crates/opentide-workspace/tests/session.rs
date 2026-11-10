//! Workspaces kept warm between runs (`serve`, UC-2.7): a kept workspace is
//! reused while nothing changed, re-reads only what changed (announced or
//! not), and always equals a fresh load.

mod session {
    use std::path::PathBuf;
    use std::sync::Arc;

    use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Session, Workspace};

    fn options(root: &str) -> Options {
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from(root)),
                cwd: PathBuf::from(root),
                ..RootOptions::default()
            },
        }
    }

    fn object(uuid: &str, name: &str) -> String {
        format!("metadata:\n  uuid: {uuid}\n  name: {name}\n")
    }

    fn sample() -> Arc<MemoryFs> {
        let fs = Arc::new(MemoryFs::new());
        fs.create_dir("/ws/.opentide/configurations");
        fs.write("/ws/objects/threats/t1.yaml", object("t-1", "a"));
        fs.write("/ws/objects/rules/r1.yaml", object("r-1", "a"));
        fs.write("/ws/objects/rules/r2.yaml", object("r-2", "a"));
        fs
    }

    fn dyn_fs(fs: &Arc<MemoryFs>) -> Arc<dyn FileSystem> {
        Arc::clone(fs) as Arc<dyn FileSystem>
    }

    #[expect(clippy::unwrap_used, reason = "a test helper: the sample resolves")]
    fn fresh(fs: &Arc<MemoryFs>) -> serde_json::Value {
        let workspace = Workspace::open(dyn_fs(fs), options("/ws")).unwrap();
        workspace.index().to_json(workspace.root())
    }

    #[expect(clippy::unwrap_used, reason = "a test helper: the sample resolves")]
    fn open(session: &mut Session, fs: &Arc<MemoryFs>) -> serde_json::Value {
        let workspace = session.open(dyn_fs(fs), options("/ws")).unwrap();
        workspace.index().to_json(workspace.root())
    }

    #[test]
    fn a_repeat_open_reads_nothing() {
        let fs = sample();
        let mut session = Session::new();
        let first = open(&mut session, &fs);
        assert_eq!(fs.reads().len(), 3);
        fs.reset_reads();
        let second = open(&mut session, &fs);
        assert!(fs.reads().is_empty(), "{:?}", fs.reads());
        assert_eq!(first, second);
        let stats = session.stats();
        assert_eq!((stats.opens, stats.hits, stats.refreshes), (2, 1, 0));
        assert_eq!((stats.kept, stats.file_reads), (1, 3));
    }

    #[test]
    fn an_edit_is_read_without_being_announced_and_only_that_file() {
        let fs = sample();
        let mut session = Session::new();
        open(&mut session, &fs);
        fs.reset_reads();
        fs.write("/ws/objects/rules/r1.yaml", object("r-1", "edited"));
        let after = open(&mut session, &fs);
        let reads: Vec<PathBuf> = fs.reads().into_keys().collect();
        assert_eq!(reads, [PathBuf::from("/ws/objects/rules/r1.yaml")]);
        assert_eq!(after, fresh(&fs));
        assert_eq!(session.stats().refreshes, 1);
    }

    #[test]
    fn created_and_deleted_files_are_seen() {
        let fs = sample();
        let mut session = Session::new();
        open(&mut session, &fs);
        fs.write("/ws/objects/rules/r3.yaml", object("r-3", "new"));
        let created = open(&mut session, &fs);
        assert_eq!(created, fresh(&fs));
        assert!(created.to_string().contains("r-3"));
        fs.remove("/ws/objects/rules/r2.yaml");
        let deleted = open(&mut session, &fs);
        assert_eq!(deleted, fresh(&fs));
        assert!(!deleted.to_string().contains("r-2"));
    }

    #[test]
    fn a_configuration_change_resolves_it_again() {
        let fs = sample();
        let mut session = Session::new();
        open(&mut session, &fs);
        fs.write(
            "/ws/.opentide/configurations/paths.toml",
            "[paths.objects]\nrule = \"elsewhere/\"\n",
        );
        fs.write("/ws/elsewhere/r9.yaml", object("r-9", "moved"));
        assert_eq!(open(&mut session, &fs), fresh(&fs));
    }

    #[test]
    fn an_announced_path_outside_the_folders_is_taken_at_the_next_open() {
        let fs = sample();
        let mut session = Session::new();
        open(&mut session, &fs);
        assert_eq!(session.invalidate(&[PathBuf::from("/elsewhere/x.toml")]), 1);
        assert_eq!(session.invalidate(&[]), 0);
        fs.reset_reads();
        let after = open(&mut session, &fs);
        // A path outside the workspace loads it again, as the Python serve does.
        assert_eq!(fs.reads().len(), 3, "{:?}", fs.reads());
        assert_eq!(after, fresh(&fs));
        fs.reset_reads();
        open(&mut session, &fs);
        assert!(fs.reads().is_empty(), "the announcement is used once");
    }

    #[test]
    fn options_key_the_workspaces_and_clear_forgets_them() {
        let fs = sample();
        fs.write("/other/objects/rules/x.yaml", object("r-x", "x"));
        let mut session = Session::new();
        open(&mut session, &fs);
        let other = session.open(dyn_fs(&fs), options("/other"));
        assert!(other.is_ok_and(|ws| ws.index().get("rule", "r-x").is_some()));
        assert_eq!(session.stats().kept, 2);
        assert_eq!(session.stats().hits, 0);
        session.clear();
        assert_eq!(session.stats().kept, 0);
        fs.reset_reads();
        open(&mut session, &fs);
        assert_eq!(fs.reads().len(), 3);
    }

    #[test]
    fn a_root_that_moved_is_opened_again() {
        let fs = Arc::new(MemoryFs::new());
        fs.create_dir("/repo/.git");
        fs.create_dir("/repo/ws/sub");
        fs.write("/repo/ws/objects/rules/a.yaml", object("r-a", "a"));
        let discovered = Options {
            roots: RootOptions {
                cwd: PathBuf::from("/repo/ws/sub"),
                ..RootOptions::default()
            },
        };
        let mut session = Session::new();
        let first = session.open(dyn_fs(&fs), discovered.clone());
        assert!(first.is_ok_and(|ws| ws.root() == std::path::Path::new("/repo/ws")));
        fs.write("/repo/ws/sub/objects/rules/b.yaml", object("r-b", "b"));
        let moved = session.open(dyn_fs(&fs), discovered);
        assert!(moved.is_ok_and(|ws| {
            ws.root() == std::path::Path::new("/repo/ws/sub")
                && ws.index().get("rule", "r-b").is_some()
        }));
    }

    #[test]
    fn a_configuration_that_stops_resolving_is_an_error_and_not_kept() {
        let fs = sample();
        let mut session = Session::new();
        open(&mut session, &fs);
        fs.write("/ws/.opentide/configurations/paths.toml", "[paths\n");
        assert!(session.open(dyn_fs(&fs), options("/ws")).is_err());
        assert_eq!(session.stats().kept, 0);
    }

    #[test]
    fn a_clone_changed_by_its_run_leaves_the_kept_one_alone() {
        let fs = sample();
        let mut session = Session::new();
        let Ok(mut mine) = session.open(dyn_fs(&fs), options("/ws")) else {
            panic!("the sample resolves");
        };
        fs.write("/ws/objects/rules/r1.yaml", object("r-1", "mine"));
        assert!(
            mine.invalidate(&[opentide_workspace::Change::changed(
                "/ws/objects/rules/r1.yaml"
            )])
            .is_ok()
        );
        fs.write("/ws/objects/rules/r1.yaml", object("r-1", "a"));
        fs.reset_reads();
        // The kept one never saw "mine": its stamp matches the file again.
        let kept = open(&mut session, &fs);
        assert!(fs.reads().is_empty());
        assert_eq!(kept, fresh(&fs));
    }

    /// The process-wide session: only while activated, and only on the disk.
    #[test]
    fn the_process_session_serves_the_disk_while_active() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let root = dir.path();
        std::fs::create_dir_all(root.join(".opentide/configurations"))
            .and_then(|()| std::fs::create_dir_all(root.join("objects/rules")))
            .and_then(|()| std::fs::write(root.join("objects/rules/r.yaml"), object("r-1", "a")))
            .unwrap_or_else(|error| panic!("{error}"));
        let disk = || {
            Workspace::open(
                Arc::new(opentide_workspace::OsFs),
                options(&root.to_string_lossy()),
            )
            .unwrap_or_else(|error| panic!("{error}"))
        };
        opentide_workspace::session::clear();
        let before = opentide_workspace::session::stats();
        disk();
        assert_eq!(
            opentide_workspace::session::stats(),
            before,
            "inactive: nothing kept"
        );
        {
            let _active = opentide_workspace::session::activate();
            disk();
            let warm = disk();
            assert_eq!(warm.stats().file_reads, 1, "the second open read nothing");
            let stats = opentide_workspace::session::stats();
            assert_eq!(stats.hits, before.hits + 1);
            // An in-memory tree is never the process's.
            let memory = sample();
            assert!(Workspace::open(dyn_fs(&memory), options("/ws")).is_ok());
            assert_eq!(opentide_workspace::session::stats().kept, 1);
            assert_eq!(
                opentide_workspace::session::invalidate(&[root.join("objects/rules/r.yaml")]),
                1
            );
        }
        opentide_workspace::session::clear();
        assert_eq!(opentide_workspace::session::stats().kept, 0);
    }
}
