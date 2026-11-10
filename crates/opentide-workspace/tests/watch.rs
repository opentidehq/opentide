//! `validate --watch`'s pass selection (UC-2.3, #818), case by case from
//! `docs/internal/cli-experience.md` ("`validate --watch`"): a pass is full
//! when a file was added or removed, a UUID in it changed, or its object
//! entered or left the registry (a finding in `UNREGISTERED_CODES` before or
//! after, or a scoped object count that does not match); a narrowed command
//! is validated whole every pass; otherwise only the changed files are.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers: the workspaces they open resolve"
)]

mod watch {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use opentide_workspace::validate::Selection;
    use opentide_workspace::watch::{
        Changes, FileChange, Pass, Validate, WatchRun, Watcher, WorkspaceValidate, references,
        scoped_pass_holds, select_pass, take_snapshot,
    };
    use opentide_workspace::{Diagnostic, FileSystem, MemoryFs, RootOptions, Workspace};

    const U1: &str = "11111111-1111-4111-8111-111111111111";
    const U2: &str = "22222222-2222-4222-8222-222222222222";
    const U3: &str = "33333333-3333-4333-8333-333333333333";

    fn refs(uuids: &[&str]) -> Option<BTreeSet<String>> {
        Some(uuids.iter().map(|u| (*u).to_owned()).collect())
    }

    fn modified(before: &[&str], after: &[&str]) -> FileChange {
        FileChange {
            references_before: refs(before),
            references_after: refs(after),
            was_unregistered: false,
        }
    }

    #[test]
    fn a_file_saved_with_the_same_uuids_is_validated_alone() {
        assert_eq!(
            select_pass(&[modified(&[U1, U2], &[U1, U2])], true),
            Pass::Scoped
        );
    }

    #[test]
    fn a_file_added_or_removed_validates_everything() {
        let added = FileChange {
            references_before: None,
            references_after: refs(&[U1]),
            was_unregistered: false,
        };
        let removed = FileChange {
            references_before: refs(&[U1]),
            references_after: None,
            was_unregistered: false,
        };
        assert_eq!(select_pass(&[added], true), Pass::Full);
        assert_eq!(select_pass(&[removed], true), Pass::Full);
    }

    #[test]
    fn a_uuid_written_in_the_file_changing_validates_everything() {
        // Its own UUID, or one it points at.
        assert_eq!(
            select_pass(&[modified(&[U1, U2], &[U1, U3])], true),
            Pass::Full
        );
        assert_eq!(select_pass(&[modified(&[U1], &[U1, U2])], true), Pass::Full);
        // One changed file among unchanged ones is enough.
        assert_eq!(
            select_pass(&[modified(&[U1], &[U1]), modified(&[U2], &[])], true),
            Pass::Full
        );
    }

    #[test]
    fn a_file_whose_object_was_out_of_the_registry_validates_everything() {
        let mut fixed = modified(&[U1], &[U1]);
        fixed.was_unregistered = true;
        assert_eq!(select_pass(&[fixed], true), Pass::Full);
    }

    #[test]
    fn a_narrowed_command_validates_its_scope_every_pass() {
        assert_eq!(select_pass(&[modified(&[U1], &[U1])], false), Pass::Full);
    }

    fn finding(code: &str, file: &str) -> Diagnostic {
        Diagnostic::error(code, "m").file(file)
    }

    #[test]
    fn a_scoped_pass_turns_full_on_what_it_finds() {
        let changed = [PathBuf::from("/w/a.yaml")];
        assert!(scoped_pass_holds(
            &[finding("vocab_unknown", "/w/a.yaml")],
            1,
            &changed
        ));
        // A finding outside the changed files.
        assert!(!scoped_pass_holds(
            &[finding("invalid_ref", "/w/b.yaml")],
            1,
            &changed
        ));
        // A finding about no file.
        assert!(!scoped_pass_holds(
            &[Diagnostic::error("config_parse", "m")],
            1,
            &changed
        ));
        // Its object left the registry.
        for code in ["yaml_parse", "missing_uuid"] {
            assert!(!scoped_pass_holds(
                &[finding(code, "/w/a.yaml")],
                1,
                &changed
            ));
        }
        // It checked another number of objects than files it was given.
        assert!(!scoped_pass_holds(&[], 0, &changed));
        assert!(!scoped_pass_holds(&[], 2, &changed));
        assert!(scoped_pass_holds(&[], 1, &changed));
    }

    /// A validator that answers from a script and records what it was asked.
    #[derive(Default)]
    struct Scripted {
        calls: Arc<Mutex<Vec<Option<Vec<PathBuf>>>>>,
        reloads: Arc<Mutex<Vec<Changes>>>,
        full: Vec<Diagnostic>,
        objects: usize,
        scoped: Vec<Diagnostic>,
        scoped_objects: Option<usize>,
    }

    impl Validate for Scripted {
        fn reload(&mut self, changes: &Changes) {
            self.reloads.lock().unwrap().push(changes.clone());
        }

        fn validate(&mut self, files: Option<&[PathBuf]>) -> (Vec<Diagnostic>, usize) {
            self.calls
                .lock()
                .unwrap()
                .push(files.map(<[PathBuf]>::to_vec));
            match files {
                None => (self.full.clone(), self.objects),
                Some(files) => (
                    self.scoped.clone(),
                    self.scoped_objects.unwrap_or(files.len()),
                ),
            }
        }
    }

    fn folder() -> MemoryFs {
        let fs = MemoryFs::new();
        fs.write("/w/rules/a.yaml", format!("uuid: {U1}\n"));
        fs.write("/w/rules/b.yaml", format!("uuid: {U2}\nthreat: {U1}\n"));
        fs
    }

    fn watcher(fs: &MemoryFs, validate: Scripted, scoped_runs: bool) -> Watcher<'_, Scripted> {
        Watcher::new(
            fs,
            vec![PathBuf::from("/w/rules")],
            validate,
            false,
            scoped_runs,
            &["platform_not_enabled"],
        )
    }

    #[test]
    fn the_watcher_validates_once_then_only_what_changed() {
        let fs = folder();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut watcher = watcher(
            &fs,
            Scripted {
                calls: Arc::clone(&calls),
                full: vec![finding("vocab_unknown", "/w/rules/b.yaml")],
                objects: 2,
                ..Scripted::default()
            },
            true,
        );
        let first = watcher.start();
        assert_eq!((first.number, first.errors, first.objects), (1, 1, 2));
        assert!(!first.scoped && first.failed);
        assert!(watcher.poll().is_none());
        // `a.yaml` saved with the same UUID: validated alone; `b.yaml`'s
        // finding is kept, so the pass reports the whole workspace.
        fs.write("/w/rules/a.yaml", format!("uuid: {U1}\nname: x\n"));
        let second = watcher.poll().unwrap();
        assert!(second.scoped);
        assert_eq!(second.changed, [PathBuf::from("/w/rules/a.yaml")]);
        assert_eq!(second.errors, 1);
        assert_eq!(second.diagnostics.len(), 1);
        assert!(second.found.is_empty());
        assert_eq!(
            *calls.lock().unwrap(),
            [None, Some(vec![PathBuf::from("/w/rules/a.yaml")])]
        );
        // A UUID changed: everything.
        fs.write("/w/rules/a.yaml", format!("uuid: {U3}\n"));
        assert!(!watcher.poll().unwrap().scoped);
        // A file added, then removed: everything.
        fs.write("/w/rules/c.yaml", "x: 1\n");
        assert!(!watcher.poll().unwrap().scoped);
        fs.remove("/w/rules/c.yaml");
        let removed: WatchRun = watcher.poll().unwrap();
        assert!(!removed.scoped);
        assert_eq!(removed.changed, [PathBuf::from("/w/rules/c.yaml")]);
        assert_eq!(removed.number, 5);
    }

    #[test]
    fn a_file_that_did_not_parse_is_validated_with_everything_once_fixed() {
        let fs = folder();
        let mut watcher = watcher(
            &fs,
            Scripted {
                full: vec![finding("yaml_parse", "/w/rules/a.yaml")],
                objects: 1,
                ..Scripted::default()
            },
            true,
        );
        watcher.start();
        fs.write("/w/rules/a.yaml", format!("uuid: {U1}\n# fixed\n"));
        assert!(!watcher.poll().unwrap().scoped);
    }

    #[test]
    fn a_scoped_pass_that_finds_more_is_run_again_whole() {
        let fs = folder();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut watcher = watcher(
            &fs,
            Scripted {
                calls: Arc::clone(&calls),
                objects: 2,
                // The object left the registry: it no longer counts.
                scoped_objects: Some(0),
                ..Scripted::default()
            },
            true,
        );
        watcher.start();
        fs.write("/w/rules/a.yaml", format!("uuid: {U1}\n  bad"));
        let run = watcher.poll().unwrap();
        assert!(!run.scoped);
        assert_eq!(calls.lock().unwrap().len(), 3);
        assert_eq!(calls.lock().unwrap()[2], None);
    }

    #[test]
    fn a_narrowed_command_is_validated_whole_every_pass() {
        let fs = folder();
        let mut watcher = watcher(&fs, Scripted::default(), false);
        watcher.start();
        fs.write("/w/rules/a.yaml", format!("uuid: {U1}\nname: y\n"));
        assert!(!watcher.poll().unwrap().scoped);
    }

    #[test]
    fn strict_fails_on_warnings_it_is_not_exempt_from() {
        let fs = folder();
        let warning = |code: &str| Diagnostic::warning(code, "m").file("/w/rules/a.yaml");
        let mut exempt = Watcher::new(
            &fs,
            vec![PathBuf::from("/w/rules")],
            Scripted {
                full: vec![warning("platform_not_enabled")],
                objects: 2,
                ..Scripted::default()
            },
            true,
            true,
            &["platform_not_enabled"],
        );
        assert!(!exempt.start().failed);
        let mut strict = Watcher::new(
            &fs,
            vec![PathBuf::from("/w/rules")],
            Scripted {
                full: vec![warning("deprecated_field")],
                objects: 2,
                ..Scripted::default()
            },
            true,
            true,
            &["platform_not_enabled"],
        );
        let run = strict.start();
        assert!(run.failed);
        assert_eq!((run.warnings, run.files), (1, 0));
    }

    #[test]
    fn snapshots_and_references_read_the_catalogue() {
        let fs = folder();
        fs.write("/w/rules/x.debug.yaml", "");
        fs.write("/w/rules/team/n.yaml", "");
        let snapshot = take_snapshot(&fs, &[PathBuf::from("/w/rules")]);
        assert_eq!(
            snapshot.keys().cloned().collect::<Vec<_>>(),
            [
                PathBuf::from("/w/rules/a.yaml"),
                PathBuf::from("/w/rules/b.yaml")
            ]
        );
        // Written in capitals, read in lower case.
        fs.write(
            "/w/rules/a.yaml",
            "uuid: AAAAAAAA-1111-4111-8111-111111111111\n",
        );
        assert_eq!(
            references(&fs, Path::new("/w/rules/a.yaml")),
            refs(&["aaaaaaaa-1111-4111-8111-111111111111"]).unwrap()
        );
        let after = take_snapshot(&fs, &[PathBuf::from("/w/rules")]);
        let changes = Changes::between(&snapshot, &after);
        assert_eq!(changes.modified.len(), 1);
        assert!(changes.added.is_empty() && changes.removed.is_empty());
        assert_eq!(changes.to_invalidation().len(), 1);
    }

    fn workspace() -> Arc<MemoryFs> {
        let fs = Arc::new(MemoryFs::new());
        fs.create_dir("/ws/.opentide/configurations");
        fs.create_dir("/ws/objects/threats");
        fs.create_dir("/ws/objects/objectives");
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!("name: A\nmetadata:\n  uuid: {U1}\n  schema: rule::1.1\n"),
        );
        fs
    }

    #[test]
    fn the_workspace_validator_reloads_what_changed() {
        let fs = workspace();
        let workspace = Workspace::open(
            Arc::clone(&fs) as Arc<dyn FileSystem>,
            opentide_workspace::Options {
                roots: RootOptions {
                    repo: Some(PathBuf::from("/ws")),
                    cwd: PathBuf::from("/ws"),
                    ..RootOptions::default()
                },
            },
        )
        .unwrap();
        let validate = WorkspaceValidate::new(workspace, Selection::default());
        let roots = validate.roots();
        assert!(roots.contains(&PathBuf::from("/ws/objects/rules")));
        let mut watcher = Watcher::new(fs.as_ref(), roots, validate, false, true, &[]);
        let first = watcher.start();
        let codes = |run: &WatchRun| {
            run.diagnostics
                .iter()
                .map(|d| d.code.clone())
                .collect::<BTreeSet<_>>()
        };
        let before = codes(&first);
        // A typo in a vocabulary value: the scoped pass reads the new text.
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!("name: A\nmetadata:\n  uuid: {U1}\n  schema: rule::1.1\n  tlp: purple\n"),
        );
        let second = watcher.poll().unwrap();
        assert!(second.scoped, "{second:?}");
        assert_eq!(second.objects, first.objects);
        assert!(
            second
                .diagnostics
                .iter()
                .any(|d| d.field_path == ["metadata", "tlp"]),
            "{:?}",
            codes(&second)
        );
        // Saved back: the finding goes, the others stay.
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!("name: A\nmetadata:\n  uuid: {U1}\n  schema: rule::1.1\n"),
        );
        let third = watcher.poll().unwrap();
        assert_eq!(codes(&third), before);
        assert!(watcher.validator().reload_error.is_none());
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn notify_wakes_the_loop_when_a_file_is_saved() {
        use opentide_workspace::OsFs;
        use opentide_workspace::watch::events::Events;
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir(&rules).unwrap();
        let events = Events::watch(&OsFs, std::slice::from_ref(&rules)).unwrap();
        // Nothing happened: the wait times out.
        assert!(!events.wait(Duration::from_millis(50)));
        std::fs::write(rules.join("a.yaml"), format!("uuid: {U1}\n")).unwrap();
        assert!(events.wait(Duration::from_secs(10)));
        // A folder that does not exist is left out, not an error.
        assert!(Events::watch(&OsFs, &[dir.path().join("none")]).is_ok());
    }
}
