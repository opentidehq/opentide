//! The incremental index equals a full rebuild after any sequence of edits,
//! creations, deletions and renames (issue #816), configuration changes
//! included.

#[path = "support/export.rs"]
mod export;

mod index {
    use crate::export::index_json;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use opentide_workspace::{
        Change, FileSystem, Invalidation, MemoryFs, Options, RootOptions, Workspace,
    };
    use proptest::prelude::*;

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

    /// The places a file can be: object folders, a nested folder, a folder
    /// `paths.toml` can switch the rules to, and elsewhere in the workspace.
    const FOLDERS: [&str; 6] = [
        "objects/rules",
        "objects/threats",
        "objects/objectives",
        "objects/rules/team",
        "detections",
        "notes",
    ];
    const NAMES: [&str; 5] = ["a.yaml", "b.yml", "c.yaml", "d.debug.yaml", "e.yaml"];
    const UUIDS: [&str; 4] = ["u-1", "u-2", "u-3", "u-4"];

    /// A file's content: objects that share UUIDs, objectives with signals,
    /// chaining, references, and files that do not load.
    fn content(kind: usize, uuid: usize, other: usize) -> Vec<u8> {
        let uuid = UUIDS[uuid % UUIDS.len()];
        let other = UUIDS[other % UUIDS.len()];
        match kind % 8 {
            0 => format!("metadata:\n  uuid: {uuid}\n  name: plain\n").into_bytes(),
            1 => format!(
                "metadata:\n  uuid: {uuid}\nobjective:\n  threats: [{other}]\n  signals:\n    - uuid: s-{other}\n    - uuid: s-{uuid}\n"
            )
            .into_bytes(),
            2 => format!(
                "metadata:\n  uuid: {uuid}\nthreat:\n  chaining:\n    - {{relation: precedes, vector: {other}}}\n"
            )
            .into_bytes(),
            3 => format!("metadata:\n  uuid: {uuid}\ndetection_model: s-{other}\n").into_bytes(),
            4 => b"metadata: [unclosed\n".to_vec(),
            5 => b"metadata:\n  name: no uuid\n".to_vec(),
            6 => b"\xff\xfe not text".to_vec(),
            _ => Vec::new(),
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        /// Write a file (an edit, or a creation).
        Write {
            folder: usize,
            name: usize,
            kind: usize,
            uuid: usize,
            other: usize,
        },
        /// Delete a file, or a whole folder.
        Delete { folder: usize, name: Option<usize> },
        /// Rename a file to another place, or a folder to another folder.
        Rename {
            from: usize,
            name: Option<usize>,
            to: usize,
            to_name: usize,
        },
        /// Point the rules at `detections/`, or back at `objects/rules/`, or
        /// break `paths.toml`.
        Paths(usize),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => (0..FOLDERS.len(), 0..NAMES.len(), 0usize..8, 0usize..4, 0usize..4).prop_map(
                |(folder, name, kind, uuid, other)| Op::Write { folder, name, kind, uuid, other }
            ),
            2 => (0..FOLDERS.len(), proptest::option::weighted(0.8, 0..NAMES.len()))
                .prop_map(|(folder, name)| Op::Delete { folder, name }),
            2 => (
                0..FOLDERS.len(),
                proptest::option::weighted(0.8, 0..NAMES.len()),
                0..FOLDERS.len(),
                0..NAMES.len()
            )
                .prop_map(|(from, name, to, to_name)| Op::Rename { from, name, to, to_name }),
            1 => (0usize..3).prop_map(Op::Paths),
        ]
    }

    fn path(folder: usize, name: Option<usize>) -> PathBuf {
        let dir = Path::new(ROOT).join(FOLDERS[folder]);
        match name {
            Some(name) => dir.join(NAMES[name]),
            None => dir,
        }
    }

    /// Applies `op` to the filesystem; the changes a watcher reports.
    fn apply(fs: &MemoryFs, op: &Op) -> Vec<Change> {
        match op {
            Op::Write {
                folder,
                name,
                kind,
                uuid,
                other,
            } => {
                let target = path(*folder, Some(*name));
                let created = !fs.is_file(&target);
                fs.write(&target, content(*kind, *uuid, *other));
                vec![if created {
                    Change::created(target)
                } else {
                    Change::changed(target)
                }]
            }
            Op::Delete { folder, name } => {
                let target = path(*folder, *name);
                if fs.remove(&target) {
                    vec![Change::deleted(target)]
                } else {
                    Vec::new()
                }
            }
            Op::Rename {
                from,
                name,
                to,
                to_name,
            } => {
                let source = path(*from, *name);
                let target = match name {
                    Some(_) => path(*to, Some(*to_name)),
                    None => path(*to, None),
                };
                if fs.rename(&source, &target) {
                    Change::renamed(source, target).to_vec()
                } else {
                    Vec::new()
                }
            }
            Op::Paths(choice) => {
                let file = Path::new(ROOT).join(".opentide/configurations/paths.toml");
                let text = match choice {
                    0 => "[paths.objects]\nrule = \"detections/\"\n",
                    1 => "[paths.objects]\nrule = \"objects/rules/\"\n",
                    _ => "[paths.objects]\nrule = \"objects/rules/team/\"\n",
                };
                let created = !fs.is_file(&file);
                fs.write(&file, text);
                vec![if created {
                    Change::created(file)
                } else {
                    Change::changed(file)
                }]
            }
        }
    }

    #[expect(
        clippy::unwrap_used,
        reason = "a test helper: every workspace it opens resolves"
    )]
    fn full(fs: &Arc<MemoryFs>) -> serde_json::Value {
        let workspace = Workspace::open(Arc::clone(fs) as Arc<dyn FileSystem>, options()).unwrap();
        index_json(workspace.index(), workspace.root())
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        #[test]
        fn incremental_equals_a_full_rebuild(
            seed in proptest::collection::vec(op(), 0..12),
            ops in proptest::collection::vec(op(), 1..24),
        ) {
            let fs = Arc::new(MemoryFs::new());
            fs.create_dir(Path::new(ROOT).join(".opentide/configurations"));
            for op in &seed {
                apply(&fs, op);
            }
            let mut workspace =
                Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, options()).unwrap();
            for op in &ops {
                let changes = apply(&fs, op);
                fs.reset_reads();
                let done = workspace.invalidate(&changes).unwrap();
                // Only the files the changes name are read again.
                if !done.full && !done.configuration {
                    for read in fs.reads().keys() {
                        prop_assert!(
                            changes.iter().any(|c| read.starts_with(&c.path)),
                            "{} read, not among {:?}", read.display(), changes
                        );
                    }
                }
                prop_assert_eq!(
                    index_json(workspace.index(), workspace.root()),
                    full(&fs),
                    "after {:?}", op
                );
            }
        }
    }

    /// An object file of the in-place tests: its UUID is its own (`u-<file>`)
    /// unless `uuid` names another file's, so most edits keep the object it
    /// is and some give it another's UUID.
    fn edited(file: usize, kind: usize, uuid: Option<usize>, other: usize) -> Vec<u8> {
        let uuid = format!("u-{}", uuid.unwrap_or(file));
        let other = format!("u-{other}");
        match kind % 9 {
            0 => format!("metadata:\n  uuid: {uuid}\nname: é😀 {file}\n").into_bytes(),
            1 => format!("metadata:\n  uuid: {uuid}\ndetection_model: {other}\n").into_bytes(),
            2 => format!("metadata:\n  uuid: {uuid}\ndetection_model: s-{other}\n").into_bytes(),
            3 => format!(
                "metadata:\n  uuid: {uuid}\nthreat:\n  chaining:\n    - {{relation: precedes, vector: {other}}}\n    - {{relation: follows, vector: {other}}}\n"
            )
            .into_bytes(),
            4 => format!("metadata:\n  uuid: {uuid}\nthreat:\n  chaining: []\n").into_bytes(),
            5 => format!(
                "metadata:\n  uuid: {uuid}\nobjective:\n  threats: [{other}]\n  signals:\n    - uuid: s-{other}\n"
            )
            .into_bytes(),
            6 => b"metadata: [unclosed\n".to_vec(),
            7 => b"metadata:\n  name: no uuid\n".to_vec(),
            _ => format!("uuid: {uuid}\n").into_bytes(),
        }
    }

    /// The file `file` of the in-place tests: rules, threats and objectives.
    fn edited_path(file: usize) -> PathBuf {
        let folder = ["objects/rules", "objects/threats", "objects/objectives"][file % 3];
        Path::new(ROOT).join(folder).join(format!("f{file}.yaml"))
    }

    /// Everything the index holds, the documents and the references' field
    /// paths included: a stricter comparison than [`index_json`].
    fn whole(workspace: &Workspace) -> String {
        format!("{:?}", workspace.index())
    }

    #[expect(clippy::unwrap_used, reason = "a test helper: the workspace resolves")]
    fn whole_from_scratch(fs: &Arc<MemoryFs>) -> String {
        whole(&Workspace::open(Arc::clone(fs) as Arc<dyn FileSystem>, options()).unwrap())
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        /// An edit of a file's content puts its document in place in the
        /// index when it can (#2122): the index is then, document for
        /// document and reference for reference, the one a full load makes,
        /// and the invalidation says what the index assembled again from
        /// every parse says (a clone held across the edit shares the index,
        /// so that workspace assembles it again).
        #[test]
        fn an_index_edited_in_place_equals_one_assembled_again(
            seed in proptest::collection::vec((0usize..9, 0usize..9), 1..12),
            edits in proptest::collection::vec(
                (
                    0usize..12,
                    0usize..9,
                    proptest::option::weighted(0.1, 0usize..12),
                    0usize..12,
                ),
                1..24,
            ),
        ) {
            let fs = Arc::new(MemoryFs::new());
            fs.create_dir(Path::new(ROOT).join(".opentide/configurations"));
            for (file, (kind, other)) in seed.iter().enumerate() {
                fs.write(edited_path(file), edited(file, *kind, None, *other));
            }
            let open = || Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, options()).unwrap();
            let mut in_place = open();
            let mut assembled = open();
            for (file, kind, uuid, other) in &edits {
                let path = edited_path(*file);
                let change = if fs.is_file(&path) {
                    Change::changed(&path)
                } else {
                    Change::created(&path)
                };
                fs.write(&path, edited(*file, *kind, *uuid, *other));
                let held = assembled.clone();
                let expected = assembled.invalidate(std::slice::from_ref(&change)).unwrap();
                drop(held);
                let done = in_place.invalidate(&[change]).unwrap();
                prop_assert_eq!(&done, &expected, "{}", path.display());
                prop_assert_eq!(whole(&in_place), whole_from_scratch(&fs), "{}", path.display());
                prop_assert_eq!(whole(&assembled), whole(&in_place));
            }
        }
    }

    /// Which edits put the new document in place in the index (it is then the
    /// same allocation) and which assemble it again.
    #[test]
    fn an_edit_that_keeps_each_object_what_it_was_is_made_in_place() {
        let fs = Arc::new(MemoryFs::new());
        for file in 0..6 {
            fs.write(edited_path(file), edited(file, 1, None, 0));
        }
        let mut ws = Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, options()).unwrap();
        // A rule's reference, then its name: in place.
        let (kept, done) = edit(&fs, &mut ws, 0, 2, None);
        assert!(kept);
        assert!(
            done.affected.contains("u-0") && done.affected.contains("s-u-4"),
            "{done:?}"
        );
        assert!(!done.identity_changed);
        let (kept, done) = edit(&fs, &mut ws, 0, 0, None);
        assert!(kept, "{done:?}");
        assert!(done.identity_changed, "{done:?}");
        // A threat's chaining links, from none to two: in place.
        assert!(edit(&fs, &mut ws, 1, 4, None).0);
        assert!(edit(&fs, &mut ws, 1, 3, None).0);
        // An objective, a UUID changed, a file that does not load or has no
        // UUID: assembled again.
        assert!(!edit(&fs, &mut ws, 2, 5, None).0);
        assert!(!edit(&fs, &mut ws, 3, 0, Some(5)).0);
        assert!(!edit(&fs, &mut ws, 3, 6, None).0);
        assert!(!edit(&fs, &mut ws, 4, 7, None).0);
        // Back to an object: assembled again; then in place again.
        assert!(!edit(&fs, &mut ws, 3, 0, None).0);
        assert!(edit(&fs, &mut ws, 3, 1, None).0);
        // A clone shares the index: assembled again.
        let held = ws.clone();
        assert!(!edit(&fs, &mut ws, 0, 1, None).0);
        drop(held);
    }

    /// Writes file `file` of the in-place tests and reports the edit: whether
    /// the index is the same allocation after it, and the invalidation.
    #[expect(clippy::unwrap_used, reason = "a test helper: the workspace resolves")]
    fn edit(
        fs: &Arc<MemoryFs>,
        workspace: &mut Workspace,
        file: usize,
        kind: usize,
        uuid: Option<usize>,
    ) -> (bool, Invalidation) {
        let before = Arc::as_ptr(workspace.index());
        fs.write(edited_path(file), edited(file, kind, uuid, 4));
        let done = workspace
            .invalidate(&[Change::changed(edited_path(file))])
            .unwrap();
        assert_eq!(whole(workspace), whole_from_scratch(fs));
        (std::ptr::eq(before, Arc::as_ptr(workspace.index())), done)
    }

    #[test]
    fn an_unreported_edit_is_not_seen_until_it_is_reported() {
        let fs = Arc::new(MemoryFs::new());
        fs.write("/ws/objects/rules/a.yaml", content(0, 0, 0));
        let mut workspace =
            Workspace::open(Arc::clone(&fs) as Arc<dyn FileSystem>, options()).unwrap();
        fs.write("/ws/objects/rules/a.yaml", content(0, 1, 0));
        workspace
            .invalidate(&[Change::changed("/ws/objects/rules/b.yaml")])
            .unwrap();
        assert!(
            workspace.index().get("rule", "u-1").is_some(),
            "the cache holds"
        );
        workspace
            .invalidate(&[Change::changed("/ws/objects/rules/a.yaml")])
            .unwrap();
        assert!(workspace.index().get("rule", "u-2").is_some());
        assert_eq!(index_json(workspace.index(), workspace.root()), full(&fs));
    }
}
