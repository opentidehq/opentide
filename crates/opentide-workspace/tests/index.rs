//! The incremental index equals a full rebuild after any sequence of edits,
//! creations, deletions and renames (issue #816), configuration changes
//! included.

mod index {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use opentide_workspace::{Change, FileSystem, MemoryFs, Options, RootOptions, Workspace};
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
        workspace.index().to_json(workspace.root())
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
                    workspace.index().to_json(workspace.root()),
                    full(&fs),
                    "after {:?}", op
                );
            }
        }
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
        assert_eq!(workspace.index().to_json(workspace.root()), full(&fs));
    }
}
