//! A workspace on disk whose `objects/rules` is a directory link (as the
//! tide corpus lays its legacy folders out) plans the same deploy as one
//! whose `objects/rules` is a plain folder, on every host.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace here is written and opens"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::Owned;
use opentide_compile::dry_run::{self, Outcome, Request};
use opentide_compile::plan::Scope;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, Options, OsFs, RootOptions, Workspace};

const UUIDS: [&str; 2] = [
    "00000000-0000-4000-8000-00000000000a",
    "00000000-0000-4000-8000-00000000000b",
];

const SENTINEL: &str = "[platform]\nenabled = true\n";

fn rule(uuid: &str) -> String {
    format!(
        "name: Rule {uuid}\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.0\ndescription: d\n\
         configurations:\n  sentinel:\n    status: STAGING\n"
    )
}

#[cfg(unix)]
fn link_dir(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

/// A directory symbolic link: GitHub's Windows runners may create one.
#[cfg(windows)]
fn link_dir(target: &Path, link: &Path) {
    std::os::windows::fs::symlink_dir(target, link).unwrap();
}

/// A workspace under `root`; its rules in `objects/rules`, or, when
/// `linked`, in `legacy/Detection Rules` with `objects/rules` linking there.
fn workspace(root: &Path, linked: bool) -> Workspace {
    let platforms = root
        .join(".opentide")
        .join("configurations")
        .join("platforms");
    fs::create_dir_all(&platforms).unwrap();
    fs::write(platforms.join("sentinel.toml"), SENTINEL).unwrap();
    let objects = root.join("objects");
    fs::create_dir_all(&objects).unwrap();
    let rules = if linked {
        let real = root.join("legacy").join("Detection Rules");
        fs::create_dir_all(&real).unwrap();
        // Relative, one component at a time, as the fixture links are.
        let target: PathBuf = ["..", "legacy", "Detection Rules"].iter().collect();
        link_dir(&target, &objects.join("rules"));
        assert!(
            fs::symlink_metadata(objects.join("rules"))
                .unwrap()
                .is_symlink()
        );
        real
    } else {
        let plain = objects.join("rules");
        fs::create_dir_all(&plain).unwrap();
        plain
    };
    for (name, uuid) in ["a.yaml", "b.yaml"].iter().zip(UUIDS) {
        fs::write(rules.join(name), rule(uuid)).unwrap();
    }
    Workspace::open(
        Arc::new(OsFs) as Arc<dyn FileSystem>,
        Options {
            roots: RootOptions {
                repo: Some(root.to_path_buf()),
                cwd: root.to_path_buf(),
                ..RootOptions::default()
            },
        },
    )
    .unwrap()
}

fn run(workspace: &Workspace, request: &Request) -> Outcome {
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let changed = |_: &Path, _: &str| -> Result<(Scope, Option<String>), String> {
        Err("no git here".to_owned())
    };
    dry_run::run(workspace, &owned, request, &changed, &|_| false)
}

/// What a run plans, without the paths it names.
fn planned(outcome: &Outcome) -> Vec<(String, String)> {
    let mut keys = vec![("exit".to_owned(), outcome.exit_code.to_string())];
    for key in ["status", "message", "plan", "changes", "summary"] {
        let value = outcome
            .payload
            .get(key)
            .map(opentide_compile::Json::to_compact)
            .unwrap_or_default();
        keys.push((key.to_owned(), value));
    }
    keys
}

#[test]
fn a_linked_rules_folder_plans_as_a_plain_one() {
    let plain_dir = tempfile::tempdir().unwrap();
    let linked_dir = tempfile::tempdir().unwrap();
    let plain_root = dunce::canonicalize(plain_dir.path()).unwrap();
    let linked_root = dunce::canonicalize(linked_dir.path()).unwrap();
    let plain = workspace(&plain_root, false);
    let linked = workspace(&linked_root, true);
    let requests = [
        Request {
            strategies: vec!["PREVIEW".into()],
            all: true,
            cwd: plain_root.clone(),
            ..Request::default()
        },
        Request {
            strategies: vec!["PREVIEW".into()],
            uuids: vec![UUIDS[0].to_owned()],
            cwd: plain_root.clone(),
            ..Request::default()
        },
    ];
    for request in &requests {
        let from_plain = run(&plain, request);
        let linked_request = Request {
            cwd: linked_root.clone(),
            ..request.clone()
        };
        let from_link = run(&linked, &linked_request);
        assert_eq!(planned(&from_plain), planned(&from_link), "{request:?}");
    }
    // Both runs plan the rules (their bodies, without a query, would fail):
    // the link is read, not skipped.
    let all = run(
        &linked,
        &Request {
            cwd: linked_root.clone(),
            ..requests[0].clone()
        },
    );
    assert_eq!(
        planned(&all)[3].1,
        format!(r#"{{"sentinel":["{}","{}"]}}"#, UUIDS[0], UUIDS[1])
    );
    let one = run(
        &linked,
        &Request {
            cwd: linked_root,
            ..requests[1].clone()
        },
    );
    assert_eq!(
        planned(&one)[3].1,
        format!(r#"{{"sentinel":["{}"]}}"#, UUIDS[0])
    );
}
