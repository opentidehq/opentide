//! `xtask::compare`'s I/O and adapters: runs read from disk, the ledger
//! read and checked, the candidate engine, and recordings as comparator runs.

#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions; a panic fails the test"
)]

use opentide_compare::FileState;
use std::collections::BTreeMap;
use std::path::Path;
#[cfg(unix)]
use xtask::compare::node_candidate;
use xtask::compare::{candidate, candidate_version, read_ledger, read_run, run_of};
use xtask::golden::case::{Case, Mode, Stdin, StdinKind};
use xtask::golden::recording::{FileRecord, Recording};
use xtask::golden::snapshot::{ChangeKind, Kind};

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn run_dir(dir: &Path) {
    write(&dir.join("exit_code"), " 2\n");
    write(&dir.join("stdout"), "out");
    write(&dir.join("stderr"), "err");
    write(&dir.join("files/docs/a.md"), "# A\n");
    write(&dir.join("files/b.json"), "{}");
    write(&dir.join("deleted"), "old.md\n\n  gone/x.yaml \n");
}

#[test]
fn a_run_is_read_with_its_files_and_deletions() {
    let dir = tempfile::tempdir().unwrap();
    run_dir(dir.path());
    let run = read_run(dir.path()).unwrap();
    assert_eq!(run.exit_code, 2);
    assert_eq!(
        (run.stdout.as_slice(), run.stderr.as_slice()),
        (&b"out"[..], &b"err"[..])
    );
    let names: Vec<&str> = run.files.keys().map(String::as_str).collect();
    assert_eq!(names, ["b.json", "docs/a.md", "gone/x.yaml", "old.md"]);
    assert_eq!(run.files["old.md"], FileState::Deleted);
    assert!(
        matches!(&run.files["docs/a.md"], FileState::Written { bytes, .. } if bytes == b"# A\n")
    );
}

#[test]
fn a_run_without_files_or_deletions_is_read() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("exit_code"), "0");
    write(&dir.path().join("stdout"), "");
    write(&dir.path().join("stderr"), "");
    assert!(read_run(dir.path()).unwrap().files.is_empty());
}

#[test]
fn a_broken_run_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let error = read_run(dir.path()).unwrap_err().to_string();
    assert!(error.contains("exit_code"), "{error}");

    write(&dir.path().join("exit_code"), "zero");
    let error = format!("{:#}", read_run(dir.path()).unwrap_err());
    assert!(error.contains("not an exit code"), "{error}");

    write(&dir.path().join("exit_code"), "0");
    let error = format!("{:#}", read_run(dir.path()).unwrap_err());
    assert!(error.contains("stdout"), "{error}");

    run_dir(dir.path());
    write(&dir.path().join("deleted"), "b.json\n");
    let error = format!("{:#}", read_run(dir.path()).unwrap_err());
    assert!(error.contains("both written and deleted"), "{error}");
}

#[test]
fn the_ledger_is_read_and_checked_against_the_changelog() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.toml");
    assert!(
        read_ledger(&path, "").is_err(),
        "a missing file is an error"
    );

    write(&path, "[[diff]]\ncommand = \"info\"\n");
    let error = format!("{:#}", read_ledger(&path, "").unwrap_err());
    assert!(error.contains("missing field"), "{error}");

    write(
        &path,
        "[[diff]]\ncommand = \"info\"\ncase = \"*\"\ntarget = \"stdout\"\nrule = \"text\"\n\
         oracle = \"a\"\ncandidate = \"b\"\nreason = \"r\"\n\
         issue = \"https://github.com/opentidehq/opentide/issues/805\"\nchangelog = \"**Lead**\"\n",
    );
    let error = format!("{:#}", read_ledger(&path, "nothing").unwrap_err());
    assert!(error.contains("begins no entry"), "{error}");
    assert_eq!(
        read_ledger(&path, "- **Lead** here").unwrap().entries.len(),
        1
    );
}

#[test]
fn the_candidate_needs_the_repository_cli() {
    let dir = tempfile::tempdir().unwrap();
    let error = candidate(dir.path()).unwrap_err().to_string();
    assert!(error.contains("uv sync --group dev"), "{error}");

    write(&dir.path().join(".venv/bin/opentide"), "");
    let engine = candidate(dir.path()).unwrap();
    assert_eq!(engine.name, "rust");
    assert!(engine.known_uuids.is_empty());

    // The UUIDs of the package's bundled data are never fresh ones.
    let uuid = "0b7a6a39-7d1d-4b5e-9c3f-0e6f1d2a3b4c";
    write(
        &dir.path().join("src/opentide/data/vocab.toml"),
        &format!("id = \"{uuid}\"\n"),
    );
    let engine = candidate(dir.path()).unwrap();
    assert!(
        engine.known_uuids.contains(uuid),
        "{:?}",
        engine.known_uuids
    );
}

#[cfg(unix)]
fn script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    write(path, &format!("#!/bin/sh\n{body}\n"));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn the_candidate_s_version_is_what_its_version_option_prints() {
    let dir = tempfile::tempdir().unwrap();
    let opentide = dir.path().join("opentide");
    script(
        &opentide,
        r#"[ "$1" = --version ] && echo "opentide 1.2.3.dev4+g0123""#,
    );
    assert_eq!(candidate_version(&opentide).unwrap(), "1.2.3.dev4+g0123");
    script(&opentide, "echo 'opentide'");
    let error = format!("{:#}", candidate_version(&opentide).unwrap_err());
    assert!(
        error.contains("read the candidate's version from `opentide`"),
        "{error}"
    );
    script(&opentide, "echo 'something else 1.0'");
    assert!(candidate_version(&opentide).is_err());
    let error = format!(
        "{:#}",
        candidate_version(&dir.path().join("none")).unwrap_err()
    );
    assert!(error.starts_with("run "), "{error}");
}

#[cfg(unix)]
#[test]
fn the_node_candidate_needs_the_built_addon() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    let error = format!("{:#}", node_candidate(dir.path(), &target).unwrap_err());
    assert!(error.starts_with("read "), "{error}");
    write(&dir.path().join("bindings/node/cli.js"), "");
    let error = node_candidate(dir.path(), &target).unwrap_err().to_string();
    assert!(
        error.ends_with("has no addon: run `npm ci && npm run build` there first"),
        "{error}"
    );
    assert!(!target.exists());
}

fn recording(exit_code: i32, stderr: &str, files: Vec<FileRecord>) -> Recording {
    Recording {
        case: Case {
            id: "info/plain/none/rules".into(),
            command: "info".into(),
            variant: "rules".into(),
            mode: Mode::Plain,
            fixture: "none".into(),
            argv: vec!["opentide".into(), "info".into()],
            cwd: ".".into(),
            env: BTreeMap::new(),
            stdin: Stdin {
                kind: StdinKind::Null,
                input: String::new(),
            },
            timeout_secs: 60,
            normalise: Vec::new(),
            cassette: None,
        },
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        exit_code,
        files,
    }
}

fn record(path: &str, change: ChangeKind, kind: Kind, mode: Option<&str>) -> FileRecord {
    FileRecord {
        path: path.into(),
        change,
        kind,
        mode: mode.map(str::to_owned),
        size: None,
        binary: false,
        target: (kind == Kind::Symlink).then(|| "target".to_owned()),
        blob: None,
        contents: (kind == Kind::File).then(|| b"bytes".to_vec()),
    }
}

#[test]
fn recordings_become_comparator_runs() {
    let run = run_of(&recording(
        0,
        "",
        vec![
            record("ws/a.md", ChangeKind::Created, Kind::File, Some("0644")),
            record("ws/d", ChangeKind::Created, Kind::Dir, Some("0755")),
            record("ws/l", ChangeKind::Modified, Kind::Symlink, None),
            record("ws/x", ChangeKind::Deleted, Kind::File, Some("0644")),
        ],
    ));
    assert_eq!(
        run.files["ws/a.md"],
        FileState::Written {
            mode: 0o644,
            bytes: b"bytes".to_vec()
        }
    );
    assert_eq!(
        run.files["ws/d"],
        FileState::Written {
            mode: 0o040_755,
            bytes: Vec::new()
        }
    );
    assert_eq!(
        run.files["ws/l"],
        FileState::Written {
            mode: 0o120_777,
            bytes: b"symlink:target".to_vec()
        }
    );
    assert_eq!(run.files["ws/x"], FileState::Deleted);
}
