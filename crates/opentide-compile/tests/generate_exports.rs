//! `generate exports` against the oracle's recordings (UC-3.2, #824): each
//! export of the tide-corpus and vscode fixtures, compared byte for byte
//! with the file the oracle wrote, and the oracle's failure where it failed.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "a test: a broken fixture is a failure")]

#[path = "common/golden.rs"]
mod golden;

use std::sync::Arc;

use opentide_compile::generate::exports::{Settings, Target, export};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{OsFs, RootOptions, Workspace};

fn open(fixture: &str) -> (tempfile::TempDir, Workspace) {
    let dir = tempfile::tempdir().unwrap();
    let ws = dunce::canonicalize(dir.path()).unwrap().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    golden::fixture(fixture, &ws);
    let options = RootOptions {
        repo: Some(ws.clone()),
        repo_root_env: Some(ws.clone()),
        tide_workspace_env: Some(ws.clone()),
        cwd: ws,
    };
    let workspace = Workspace::open(
        Arc::new(OsFs),
        opentide_workspace::Options { roots: options },
    )
    .unwrap();
    (dir, workspace)
}

fn check(fixture: &str, target: Target, case: &str) {
    let (_dir, workspace) = open(fixture);
    let settings = Settings::new(workspace.configuration(), workspace.root());
    let (code, files) = golden::recorded(case);
    let result = export(
        target,
        workspace.index(),
        &settings,
        &Vocabularies::bundled(),
    );
    if code != 0 {
        let stdout = std::fs::read_to_string(golden::case(case).join("stdout")).unwrap();
        let error = result.unwrap_err();
        // The failure is the oracle's but for the quotes around the key it
        // names (APPROVED_DIFFS.toml, **Messages quote values the same way
        // everywhere**): Rust's where the oracle's were Python's repr.
        let unquoted = |text: &str| -> String {
            text.chars()
                .filter(|c| !matches!(c, '\'' | '"' | '\\'))
                .collect()
        };
        assert!(
            unquoted(&stdout).contains(&unquoted(&format!("\"message\":\"exports: {error}\""))),
            "{case}: {error} is not the oracle's failure: {stdout}"
        );
        return;
    }
    let output = result.unwrap();
    let relative = output
        .path
        .strip_prefix(workspace.root())
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let expected = files
        .get(&relative)
        .unwrap_or_else(|| panic!("{case}: the oracle wrote no {relative}"));
    assert_eq!(
        String::from_utf8_lossy(&output.bytes),
        String::from_utf8_lossy(expected),
        "{case}: {relative}"
    );
}

#[test]
#[ignore = "byte-level replay against the Python oracle: run by hand with --run-ignored only"]
fn every_export_is_the_oracles() {
    for fixture in ["tide-corpus", "vscode"] {
        for target in Target::ALL {
            let case = format!("generate.exports.{}/json/{fixture}/default", target.name());
            check(fixture, target, &case);
        }
    }
}

#[test]
#[ignore = "byte-level replay against the Python oracle: run by hand with --run-ignored only"]
fn generate_exports_writes_the_oracles_three_files() {
    let (_dir, workspace) = open("tide-corpus");
    let settings = Settings::new(workspace.configuration(), workspace.root());
    let (_, files) = golden::recorded("generate.exports/plain/tide-corpus/default");
    assert_eq!(files.len(), 3);
    for target in Target::ALL {
        let output = export(
            target,
            workspace.index(),
            &settings,
            &Vocabularies::bundled(),
        )
        .unwrap();
        let relative = output.path.strip_prefix(workspace.root()).unwrap();
        assert_eq!(
            files[&relative.to_string_lossy().into_owned()],
            output.bytes
        );
    }
}
