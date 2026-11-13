//! `golden check --engine rust`'s comparison (`xtask::compare::golden`):
//! a deliberately divergent fake candidate run is caught, an approved
//! difference passes, and a stale ledger entry fails the run (#805).

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions; a panic fails the test"
)]

use std::collections::BTreeMap;
use std::path::Path;
use xtask::golden::case::{Case, Mode, Stdin, StdinKind};
use xtask::golden::recording::Recording;

const ID: &str = "info/json/none/rules";

fn recording(stdout: &str) -> Recording {
    Recording {
        case: Case {
            id: ID.into(),
            command: "info".into(),
            variant: "rules".into(),
            mode: Mode::Json,
            fixture: "none".into(),
            argv: vec![
                "opentide".into(),
                "--json".into(),
                "info".into(),
                "rules".into(),
            ],
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
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
        exit_code: 0,
        files: Vec::new(),
    }
}

/// A repository with the oracle's recording of one case, and `ledger`.
fn repo(dir: &Path, ledger: &str) {
    let golden = dir.join("tests/golden");
    std::fs::create_dir_all(golden.join("blobs")).unwrap();
    recording("{\"ok\":true,\"summary\":{\"rules\":3}}\n")
        .write(&golden.join("cases").join(ID), &golden.join("blobs"))
        .expect("write the recording");
    std::fs::write(golden.join("APPROVED_DIFFS.toml"), ledger).unwrap();
    std::fs::write(dir.join("CHANGELOG.md"), "- **Rules counted again**\n").unwrap();
}

fn entry(pointer: &str, oracle: &str, candidate: &str) -> String {
    format!(
        "[[diff]]\ncommand = \"info\"\ncase = \"info/json/*\"\ntarget = \"stdout\"\n\
         rule = \"json:{pointer}\"\noracle = '{oracle}'\ncandidate = '{candidate}'\n\
         reason = \"r\"\nissue = \"https://github.com/opentidehq/opentide/issues/805\"\n\
         changelog = \"**Rules counted again**\"\n"
    )
}

fn run(dir: &Path, candidate: &str) -> (bool, serde_json::Value) {
    run_versions(dir, candidate, ("0.23.0", "0.23.0"))
}

fn run_versions(dir: &Path, candidate: &str, versions: (&str, &str)) -> (bool, serde_json::Value) {
    let golden = dir.join("tests/golden");
    let report = dir.join("report.json");
    let passed = xtask::compare::golden(
        dir,
        &golden.join("cases"),
        &golden.join("blobs"),
        &[Ok(recording(candidate))],
        true,
        Some(&report),
        false,
        versions,
    )
    .expect("the comparison runs");
    let text = std::fs::read_to_string(report).unwrap();
    (passed, serde_json::from_str(&text).unwrap())
}

#[test]
fn comparator_golden_catches_a_divergent_fake_candidate() {
    let dir = tempfile::tempdir().unwrap();
    repo(dir.path(), "");
    let (passed, report) = run(dir.path(), "{\"ok\":true,\"summary\":{\"rules\":4}}\n");
    assert!(!passed);
    assert_eq!(
        report["cases"][0]["differences"][0]["pointer"],
        "/summary/rules"
    );
    let (passed, _) = run(dir.path(), "{\"ok\":true,\"summary\":{\"rules\":3}}\n");
    assert!(passed);
}

#[test]
fn comparator_golden_applies_the_ledger_and_fails_a_stale_entry() {
    let dir = tempfile::tempdir().unwrap();
    repo(dir.path(), &entry("/summary/rules", "3", "4"));
    let (passed, report) = run(dir.path(), "{\"ok\":true,\"summary\":{\"rules\":4}}\n");
    assert!(passed, "{report}");
    assert_eq!(report["cases"][0]["approved"][0]["entry"], 1);

    // The candidate matches the oracle again: the entry approves nothing.
    let (passed, report) = run(dir.path(), "{\"ok\":true,\"summary\":{\"rules\":3}}\n");
    assert!(!passed);
    assert_eq!(report["stale"][0]["entry"], 1);
}

#[test]
fn comparator_golden_compares_each_sides_own_version_as_a_placeholder() {
    let dir = tempfile::tempdir().unwrap();
    repo(dir.path(), "");
    let golden = dir.path().join("tests/golden");
    std::fs::remove_dir_all(golden.join("cases")).unwrap();
    recording("{\"version\":\"0.23.0\",\"requires\":\"0.23.0\"}\n")
        .write(&golden.join("cases").join(ID), &golden.join("blobs"))
        .unwrap();
    let build = "0.23.1.dev5+g34227995";
    // Each side reports its own version: equal.
    let (passed, report) = run_versions(
        dir.path(),
        &format!("{{\"version\":\"{build}\",\"requires\":\"{build}\"}}\n"),
        ("0.23.0", build),
    );
    assert!(passed, "{report}");
    // The candidate printing the oracle's version, not its own, still differs.
    let (passed, report) = run_versions(
        dir.path(),
        &format!("{{\"version\":\"0.23.0\",\"requires\":\"{build}\"}}\n"),
        ("0.23.0", build),
    );
    assert!(!passed);
    assert_eq!(report["cases"][0]["differences"][0]["pointer"], "/version");
    // Another version-shaped value is still compared.
    let (passed, _) = run_versions(
        dir.path(),
        &format!("{{\"version\":\"{build}\",\"requires\":\"0.23.1\"}}\n"),
        ("0.23.0", build),
    );
    assert!(!passed);
}
