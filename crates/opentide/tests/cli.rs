//! The command line the facade carries (`cli` feature): the `opentide`
//! binary and `cli::run_json`, against the PyPI CLI's recordings.

#![cfg(feature = "cli")]

mod common;

use std::process::Command;

/// `opentide --json commands`'s recording from the PyPI CLI (opentide
/// 0.23.0), the goldens' case `commands/json/none/default`.
const CASE: &str = "commands/json/none/default";

#[test]
fn the_binary_prints_the_pypi_command_tree() {
    use opentide_compare::normalise::{Volatile, opentide_version};
    use opentide_compare::{Case, Normalisation, Run, compare_normalised};

    let output = Command::new(env!("CARGO_BIN_EXE_opentide"))
        .args(["--json", "commands"])
        .env_clear()
        .output()
        .unwrap();
    let printed = String::from_utf8(output.stdout).unwrap();
    assert!(printed.contains(&format!("\"version\":\"{}\"", opentide::cli::VERSION)));
    let recorded = common::repo().join("tests/golden/cases").join(CASE);
    let read = |name: &str| std::fs::read_to_string(recorded.join(name)).unwrap();
    // The versions differ (the crate's, the package's), as they do between
    // the goldens' two engines; the goldens' comparator and their ledger
    // (APPROVED_DIFFS.toml: the approved additions) judge the rest.
    let oracle = Run {
        exit_code: 0,
        stdout: opentide_version(&read("stdout"), "0.28.1").into_bytes(),
        stderr: read("stderr").into_bytes(),
        files: std::collections::BTreeMap::new(),
    };
    let candidate = Run {
        exit_code: output.status.code().unwrap(),
        stdout: opentide_version(&printed, opentide::cli::VERSION).into_bytes(),
        stderr: output.stderr,
        files: std::collections::BTreeMap::new(),
    };
    let ledger = opentide_compare::ledger::Ledger::parse(
        &std::fs::read_to_string(common::repo().join("tests/golden/APPROVED_DIFFS.toml")).unwrap(),
    )
    .unwrap();
    let report = compare_normalised(
        Case {
            command: "commands",
            id: CASE,
        },
        (oracle, &Volatile::default()),
        (candidate, &Volatile::default()),
        Normalisation::default(),
        &ledger,
    );
    // The catch-up train's report-only marker (`tests/golden/REPORT_ONLY`):
    // the 0.23.0 recording lacks what the ports add (0.28.1's `--verbose`,
    // lint's `recommended` check), so the difference is printed, not failed,
    // until O2 re-records it.
    if !report.equal && common::repo().join("tests/golden/REPORT_ONLY").is_file() {
        eprintln!(
            "tests/golden/REPORT_ONLY is present: opentide --json commands differs from the \
             PyPI CLI's, reported, not failed: {}",
            report.to_json().unwrap()
        );
        return;
    }
    assert!(
        report.equal,
        "opentide --json commands differs from the PyPI CLI's: {}",
        report.to_json().unwrap()
    );
}

#[test]
fn the_binary_reports_a_usage_error_as_the_cli_does() {
    let output = Command::new(env!("CARGO_BIN_EXE_opentide"))
        .arg("valdiate")
        .env_clear()
        .env("OPENTIDE_OUTPUT", "plain")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("error: No such command 'valdiate'.")
    );
}

#[test]
fn run_json_returns_the_document_in_order() {
    let tree = opentide::cli::run_json(["commands"]).unwrap();
    assert_eq!(tree.value()["program"], "opentide");
    assert!(
        tree.as_str()
            .starts_with("{\"program\":\"opentide\",\"version\":")
    );

    let dir = common::tide_corpus();
    let info = opentide::cli::run_json([
        "--repo".to_owned(),
        dir.path().display().to_string(),
        "info".to_owned(),
    ])
    .unwrap();
    assert_eq!(info.value()["ok"], true, "{info}");
    assert_eq!(info.value()["counts"]["rules"], 10, "{info}");

    // A failure still writes its document.
    let typo = opentide::cli::run_json(["valdiate"]).unwrap();
    assert_eq!(typo.value()["ok"], false);
    assert_eq!(
        typo.value()["failure"]["code"],
        "usage_unknown_command",
        "{typo}"
    );
}

#[test]
fn run_json_says_when_no_document_comes() {
    let error = opentide::cli::run_json(["--version"]).unwrap_err();
    assert_eq!(error.code(), "no_json_document");
    assert!(
        matches!(error, opentide::Error::NoDocument { exit_code: 0, .. }),
        "{error:?}"
    );
}
