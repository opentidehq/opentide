//! The command line the facade carries (`cli` feature): the `opentide`
//! binary and `cli::run_json`. What `opentide commands` prints is held by the
//! CLI's snapshots (`crates/opentide-cli/tests/cli_snapshots.rs`).

#![cfg(feature = "cli")]

mod common;

use std::process::Command;

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
            .starts_with("error: unrecognized subcommand 'valdiate'")
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
