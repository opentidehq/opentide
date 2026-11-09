//! The `opentide` binary end to end: `main`, the process's streams and exit
//! codes, and the catalogue it prints.

#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a binary that does not start is a failure"
)]

use std::process::Command;

fn opentide(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_opentide"))
        .args(args)
        .env_clear()
        .env("OPENTIDE_OUTPUT", "plain")
        .output()
        .unwrap()
}

#[test]
fn framework_binary_prints_the_catalogue_and_usage_errors() {
    let catalogue = opentide(&["--json", "commands"]);
    assert_eq!(catalogue.status.code(), Some(0));
    let text = String::from_utf8(catalogue.stdout).unwrap();
    assert!(text.starts_with("{\"program\":\"opentide\",\"version\":\""));
    assert!(text.ends_with("\"failure\":null}\n"));
    assert!(catalogue.stderr.is_empty());

    let typo = opentide(&["valdiate"]);
    assert_eq!(typo.status.code(), Some(2));
    assert!(typo.stdout.is_empty());
    assert_eq!(
        String::from_utf8(typo.stderr).unwrap(),
        "error: No such command 'valdiate'.\n  help: did you mean 'validate'?\n  usage: opentide [OPTIONS] COMMAND [ARGS]...\n  help: run 'opentide --help'\n"
    );

    let version = opentide(&["--version"]);
    assert!(
        String::from_utf8(version.stdout)
            .unwrap()
            .starts_with("opentide ")
    );
}
