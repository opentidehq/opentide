//! The command line's behaviour, held to snapshots of its own output (#1139):
//! every case of `tests/golden/cases.toml`, grouped by command, run
//! in-process and compared with `tests/cli_snapshots/<command>/*.snap`
//! (`common/snapshot.rs`). After an intended change: `cargo insta review`
//! (tests/golden/README.md, "Snapshots").

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test harness: a broken manifest or fixture is a failure"
)]

#[path = "common/replay.rs"]
mod replay;
#[path = "common/snapshot.rs"]
mod snapshot;

/// The root's own runs: `--version`, a bare `opentide`, typos, `--repo`,
/// `--debug`; and the bare groups, which print their help to a person and
/// a usage error to a program.
#[test]
fn root_and_groups() {
    snapshot::check(
        &[
            "_root",
            "generate.extract",
            "lsp",
            "mcp",
            "migrate",
            "new",
            "rules",
        ],
        60,
    );
}

#[test]
fn explain() {
    snapshot::check(&["explain"], 20);
}

#[test]
fn validate() {
    snapshot::check(&["validate"], 190);
}
