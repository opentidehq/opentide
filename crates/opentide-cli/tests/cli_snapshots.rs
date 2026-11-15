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

/// Every group: its test, its command directories, and how many cases the
/// manifest expands for them. One test per group, so nextest runs the
/// groups side by side.
const GROUPS: &[(&str, &[&str], usize)] = &[
    // The root's own runs (`--version`, a bare `opentide`, typos, `--repo`,
    // `--debug`) and the bare groups, which print their help to a person
    // and a usage error to a program.
    (
        "root_and_groups",
        &[
            "_root",
            "generate.extract",
            "lsp",
            "mcp",
            "migrate",
            "new",
            "rules",
        ],
        80,
    ),
    ("explain", &["explain"], 22),
    ("validate", &["validate"], 190),
];

fn group(name: &str) {
    let (_, commands, expected) = GROUPS.iter().find(|group| group.0 == name).unwrap();
    snapshot::check(commands, *expected);
}

#[test]
fn root_and_groups() {
    group("root_and_groups");
}

#[test]
fn explain() {
    group("explain");
}

#[test]
fn validate() {
    group("validate");
}
