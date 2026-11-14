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
    // The read-only reports, and the protocol commands' help and refusals.
    (
        "reports_and_protocols",
        &[
            "lint",
            "info",
            "commands",
            "doctor",
            "tui",
            "serve",
            "lsp.start",
            "mcp.start",
        ],
        222,
    ),
    (
        "generate",
        &[
            "generate",
            "generate.docs",
            "generate.docs.index",
            "generate.docs.objectives",
            "generate.docs.rules",
            "generate.docs.threats",
            "generate.explorer",
            "generate.exports",
            "generate.exports.navigator",
            "generate.exports.objects",
            "generate.exports.revisions",
            "generate.extract.defender",
            "generate.extract.elastic",
            "generate.extract.sentinel",
            "generate.inflight",
            "generate.inflight.prune",
        ],
        274,
    ),
    // The commands that write objects.
    (
        "new_migrate_and_rules",
        &[
            "new.threat",
            "new.rule",
            "new.objective",
            "migrate.vocab-scope",
            "rules.unreviewed",
        ],
        114,
    ),
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

#[test]
fn reports_and_protocols() {
    group("reports_and_protocols");
}

#[test]
fn generate() {
    group("generate");
}

#[test]
fn new_migrate_and_rules() {
    group("new_migrate_and_rules");
}
