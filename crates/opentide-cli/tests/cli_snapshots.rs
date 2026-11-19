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

#[path = "common/normalise.rs"]
mod normalise;
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
    ("validate", &["validate"], 203),
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
    // `setup` and its subcommands, the skills catalogue served from its
    // cassettes.
    (
        "setup",
        &[
            "setup",
            "setup.ci",
            "setup.env",
            "setup.hooks",
            "setup.mcp",
            "setup.platforms",
            "setup.repo",
            "setup.skills",
            "setup.skills.discover",
            "setup.skills.show",
            "setup.vscode",
        ],
        303,
    ),
    // Dry runs, and sends to tenants served from cassettes.
    ("deploy", &["deploy", "deploy.migrate-state"], 163),
    // Offline, and against tenants served from cassettes.
    ("query", &["query", "validate.query"], 222),
    // The MISP destinations served from cassettes.
    (
        "share",
        &[
            "share",
            "share.preview",
            "share.push",
            "share.retract",
            "share.status",
            "share.targets",
        ],
        160,
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

/// The cases on the generated fixtures, whose workspaces `cargo xtask
/// corpus` writes: run when `OPENTIDE_REPLAY_FIXTURES` names them, as the
/// CI jobs do. One test each, for the time they take.
#[test]
fn generated_fault() {
    snapshot::check_generated("fault", 58);
}

#[test]
fn generated_fault_lint() {
    snapshot::check_generated("fault-lint", 23);
}

#[test]
fn generated_heavy_small() {
    snapshot::check_generated("heavy-small", 20);
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

#[test]
fn setup() {
    group("setup");
}

#[test]
fn deploy() {
    group("deploy");
}

#[test]
fn query() {
    group("query");
}

#[test]
fn share() {
    group("share");
}

/// Every case of the manifest is in a group (a new command's cases are not
/// left without a snapshot), and every committed snapshot is a case's (a
/// case removed or renamed takes its snapshot with it).
#[test]
fn every_case_has_a_group_and_every_snapshot_a_case() {
    let cases = snapshot::cases();
    let grouped: Vec<&str> = GROUPS
        .iter()
        .flat_map(|(_, commands, _)| commands.iter().copied())
        .collect();
    let orphans: Vec<&str> = cases
        .iter()
        .filter(|case| !grouped.contains(&case.command_dir.as_str()))
        .map(|case| case.id.as_str())
        .collect();
    assert!(orphans.is_empty(), "cases in no group: {orphans:#?}");
    let expected: std::collections::BTreeSet<String> = cases
        .iter()
        .map(|case| {
            format!(
                "{}/{}.snap",
                case.command_dir,
                snapshot::snapshot_name(case)
            )
        })
        .chain(snapshot::session_snapshots())
        .collect();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cli_snapshots");
    let mut stale = Vec::new();
    for command in std::fs::read_dir(&dir).unwrap() {
        let command = command.unwrap();
        for file in std::fs::read_dir(command.path()).unwrap() {
            let name = format!(
                "{}/{}",
                command.file_name().to_string_lossy(),
                file.unwrap().file_name().to_string_lossy()
            );
            if std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext == "snap")
                && !expected.contains(&name)
            {
                stale.push(name);
            }
        }
    }
    assert!(stale.is_empty(), "snapshots of no case: {stale:#?}");
}

#[test]
fn a_date_the_inputs_hold_is_not_the_clock() {
    let held = ["{\"at\": \"2026-10-27T07:51:00Z\"}", "created: 2026-01-01"];
    let candidates = ["2026-10-27", "2026-11-03", "2026-01-01"].map(str::to_owned);
    assert_eq!(
        snapshot::clock_dates(candidates.to_vec(), &held),
        ["2026-11-03"]
    );
    assert_eq!(snapshot::clock_dates(candidates.to_vec(), &[]), candidates);
}

#[test]
fn the_git_version_keeps_the_vendors_suffix() {
    assert_eq!(
        snapshot::git_version_in("git version 2.54.0 (Apple Git-157)\n").as_deref(),
        Some("2.54.0 (Apple Git-157)")
    );
    assert_eq!(
        snapshot::git_version_in("git version 2.43.0\n").as_deref(),
        Some("2.43.0")
    );
    assert_eq!(snapshot::git_version_in("not git"), None);
}
