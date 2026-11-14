//! `golden check --engine rust`'s comparison (`xtask::compare::golden`):
//! a deliberately divergent fake candidate run is caught, an approved
//! difference passes, and a stale ledger entry fails the run (#805); the
//! preview-oracle flags (`--oracle`, `--out`, `--recordings`) of O1.

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
    run_kept(dir, candidate, versions, None)
}

fn run_kept(
    dir: &Path,
    candidate: &str,
    versions: (&str, &str),
    keep: Option<&Path>,
) -> (bool, serde_json::Value) {
    let golden = dir.join("tests/golden");
    let report = dir.join("report.json");
    let passed = xtask::compare::golden(
        dir,
        &golden.join("cases"),
        &golden.join("blobs"),
        &[Ok(recording(candidate))],
        xtask::compare::StaleCheck::Fail,
        Some(&report),
        false,
        versions,
        keep,
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

/// `--keep DIR`: a case that differs has its candidate run written as a
/// recording; a case that matches has none.
#[test]
fn comparator_golden_keeps_the_candidate_run_of_a_differing_case() {
    let dir = tempfile::tempdir().unwrap();
    repo(dir.path(), "");
    let keep = dir.path().join("kept");
    let stdout = "{\"ok\":true,\"summary\":{\"rules\":4}}\n";
    let (passed, _) = run_kept(dir.path(), stdout, ("0.23.0", "0.23.0"), Some(&keep));
    assert!(!passed);
    let kept = Recording::read(&keep.join("cases").join(ID), &keep.join("blobs")).unwrap();
    assert_eq!(kept.stdout, stdout.as_bytes());
    let again = dir.path().join("kept-again");
    let same = "{\"ok\":true,\"summary\":{\"rules\":3}}\n";
    let (passed, _) = run_kept(dir.path(), same, ("0.23.0", "0.23.0"), Some(&again));
    assert!(passed);
    assert!(!again.join("cases").join(ID).exists());
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

/// One part of a partitioned run (`--partition K/N --unused FILE`): an entry
/// that applied to none of the part's cases does not fail it, but is written
/// to FILE, for the gather that finds it stale when every part lists it.
#[test]
fn comparator_golden_part_writes_its_unused_entries_instead_of_failing() {
    let dir = tempfile::tempdir().unwrap();
    repo(dir.path(), &entry("/summary/rules", "3", "4"));
    let golden = dir.path().join("tests/golden");
    let unused = dir.path().join("unused.json");
    let part = |candidate: &str| {
        xtask::compare::golden(
            dir.path(),
            &golden.join("cases"),
            &golden.join("blobs"),
            &[Ok(recording(candidate))],
            xtask::compare::StaleCheck::Write(Some(&unused)),
            None,
            false,
            ("0.23.0", "0.23.0"),
            None,
        )
        .expect("the comparison runs")
    };
    // The entry applies: nothing is unused.
    assert!(part("{\"ok\":true,\"summary\":{\"rules\":4}}\n"));
    let listed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&unused).unwrap()).unwrap();
    assert_eq!(listed, serde_json::json!([]));
    // It applies to no case of this part: listed, and the part still passes.
    assert!(part("{\"ok\":true,\"summary\":{\"rules\":3}}\n"));
    let listed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&unused).unwrap()).unwrap();
    assert_eq!(listed[0]["entry"], 1);
    assert_eq!(listed[0]["case"], "info/json/*");
    // A difference still fails the part.
    assert!(!part("{\"ok\":true,\"summary\":{\"rules\":5}}\n"));
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

/// `golden check --recordings DIR` against a preview's recordings
/// (`golden record --out DIR`): a case the preview lacks fails on its own,
/// the others are still compared and reported, and the ledger, the committed
/// oracle's, finds no stale entry in a preview run (`complete` false).
#[test]
fn comparator_golden_against_a_preview_reports_each_missing_case() {
    let dir = tempfile::tempdir().unwrap();
    repo(dir.path(), &entry("/summary/rules", "1", "4"));
    let preview = dir.path().join("target/golden-next");
    std::fs::create_dir_all(preview.join("blobs")).unwrap();
    recording("{\"ok\":true,\"summary\":{\"rules\":4}}\n")
        .write(&preview.join("cases").join(ID), &preview.join("blobs"))
        .unwrap();
    let mut other = recording("{}\n");
    other.case.id = "info/json/none/other".into();
    let report = dir.path().join("preview.json");
    let passed = xtask::compare::golden(
        dir.path(),
        &preview.join("cases"),
        &preview.join("blobs"),
        &[
            Ok(recording("{\"ok\":true,\"summary\":{\"rules\":4}}\n")),
            Ok(other),
        ],
        xtask::compare::StaleCheck::Skip,
        Some(&report),
        false,
        ("0.28.1", "0.28.1"),
        None,
    )
    .expect("a missing recording fails its case, not the run");
    assert!(!passed);
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(report).unwrap()).unwrap();
    assert_eq!(report["cases"][0]["case"], ID);
    assert_eq!(report["cases"][0]["equal"], true);
    assert!(
        report["stale"].as_array().is_none_or(Vec::is_empty),
        "{report}"
    );
}

/// The three preview flags belong to their commands: `--oracle` to `record`
/// and `lock`, `--out` to `record` (and outside tests/golden), `--recordings`
/// to `check` and `diff`. Each misuse is a usage error before anything runs.
#[test]
fn golden_refuses_the_preview_flags_where_they_do_not_belong() {
    // Absolute paths: cargo runs this test in xtask/, not at the repository's root.
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the repository")
        .to_path_buf();
    let path = |p: &str| repo.join(p).to_string_lossy().into_owned();
    let next = path("tests/golden/ORACLE.next");
    let out = tempfile::tempdir().unwrap();
    let out = out.path().to_string_lossy().into_owned();
    let inside = path("tests/golden/cases/../next");
    let usage = std::process::ExitCode::from(2);
    for args in [
        vec!["check", "--oracle", &next],
        vec!["diff", "--out", &out],
        vec!["lock", "--out", &out],
        vec!["record", "--recordings", &out],
        vec!["coverage", "--oracle", &next],
        // A preview oracle never overwrites the committed recordings.
        vec!["record", "--oracle", &next],
        vec!["record", "--out", &inside],
        // A preview's recordings carry their oracle: DIR/ORACLE.
        vec!["check", "--recordings", &out],
    ] {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        assert_eq!(xtask::golden::main(&args), usage, "{args:?}");
    }
}

/// The committed preview oracle parses, and its requirements pin its wheel
/// by that wheel's hash alone (`golden lock --oracle tests/golden/ORACLE.next`).
#[test]
fn the_preview_oracle_and_its_requirements_agree() {
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/golden");
    let (oracle, dir) = xtask::golden::oracle::Oracle::read_file(&golden.join("ORACLE.next"))
        .expect("tests/golden/ORACLE.next");
    assert_eq!(oracle.version, "0.28.1");
    assert_eq!(oracle.requirements, "oracle-requirements.next.txt");
    // A Windows checkout may hold the file with CRLF line endings.
    let requirements = std::fs::read_to_string(dir.join(&oracle.requirements))
        .unwrap()
        .replace("\r\n", "\n");
    oracle.check_requirements(&requirements).unwrap();
    assert!(requirements.starts_with(
        "# Generated by `cargo xtask golden lock` from tests/golden/ORACLE.next: never edit.\n"
    ));
}

/// `cassettes record` and `mcp record` take the same oracle file: each reads
/// it before anything runs, and a bad command line installs nothing.
#[test]
fn cassettes_and_mcp_record_take_an_oracle_file() {
    let args = |list: &[&str]| -> Vec<String> { list.iter().map(|a| (*a).to_owned()).collect() };
    let missing = tempfile::tempdir().unwrap();
    let missing = missing.path().join("ORACLE.none");
    let missing = missing.to_string_lossy();

    assert_eq!(
        xtask::cassettes::run(&args(&["record", "--all", "--oracle"])).unwrap(),
        2
    );
    assert_eq!(
        xtask::cassettes::run(&args(&["record", "--all", "--nope"])).unwrap(),
        2
    );
    let error = xtask::cassettes::run(&args(&["record", "--all", "--oracle", &missing]))
        .unwrap_err()
        .to_string();
    assert!(error.contains("ORACLE.none"), "{error}");

    let error = xtask::mcp::run(&args(&["record", "--python", "py", "--oracle", &missing]))
        .unwrap_err()
        .to_string();
    assert!(error.contains("not both"), "{error}");
    let error = xtask::mcp::run(&args(&["record"])).unwrap_err().to_string();
    assert!(error.contains("--oracle FILE"), "{error}");
    let error = xtask::mcp::run(&args(&["record", "--oracle", &missing]))
        .unwrap_err()
        .to_string();
    assert!(error.contains("ORACLE.none"), "{error}");
}
