//! The commands of UC-3.5 (#827) against the oracle's recordings: every
//! recorded case on the static fixtures, replayed in-process
//! (`common/replay.rs`) and compared under `APPROVED_DIFFS.toml`. The
//! generated fixtures (`fault`, `heavy-small`) are `cargo xtask golden check
//! --engine compare`'s. `OPENTIDE_REPLAY_FILTER=<part of a case id>` narrows a
//! run while debugging.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken recording is a failure"
)]

#[path = "common/replay.rs"]
mod replay;

fn check(commands: &[&str], at_least: usize) {
    let (problems, ran) = replay::replay_commands(commands, true);
    if std::env::var_os("OPENTIDE_REPLAY_FILTER").is_none() {
        assert!(ran >= at_least, "only {ran} cases found");
    }
    assert!(
        problems.is_empty(),
        "{} problem(s):\n\n{}",
        problems.len(),
        problems.join("\n\n")
    );
}

/// A replayed case's root is named and placed as `cargo xtask golden
/// check` places it (`/tmp/golden-XXXXXX`): a frame wraps a message by the
/// length of the path in it, so a root of another length (`tempfile`'s
/// `.tmpXXXXXX`) let a replay pass where the real compare differed.
#[test]
fn a_case_root_is_as_long_as_the_golden_checks() {
    let root = replay::case_root();
    let name = root.path().file_name().unwrap().to_str().unwrap();
    assert!(
        name.starts_with("golden-") && name.len() == "golden-".len() + 6,
        "{name}"
    );
    assert_eq!(root.path().parent().unwrap(), std::path::Path::new("/tmp"));
}

#[test]
fn explain_cases_are_the_oracles() {
    check(&["explain"], 12);
}

#[test]
fn validate_cases_are_the_oracles() {
    check(&["validate"], 100);
}

/// `validate --watch` in `plain` mode: one pass's frames and outcome line,
/// then Ctrl-C (already pressed here) stops it with exit 0 and nothing on
/// stderr.
#[test]
fn a_watch_shows_a_pass_and_ctrl_c_exits_0() {
    use opentide_cli::env::Env;
    use opentide_cli::logging::Sink;
    use opentide_cli::{Host, run};
    use std::sync::{Arc, Mutex};
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus-typo", &ws);
    let interrupt = opentide_cli::app::Interrupt::default();
    interrupt.request();
    let sink: Sink = Arc::new(Mutex::new(replay::Buffer::default()));
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.clone()),
        width: None,
        interrupt,
    };
    let argv: Vec<String> = ["validate", "--watch"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let env = Env::from_pairs([("HOME".to_owned(), ws.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), replay::Buffer::default());
    let code = run(&argv, &env, &host, &mut out, &mut err);
    let stdout = String::from_utf8(out).unwrap();
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.starts_with("error[vocab_unknown]: 'high' is not a alert severity value\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("\n✗ 1 error in 1 file · 1 fixable with --fix · 12 objects checked · "),
        "{stdout}"
    );
    assert!(err.0.lock().unwrap().is_empty());
}

#[test]
fn lint_cases_are_the_oracles() {
    check(&["lint"], 50);
}

#[test]
fn commands_cases_are_the_oracles() {
    check(&["commands"], 10);
}

/// Runs `words` in-process at `ws` (not a terminal); the exit code and
/// stdout.
fn run_at(ws: &std::path::Path, words: &[&str]) -> (i32, String) {
    use opentide_cli::env::Env;
    use opentide_cli::logging::Sink;
    use opentide_cli::{Host, run};
    use std::sync::{Arc, Mutex};
    let sink: Sink = Arc::new(Mutex::new(replay::Buffer::default()));
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
    let home = ws.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs([("HOME".to_owned(), home.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), replay::Buffer::default());
    let code = run(&argv, &env, &host, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap())
}

/// The tide corpus with one rule's `response` on one line, where the
/// misspelt `alert_severity` (a safe fix) and an unknown key (no fix) are
/// two findings on the same line.
fn two_findings_on_one_line() -> (tempfile::TempDir, std::path::PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus", &ws);
    let path = ws.join("Objects/Detection Rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    let block = "response:\n  alert_severity: High\n";
    assert_eq!(text.matches(block).count(), 1);
    std::fs::write(
        &path,
        text.replace(block, "response: {alert_severity: high, bogus: 1}\n"),
    )
    .unwrap();
    (scratch, ws)
}

/// `--fix --dry-run` shows the diff and leaves out the frame of the finding
/// it would fix, and only that one: the other finding on the same line is
/// still shown.
#[test]
fn a_dry_run_hides_the_findings_it_would_fix_and_no_other() {
    let (_scratch, ws) = two_findings_on_one_line();
    let (code, stdout) = run_at(&ws, &["validate", "--fix", "--dry-run"]);
    assert_eq!(code, 1, "{stdout}");
    assert!(
        stdout.contains("\n+response: {alert_severity: High, bogus: 1}\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("error[schema_validation]: response.bogus: Extra inputs are not permitted"),
        "{stdout}"
    );
    assert!(!stdout.contains("error[vocab_unknown]"), "{stdout}");
    // Without --dry-run's diff, both are frames.
    let (_, plain) = run_at(&ws, &["validate"]);
    assert!(plain.contains("error[vocab_unknown]"), "{plain}");
    assert!(plain.contains("error[schema_validation]"), "{plain}");
}

/// A run narrowed to objects that do not exist fails with `scope_no_match`;
/// it is not the empty workspace's pass, which suggests `opentide setup`.
#[test]
fn a_scoped_run_that_matches_nothing_is_not_an_empty_workspace() {
    let scratch = tempfile::tempdir().unwrap();
    let dir = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    std::fs::create_dir_all(&dir).unwrap();
    let (code, stdout) = run_at(&dir, &["--json", "validate", "--type", "rule"]);
    assert_eq!(code, 1, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(document["message"], "Validation failed");
    assert_eq!(document["report"]["issues"][0]["code"], "scope_no_match");
    assert!(!stdout.contains("setup"), "{stdout}");
    // Unscoped, the same folder is a pass that names what it did not find.
    let (code, stdout) = run_at(&dir, &["--json", "validate"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["message"],
        "Validation passed, but no detection objects were found under ./"
    );
    assert_eq!(
        document["next_actions"][0]["command"],
        "opentide --json setup"
    );
}
