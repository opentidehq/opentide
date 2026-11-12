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

/// `setup skills discover` and `setup skills show` (UC-4.1, #831): the
/// network refused, and the catalogue served from its cassette
/// (`tests/cassettes/skills/manifest.json`), the requests checked against it.
#[test]
fn skills_catalogue_cases_are_the_oracles() {
    check(&["setup.skills.discover", "setup.skills.show"], 20);
}

#[test]
fn explain_cases_are_the_oracles() {
    check(&["explain"], 12);
}

#[test]
fn validate_cases_are_the_oracles() {
    check(&["validate"], 100);
}

/// `tui`'s refusals (UC-3.6b, #947): `usage_tui_needs_tty` wherever nobody
/// can use the UI, and its help. The UI itself is recorded nowhere (a
/// full-screen app redraws on a timer).
#[test]
fn tui_cases_are_the_oracles() {
    check(&["tui"], 6);
}

/// `validate query` offline (UC-3.5b, #927) and `--live` (UC-4.2c, #832;
/// UC-4.6, #979): Splunk's, Carbon Black Cloud's and Elastic's tenants served
/// from their cassettes.
#[test]
fn validate_query_cases_are_the_oracles() {
    check(&["validate.query"], 20);
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

/// `new threat|objective|rule` (UC-3.5d, #933): the object written, the
/// templates and schemas generated first, the failures. One test per family,
/// so nextest runs them side by side: each case generates the schemas.
#[test]
fn new_threat_cases_are_the_oracles() {
    check(&["new.threat"], 23);
}

#[test]
fn new_objective_cases_are_the_oracles() {
    check(&["new.objective"], 8);
}

#[test]
fn new_rule_cases_are_the_oracles() {
    check(&["new.rule"], 11);
}

/// `new rule --objective` takes the UUID of an existing objective in any
/// case: the catalogue's UUIDs are compared in lower case, so an upper-case
/// one is the same object, not `reference_not_found`.
#[test]
fn new_finds_a_reference_whatever_the_case_of_its_uuid() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("vscode", &ws);
    for (uuid, name) in [
        (
            "04149254-2A5B-4C1E-9F0E-3C1D2B5A6E7F",
            "Upper Case Reference",
        ),
        (
            "04149254-2a5b-4c1e-9f0e-3c1d2b5a6e7f",
            "Lower Case Reference",
        ),
    ] {
        let (code, stdout) = run_at(
            &ws,
            &["--json", "new", "rule", "--name", name, "--objective", uuid],
        );
        assert_eq!(code, 0, "{stdout}");
        let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(document["ok"], true, "{stdout}");
    }
    // An objective that is not there is still refused.
    let (code, stdout) = run_at(
        &ws,
        &[
            "--json",
            "new",
            "rule",
            "--name",
            "Missing",
            "--objective",
            "04149254-2A5B-4C1E-9F0E-3C1D2B5A6E70",
        ],
    );
    assert_eq!(code, 2, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(document["failure"]["code"], "reference_not_found");
}

/// `new` warns when the file it wrote does not match the `lint.toml`
/// `[filenames]` pattern (the kind's own table first), naming the key, and
/// not when it does.
#[test]
fn new_warns_when_the_file_breaks_the_lint_filename_pattern() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus", &ws);
    let lint = ws.join(".opentide/configurations/lint.toml");
    std::fs::write(
        &lint,
        "[filenames]\npattern = \"rule-.*\"\n\n[filenames.threats]\npattern = \"tv-.*\"\n",
    )
    .unwrap();
    let (code, stdout) = run_at(
        &ws,
        &["--json", "new", "threat", "--name", "Credential Dumping"],
    );
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["warnings"][0],
        "credential-dumping.yaml does not match lint.toml [filenames.threats].pattern tv-.*; \
         rename it before opentide lint runs",
        "{stdout}"
    );
    // A name the pattern takes: no warning.
    let (code, stdout) = run_at(&ws, &["--json", "new", "threat", "--name", "TV Dumping"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let warnings = document["warnings"].as_array().unwrap();
    assert!(!warnings.is_empty(), "{stdout}");
    assert!(
        warnings.iter().all(|warning| !warning
            .as_str()
            .unwrap()
            .contains("does not match lint.toml")),
        "{stdout}"
    );
}

/// The replay reads `RUST_COMMANDS` as the dispatch does: every entry, with
/// its `requires`, so it tolerates a refusal only of a run the table does not
/// cover (a bare `generate`) and fails on any other.
#[test]
fn the_replay_tolerates_a_refusal_only_where_rust_commands_does_not_cover_the_run() {
    let words =
        |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_owned).collect() };
    let table = replay::rust_commands();
    assert_eq!(table["validate"], Vec::<String>::new());
    assert_eq!(table["deploy"], ["--dry-run"]);
    assert_eq!(
        table["generate"],
        ["schemas", "templates", "vocabs", "snippets"]
    );
    assert_eq!(table["generate docs rules"], Vec::<String>::new());
    assert!(replay::covers(
        "generate",
        &words("--json generate schemas")
    ));
    assert!(!replay::covers("generate", &words("--json generate")));
    assert!(!replay::covers("generate", &words("generate --help")));
    assert!(!replay::covers("generate", &words("generate -- schemas")));
    assert!(replay::covers("new threat", &words("new threat --name x")));
    assert!(replay::covers("doctor", &words("doctor --offline")));
    assert!(!replay::covers("doctor", &words("doctor")));
    assert!(replay::covers("setup", &words("setup --plan")));
    assert!(replay::covers("setup vscode", &words("setup vscode")));
    assert!(!replay::covers(
        "setup skills",
        &words("setup skills --claude-code")
    ));
    // A multi-line entry, and one the parser cannot read, which is no table.
    let source = "x = 1\nRUST_COMMANDS: dict[tuple[str, ...], RustCommand] = {\n    \
                  (\"a\",): RustCommand(launch=RUST_CLI),\n    (\"b\", \"c\"): RustCommand(\n        \
                  launch=RUST_CLI, requires=(\"--x\", \"y\")\n    ),\n}\n";
    let parsed = replay::parse_rust_commands(source);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed["b c"], ["--x", "y"]);
    let unreadable = source.replace("(\"a\",)", "KEY");
    assert!(std::panic::catch_unwind(|| replay::parse_rust_commands(&unreadable)).is_err());
}

/// `generate <phase>...` (UC-3.5d, #933): the `schemas`, `templates`,
/// `vocabs` and `snippets` phases run in Rust; the full pipeline is refused
/// with `engine_not_ported` (Python runs it alone under `compare`).
#[test]
fn generate_phase_cases_are_the_oracles() {
    let refused = replay::refused();
    check(&["generate"], 4);
    let refused = replay::refused() - refused;
    if std::env::var_os("OPENTIDE_REPLAY_FILTER").is_none() {
        assert!(refused >= 8, "only {refused} refused");
    }
}

/// `setup` and its file-writing subcommands (UC-3.6, #828): plan mode and
/// non-interactive runs with the files written, and the wizard's refusals.
#[test]
fn setup_cases_are_the_oracles() {
    check(
        &[
            "setup",
            "setup.env",
            "setup.hooks",
            "setup.mcp",
            "setup.platforms",
            "setup.repo",
            "setup.vscode",
        ],
        48,
    );
}
