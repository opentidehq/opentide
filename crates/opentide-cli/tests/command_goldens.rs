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
/// `.tmpXXXXXX`) let a replay pass where the real compare differed. Where
/// `/tmp` is a link to a longer folder (macOS), the name is shortened to
/// keep the canonical root, the path the replay reads, that length.
#[test]
fn a_case_root_is_as_long_as_the_golden_checks() {
    let root = replay::case_root();
    let name = root.path().file_name().unwrap().to_str().unwrap();
    let canonical = std::fs::canonicalize(root.path()).unwrap();
    let (prefix, random) = replay::root_name(canonical.parent().unwrap());
    assert!(
        name.starts_with(prefix) && name.len() == prefix.len() + random,
        "{name}"
    );
    assert_eq!(root.path().parent().unwrap(), std::path::Path::new("/tmp"));
    if canonical.parent() == Some(std::path::Path::new("/tmp")) {
        assert_eq!((prefix, random), ("golden-", 6));
    } else if cfg!(unix) {
        assert_eq!(
            canonical.as_os_str().len(),
            "/tmp/golden-XXXXXX".len(),
            "{}",
            canonical.display()
        );
    }
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

/// `deploy` (UC-3.1c, #896; UC-4.6, #979): the dry runs, and the deploys
/// that send, each platform's tenant served from its cassette and the
/// deployment state it writes compared with the oracle's.
#[test]
fn deploy_cases_are_the_oracles() {
    check(&["deploy"], 60);
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

/// `query` (UC-4.2c, #832): its refusals and usage errors, the unset
/// credentials of each platform, and the runs on the stand-in tenants
/// (`tenants`) answered by their cassettes (`tests/cassettes/golden/`), as
/// a table, JSON lines, CSV and the JSON document, the requests checked
/// against each cassette.
#[test]
fn query_cases_are_the_oracles() {
    check(&["query"], 60);
}

/// `deploy migrate-state` (UC-4.4, #834): ids moved into shards, a rule
/// refused, a clean run.
#[test]
fn deploy_migrate_state_cases_are_the_oracles() {
    check(&["deploy.migrate-state"], 16);
}

/// `share` and its subcommands (UC-4.4b, #834): the MISP stand-in's
/// cassettes for a push and a retract, and the runs that stop before any
/// request; `share push --changed` on the git checkouts of a push (UC-4.4e).
#[test]
fn share_cases_are_the_oracles() {
    check(
        &[
            "share",
            "share.push",
            "share.preview",
            "share.status",
            "share.retract",
            "share.targets",
        ],
        120,
    );
}

/// `generate extract defender` and `generate extract elastic` (UC-4.4b,
/// #834): the stand-in tenants' cassettes, the files written under
/// `Imported/` and Defender's deployment state; `generate extract sentinel`'s
/// runs without a tenant (UC-4.4e; its tenant's run is
/// `tests/extract_sentinel.rs`').
#[test]
fn generate_extract_cases_are_the_oracles() {
    check(
        &[
            "generate.extract.defender",
            "generate.extract.elastic",
            "generate.extract.sentinel",
        ],
        30,
    );
}

/// The rules `generate extract elastic` writes (#834) are serde-saphyr's
/// YAML, formatted differently from PyYAML's (`APPROVED_DIFFS.toml`): each
/// file a stand-in tenant's case writes loads to the oracle's data, every
/// value and every key in the oracle's order.
#[test]
fn extracted_elastic_rules_load_as_the_oracles_data() {
    use opentide_compare::FileState;
    let as_data = |path: &str, bytes: &[u8]| {
        let text = std::str::from_utf8(bytes).unwrap();
        let loaded = opentide_schema::node::load(text)
            .unwrap_or_else(|error| panic!("{path}: {error:?}\n{text}"));
        opentide_compile::json::Json::from_node(loaded.root().unwrap()).to_compact()
    };
    let cases = replay::repo().join("tests/golden/cases/generate.extract.elastic");
    let ledger = replay::ledger();
    let mut usage = opentide_compare::ledger::Usage::default();
    let mut compared = 0;
    for mode in std::fs::read_dir(&cases).unwrap() {
        let mode = mode.unwrap().path();
        let Ok(variants) = std::fs::read_dir(mode.join("tenants")) else {
            continue;
        };
        for dir in variants {
            let dir = dir.unwrap().path();
            let id = dir.strip_prefix(&cases).unwrap().display().to_string();
            // The comparison under the ledger is `generate_extract_cases_are_the_oracles`'.
            let _ = replay::replay(&id, &dir, &ledger, &mut usage);
            let outcome: toml::Table = std::fs::read_to_string(dir.join("outcome.toml"))
                .unwrap()
                .parse()
                .unwrap();
            let candidate = replay::last_files();
            for (path, state) in replay::recorded_files(&dir, &outcome) {
                let FileState::Written { bytes, .. } = state else {
                    continue;
                };
                if !path.starts_with("ws/Imported/") {
                    continue;
                }
                let Some(FileState::Written { bytes: written, .. }) = candidate.get(&path) else {
                    panic!("{id}: Rust did not write {path}");
                };
                assert_eq!(
                    as_data(&path, written),
                    as_data(&path, &bytes),
                    "{id}: {path} loads to other data than the oracle's"
                );
                compared += 1;
            }
        }
    }
    assert!(compared >= 12, "only {compared} files compared");
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
/// its `requires`, `refuses` and `platforms`, so it tolerates a refusal only
/// of a run the table does not cover (a bare `generate`, `query` of a rule)
/// and fails on any other.
#[test]
fn the_replay_tolerates_a_refusal_only_where_rust_commands_does_not_cover_the_run() {
    let words =
        |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_owned).collect() };
    let table = replay::rust_commands();
    assert_eq!(table["validate"], replay::Coverage::default());
    assert_eq!(table["deploy"].requires, Vec::<String>::new());
    assert_eq!(table["deploy"].offline, ["--dry-run"]);
    assert!(table["deploy"].platforms.contains(&"sysdig".to_owned()));
    assert!(replay::covers("deploy", &words("deploy --dry-run --all")));
    assert!(replay::covers(
        "deploy",
        &words("deploy --platform sysdig --all")
    ));
    assert!(!replay::covers(
        "deploy",
        &words("deploy --strategy PREVIEW --all")
    ));
    assert!(!replay::covers("deploy", &words("deploy -- --dry-run")));
    assert_eq!(
        table["generate"].requires,
        ["schemas", "templates", "vocabs", "snippets"]
    );
    assert_eq!(table["generate docs rules"], replay::Coverage::default());
    assert_eq!(table["setup"].refuses, ["--skills", "--plugin"]);
    // A tuple named by its constant, and a scope of its own.
    assert_eq!(table["query"].refuses, ["--rule", "--file"]);
    assert!(table["query"].platforms.contains(&"elastic".to_owned()));
    assert_eq!(table["validate query"].platform_scope, ["--live"]);
    assert!(replay::covers(
        "generate",
        &words("--json generate schemas")
    ));
    assert!(!replay::covers("generate", &words("--json generate")));
    assert!(!replay::covers("generate", &words("generate --help")));
    assert!(!replay::covers("generate", &words("generate -- schemas")));
    assert!(replay::covers("new threat", &words("new threat --name x")));
    assert!(replay::covers("doctor", &words("doctor --offline")));
    // doctor's network checks run on Rust too (UC-4.4, #834).
    assert!(replay::covers("doctor", &words("doctor")));
    assert!(replay::covers(
        "deploy migrate-state",
        &words("deploy migrate-state")
    ));
    assert!(replay::covers("setup", &words("setup --plan")));
    assert!(!replay::covers("setup", &words("setup --skills")));
    assert!(replay::covers("setup vscode", &words("setup vscode")));
    assert!(!replay::covers(
        "setup skills",
        &words("setup skills --claude-code")
    ));
    assert!(replay::covers(
        "query",
        &words("query --platform elastic q")
    ));
    assert!(replay::covers(
        "query",
        &words("query --platform=crowdstrike q")
    ));
    // Every platform with a query runner, Splunk too since UC-4.3 (#833).
    assert!(replay::covers("query", &words("query --platform splunk q")));
    assert!(!replay::covers("query", &words("query q")));
    assert!(!replay::covers(
        "query",
        &words("query --platform elastic --rule r")
    ));
    assert!(replay::covers(
        "validate query",
        &words("validate query --file q.kql")
    ));
    // Every platform's live validation is Rust's since UC-4.6 (#979); a
    // `--live` run that names no platform stays Python's.
    assert!(replay::covers(
        "validate query",
        &words("validate query --live --platform elastic")
    ));
    assert!(!replay::covers(
        "validate query",
        &words("validate query --live")
    ));
    assert!(replay::covers(
        "validate query",
        &words("validate query --live --platform sysdig")
    ));
    // A multi-line entry, a tuple named by a constant, and one the parser
    // cannot read, which is no table.
    let source = "x = 1\nPLATFORMS: tuple[str, ...] = (\n    \"p\",\n    \"q\",\n)\n\
                  RUST_COMMANDS: dict[tuple[str, ...], RustCommand] = {\n    \
                  (\"a\",): RustCommand(launch=RUST_CLI),\n    (\"b\", \"c\"): RustCommand(\n        \
                  launch=RUST_CLI, requires=(\"--x\", \"y\"),\n        refuses=(\"--z\",),\n        \
                  platforms=PLATFORMS,\n    ),\n}\n";
    let parsed = replay::parse_rust_commands(source);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed["a"], replay::Coverage::default());
    assert_eq!(parsed["b c"].requires, ["--x", "y"]);
    assert_eq!(parsed["b c"].refuses, ["--z"]);
    assert_eq!(parsed["b c"].platforms, ["p", "q"]);
    let unreadable = source.replace("(\"a\",)", "KEY");
    assert!(std::panic::catch_unwind(|| replay::parse_rust_commands(&unreadable)).is_err());
    let undefined = source.replace("platforms=PLATFORMS", "platforms=NOWHERE");
    assert!(std::panic::catch_unwind(|| replay::parse_rust_commands(&undefined)).is_err());
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

#[test]
fn a_case_root_keeps_the_recorded_length_behind_a_longer_tmp() {
    use std::path::Path;
    // Linux's `/tmp`: the name `cargo xtask golden check` gives.
    assert_eq!(replay::root_name(Path::new("/tmp")), ("golden-", 6));
    // macOS's `/tmp` is `/private/tmp`: `/private/tmp/goXXX` is as long as
    // `/tmp/golden-XXXXXX`, so paths wrap where the recordings wrap.
    let (prefix, random) = replay::root_name(Path::new("/private/tmp"));
    assert_eq!(
        "/private/tmp/".len() + prefix.len() + random,
        "/tmp/golden-XXXXXX".len()
    );
    assert!(random >= 3);
    // No room for three random characters: the recorded name, as before.
    assert_eq!(
        replay::root_name(Path::new("/a/very/long/temporary/folder")),
        ("golden-", 6)
    );
}
