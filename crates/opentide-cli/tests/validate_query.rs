//! Offline `validate query` (UC-3.5b, #927) beyond its recorded cases:
//! query files, the scoping flags and their refusals, files that cannot be
//! read, `--queries warn` and `--strict`, the options handed down from
//! `validate`, the load-error log lines and `--live`'s hand-back. Each runs
//! in-process on a copy of the tide corpus (`common/replay.rs`).

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken fixture is a failure"
)]

#[path = "common/replay.rs"]
mod replay;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};
use serde_json::Value;

const SENTINEL_RULE: &str = "Objects/Detection Rules/rule-0001-sentinel-kql.yaml";
const SENTINEL_UUID: &str = "00000000-0000-4000-8003-000000000001";

/// A copy of the tide corpus; the directory that holds it and the workspace.
fn corpus() -> (tempfile::TempDir, PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus", &ws);
    (scratch, ws)
}

/// What a run printed: exit code, stdout and stderr (log lines included).
struct Ran {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Ran {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|_| panic!("{}", self.stdout))
    }
}

/// Runs `opentide <words>` from `cwd` with `extra` variables.
fn opentide(cwd: &Path, words: &[&str], extra: &[(&str, &str)]) -> Ran {
    let log = replay::Buffer::default();
    let sink: Sink = Arc::new(Mutex::new(log.clone()));
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(cwd.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
    let home = cwd.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut pairs = vec![("HOME".to_owned(), home.display().to_string())];
    pairs.extend(
        extra
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
    );
    let env = Env::from_pairs(pairs);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run(&argv, &env, &host, &mut out, &mut err);
    let mut stderr = String::from_utf8(err).unwrap();
    stderr.push_str(&String::from_utf8(log.0.lock().unwrap().clone()).unwrap());
    Ran {
        code,
        stdout: String::from_utf8(out).unwrap(),
        stderr,
    }
}

fn failure_code(document: &Value) -> &str {
    document["failure"]["code"].as_str().unwrap()
}

#[test]
fn a_query_file_is_checked_in_the_language_of_its_extension() {
    let (_scratch, ws) = corpus();
    std::fs::write(
        ws.join("hunt.KQL"),
        "SecurityEvent\n| where EventID == 4625\n",
    )
    .unwrap();
    std::fs::write(ws.join("broken.spl"), "index=main | stats count by\n").unwrap();
    let ran = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--file",
            "hunt.KQL",
            "--file",
            "broken.spl",
        ],
        &[],
    );
    let document = ran.json();
    assert_eq!(ran.code, 1, "{}", ran.stdout);
    assert_eq!(failure_code(&document), "issues_found");
    assert_eq!(document["scope"], "selected");
    assert_eq!(document["queries_validated"], 2);
    let queries = document["queries"].as_array().unwrap();
    assert_eq!(queries[0]["path"], "hunt.KQL");
    assert_eq!(queries[0]["language"], "kql");
    assert_eq!(queries[0]["platform"], Value::Null);
    assert_eq!(queries[0]["field_path"], serde_json::json!([]));
    assert_eq!(
        (queries[0]["line"].clone(), queries[0]["column"].clone()),
        (1.into(), 1.into())
    );
    assert_eq!(queries[1]["language"], "spl");
    assert!(queries[1]["errors"].as_u64().unwrap() > 0);
    // No platform is named, so none is listed.
    assert_eq!(document["platforms"], serde_json::json!([]));
    let diagnostics = document["diagnostics"].as_array().unwrap();
    assert!(diagnostics.iter().all(|item| item["path"] == "broken.spl"));
    assert_eq!(
        document["next_actions"][1]["command"],
        "opentide --json validate query --file hunt.KQL --file broken.spl"
    );
    // Query files alone read no rule: no object file is loaded or logged.
    assert!(ran.stderr.is_empty(), "{}", ran.stderr);
}

#[test]
fn a_platform_s_profile_applies_to_its_query_files_and_others_are_refused() {
    let (_scratch, ws) = corpus();
    std::fs::write(ws.join("a.kql"), "DeviceProcessEvents | take 1\n").unwrap();
    std::fs::write(ws.join("b.spl"), "index=main\n").unwrap();
    let ran = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--platform",
            "defender_for_endpoint",
            "--file",
            "a.kql",
        ],
        &[],
    );
    assert_eq!(ran.code, 0, "{}", ran.stdout);
    assert_eq!(
        ran.json()["platforms"],
        serde_json::json!(["defender_for_endpoint"])
    );
    let refused = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--platform",
            "sentinel",
            "--file",
            "b.spl",
        ],
        &[],
    );
    let document = refused.json();
    assert_eq!(refused.code, 2);
    assert_eq!(failure_code(&document), "usage_error");
    assert_eq!(document["failure"]["argument"], "--file");
    assert_eq!(
        document["message"],
        "--platform sentinel checks kql: not b.spl (spl)"
    );
    assert_eq!(document["mode"], "offline");
}

#[test]
fn a_missing_or_empty_query_file_is_refused_or_fails() {
    let (_scratch, ws) = corpus();
    let missing = opentide(
        &ws,
        &["--json", "validate", "query", "--file", "nope.kql"],
        &[],
    );
    let document = missing.json();
    assert_eq!(missing.code, 2);
    assert_eq!(failure_code(&document), "usage_error");
    assert_eq!(document["unmatched"], serde_json::json!(["nope.kql"]));
    std::fs::write(ws.join("empty.esql"), "  \n").unwrap();
    std::fs::write(ws.join("latin.eql"), b"process where \xe9\n").unwrap();
    let unreadable = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--file",
            "empty.esql",
            "--file",
            "latin.eql",
        ],
        &[],
    );
    let document = unreadable.json();
    assert_eq!(unreadable.code, 1);
    assert_eq!(failure_code(&document), "command_failed");
    let message = document["message"].as_str().unwrap();
    assert!(message.starts_with("Cannot check empty.esql: it holds no query; latin.eql: "));
    assert!(message.contains("not UTF-8"), "{message}");
}

#[test]
fn rule_files_are_selected_by_file_and_uuid() {
    let (_scratch, ws) = corpus();
    let by_uuid = opentide(
        &ws,
        &["--json", "validate", "query", "--uuid", SENTINEL_UUID],
        &[],
    );
    let document = by_uuid.json();
    assert_eq!(by_uuid.code, 0, "{}", by_uuid.stdout);
    assert_eq!(document["scope"], "selected");
    assert_eq!(document["queries"][0]["path"], SENTINEL_RULE);
    assert_eq!(document["queries_validated"], 1);
    let unmatched = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--file",
            "nothing.yaml",
            "--uuid",
            "abc",
        ],
        &[],
    );
    let document = unmatched.json();
    assert_eq!(unmatched.code, 1);
    assert_eq!(failure_code(&document), "command_failed");
    assert_eq!(
        document["unmatched"],
        serde_json::json!(["nothing.yaml", "abc"])
    );
    assert_eq!(
        document["message"],
        "No rule file directly in Objects/Detection Rules matched: nothing.yaml, abc"
    );
    // A rule with no query of the platform asked for: nothing is checked.
    let skipped = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--platform",
            "splunk",
            "--file",
            SENTINEL_RULE,
        ],
        &[],
    );
    let document = skipped.json();
    assert_eq!(skipped.code, 0);
    assert_eq!(document["status"], "skipped");
    assert_eq!(
        document["message"],
        "No selected rule has a splunk query the engine checks"
    );
    assert_eq!(
        document["summary"],
        serde_json::json!({"queries": 0, "files": 0})
    );
}

#[test]
fn changed_reads_the_diff_and_refuses_a_selection() {
    let (_scratch, ws) = corpus();
    let both = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--changed",
            "--uuid",
            SENTINEL_UUID,
        ],
        &[],
    );
    assert_eq!(both.code, 2);
    assert_eq!(
        both.json()["message"],
        "--changed cannot be combined with --file or --uuid"
    );
    let no_git = opentide(
        &ws,
        &["--json", "validate", "query", "--changed"],
        &[(
            "GIT_CEILING_DIRECTORIES",
            ws.parent().unwrap().to_str().unwrap(),
        )],
    );
    let document = no_git.json();
    assert_eq!(no_git.code, 1, "{}", no_git.stdout);
    assert_eq!(failure_code(&document), "command_failed");
    assert!(
        document["message"]
            .as_str()
            .unwrap()
            .starts_with("--changed needs a git checkout; no .git was found from "),
        "{document}"
    );
}

#[test]
fn queries_warn_reports_rejections_as_warnings_and_strict_fails_on_them() {
    let (_scratch, ws) = corpus();
    std::fs::write(ws.join("bad.kql"), "SecurityEvent | where\n").unwrap();
    let warned = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--file",
            "bad.kql",
            "--queries",
            "warn",
        ],
        &[],
    );
    let document = warned.json();
    assert_eq!(warned.code, 0, "{}", warned.stdout);
    assert_eq!(document["status"], "passed");
    assert_eq!(document["diagnostics"][0]["severity"], "warning");
    assert!(document["summary"]["warnings"].as_u64().unwrap() > 0);
    let plain = opentide(
        &ws,
        &[
            "validate",
            "query",
            "--file",
            "bad.kql",
            "--queries",
            "warn",
        ],
        &[],
    );
    assert!(
        plain
            .stdout
            .contains("--queries warn reports it as a warning"),
        "{}",
        plain.stdout
    );
    assert!(
        plain
            .stdout
            .contains("! 1 warning in 1 file · 1 query checked"),
        "{}",
        plain.stdout
    );
    let strict = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--file",
            "bad.kql",
            "--queries",
            "warn",
            "--strict",
        ],
        &[],
    );
    let document = strict.json();
    assert_eq!(strict.code, 1);
    assert_eq!(failure_code(&document), "issues_found");
    assert_eq!(
        document["next_actions"][1]["command"],
        "opentide --json validate query --file bad.kql --queries warn --strict"
    );
}

#[test]
fn an_unreadable_rule_file_is_a_yaml_parse_finding_and_a_log_line() {
    let (_scratch, ws) = corpus();
    let rules = ws.join("Objects/Detection Rules");
    std::fs::write(rules.join("rule-0099-broken.yaml"), "name: [unclosed\n").unwrap();
    let ran = opentide(&ws, &["--json", "validate", "query"], &[]);
    let document = ran.json();
    assert_eq!(ran.code, 1, "{}", ran.stdout);
    let first = &document["diagnostics"][0];
    assert_eq!(first["code"], "yaml_parse");
    assert_eq!(
        first["path"],
        "Objects/Detection Rules/rule-0099-broken.yaml"
    );
    assert!(
        first["message"]
            .as_str()
            .unwrap()
            .starts_with("cannot check this file's queries: ")
    );
    assert!(first["line"].is_u64() && first["column"].is_u64());
    assert_eq!(
        first["help"],
        "opentide validate reports the file; fix it, then check its queries again"
    );
    // The workspace's load error is logged, as a JSON line in --json.
    let line: Value = serde_json::from_str(ran.stderr.lines().next().unwrap()).unwrap();
    assert_eq!(line["event"], "malformed_object_yaml");
    assert_eq!(line["level"], "error");
    assert_eq!(
        line["path"],
        "Objects/Detection Rules/rule-0099-broken.yaml"
    );
}

#[test]
fn google_secops_sections_and_yaral_files_are_checked_offline() {
    let (_scratch, ws) = corpus();
    let rules = ws.join("objects/rules");
    std::fs::write(
        rules.join("secops.yaml"),
        "name: Secops rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-0000000005ec\n  schema: \
         rule::1.1\n  version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  tlp: \
         clear\ndescription: d\nconfigurations:\n  google_secops:\n    status: STAGING\n    \
         events: |\n      $a.metadata.event_type = \"USER_LOGIN\"\n      $b.metadata.event_type \
         = \"USER_LOGIN\"\n    outcome: |\n      $risk_score = 40\n    condition: |\n      $a \
         and $b\n",
    )
    .unwrap();
    let ran = opentide(
        &ws,
        &["--json", "validate", "query", "--platform", "google_secops"],
        &[],
    );
    let document = ran.json();
    assert_eq!(ran.code, 1, "{}", ran.stdout);
    let codes: Vec<&str> = document["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["code"].as_str())
        .collect();
    // Two event variables need a `match`: the assembled rule says so.
    assert!(codes.contains(&"yaral_multi_event_match"), "{codes:?}");
    std::fs::write(
        ws.join("search.yaral"),
        "metadata.event_type = \"USER_LOGIN\"\n",
    )
    .unwrap();
    let file = opentide(
        &ws,
        &["--json", "validate", "query", "--file", "search.yaral"],
        &[],
    );
    assert_eq!(file.code, 0, "{}", file.stdout);
    assert_eq!(file.json()["queries"][0]["language"], "yaral");
}

#[test]
fn bitdefender_signatures_and_yar_files_are_checked_offline_as_yara() {
    let (_scratch, ws) = corpus();
    std::fs::write(ws.join("broken.yar"), "rule A { condition: \n").unwrap();
    let broken = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--platform",
            "bitdefender",
            "--file",
            "broken.yar",
        ],
        &[],
    );
    let document = broken.json();
    assert_eq!(broken.code, 1, "{}", broken.stdout);
    assert_eq!(document["supported"], true);
    assert_eq!(document["mode"], "offline");
    assert_eq!(document["queries"][0]["language"], "yara");
    assert_eq!(document["diagnostics"][0]["code"], "yara_parse_error");
    std::fs::write(ws.join("ok.yara"), "rule A { condition: true }\n").unwrap();
    let valid = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--platform",
            "bitdefender",
            "--file",
            "ok.yara",
        ],
        &[],
    );
    assert_eq!(valid.code, 0, "{}", valid.stdout);
    assert_eq!(valid.json()["queries_validated"], 1);
}

#[test]
fn platforms_the_engine_cannot_parse_are_refused() {
    let (_scratch, ws) = corpus();
    let tenant_only = opentide(
        &ws,
        &["--json", "validate", "query", "--platform", "sentinel_one"],
        &[],
    );
    let document = tenant_only.json();
    assert_eq!(tenant_only.code, 2);
    assert_eq!(failure_code(&document), "usage_missing_option");
    assert_eq!(document["failure"]["argument"], "--live");
    let neither = opentide(
        &ws,
        &["--json", "validate", "query", "--platform", "harfanglab"],
        &[],
    );
    let document = neither.json();
    assert_eq!(neither.code, 1);
    assert_eq!(document["supported"], false);
    assert_eq!(document["valid"], Value::Null);
    assert_eq!(
        document["message"],
        "query validation not supported for harfanglab"
    );
}

#[test]
fn live_without_a_platform_is_refused_and_tenant_options_need_it() {
    let (_scratch, ws) = corpus();
    // A live check reads one platform's tenants: a run that names none is
    // refused as the oracle refuses it (UC-4.4c, #834).
    let live = opentide(&ws, &["--json", "validate", "query", "--live"], &[]);
    assert_eq!(live.code, 2);
    assert_eq!(failure_code(&live.json()), "usage_missing_option");
    assert_eq!(live.json()["failure"]["argument"], "--platform");
    assert_eq!(live.json()["mode"], "live");
    assert_eq!(live.json()["supported"], true);
    assert_eq!(
        live.json()["message"],
        "--live checks one platform's tenants: pass --platform"
    );
    // One that names it runs here (UC-4.6): the corpus's Elastic tenant has
    // no credential set.
    let elastic = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--live",
            "--platform",
            "elastic",
        ],
        &[],
    );
    assert_eq!(elastic.code, 1);
    assert_eq!(elastic.json()["mode"], "live");
    assert!(
        elastic.json()["message"]
            .as_str()
            .unwrap()
            .starts_with("Elastic credentials are unset")
    );
    for (flag, value) in [
        ("--strategy", Some("PREVIEW")),
        ("--wide", None),
        ("--check-timeout", Some("5")),
    ] {
        let mut words = vec!["--json", "validate", "query", flag];
        words.extend(value);
        let refused = opentide(&ws, &words, &[]);
        assert_eq!(refused.code, 2, "{flag}");
        assert_eq!(refused.json()["failure"]["argument"], flag);
    }
    let off = opentide(
        &ws,
        &["--json", "validate", "query", "--queries", "off"],
        &[],
    );
    assert_eq!(off.code, 2);
    assert_eq!(failure_code(&off.json()), "usage_error");
}

#[test]
fn options_typed_before_query_are_its_own_or_refused() {
    let (_scratch, ws) = corpus();
    let handed = opentide(
        &ws,
        &["--json", "validate", "--uuid", SENTINEL_UUID, "query"],
        &[],
    );
    assert_eq!(handed.code, 0, "{}", handed.stdout);
    assert_eq!(handed.json()["queries_validated"], 1);
    let refused = opentide(&ws, &["--json", "validate", "--fix", "query"], &[]);
    let document = refused.json();
    assert_eq!(refused.code, 2);
    assert_eq!(failure_code(&document), "usage_invalid_value");
    assert_eq!(
        document["message"],
        "Invalid value: --fix configures `opentide validate` itself and would be ignored by \
         `opentide validate query`."
    );
    let twice = opentide(
        &ws,
        &["--json", "validate", "--strict", "query", "--strict"],
        &[],
    );
    assert_eq!(twice.code, 2);
    assert!(
        twice.json()["message"]
            .as_str()
            .unwrap()
            .contains("Pass --strict once, before or after `query`, not both")
    );
}

/// Runs git in `dir`, without the host's configuration.
fn git(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

#[test]
fn a_platform_s_profile_decides_which_tables_a_query_file_may_read() {
    let (_scratch, ws) = corpus();
    // `SecurityEvent` is a Sentinel table, not a Defender for Endpoint one.
    std::fs::write(ws.join("c.kql"), "SecurityEvent | take 1\n").unwrap();
    let plain = opentide(
        &ws,
        &["--json", "validate", "query", "--file", "c.kql"],
        &[],
    );
    assert_eq!(plain.code, 0, "{}", plain.stdout);
    assert_eq!(plain.json()["status"], "passed");
    let profiled = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--platform",
            "defender_for_endpoint",
            "--file",
            "c.kql",
        ],
        &[],
    );
    let document = profiled.json();
    assert_eq!(profiled.code, 1, "{}", profiled.stdout);
    assert_eq!(document["status"], "failed");
    assert_eq!(failure_code(&document), "issues_found");
    let codes: Vec<&str> = document["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["code"].as_str().unwrap())
        .collect();
    assert_eq!(codes, ["kql_unknown_table"], "{document}");
}

#[test]
fn error_files_counts_each_file_once() {
    let (_scratch, ws) = corpus();
    let path = ws.join(SENTINEL_RULE);
    let text = std::fs::read_to_string(&path).unwrap();
    let broken = text.replace(
        "      SecurityEvent\n      | where EventID == 4688\n      | take 1\n",
        "      SecurityEvent | where\n",
    );
    assert_ne!(broken, text);
    // A second rejected query in the same file, on another platform.
    let broken = format!(
        "{broken}  defender_for_endpoint:\n    query: |\n      DeviceProcessEvents | where\n"
    );
    std::fs::write(&path, broken).unwrap();
    let ran = opentide(
        &ws,
        &["--json", "validate", "query", "--file", SENTINEL_RULE],
        &[],
    );
    let document = ran.json();
    assert_eq!(ran.code, 1, "{}", ran.stdout);
    assert_eq!(document["queries_validated"], 2);
    assert_eq!(document["summary"]["errors"], 2, "{document}");
    assert_eq!(document["summary"]["error_files"], 1, "{document}");
}

#[test]
fn a_placeholder_query_is_neither_checked_nor_counted_by_validate_query() {
    let (_scratch, ws) = corpus();
    let path = ws.join(SENTINEL_RULE);
    let text = std::fs::read_to_string(&path).unwrap();
    let placeholder = text.replace(
        "    query: |\n      SecurityEvent\n      | where EventID == 4688\n      | take 1\n",
        "    query: ...  # opentide:placeholder\n",
    );
    assert_ne!(placeholder, text);
    std::fs::write(&path, placeholder).unwrap();
    std::fs::write(ws.join("a.kql"), "SecurityEvent | take 1\n").unwrap();
    let ran = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--file",
            SENTINEL_RULE,
            "--file",
            "a.kql",
        ],
        &[],
    );
    let document = ran.json();
    assert_eq!(ran.code, 0, "{}", ran.stdout);
    assert_eq!(document["queries_validated"], 1, "{document}");
    assert_eq!(document["queries"][0]["path"], "a.kql");
    assert_eq!(document["diagnostics"], serde_json::json!([]));
}

#[test]
fn a_query_file_is_shown_relative_to_the_workspace_root_or_as_typed() {
    let (scratch, ws) = corpus();
    let sub = ws.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("a.kql"), "SecurityEvent | take 1\n").unwrap();
    let inside = opentide(
        &sub,
        &["--json", "validate", "query", "--file", "a.kql"],
        &[],
    );
    assert_eq!(inside.code, 0, "{}", inside.stdout);
    assert_eq!(inside.json()["queries"][0]["path"], "sub/a.kql");
    // A file outside the workspace keeps the path it was given.
    let outside = scratch.path().join("outside.kql");
    std::fs::write(&outside, "SecurityEvent | take 1\n").unwrap();
    let ran = opentide(
        &ws,
        &["--json", "validate", "query", "--file", "../outside.kql"],
        &[],
    );
    assert_eq!(ran.code, 0, "{}", ran.stdout);
    assert_eq!(ran.json()["queries"][0]["path"], "../outside.kql");
}

#[test]
fn changed_refuses_a_query_file() {
    let (_scratch, ws) = corpus();
    std::fs::write(ws.join("q.kql"), "SecurityEvent | take 1\n").unwrap();
    let ran = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--changed",
            "--file",
            "q.kql",
        ],
        &[],
    );
    let document = ran.json();
    assert_eq!(ran.code, 2, "{}", ran.stdout);
    assert_eq!(failure_code(&document), "usage_error");
    assert_eq!(
        document["message"],
        "--changed cannot be combined with --file or --uuid"
    );
}

#[test]
fn changed_in_a_repository_with_no_commit_warns() {
    let (_scratch, ws) = corpus();
    git(&ws, &["init", "-q", "-b", "main"]);
    let ran = opentide(
        &ws,
        &["--json", "validate", "query", "--changed"],
        &[(
            "GIT_CEILING_DIRECTORIES",
            ws.parent().unwrap().to_str().unwrap(),
        )],
    );
    let document = ran.json();
    assert_eq!(ran.code, 0, "{}", ran.stdout);
    assert_eq!(document["scope"], "changed");
    assert_eq!(document["queries_validated"], 0);
    let warnings = document["warnings"].as_array().unwrap();
    assert!(
        warnings.iter().any(|warning| warning
            .as_str()
            .unwrap()
            .ends_with("commit the rules, or drop --changed to check every rule")),
        "{document}"
    );
}

#[test]
fn file_strict_and_queries_typed_before_query_are_handed_down() {
    let (_scratch, ws) = corpus();
    std::fs::write(ws.join("bad.kql"), "SecurityEvent | where\n").unwrap();
    // --file on `validate`: only the query file is checked.
    let file = opentide(
        &ws,
        &["--json", "validate", "--file", "bad.kql", "query"],
        &[],
    );
    let document = file.json();
    assert_eq!(file.code, 1, "{}", file.stdout);
    assert_eq!(document["queries_validated"], 1);
    assert_eq!(document["queries"][0]["path"], "bad.kql");
    // --queries warn on `validate`: the rejection is a warning.
    let warned = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "--queries",
            "warn",
            "query",
            "--file",
            "bad.kql",
        ],
        &[],
    );
    let document = warned.json();
    assert_eq!(warned.code, 0, "{}", warned.stdout);
    assert_eq!(document["diagnostics"][0]["severity"], "warning");
    // --strict on `validate`: the warning fails the run.
    let strict = opentide(
        &ws,
        &[
            "--json",
            "validate",
            "--strict",
            "query",
            "--file",
            "bad.kql",
            "--queries",
            "warn",
        ],
        &[],
    );
    let document = strict.json();
    assert_eq!(strict.code, 1, "{}", strict.stdout);
    assert_eq!(failure_code(&document), "issues_found");
    // --type is `validate`'s own: refused, not dropped.
    let typed = opentide(&ws, &["--json", "validate", "--type", "rule", "query"], &[]);
    let document = typed.json();
    assert_eq!(typed.code, 2, "{}", typed.stdout);
    assert_eq!(failure_code(&document), "usage_invalid_value");
    assert_eq!(
        document["message"],
        "Invalid value: --type configures `opentide validate` itself and would be ignored by \
         `opentide validate query`."
    );
}
