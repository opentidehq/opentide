//! Every `cql_*` code through the command line (C1/O2, #790): CrowdStrike's
//! CQL is checked by the Rust CLI, while the 0.28.1 oracle never checks it
//! (`tests/corpora/faults.toml` marks the codes unreachable there), so this
//! is where each code is held above the engine's own unit tests
//! (`crates/opentide-cql/src/tests.rs`). `validate query --file x.cql`
//! reports every code a query file can carry; a CrowdStrike rule's query
//! adds the correlation rule's own code, `validate` reports its errors and
//! `lint` its warnings.

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

/// Each error code a `.cql` file can carry, and a query that has it alone
/// (the engine's own cases, `crates/opentide-cql/src/tests.rs`).
const ERRORS: [(&str, &str); 15] = [
    ("cql_parse_error", "groupBy(aid\n"),
    ("cql_unknown_function", "groupBi([aid])\n"),
    ("cql_removed_function", "rdns(ip)\n"),
    ("cql_unknown_parameter", "groupBy(aid, fuction=count())\n"),
    ("cql_duplicate_parameter", "groupBy(aid, field=cid)\n"),
    ("cql_unnamed_argument", "count(aid, cid)\n"),
    ("cql_missing_parameter", "in(values=[a])\n"),
    ("cql_parameter_value", "sort(x, order=down)\n"),
    ("cql_regex_flag", "CommandLine=/whoami/x\n"),
    ("cql_free_text_after_aggregate", "groupBy(aid) | error\n"),
    (
        "cql_event_function_after_aggregate",
        "groupBy(class) | eventSize()\n",
    ),
    ("cql_assignment_as", "x := count(as=y)\n"),
    ("cql_link_outside_correlate", "a <=> b.c\n"),
    (
        "cql_correlate_placement",
        "correlate(A: { a=1 | count() }, B: { b=1 | x <=> A.x }, within=5m)\n",
    ),
    ("cql_match_guard", "x match { count() => * }\n"),
];

/// The warnings, one line of a CrowdStrike rule's query each: `lint`
/// reports them, `validate` keeps only errors.
const WARNINGS: [(&str, &str); 4] = [
    ("cql_unknown_event", "#event_simpleName=ProcessRollup"),
    ("cql_deprecated_function", "| lowercase(field)"),
    ("cql_string_escape", "| x := \"a\\qb\""),
    (
        "cql_regex_group_under_or",
        "| type=FOO or /disk_free=(?<space>[0-9]+)/",
    ),
];

/// The correlation rule's own code: `correlate()` with another aggregate,
/// which plain LogScale (a `.cql` file) allows.
const CORRELATE_AGGREGATE: (&str, &str) = (
    "cql_correlate_aggregate",
    "correlate(A: { #event_simpleName=UserLogon }, B: { #event_simpleName=ProcessRollup2 | aid <=> A.aid }, within=10m) | groupBy(aid)",
);

const CROWDSTRIKE_RULE: &str = "Objects/Detection Rules/rule-0006-crowdstrike-deploy-only.yaml";

/// The corpus's CrowdStrike rule with `lines` as its query.
fn crowdstrike_query(ws: &Path, lines: &[&str]) {
    let path = ws.join(CROWDSTRIKE_RULE);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("    query: index=main\n"), "{text}");
    let query: String = lines.iter().fold(String::new(), |mut query, line| {
        query.push_str("      ");
        query.push_str(line);
        query.push('\n');
        query
    });
    std::fs::write(
        &path,
        text.replace("    query: index=main\n", &format!("    query: |\n{query}")),
    )
    .unwrap();
}

/// The codes of `findings` on `path`, in order.
fn codes_on<'a>(findings: &'a Value, path: &str) -> Vec<&'a str> {
    findings
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["path"] == path)
        .filter_map(|item| item["code"].as_str())
        .collect()
}

#[test]
fn every_cql_code_is_held_here() {
    let held: std::collections::BTreeSet<&str> = ERRORS
        .iter()
        .chain(WARNINGS.iter())
        .map(|(code, _)| *code)
        .chain([CORRELATE_AGGREGATE.0])
        .collect();
    let declared: std::collections::BTreeSet<&str> = opentide_core::codes::ALL
        .iter()
        .copied()
        .filter(|code| code.starts_with("cql_"))
        .collect();
    assert_eq!(held, declared, "a cql_ code without a command-line case");
}

#[test]
fn validate_query_reports_each_cql_error_in_a_query_file() {
    let (_scratch, ws) = corpus();
    let mut words = vec!["--json", "validate", "query"];
    let names: Vec<String> = ERRORS
        .iter()
        .map(|(code, _)| format!("{code}.cql"))
        .collect();
    for ((_, query), name) in ERRORS.iter().zip(&names) {
        std::fs::write(ws.join(name), query).unwrap();
        words.extend(["--file", name.as_str()]);
    }
    let ran = opentide(&ws, &words, &[]);
    let document = ran.json();
    assert_eq!(ran.code, 1, "{}{}", ran.stdout, ran.stderr);
    assert_eq!(document["queries_validated"], ERRORS.len());
    for ((code, _), name) in ERRORS.iter().zip(&names) {
        assert_eq!(
            codes_on(&document["diagnostics"], name),
            [*code],
            "{}",
            ran.stdout
        );
    }
    let languages: Vec<&Value> = document["queries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|query| &query["language"])
        .collect();
    assert!(
        languages.iter().all(|language| *language == "cql"),
        "{languages:?}"
    );
}

#[test]
fn lint_reports_the_cql_warnings_of_a_crowdstrike_rule() {
    let (_scratch, ws) = corpus();
    let lines: Vec<&str> = WARNINGS.iter().map(|(_, line)| *line).collect();
    crowdstrike_query(&ws, &lines);
    let ran = opentide(&ws, &["--json", "lint"], &[]);
    let document = ran.json();
    let path = "objects/rules/rule-0006-crowdstrike-deploy-only.yaml";
    let cql: Vec<&str> = codes_on(&document["findings"], path)
        .into_iter()
        .filter(|code| code.starts_with("cql_"))
        .collect();
    let expected: Vec<&str> = WARNINGS.iter().map(|(code, _)| *code).collect();
    assert_eq!(cql, expected, "{}", ran.stdout);
    // Warnings are lint's: `validate` passes the same rule's queries.
    let ran = opentide(&ws, &["--json", "validate"], &[]);
    assert_eq!(
        ran.json()["checks"]["queries"]["status"],
        "passed",
        "{}",
        ran.stdout
    );
}

#[test]
fn validate_reports_correlate_with_an_aggregate_in_a_correlation_rule_only() {
    let (_scratch, ws) = corpus();
    let (code, query) = CORRELATE_AGGREGATE;
    crowdstrike_query(&ws, &[query]);
    let ran = opentide(&ws, &["--json", "validate"], &[]);
    let document = ran.json();
    assert_eq!(ran.code, 1, "{}{}", ran.stdout, ran.stderr);
    let issues: Vec<&Value> = document["report"]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|issue| issue["path"] == CROWDSTRIKE_RULE)
        .collect();
    assert!(!issues.is_empty(), "{}", ran.stdout);
    assert!(
        issues.iter().all(|issue| issue["code"] == code
            && issue["field_path"]
                == serde_json::json!(["configurations", "crowdstrike", "query"])),
        "{issues:#?}"
    );
    // The same query in a `.cql` file is plain LogScale, which allows it.
    std::fs::write(ws.join("hunt.cql"), format!("{query}\n")).unwrap();
    let ran = opentide(
        &ws,
        &["--json", "validate", "query", "--file", "hunt.cql"],
        &[],
    );
    assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
}
