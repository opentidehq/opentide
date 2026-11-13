//! The queries check on the query engines (`opentide_cli::queries`, UC-2.5,
//! #820): what `validate` reports for each query an object carries.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: crates/AGENTS.md, Lints"
)]

use std::path::PathBuf;
use std::sync::Arc;

use opentide_cli::queries::{EngineLintQueries, EngineQueries, Profiles, REPORTED_AS_WARNING_NOTE};
use opentide_workspace::validate::{Check, Options, QueriesMode, QueryCheck, QueryObject};
use opentide_workspace::{Diagnostic, FileSystem, MemoryFs, RootOptions, Severity, Workspace};
use serde_json::{Value, json};

const UUID: &str = "11111111-1111-4111-8111-111111111111";
const FILE: &str = "/ws/objects/rules/a.yaml";

fn workspace(files: &[(&str, &str)]) -> Workspace {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations");
    fs.create_dir("/ws/objects/rules");
    for (path, text) in files {
        fs.write(path, *text);
    }
    Workspace::open(
        fs as Arc<dyn FileSystem>,
        opentide_workspace::Options {
            roots: RootOptions {
                repo: Some(PathBuf::from("/ws")),
                cwd: PathBuf::from("/ws"),
                ..RootOptions::default()
            },
        },
    )
    .unwrap()
}

fn rule(configurations: &str) -> String {
    format!(
        "name: A\nmetadata:\n  uuid: {UUID}\n  schema: rule::1.1\nconfigurations:\n{configurations}"
    )
}

/// What the check finds in `text`, as a rule file of a workspace.
fn check(text: &str, as_warnings: bool) -> (Vec<Diagnostic>, Vec<Diagnostic>, usize) {
    let ws = workspace(&[(FILE, text)]);
    let path = PathBuf::from(FILE);
    let objects = [QueryObject {
        path: &path,
        uuid: UUID,
        family: "rule",
        source: text,
    }];
    let found = EngineQueries.check(&ws, &objects, as_warnings);
    (found.errors, found.warnings, found.queries)
}

const SENTINEL_BROKEN: &str = "  sentinel:\n    query: |\n      SecurityEvent\n      | where (\n";

#[test]
fn a_rejected_query_is_an_error_at_its_place_with_the_engine_s_context() {
    let (errors, warnings, queries) = check(&rule(SENTINEL_BROKEN), false);
    assert_eq!(queries, 1);
    assert!(warnings.is_empty());
    assert_eq!(errors.len(), 1, "{errors:#?}");
    let json = serde_json::to_value(&errors[0]).unwrap();
    assert_eq!(json["code"], "kql_parse_error");
    assert_eq!(json["severity"], "error");
    assert_eq!(json["object_uuid"], UUID);
    assert_eq!(json["object_type"], "rule");
    assert_eq!(json["file_path"], FILE);
    assert_eq!(json["path"], "objects/rules/a.yaml");
    assert_eq!(
        json["field_path"],
        json!(["configurations", "sentinel", "query"])
    );
    let line = json["line"].as_u64().unwrap();
    assert_eq!(line, 9, "{json}");
    assert_eq!(json["yaml_line"], json!(line - 1));
    // The span ends on the line of its last character, not at column 1 of
    // the next one.
    assert_eq!(json["end_line"], json!(line));
    // The context's keys in the oracle's order (the serialised text keeps it).
    let text = serde_json::to_string(&errors[0].context).unwrap();
    assert!(
        text.starts_with(
            r#"{"source":"engine","language":"kql","platform":"sentinel","position":{"line":"#
        ),
        "{text}"
    );
    assert_eq!(json["context"]["source"], "engine");
    assert_eq!(json["context"]["language"], "kql");
    assert_eq!(json["context"]["platform"], "sentinel");
    assert_eq!(
        json["context"]["position"],
        json!({
            "line": json["line"], "column": json["column"],
            "end_line": json["end_line"], "end_column": json["end_column"],
        })
    );
    assert_eq!(
        json["help"],
        "the KQL reference: https://learn.microsoft.com/kusto/query/"
    );
    assert_eq!(json["fix"], Value::Null);
    assert_eq!(json["explain"], "opentide explain kql_parse_error");
}

#[test]
fn queries_warn_reports_the_error_as_a_warning_with_a_note() {
    let (errors, warnings, _) = check(&rule(SENTINEL_BROKEN), true);
    assert!(errors.is_empty());
    assert_eq!(warnings.len(), 1);
    let warning = &warnings[0];
    assert_eq!(warning.severity, Severity::Warning);
    let json = serde_json::to_value(warning).unwrap();
    assert_eq!(json["context"]["reported_as_warning"], true);
    assert_eq!(
        warning.notes,
        [("note".to_owned(), REPORTED_AS_WARNING_NOTE.to_owned())]
    );
}

#[test]
fn style_findings_are_lint_s_and_a_clean_query_is_counted() {
    // `search` with no table is a lint warning, never validate's.
    let text = rule("  sentinel:\n    query: |\n      search \"error\"\n");
    let (errors, warnings, queries) = check(&text, false);
    assert_eq!((errors.len(), warnings.len(), queries), (0, 0, 1));
}

#[test]
fn a_placeholder_query_is_neither_checked_nor_counted() {
    let text = rule("  sentinel:\n    query: |  # opentide:placeholder\n      ...\n");
    assert_eq!(check(&text, false).2, 0);
    // A query written under a marker someone forgot to delete is checked.
    let text = rule(
        "  sentinel:\n    query: |  # opentide:placeholder\n      SecurityEvent\n      | where (\n",
    );
    let (errors, _, queries) = check(&text, false);
    assert_eq!((errors.len(), queries), (1, 1));
}

#[test]
fn a_hunt_is_reported_at_its_own_path_on_its_system_s_platform() {
    // `query` before `system` (#696).
    let text = format!(
        "name: A\nmetadata:\n  uuid: {UUID}\n  schema: rule::1.1\nresponse:\n  procedure:\n    \
         searches:\n      - purpose: hunt\n        query: |\n          index=a | stats\n        \
         system: splunk\n"
    );
    let (errors, _, queries) = check(&text, false);
    assert_eq!(queries, 1);
    assert_eq!(errors.len(), 1, "{errors:#?}");
    let json = serde_json::to_value(&errors[0]).unwrap();
    assert_eq!(json["code"], "spl_empty_command");
    assert_eq!(
        json["field_path"],
        json!(["response", "procedure", "searches", "0", "query"])
    );
    assert_eq!(json["context"]["platform"], "splunk");
    assert_eq!(json["context"]["language"], "spl");
    assert_eq!(json["line"], 10);
}

#[test]
fn every_platform_s_query_is_checked_in_its_language() {
    let text = rule(concat!(
        "  sentinel:\n    query: SecurityEvent | take 1\n",
        "  defender_for_endpoint:\n    query: DeviceProcessEvnts | take 1\n",
        "  splunk:\n    query: stats count by host\n",
        "  carbon_black_cloud:\n    query: 'process_name:(a'\n",
        "  elastic:\n    type: eql\n    query: process where true | unique process.name\n",
        "  sysdig:\n    condition: proc.pid = abc\n",
    ));
    let (errors, _, queries) = check(&text, false);
    assert_eq!(queries, 6);
    let found: Vec<(String, String, String)> = errors
        .iter()
        .map(|error| {
            let json = serde_json::to_value(error).unwrap();
            (
                error.code.clone(),
                json["context"]["platform"].as_str().unwrap().to_owned(),
                json["context"]["language"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let expect = |code: &str, platform: &str, language: &str| {
        assert!(
            found.contains(&(code.to_owned(), platform.to_owned(), language.to_owned())),
            "{code} on {platform}: {found:#?}"
        );
    };
    // The Defender schema has no such table; Sentinel takes what it does not know.
    expect("kql_unknown_table", "defender_for_endpoint", "kql");
    expect("spl_command_without_pipe", "splunk", "spl");
    expect("lucene_parse_error", "carbon_black_cloud", "lucene");
    expect("eql_unsupported", "elastic", "eql");
    expect("falco_value_type", "sysdig", "falco");
    assert!(!found.iter().any(|(_, platform, _)| platform == "sentinel"));
}

#[test]
fn line_endings_count_as_a_text_mode_read_counts_them() {
    let lf = rule(SENTINEL_BROKEN);
    let crlf = lf.replace('\n', "\r\n");
    let place = |text: &str| {
        let (errors, _, _) = check(text, false);
        let json = serde_json::to_value(&errors[0]).unwrap();
        (
            json["line"].clone(),
            json["column"].clone(),
            json["end_line"].clone(),
            json["end_column"].clone(),
        )
    };
    assert_eq!(place(&crlf), place(&lf));
    // A lone `\r` ends a line too, as a text-mode read reads it.
    let cr = lf.replace('\n', "\r");
    assert_eq!(place(&cr), place(&lf));
}

#[test]
fn a_broken_visibility_toml_declares_nothing_not_the_last_workspace_s_datasets() {
    let text = rule("  defender_for_endpoint:\n    query: MyCustomTable | take 1\n");
    let unknown_in = |fs: &MemoryFs| {
        let _engine = opentide_cli::queries::ENGINE.lock().unwrap();
        let profiles = Profiles::install(fs, Some(std::path::Path::new("/ws")));
        let unknown = profiles.check_object(&text)[0]
            .findings
            .iter()
            .filter(|finding| finding.code == "kql_unknown_table")
            .count();
        (unknown, profiles.visibility_problem)
    };
    let visibility_path = "/ws/.opentide/configurations/visibility.toml";
    // One workspace declares the table, in the same process as the next.
    let declared = MemoryFs::new();
    declared.write(
        visibility_path,
        "[[logsources]]\nname = \"MyCustomTable\"\nsystem = \"defender_for_endpoint\"\n",
    );
    let (unknown, problem) = unknown_in(&declared);
    assert_eq!(unknown, 0);
    assert!(problem.is_none(), "{problem:?}");
    // The next one's visibility.toml is not TOML: it declares nothing.
    let broken = MemoryFs::new();
    broken.write(
        visibility_path,
        "[[logsources]\nname = = \"MyCustomTable\"\n",
    );
    let (unknown, problem) = unknown_in(&broken);
    assert_eq!(unknown, 1);
    let problem = problem.unwrap();
    assert!(
        problem.starts_with("the declared datasets could not be read: "),
        "{problem}"
    );
}

/// An ES|QL `RLIKE (…)` pattern list: Elasticsearch 9.2 and later.
const ESQL_9_2: &str = "  elastic:\n    type: esql\n    query: 'FROM logs-* | WHERE process.name RLIKE (\"a.*\", \"b.*\")'\n";

/// The `esql_unavailable` findings of the rule's query, with the workspace's
/// `elastic.toml` (`None`: none).
fn esql_unavailable(elastic: Option<&str>) -> Vec<(opentide_analysis::Severity, String)> {
    let text = rule(ESQL_9_2);
    let mut files = vec![(FILE, text.as_str())];
    if let Some(elastic) = elastic {
        files.push((
            "/ws/.opentide/configurations/platforms/elastic.toml",
            elastic,
        ));
    }
    let ws = workspace(&files);
    let _engine = opentide_cli::queries::ENGINE.lock().unwrap();
    let profiles = Profiles::install(ws.fs().as_ref(), Some(ws.root()));
    let checked = profiles.check_object(&text);
    assert_eq!(checked.len(), 1);
    assert_eq!(checked[0].language, "esql");
    checked[0]
        .findings
        .iter()
        .filter(|finding| finding.code == "esql_unavailable")
        .map(|finding| (finding.severity, finding.message.clone()))
        .collect()
}

#[test]
fn es_ql_is_checked_against_the_lowest_stack_its_tenants_declare() {
    let tenants = "[[tenants]]\nname = \"old\"\n[tenants.setup]\nversion = \"9.1\"\n\n\
                   [[tenants]]\nname = \"new\"\n[tenants.setup]\nversion = \"9.3\"\n";
    let found = esql_unavailable(Some(tenants));
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].0, opentide_analysis::Severity::Warning);
    assert!(
        found[0].1.contains("Elasticsearch 9.1 rejects it"),
        "{}",
        found[0].1
    );
    // Without the file: every supported line from the 8.19 floor, and the
    // newest accepts it, so it is information, naming no declared stack.
    let found = esql_unavailable(None);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].0, opentide_analysis::Severity::Information);
    assert!(!found[0].1.contains("rejects it"), "{}", found[0].1);
    // Tenants on a stack that has it: nothing to say.
    let found = esql_unavailable(Some(
        "[[tenants]]\nname = \"new\"\n[tenants.setup]\nversion = \"9.3\"\n",
    ));
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn declared_datasets_come_from_the_workspace_s_visibility_toml() {
    let text = rule("  defender_for_endpoint:\n    query: MyCustomTable | take 1\n");
    let unknown = |files: &[(&str, &str)]| {
        let ws = workspace(files);
        let path = PathBuf::from(FILE);
        let objects = [QueryObject {
            path: &path,
            uuid: UUID,
            family: "rule",
            source: &text,
        }];
        EngineQueries
            .check(&ws, &objects, false)
            .errors
            .iter()
            .filter(|error| error.code == "kql_unknown_table")
            .count()
    };
    assert_eq!(unknown(&[(FILE, &text)]), 1);
    let visibility =
        "[[logsources]]\nname = \"MyCustomTable\"\nsystem = \"defender_for_endpoint\"\n";
    assert_eq!(
        unknown(&[
            (FILE, &text),
            ("/ws/.opentide/configurations/visibility.toml", visibility)
        ]),
        0
    );
}

#[test]
fn validate_runs_the_engines_and_drops_what_the_schema_check_rejects() {
    let text = rule(SENTINEL_BROKEN);
    let ws = workspace(&[(FILE, &text)]);
    let validation = ws.validate(&Options {
        check: Some(Check::Queries),
        queries: QueriesMode::Error,
        query_check: Some(&EngineQueries),
        ..Options::default()
    });
    assert_eq!(validation.report.stats.queries_checked, Some(1));
    assert_eq!(validation.summary.queries, Some(1));
    assert!(validation.failed);
    assert_eq!(validation.checks, [(Check::Queries, "failed")]);
    assert_eq!(validation.report.issues[0].code, "kql_parse_error");
    // The profiles a host reads, without validate.
    let _engine = opentide_cli::queries::ENGINE.lock().unwrap();
    let fs = MemoryFs::new();
    let profiles = Profiles::install(&fs, None);
    assert!(profiles.visibility_problem.is_none());
    let checked = profiles.check_object(&text);
    assert_eq!(checked.len(), 1);
    assert!(checked[0].is_rule_query());
    assert_eq!(checked[0].errors(), 1);
}

/// What lint's queries check finds in `text`, as a rule file of a
/// workspace: (code, severity, line) per finding.
fn lint_check(text: &str) -> Vec<(String, String, usize)> {
    use opentide_workspace::lint::LintQueryCheck;
    let _engine = opentide_cli::queries::ENGINE.lock().unwrap();
    let fs = MemoryFs::new();
    fs.create_dir("/ws/.opentide/configurations");
    let check = EngineLintQueries::install(&fs, std::path::Path::new("/ws"));
    check
        .check(
            std::path::Path::new(FILE),
            "objects/rules/a.yaml",
            Some(UUID),
            text,
        )
        .unwrap()
        .into_iter()
        .map(|finding| {
            assert_eq!(finding.json["check"], "queries");
            assert_eq!(finding.json["uuid"], UUID);
            (
                finding.diagnostic.code.clone(),
                finding.diagnostic.severity.as_str().to_owned(),
                finding.diagnostic.line.unwrap(),
            )
        })
        .collect()
}

const ELASTIC_KUERY: &str = "  elastic:\n    type: query\n    language: kuery\n";

#[test]
fn lint_reports_query_warnings_and_advisories_but_not_engine_errors() {
    let text = rule(&format!(
        "  sentinel:\n    query: |\n      search \"error\"\n  defender_for_endpoint:\n    \
         query: |\n      DeviceProcessEvents\n      | where (\n{ELASTIC_KUERY}    query: \
         'process.name: \"a\"'\n    scheduling:\n      interval: 5m\n      lookback: 0m\n"
    ));
    let found = lint_check(&text);
    // The unscoped search is a warning on the Sentinel query's line.
    assert!(
        found.contains(&("kql_unscoped_search".into(), "warning".into(), 8)),
        "{found:#?}"
    );
    // Elastic's block advisory is lint's.
    assert!(
        found
            .iter()
            .any(|(code, severity, line)| code == "lookback_zero"
                && severity == "warning"
                && *line == 19),
        "{found:#?}"
    );
    // The query the engine rejects (`kql_parse_error` on line 12) is
    // validate's, and the object's other findings (schema, metadata) are not
    // the queries check's.
    assert_eq!(found.len(), 2, "{found:#?}");
}

#[test]
fn lint_leaves_a_placeholder_query_to_the_placeholders_check() {
    // `...` is a free-text Kuery query: a note where it is not a placeholder.
    let written = rule(&format!("{ELASTIC_KUERY}    query: ...\n"));
    assert_eq!(
        lint_check(&written),
        [("kuery_free_text".to_owned(), "info".to_owned(), 9)]
    );
    // The marker on the key's own line, or on the line above the stand-in.
    let inline = rule(&format!(
        "{ELASTIC_KUERY}    query: ...  # opentide:placeholder\n"
    ));
    assert_eq!(lint_check(&inline), []);
    let next_line = rule(&format!(
        "{ELASTIC_KUERY}    query: |  # opentide:placeholder\n      ...\n"
    ));
    assert_eq!(lint_check(&next_line), []);
    // A marker without its stand-in leaves the query checked.
    let replaced = rule(&format!(
        "{ELASTIC_KUERY}    query: |  # opentide:placeholder\n      process.name: \"a\" or ...\n"
    ));
    assert!(
        lint_check(&replaced)
            .iter()
            .any(|(code, _, _)| code == "kuery_free_text"),
        "{:#?}",
        lint_check(&replaced)
    );
}

#[test]
fn is_stand_in_reads_the_value_without_its_marker() {
    assert!(opentide_cli::queries::is_stand_in(
        "...  # opentide:placeholder"
    ));
    assert!(opentide_cli::queries::is_stand_in("  ...  "));
    assert!(!opentide_cli::queries::is_stand_in(
        "a ...  # opentide:placeholder"
    ));
    assert!(!opentide_cli::queries::is_stand_in(""));
}

#[test]
fn lint_reports_every_elastic_block_advisory() {
    let codes = |text: &str| -> Vec<String> {
        lint_check(text)
            .into_iter()
            .map(|(code, _, _)| code)
            .collect()
    };
    let query = "    query: 'process.name: \"a\"'\n";
    let long = rule(&format!(
        "{ELASTIC_KUERY}{query}    scheduling:\n      interval: 5m\n      lookback: 2h\n"
    ));
    assert_eq!(codes(&long), ["lookback_long"]);
    let threshold = rule(&format!(
        "  elastic:\n    type: threshold\n    language: kuery\n{query}    threshold:\n      \
         field:\n        - host.name\n      value: 4\n    scheduling:\n      interval: 5m\n      \
         lookback: 10m\n"
    ));
    assert_eq!(codes(&threshold), ["threshold_lookback"]);
    let risk = format!(
        "name: A\nmetadata:\n  uuid: {UUID}\n  schema: rule::1.1\nresponse:\n  \
         alert_severity: High\nconfigurations:\n{ELASTIC_KUERY}{query}    risk: 90\n"
    );
    assert_eq!(codes(&risk), ["risk_band"]);
    let mobile = format!(
        "name: A\nmetadata:\n  uuid: {UUID}\n  schema: rule::1.1\ntechniques:\n  - T1626\n\
         configurations:\n{ELASTIC_KUERY}{query}"
    );
    assert_eq!(codes(&mobile), ["technique_not_enterprise"]);
}

#[test]
fn lint_reports_yaral_warnings_on_their_section() {
    // An event with no `metadata.event_type` filter scans every event
    // (`yaral_unfiltered_event`, a warning): lint reports it on `events`.
    let text = rule(
        "  google_secops:\n    events: |\n      $e.principal.hostname = \"web01\"\n    outcome: \
         |\n      $risk_score = 40\n    condition: |\n      $e\n",
    );
    let found = lint_check(&text);
    assert!(
        found
            .iter()
            .any(|(code, severity, line)| code == "yaral_unfiltered_event"
                && severity == "warning"
                && *line == 8),
        "{found:?}"
    );
}

#[test]
fn lint_reports_the_google_secops_block_advisories() {
    let text = rule(
        "  google_secops:\n    run_frequency: LIVE\n    events: |\n      $a.metadata.event_type \
         = \"X\"\n      $b.metadata.event_type = \"Y\"\n    outcome: |\n      $host = \
         $a.principal.hostname\n    condition: |\n      $a and $b\n",
    );
    let found = lint_check(&text);
    let advisories: Vec<(String, String, usize)> = found
        .into_iter()
        .filter(|(code, _, _)| code.starts_with("google_secops_"))
        .collect();
    assert_eq!(
        advisories,
        [
            (
                "google_secops_risk_score_missing".to_owned(),
                "warning".to_owned(),
                11
            ),
            (
                "google_secops_live_frequency_unavailable".to_owned(),
                "warning".to_owned(),
                7
            ),
        ]
    );
}

#[test]
fn lint_reports_the_bitdefender_block_advisories_on_one_line() {
    let text = rule(
        "  bitdefender:\n    enabled: true\n    schema: platform::bitdefender::1.0\n    \
         status: PRODUCTION\n    detection:\n      target: registry\n      criteria:\n      - \
         field: Registry.Key\n        contains: HKEY_LOCAL_MACHINE\\Software\\Run\n",
    );
    let document = lint_run(&text, &["--check", "queries"]);
    let found: Vec<(String, Value, Value)> = document["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("{document}"))
        .iter()
        .filter(|finding| {
            finding["code"]
                .as_str()
                .is_some_and(|code| code.starts_with("bitdefender_"))
        })
        .map(|finding| {
            (
                finding["code"].as_str().unwrap().to_owned(),
                finding["line"].clone(),
                finding["end_line"].clone(),
            )
        })
        .collect();
    let codes: Vec<&str> = found.iter().map(|(code, _, _)| code.as_str()).collect();
    assert_eq!(
        codes,
        [
            "bitdefender_registry_full_hive",
            "bitdefender_contains_no_wildcard"
        ],
        "{document}"
    );
    assert!(
        found
            .iter()
            .all(|(_, line, end_line)| line.is_u64() && line == end_line),
        "{found:?}"
    );
}

#[test]
fn lint_reports_the_exabeam_block_advisories() {
    let text = rule(
        "  exabeam:\n    status: PREVIEW\n    outcome: none\n    sequences:\n      - query: \
         activity_type = \"a\"\n      - query: activity_type = \"b\"\n        threshold:\n          \
         within: 10m\n    correlation:\n      within: 12m\n",
    );
    let found = lint_check(&text);
    let advisories: Vec<(String, String, usize)> = found
        .into_iter()
        .filter(|(code, _, _)| code.starts_with("exabeam_"))
        .collect();
    assert_eq!(
        advisories,
        [
            ("exabeam_outcome_silent".to_owned(), "warning".to_owned(), 8),
            (
                "exabeam_correlation_window".to_owned(),
                "warning".to_owned(),
                15
            ),
        ]
    );
}

/// `opentide --json lint` with `words` after it, in-process, in a workspace
/// on disk holding `text` as its one rule: the JSON document.
fn lint_run(text: &str, words: &[&str]) -> Value {
    use std::sync::Mutex;
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    std::fs::create_dir_all(ws.join(".opentide/configurations")).unwrap();
    std::fs::create_dir_all(ws.join("objects/rules")).unwrap();
    std::fs::write(ws.join("objects/rules/a.yaml"), text).unwrap();
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let host = opentide_cli::Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: Arc::new(Mutex::new(Sink::default())),
        cwd: Some(ws),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = ["--json", "lint"]
        .iter()
        .chain(words)
        .map(|word| (*word).to_owned())
        .collect();
    let env = opentide_cli::env::Env::from_pairs([("HOME".to_owned(), home.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), Sink::default());
    opentide_cli::run(&argv, &env, &host, &mut out, &mut err);
    serde_json::from_slice(&out).unwrap()
}

#[test]
fn a_default_lint_run_includes_the_queries_check() {
    let text = rule("  sentinel:\n    query: |\n      search \"error\"\n");
    let queries = |document: &Value| -> Vec<String> {
        document["findings"]
            .as_array()
            .unwrap_or_else(|| panic!("{document}"))
            .iter()
            .filter(|finding| finding["check"] == "queries")
            .map(|finding| finding["code"].as_str().unwrap().to_owned())
            .collect()
    };
    let default = lint_run(&text, &[]);
    assert_eq!(queries(&default), ["kql_unscoped_search"], "{default}");
    let only = lint_run(&text, &["--check", "queries"]);
    assert_eq!(queries(&only), ["kql_unscoped_search"], "{only}");
    let other = lint_run(&text, &["--check", "metadata"]);
    assert_eq!(queries(&other), Vec::<String>::new(), "{other}");
}
