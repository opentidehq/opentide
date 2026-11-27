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
        "  microsoft_defender:\n    query: DeviceProcessEvnts | take 1\n",
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
    expect("kql_unknown_table", "microsoft_defender", "kql");
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
    let text = rule("  microsoft_defender:\n    query: MyCustomTable | take 1\n");
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
        "[[logsources]]\nname = \"MyCustomTable\"\nsystem = \"microsoft_defender\"\n",
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
    let text = rule("  microsoft_defender:\n    query: MyCustomTable | take 1\n");
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
    let visibility = "[[logsources]]\nname = \"MyCustomTable\"\nsystem = \"microsoft_defender\"\n";
    assert_eq!(
        unknown(&[
            (FILE, &text),
            ("/ws/.opentide/configurations/visibility.toml", visibility)
        ]),
        0
    );
}

/// #1142: validate's queries check run as the jobs of a thread pool, the
/// way a host spawns one per request, two workspaces at once, one
/// declaring the table. The check took a process-wide lock and then spread
/// over the pool: while the thread that held it waited for a job another
/// thread had taken, it ran the next request from the pool's queue, which
/// took the lock again on the same thread, and hung. Each run now uses its
/// own workspace's datasets and takes no lock. The second request comes
/// after a few delays, so that one of them lands while the first waits;
/// the watchdog fails the test instead of letting it hang.
#[test]
fn queries_checks_spawned_on_a_thread_pool_each_use_their_workspace_s_datasets() {
    let text = rule("  microsoft_defender:\n    query: MyCustomTable | take 1\n");
    let visibility = "[[logsources]]\nname = \"MyCustomTable\"\nsystem = \"microsoft_defender\"\n";
    // Enough objects that each check's own jobs split across the pool.
    const OBJECTS: usize = 48;
    let unknown = move |declared: bool| {
        let mut files: Vec<(&str, &str)> = vec![(FILE, &text)];
        if declared {
            files.push(("/ws/.opentide/configurations/visibility.toml", visibility));
        }
        let ws = workspace(&files);
        let paths: Vec<PathBuf> = (0..OBJECTS)
            .map(|i| PathBuf::from(format!("/ws/objects/rules/r{i}.yaml")))
            .collect();
        let objects: Vec<QueryObject<'_>> = paths
            .iter()
            .map(|path| QueryObject {
                path,
                uuid: UUID,
                family: "rule",
                source: &text,
            })
            .collect();
        EngineQueries
            .check(&ws, &objects, false)
            .errors
            .iter()
            .filter(|error| error.code == "kql_unknown_table")
            .count()
    };
    let unknown = Arc::new(unknown);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    let (done, finished) = std::sync::mpsc::channel();
    let delays = [0, 1, 2, 5, 10, 20, 40, 80];
    for delay in delays {
        for declared in [true, false] {
            let (unknown, done) = (Arc::clone(&unknown), done.clone());
            pool.spawn(move || {
                let _ = done.send((declared, unknown(declared)));
            });
            if declared {
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }
    }
    for _ in 0..delays.len() * 2 {
        let (declared, unknown) = finished
            .recv_timeout(std::time::Duration::from_secs(120))
            .expect("the checks on the pool did not finish: deadlocked");
        // Every object's query: the table is unknown unless declared.
        assert_eq!(
            unknown,
            if declared { 0 } else { OBJECTS },
            "declared: {declared}"
        );
    }
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
    let file = std::path::Path::new(FILE);
    let found = check
        .check(file, "objects/rules/a.yaml", Some(UUID), text)
        .unwrap();
    // Given lint's parse of the file (#1233), the check finds the same.
    let document = opentide_schema::node::load(text).unwrap();
    let parsed = check
        .check_parsed(file, "objects/rules/a.yaml", Some(UUID), text, &document)
        .unwrap();
    assert_eq!(parsed, found);
    found
        .into_iter()
        .map(|finding| {
            assert_eq!(
                finding.entry.check,
                opentide_workspace::lint::LintCheck::Queries
            );
            assert_eq!(finding.entry.uuid.as_deref(), Some(UUID));
            (
                finding.diagnostic.code.clone(),
                finding.diagnostic.severity.as_str().to_owned(),
                finding.diagnostic.line.unwrap(),
            )
        })
        .collect()
}

const ELASTIC_KUERY: &str = "  elastic:\n    type: query\n    language: kuery\n";

/// #1142: lint's queries check reads the workspace's `visibility.toml`,
/// on whichever thread runs it and through both of its entry points (the
/// text, and lint's own parse): a dataset the workspace does not declare
/// is a warning, one it declares is none.
#[test]
fn lint_reports_the_datasets_the_workspace_does_not_declare() {
    use opentide_workspace::lint::LintQueryCheck;
    let text =
        rule("  splunk:\n    query: |\n      index=main sourcetype=linux_secure | stats count\n");
    let undeclared = |visibility: &str| -> [usize; 2] {
        let fs = MemoryFs::new();
        fs.create_dir("/ws/.opentide/configurations");
        fs.write("/ws/.opentide/configurations/visibility.toml", visibility);
        let check = EngineLintQueries::install(&fs, std::path::Path::new("/ws"));
        let file = std::path::Path::new(FILE);
        let document = opentide_schema::node::load(&text).unwrap();
        let count = |found: Vec<opentide_workspace::lint::LintFinding>| {
            found
                .iter()
                .filter(|finding| finding.diagnostic.code == "spl_dataset_not_declared")
                .count()
        };
        // On another thread, as lint's jobs run.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    [
                        count(
                            check
                                .check(file, "objects/rules/a.yaml", Some(UUID), &text)
                                .unwrap(),
                        ),
                        count(
                            check
                                .check_parsed(
                                    file,
                                    "objects/rules/a.yaml",
                                    Some(UUID),
                                    &text,
                                    &document,
                                )
                                .unwrap(),
                        ),
                    ]
                })
                .join()
                .unwrap()
        })
    };
    let declares = |sourcetype: &str| {
        format!(
            "[[logsources]]\nname = \"main\"\ndescription = \"x\"\nsystem = \"splunk\"\n\
             [[logsources]]\nname = \"{sourcetype}\"\ndescription = \"x\"\nsystem = \"splunk\"\n"
        )
    };
    assert_eq!(undeclared(&declares("other")), [1, 1]);
    assert_eq!(undeclared(&declares("linux_secure")), [0, 0]);
}

/// #1233: a file whose line endings the check rewrites is parsed again
/// from the rewritten text, not read from lint's parse of the original:
/// the findings and their lines are those of the `\n` text.
#[test]
fn lint_reads_crlf_and_cr_files_as_their_lf_text() {
    let lf = rule(&format!(
        "  sentinel:\n    query: |\n      search \"error\"\n{ELASTIC_KUERY}    query: \
         'process.name: \"a\"'\n    scheduling:\n      interval: 5m\n      lookback: 0m\n"
    ));
    let expected = lint_check(&lf);
    assert!(
        expected.iter().any(|(code, ..)| code == "lookback_zero"),
        "{expected:#?}"
    );
    assert!(
        expected
            .iter()
            .any(|(code, ..)| code == "kql_unscoped_search"),
        "{expected:#?}"
    );
    for ending in ["\r\n", "\r"] {
        assert_eq!(
            lint_check(&lf.replace('\n', ending)),
            expected,
            "{ending:?}"
        );
    }
}

#[test]
fn lint_reports_query_warnings_and_advisories_but_not_engine_errors() {
    let text = rule(&format!(
        "  sentinel:\n    query: |\n      search \"error\"\n  microsoft_defender:\n    \
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
    // So is Defender's: the block maps no entity.
    assert!(
        found.contains(&("microsoft_defender_no_entities".into(), "warning".into(), 9)),
        "{found:#?}"
    );
    // The query the engine rejects (`kql_parse_error` on line 12) is
    // validate's, and the object's other findings (schema, metadata) are not
    // the queries check's.
    assert_eq!(found.len(), 3, "{found:#?}");
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

const GRAYLOG_CONFIGURATION: &str = "/ws/.opentide/configurations/platforms/graylog.toml";

/// A Graylog configuration with one tenant, `lab`, and its setup's `extra`.
fn graylog_tenant(extra: &str) -> String {
    format!(
        "[platform]\nenabled = true\nname = \"Graylog\"\n\n[[tenants]]\nname = \"lab\"\n\n\
         [tenants.setup]\nurl = \"https://graylog.example\"\ntoken = \"$GRAYLOG_TOKEN\"\n{extra}"
    )
}

fn graylog_block(query: &str) -> String {
    format!(
        "  graylog:\n    enabled: true\n    status: STAGING\n    streams: sysmon\n    \
         schedule: {{every: 10m, window: 10m}}\n    query: '{query}'\n"
    )
}

/// Each code the queries check reports on `text`, as a rule of a workspace
/// that also holds `files`, with the errors first.
fn checked_codes(text: &str, files: &[(&str, &str)]) -> (Vec<String>, Vec<String>) {
    let mut all = vec![(FILE, text)];
    all.extend_from_slice(files);
    let ws = workspace(&all);
    let path = PathBuf::from(FILE);
    let objects = [QueryObject {
        path: &path,
        uuid: UUID,
        family: "rule",
        source: text,
    }];
    let found = EngineQueries.check(&ws, &objects, false);
    let codes = |items: Vec<Diagnostic>| items.into_iter().map(|d| d.code).collect();
    (codes(found.errors), codes(found.warnings))
}

#[test]
fn a_graylog_query_is_checked_in_the_graylog_dialect() {
    // Graylog's own refusal, not Elastic's Lucene warning.
    let (errors, warnings) = checked_codes(&rule(&graylog_block("image_lc:/(?i)mshta/")), &[]);
    assert_eq!(errors, ["graylog_regex_unsupported"]);
    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn a_leading_wildcard_is_refused_unless_every_reached_tenant_allows_it() {
    let text = rule(&graylog_block("image_lc:*mshta.exe"));
    // Offline, with no tenant, it stays an error.
    assert_eq!(checked_codes(&text, &[]).0, ["graylog_leading_wildcard"]);
    let refused = graylog_tenant("allow_leading_wildcard = false\n");
    assert_eq!(
        checked_codes(&text, &[(GRAYLOG_CONFIGURATION, &refused)]).0,
        ["graylog_leading_wildcard"]
    );
    let allowed = graylog_tenant("allow_leading_wildcard = true\n");
    assert_eq!(
        checked_codes(&text, &[(GRAYLOG_CONFIGURATION, &allowed)]),
        (Vec::new(), Vec::new())
    );
    // A block that reaches no tenant keeps it.
    let elsewhere = text.replace(
        "    streams: sysmon\n",
        "    streams: sysmon\n    tenants: [prod]\n",
    );
    assert_eq!(
        checked_codes(&elsewhere, &[(GRAYLOG_CONFIGURATION, &allowed)]).0,
        ["graylog_leading_wildcard"]
    );
}

#[test]
fn lint_reports_the_graylog_block_advisories() {
    use opentide_workspace::lint::LintQueryCheck;
    let block = "  graylog:\n    enabled: true\n    status: STAGING\n    \
                 schedule: {every: 5m, window: 15m}\n    query: 'EventID:1'\n";
    let text = rule(block);
    let _engine = opentide_cli::queries::ENGINE.lock().unwrap();
    let fs = MemoryFs::new();
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.write(GRAYLOG_CONFIGURATION, graylog_tenant(""));
    let check = EngineLintQueries::install(&fs, std::path::Path::new("/ws"));
    let found: Vec<(String, String, String)> = check
        .check(
            std::path::Path::new(FILE),
            "objects/rules/a.yaml",
            Some(UUID),
            &text,
        )
        .unwrap()
        .into_iter()
        .filter(|finding| finding.diagnostic.code.starts_with("graylog_"))
        .map(|finding| {
            (
                finding.diagnostic.code.clone(),
                finding.diagnostic.field_path.join("."),
                finding.diagnostic.message.clone(),
            )
        })
        .collect();
    // The engine's block check first, in its words, then the block's
    // advisories, as 0.28.1's lint reports them.
    let schedule = "configurations.graylog.schedule";
    assert_eq!(
        found
            .iter()
            .map(|(code, path, _)| (code.as_str(), path.as_str()))
            .collect::<Vec<_>>(),
        [
            ("graylog_overlapping_window", schedule),
            ("graylog_overlapping_window", schedule),
            ("graylog_all_streams", "configurations.graylog"),
        ]
    );
    assert_eq!(
        found[0].2,
        "this filter searches 900s every 300s, so runs overlap and each message alerts \
         once per run that sees it; set `window` to `every`, or aggregate"
    );
    assert!(
        found[1]
            .2
            .starts_with("the window (15m) is longer than the interval (5m)")
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
         activity_type:\"app-login\"\n      - query: activity_type:\"app-login\"\n        threshold:\n          \
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

#[test]
fn lint_reports_the_datadog_block_advisories() {
    let text = rule(
        "  datadog:\n    status: PREVIEW\n    queries:\n      - query: source:a\n      - query: \
         source:b\n      - query: source:c\n    cases:\n      - condition: a > 1 || b > 1 && c > \
         1\n",
    );
    let found = lint_check(&text);
    let advisories: Vec<(String, String)> = found
        .into_iter()
        .filter(|(code, _, _)| code.starts_with("datadog_condition"))
        .map(|(code, severity, _)| (code, severity))
        .collect();
    assert_eq!(
        advisories,
        [("datadog_condition_mixed".to_owned(), "warning".to_owned())]
    );
}

/// A block's query is a detection rule's (profile `rule`): full-text
/// `*:term` is a warning there; the same text in a `system: datadog` hunt is
/// a search (profile `search`), where it is not (RFC rfc-datadog-cloud-siem
/// §6.1).
#[test]
fn lint_checks_a_datadog_block_query_as_a_rule_and_a_hunt_as_a_search() {
    let text = format!(
        "{}response:\n  procedure:\n    searches:\n      - purpose: p\n        system: \
         datadog\n        query: '*:mimikatz'\n",
        rule(
            "  datadog:\n    status: PREVIEW\n    queries:\n      - query: '*:mimikatz'\n    \
             cases:\n      - condition: a > 0\n"
        )
    );
    let found: Vec<(String, String, usize)> = lint_check(&text)
        .into_iter()
        .filter(|(code, _, _)| code == "datadog_full_text_in_rule")
        .collect();
    assert_eq!(
        found,
        [(
            "datadog_full_text_in_rule".to_owned(),
            "warning".to_owned(),
            9
        )]
    );
}

/// Advanced hunting's own functions (#1914): a Sentinel block that calls one
/// gets lint's warning `kql_function_unavailable` at the function's name; a
/// Defender block that calls it gets nothing, and `validate` fails neither.
#[test]
fn lint_reports_a_defender_function_in_a_sentinel_query() {
    let query =
        "query: |\n      DeviceFileEvents\n      | project SHA1\n      | invoke FileProfile()\n";
    let sentinel = rule(&format!("  sentinel:\n    status: STAGING\n    {query}"));
    let found: Vec<(String, String, usize)> = lint_check(&sentinel)
        .into_iter()
        .filter(|(code, _, _)| code == "kql_function_unavailable")
        .collect();
    assert_eq!(
        found,
        [(
            "kql_function_unavailable".to_owned(),
            "warning".to_owned(),
            11
        )]
    );
    let (errors, warnings, _) = check(&sentinel, false);
    assert!(
        errors
            .iter()
            .chain(&warnings)
            .all(|d| d.code != "kql_function_unavailable"),
        "{errors:?} {warnings:?}"
    );
    let defender = rule(&format!(
        "  microsoft_defender:\n    status: STAGING\n    schedule:\n      frequency: 1H\n    {query}"
    ));
    assert!(
        lint_check(&defender)
            .iter()
            .all(|(code, _, _)| code != "kql_function_unavailable"),
        "{:?}",
        lint_check(&defender)
    );
}

/// Microsoft's documented custom detection limits (#1890): the alert's are
/// block advisories, which lint reports like `validate`; a continuous rule's
/// query is the engine's warning, lint's and not `validate`'s.
#[test]
fn lint_reports_the_microsoft_defender_documented_limits() {
    let details = (1..=21)
        .map(|n| format!("        Detail{n}: Column{n}\n"))
        .collect::<Vec<_>>()
        .concat();
    let text = rule(&format!(
        "  microsoft_defender:\n    status: STAGING\n    schedule:\n      frequency: NRT\n    \
         query: |\n      DeviceEvents\n      | join (DeviceInfo) on DeviceId\n    entities:\n      \
         hosts: [{{device_id: DeviceId}}]\n    alert:\n      title: \"{{{{A}}}} {{{{B}}}} {{{{C}}}} \
         {{{{D}}}}\"\n      custom_details:\n{details}"
    ));
    // #1885's output findings on the same block are its own tests'.
    let limits = [
        "microsoft_defender_custom_details_limit",
        "microsoft_defender_nrt_query",
        "microsoft_defender_placeholder_limit",
    ];
    let found: Vec<(String, String, usize)> = lint_check(&text)
        .into_iter()
        .filter(|(code, _, _)| limits.contains(&code.as_str()))
        .collect();
    let warning = |code: &str, line: usize| (code.to_owned(), "warning".to_owned(), line);
    assert_eq!(
        found,
        [
            warning("microsoft_defender_nrt_query", 12),
            warning("microsoft_defender_nrt_query", 12),
            warning("microsoft_defender_custom_details_limit", 17),
            warning("microsoft_defender_placeholder_limit", 16),
        ]
    );
    // `validate`'s queries check reports the engine's errors only.
    let (errors, warnings, _) = check(&text, false);
    assert!(
        errors.is_empty() && warnings.is_empty(),
        "{errors:#?} {warnings:#?}"
    );
}

/// #1890: `lint --strict` fails on the three Defender limit warnings, and
/// `[queries.codes]` in lint.toml, the changelog's Upgrade step, sets each
/// to `info`, which keeps them reported without failing: the block
/// advisories as the engine's NRT finding.
#[test]
fn lint_strict_fails_on_the_defender_limits_unless_lint_toml_lowers_them() {
    let details = (1..=21)
        .map(|n| format!("        Detail{n}: Column{n}\n"))
        .collect::<Vec<_>>()
        .concat();
    let text = rule(&format!(
        "  microsoft_defender:\n    status: STAGING\n    schedule:\n      frequency: NRT\n    \
         query: |\n      // all devices\n      DeviceEvents\n    entities:\n      hosts: \
         [{{device_id: DeviceId}}]\n    alert:\n      title: \"{{{{A}}}} {{{{B}}}} {{{{C}}}} \
         {{{{D}}}}\"\n      custom_details:\n{details}"
    ));
    const CODES: [&str; 3] = [
        "microsoft_defender_custom_details_limit",
        "microsoft_defender_nrt_query",
        "microsoft_defender_placeholder_limit",
    ];
    let defender = |document: &Value| -> Vec<(String, String)> {
        let mut found: Vec<(String, String)> = document["findings"]
            .as_array()
            .unwrap_or_else(|| panic!("{document}"))
            .iter()
            .filter(|finding| CODES.contains(&finding["code"].as_str().unwrap()))
            .map(|finding| {
                (
                    finding["code"].as_str().unwrap().to_owned(),
                    finding["severity"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        found.sort();
        found
    };
    let strict = lint_run(&text, &["--strict"]);
    assert_eq!(strict["exit_code"], 1, "{strict}");
    assert_eq!(
        defender(&strict),
        CODES.map(|code| (code.to_owned(), "warning".to_owned())),
        "{strict}"
    );
    let lowered = lint_run_with(
        &text,
        Some(
            "[queries.codes]\nmicrosoft_defender_custom_details_limit = \"info\"\n\
             microsoft_defender_placeholder_limit = \"info\"\n\
             microsoft_defender_nrt_query = \"info\"\n",
        ),
        &["--strict"],
    );
    assert_eq!(
        defender(&lowered),
        CODES.map(|code| (code.to_owned(), "info".to_owned())),
        "{lowered}"
    );
    assert_eq!(lowered["exit_code"], 0, "{lowered}");
}

/// `opentide --json lint` with `words` after it, in-process, in a workspace
/// on disk holding `text` as its one rule: the JSON document.
fn lint_run(text: &str, words: &[&str]) -> Value {
    lint_run_with(text, None, words)
}

/// [`lint_run`] with `lint_toml`, when given, as the workspace's
/// `.opentide/configurations/lint.toml`.
fn lint_run_with(text: &str, lint_toml: Option<&str>, words: &[&str]) -> Value {
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
    if let Some(lint_toml) = lint_toml {
        std::fs::write(ws.join(".opentide/configurations/lint.toml"), lint_toml).unwrap();
    }
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let host = opentide_cli::Host {
        version: "0.28.1".into(),
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
