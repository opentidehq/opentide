//! Elastic query languages through `opentide_analysis::analyze`.
//!
//! Every `__invalid` corpus fixture must produce an error, and a raw `.esql`,
//! `.eql`, `.kuery`, or `.lucene` document must get the same query
//! diagnostics as the same text inside a `configurations.elastic` block.

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, analyze};
use opentide_core::{LanguageId, Severity, codes};
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn diagnostics(uri: &str, language: LanguageId, text: &str) -> Vec<(String, Severity)> {
    let host = MemoryWorkspace {
        files: vec![(uri.to_string(), text.to_string())],
    };
    analyze(
        &host,
        AnalyzeRequest {
            uri: uri.to_string(),
            language,
            text: text.to_string(),
        },
    )
    .diagnostics
    .into_iter()
    .map(|d| (d.code, d.severity))
    .collect()
}

#[test]
fn invalid_fixtures_produce_an_error() {
    for (id, language) in [
        ("esql", LanguageId::Esql),
        ("eql", LanguageId::Eql),
        ("kuery", LanguageId::Kuery),
        ("lucene", LanguageId::Lucene),
    ] {
        let dir = repo_root().join("testdata/corpus").join(id);
        let mut checked = 0;
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.contains("__invalid") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            let body: String = text.lines().skip(1).collect::<Vec<_>>().join("\n");
            let found = diagnostics(&name, language, &body);
            assert!(
                found.iter().any(|(_, s)| *s == Severity::Error),
                "{id}/{name} produced no error: {found:?}"
            );
            checked += 1;
        }
        assert!(checked >= 10, "expected invalid fixtures under {id}");
    }
}

fn elastic_rule(rule_type: &str, language: Option<&str>, query: &str) -> String {
    let body = query
        .lines()
        .map(|line| format!("      {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    let language = language
        .map(|l| format!("    language: {l}\n"))
        .unwrap_or_default();
    format!(
        "\
name: Composability
metadata:
  uuid: 00000000-0000-4000-8003-000000000099
  schema: rule::1.1
configurations:
  elastic:
    enabled: true
    status: STAGING
    type: {rule_type}
{language}    query: |
{body}
"
    )
}

fn query_codes(uri: &str, language: LanguageId, text: &str) -> Vec<String> {
    let host = MemoryWorkspace {
        files: vec![(uri.to_string(), text.to_string())],
    };
    let mut codes: Vec<String> = analyze(
        &host,
        AnalyzeRequest {
            uri: uri.to_string(),
            language,
            text: text.to_string(),
        },
    )
    .diagnostics
    .into_iter()
    .filter(|d| {
        language != LanguageId::TideYaml
            || d.field_path
                .as_ref()
                .is_some_and(|p| p.first().map(String::as_str) == Some("configurations"))
    })
    .map(|d| d.code)
    .collect();
    codes.sort();
    codes
}

#[test]
fn raw_and_injected_queries_agree() {
    let cases: &[(&str, Option<&str>, LanguageId, &str, &str)] = &[
        (
            "esql",
            None,
            LanguageId::Esql,
            "rule.esql",
            "FROM logs-* METADATA _id\n| WEHRE process.name == \"x\"",
        ),
        (
            "eql",
            None,
            LanguageId::Eql,
            "rule.eql",
            "process where startsWth(process.name, \"x\")",
        ),
        (
            "query",
            None,
            LanguageId::Kuery,
            "rule.kuery",
            "message: cannot run and _exists_:host.name",
        ),
        (
            "new_terms",
            Some("lucene"),
            LanguageId::Lucene,
            "rule.lucene",
            "process.name:cmd.exe and user.name:root",
        ),
    ];
    for (rule_type, language_key, language, uri, query) in cases {
        let raw = query_codes(uri, *language, query);
        assert!(!raw.is_empty(), "{uri} should diagnose: {query}");
        let tide = elastic_rule(rule_type, *language_key, query);
        let injected = query_codes(
            "objects/rules/composability.yaml",
            LanguageId::TideYaml,
            &tide,
        );
        assert_eq!(raw, injected, "{uri}: raw and injected diagnostics differ");
    }
}

#[test]
fn injected_eql_reports_maxspan_against_the_schedule() {
    let query = "sequence with maxspan=30m\n  [process where true]\n  [file where true]";
    let tide = elastic_rule("eql", None, query).replace(
        "    query: |",
        "    scheduling:\n      interval: 5m\n      lookback: 1m\n    query: |",
    );
    let found = query_codes("objects/rules/eql.yaml", LanguageId::TideYaml, &tide);
    assert!(
        found.contains(&codes::EQL_MAXSPAN_WINDOW.to_string()),
        "{found:?}"
    );
}

#[test]
fn declared_tenant_versions_reach_esql_checks() {
    let rule = elastic_rule("esql", None, "FROM logs-* | WHERE host.name == \"x\"");
    let config = "[[tenants]]\nname = \"prod\"\n[tenants.setup]\nversion = \"9.5\"\n";
    let run = |files: Vec<(&str, &str)>| -> Vec<String> {
        let host = MemoryWorkspace {
            files: files
                .into_iter()
                .map(|(p, t)| (p.to_string(), t.to_string()))
                .collect(),
        };
        analyze(
            &host,
            AnalyzeRequest {
                uri: "objects/rules/r.yaml".into(),
                language: LanguageId::TideYaml,
                text: rule.clone(),
            },
        )
        .diagnostics
        .into_iter()
        .map(|d| d.code)
        .collect()
    };
    // No tenants: the 8.19 floor, where Kibana does not add METADATA _id.
    assert!(
        run(vec![("objects/rules/r.yaml", &rule)]).contains(&codes::ESQL_METADATA_ID.to_string())
    );
    // Every target declares 9.5: Kibana adds it, so the advisory goes.
    let found = run(vec![
        ("objects/rules/r.yaml", &rule),
        (
            "/ws/.opentide/configurations/platforms/elastic.toml",
            config,
        ),
    ]);
    assert!(
        !found.contains(&codes::ESQL_METADATA_ID.to_string()),
        "{found:?}"
    );
}
