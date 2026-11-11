//! Graylog queries are Lucene in the Graylog dialect (graylog-1.0): the
//! block's query, a query file under `--platform graylog`, hover, and
//! completion, with Graylog's message fields and never ECS.

use opentide_analysis::{
    AnalyzeRequest, LanguageId, MemoryWorkspace, QueryRequest, analyze, analyze_query, codes,
    completions, hover,
};

const PATH: &str = "/w/objects/rules/graylog.yaml";

fn rule(query: &str) -> String {
    format!(
        "name: Graylog\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000068\n  schema: rule::1.0\nconfigurations:\n  graylog:\n    status: STAGING\n    query: {query}\n"
    )
}

fn codes_of(text: &str) -> Vec<String> {
    let host = MemoryWorkspace {
        files: vec![(PATH.into(), text.into())],
    };
    analyze(
        &host,
        AnalyzeRequest {
            uri: PATH.into(),
            language: LanguageId::TideYaml,
            text: text.into(),
        },
    )
    .diagnostics
    .into_iter()
    .map(|d| d.code)
    .collect()
}

#[test]
fn the_block_query_is_checked_in_the_graylog_dialect() {
    let found = codes_of(&rule("'Image:*cmd.exe'"));
    assert!(
        found.contains(&codes::GRAYLOG_LEADING_WILDCARD.to_string()),
        "{found:?}"
    );
    assert!(
        !codes_of(&rule("'Image:/.*cmd\\.exe/'"))
            .iter()
            .any(|c| c.starts_with("graylog_") || c.starts_with("lucene_"))
    );
}

#[test]
fn a_query_file_takes_the_platform_dialect() {
    let request = |platform: Option<&str>| QueryRequest {
        language: LanguageId::Lucene,
        platform: platform.map(str::to_string),
        stack: None,
        text: "message:/(?i)fail.*/".into(),
    };
    let graylog: Vec<String> = analyze_query(&request(Some("graylog")))
        .into_iter()
        .map(|d| d.code)
        .collect();
    assert!(
        graylog.contains(&codes::GRAYLOG_REGEX_UNSUPPORTED.to_string())
            && graylog.contains(&codes::GRAYLOG_ANALYZED_FIELD.to_string()),
        "{graylog:?}"
    );
    let elastic: Vec<String> = analyze_query(&request(None))
        .into_iter()
        .map(|d| d.code)
        .collect();
    assert!(
        !elastic.iter().any(|c| c.starts_with("graylog_")),
        "{elastic:?}"
    );
}

#[test]
fn hover_and_completion_offer_graylog_fields_not_ecs() {
    let text = rule("message:x AND full_");
    let host = MemoryWorkspace {
        files: vec![(PATH.into(), text.clone())],
    };
    let at = text.find("message").unwrap() + 2;
    let docs = hover(&host, LanguageId::TideYaml, &text, at).expect("hover");
    assert!(docs.contains("Graylog message field"), "{docs}");
    let end = text.find("full_").unwrap() + "full_".len();
    let items = completions(&host, LanguageId::TideYaml, &text, end);
    let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
    assert!(labels.contains(&"full_message"), "{labels:?}");
    assert!(labels.contains(&"_exists_"), "{labels:?}");
    assert!(
        !labels.iter().any(|l| l.starts_with("process.")),
        "an ECS field: {labels:?}"
    );
}
