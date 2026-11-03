//! Carbon Black Cloud queries get Carbon Black's fields, never ECS (#162).

use opentide_analysis::{
    AnalyzeRequest, LanguageId, MemoryWorkspace, analyze, codes, completions, hover,
};

const PATH: &str = "/w/objects/rules/cbc.yaml";

fn rule(query: &str) -> String {
    format!(
        "name: CBC\nmetadata:\n  uuid: 00000000-0000-4000-8003-0000000000cb\n  schema: rule::1.0\nconfigurations:\n  carbon_black_cloud:\n    query: {query}\n"
    )
}

fn elastic(query: &str) -> String {
    format!(
        "name: Elastic\nmetadata:\n  uuid: 00000000-0000-4000-8003-0000000000ec\n  schema: rule::1.1\nconfigurations:\n  elastic:\n    type: query\n    language: lucene\n    query: {query}\n"
    )
}

fn codes_of(text: &str) -> Vec<(String, Option<String>)> {
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
    .map(|d| (d.code, d.suggestion))
    .collect()
}

#[test]
fn a_misspelt_field_is_reported_in_carbon_black_only() {
    let found = codes_of(&rule("process_nmae:cmd.exe"));
    assert!(
        found.contains(&(
            codes::CBC_UNKNOWN_FIELD.to_string(),
            Some("process_name".to_string())
        )),
        "{found:?}"
    );
    assert!(
        !codes_of(&rule("process_name:cmd.exe"))
            .iter()
            .any(|(c, _)| c == codes::CBC_UNKNOWN_FIELD)
    );
    // The same text in an Elastic `language: lucene` query is ECS's business.
    assert!(
        !codes_of(&elastic("process_nmae:cmd.exe"))
            .iter()
            .any(|(c, _)| c == codes::CBC_UNKNOWN_FIELD)
    );
}

#[test]
fn hover_and_completion_offer_carbon_black_fields_not_ecs() {
    let text = rule("process_name:cmd.exe AND proc");
    let host = MemoryWorkspace {
        files: vec![(PATH.into(), text.clone())],
    };
    let at = text.find("process_name").unwrap() + 3;
    let docs = hover(&host, LanguageId::TideYaml, &text, at).expect("hover");
    assert!(docs.contains("Carbon Black Cloud process search"), "{docs}");
    let end = text.find("AND proc").unwrap() + "AND proc".len();
    let items = completions(&host, LanguageId::TideYaml, &text, end);
    let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
    assert!(labels.contains(&"process_cmdline"), "{labels:?}");
    assert!(
        !labels.iter().any(|l| l.contains('.')),
        "an ECS field: {labels:?}"
    );
    // A raw `.lucene` file keeps the Elastic behaviour.
    let raw = "process.name:a AND pro";
    let host = MemoryWorkspace::default();
    let raw_items = completions(&host, LanguageId::Lucene, raw, raw.len());
    assert!(
        raw_items.iter().any(|i| i.label.contains('.')),
        "ECS fields"
    );
}

/// The cursor after a query's last character, as it is while the author
/// types, is inside the query, whatever the language.
#[test]
fn completion_works_at_the_end_of_an_injected_query() {
    for (platform, query) in [
        ("sentinel", "SecurityEvent | wh"),
        ("carbon_black_cloud", "process_name:a AND proc"),
    ] {
        let text = format!(
            "name: X\nmetadata:\n  schema: rule::1.0\nconfigurations:\n  {platform}:\n    query: {query}\n"
        );
        let host = MemoryWorkspace::default();
        let end = text.find(query).unwrap() + query.len();
        assert!(
            !completions(&host, LanguageId::TideYaml, &text, end).is_empty(),
            "{platform}"
        );
    }
}
