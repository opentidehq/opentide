//! The Kibana KQL engine takes the Lucene grammar's verdict as an argument
//! (`opentide_kuery::analyze`); the two places that call it pass the real one.
//! A KQL error that Lucene accepts is one sign of a rule written for
//! `language: lucene`, in a raw query document and in a rule's query.

use opentide_analysis::{AnalyzeRequest, LanguageId, MemoryWorkspace, analyze, codes};

/// Implicit AND is a KQL error that Lucene accepts; `_exists_` is the second sign.
const QUERY: &str = "a:1 b:2 AND _exists_:c";

fn hint(uri: &str, language: LanguageId, text: &str) -> Option<String> {
    let host = MemoryWorkspace {
        files: vec![(uri.into(), text.into())],
    };
    analyze(
        &host,
        AnalyzeRequest {
            uri: uri.into(),
            language,
            text: text.into(),
        },
    )
    .diagnostics
    .into_iter()
    .find(|d| d.code == codes::KUERY_LOOKS_LIKE_LUCENE)
    .map(|d| d.message)
}

#[test]
fn a_raw_kuery_document_gets_the_lucene_verdict() {
    let message = hint("/w/q.kuery", LanguageId::Kuery, QUERY).expect("the hint");
    assert!(message.contains("text only Lucene parses"), "{message}");
}

#[test]
fn a_rules_kuery_query_gets_the_lucene_verdict() {
    let rule = format!(
        "name: Elastic\nmetadata:\n  uuid: 00000000-0000-4000-8003-0000000000ed\n  schema: rule::1.1\nconfigurations:\n  elastic:\n    type: query\n    language: kuery\n    query: '{QUERY}'\n"
    );
    let message =
        hint("/w/objects/rules/kuery.yaml", LanguageId::TideYaml, &rule).expect("the hint");
    assert!(message.contains("text only Lucene parses"), "{message}");
}
