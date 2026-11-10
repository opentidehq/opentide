//! What KQL suggests for a table a workspace declares in `visibility.toml`
//! (#790): a declared table is suggested by the shared rule
//! (`opentide_core::suggest`), and a declared pattern (`*`) never is, since
//! it is not a name a query can read.

use opentide_analysis::{Catalog, LanguageId, QueryRequest, analyze_query, install_catalog};

const DECLARED: &str = r#"[[logsources]]
name = "ContosoAuditTrail_CL"
description = "A custom audit table."
system = "sentinel"

[[logsources]]
name = "Proxy*Logs"
description = "Proxy tables."
system = "sentinel"
"#;

/// The suggestions on the diagnostics `query` gets.
fn suggestions(query: &str) -> Vec<String> {
    analyze_query(&QueryRequest {
        language: LanguageId::Kql,
        platform: Some("sentinel".into()),
        stack: None,
        text: query.into(),
    })
    .into_iter()
    .filter_map(|d| d.suggestion)
    .collect()
}

// One test: the declared datasets are process-wide.
#[test]
fn declared_tables_are_suggested_and_patterns_are_not() {
    install_catalog(&Catalog {
        visibility: Some(DECLARED.into()),
        ..Catalog::default()
    })
    .unwrap();
    // Two letters cut from a declared name, side by side: still found.
    assert_eq!(
        suggestions("ContosoAuditTrai_CL | take 1"),
        ["ContosoAuditTrail_CL"]
    );
    // Two letters changed side by side.
    assert_eq!(
        suggestions("ContosoAuditTrxx_CL | take 1"),
        ["ContosoAuditTrail_CL"]
    );
    // `Proxy*Logs` is two edits from `ProxyLogz`, but a pattern is not a
    // table name: it is never the suggestion.
    let proxy = suggestions("ProxyLogz | take 1");
    assert!(
        !proxy.iter().any(|s| s.contains('*')),
        "a declared pattern was suggested: {proxy:?}"
    );
    install_catalog(&Catalog::default()).unwrap();
}
