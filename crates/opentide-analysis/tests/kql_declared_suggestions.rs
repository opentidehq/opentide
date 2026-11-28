//! What KQL suggests for a table a workspace declares in `visibility.toml`
//! (#790): a declared table is suggested by the shared rule
//! (`opentide_core::suggest`), and a declared pattern (`*`) never is, since
//! it is not a name a query can read.

use opentide_analysis::{Catalog, LanguageId, QueryRequest, analyze_query, codes, install_catalog};

const DECLARED: &str = r#"[[logsources]]
name = "ContosoAuditTrail_CL"
description = "A custom audit table."
system = "sentinel"

[[logsources]]
name = "Azure Activity"
description = "A display name, not a KQL identifier."
system = "sentinel"

[[logsources]]
name = "Contoso Audit"
description = "A display name with columns: a catalog row named after it."
system = "sentinel"

[logsources.columns]
TimeGenerated = { type = "datetime" }

[[logsources]]
name = "Proxy*Logs"
description = "Proxy tables."
system = "sentinel"
"#;

/// The suggestions on the diagnostics `query` gets.
fn suggestions(query: &str) -> Vec<String> {
    analyze_query(&QueryRequest::new(LanguageId::Kql, query).with_platform(Some("sentinel")))
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
    // A declared display name is not a KQL identifier: `Azure Activity` is
    // never offered, so the quick fix cannot break the query. `AzureActivity`
    // is a table the catalog knows: undeclared, not misspelt, so no rename.
    let known = analyze_query(
        &QueryRequest::new(LanguageId::Kql, "AzureActivity | take 1")
            .with_platform(Some("sentinel")),
    );
    assert_eq!(known.len(), 1, "{known:?}");
    assert_eq!(known[0].code, codes::KQL_TABLE_NOT_DECLARED);
    assert_eq!(known[0].suggestion, None, "{known:?}");
    // An unknown near miss gets the catalog table, never a declared display name.
    assert_eq!(suggestions("AzureActivty | take 1"), ["AzureActivity"]);
    // A declared display name with columns is a catalog row too: it is not
    // offered through that fallback either.
    let audit = suggestions("ContosoAudt | take 1");
    assert!(
        !audit.iter().any(|s| s.contains(' ')),
        "a display name was suggested: {audit:?}"
    );
    install_catalog(&Catalog::default()).unwrap();
}
