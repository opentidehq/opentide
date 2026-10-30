//! Tables a workspace declares in visibility.toml are known; with
//! declarations, an undeclared table warns (#114). Declared datasets are
//! process-wide, so this file holds one test.

use opentide_analysis::{Catalog, LanguageId, QueryRequest, analyze_query, codes, install_catalog};

fn findings(platform: &str, text: &str) -> Vec<(String, String)> {
    analyze_query(&QueryRequest {
        language: LanguageId::Kql,
        platform: Some(platform.into()),
        stack: None,
        text: text.into(),
    })
    .into_iter()
    .map(|d| (d.code, format!("{:?}", d.severity)))
    .collect()
}

fn declare(json: Option<&str>) {
    install_catalog(&Catalog {
        visibility: json.map(str::to_string),
        ..Catalog::default()
    })
    .unwrap();
}

#[test]
fn declared_tables_are_known_and_undeclared_ones_warn_once_a_workspace_declares_any() {
    let warning = |code: &str| vec![(code.to_string(), "Warning".to_string())];

    // No declarations: #111.
    declare(None);
    assert_eq!(
        findings("sentinel", "Custom_CL | take 1"),
        warning(codes::KQL_UNKNOWN_TABLE)
    );
    assert!(findings("sentinel", "SigninLogs | take 1").is_empty());

    // A Splunk index never makes a KQL table known.
    declare(Some(
        r#"[[logsources]]
name = "splunk datasets"
description = "Test log source."
system = "splunk"
indexes = ["Custom_CL", "SigninLogs"]
"#,
    ));
    assert_eq!(
        findings("sentinel", "Custom_CL | take 1"),
        warning(codes::KQL_UNKNOWN_TABLE)
    );
    assert!(findings("sentinel", "SigninLogs | take 1").is_empty());

    declare(Some(
        r#"[[logsources]]
name = "sentinel datasets"
description = "Test log source."
system = "sentinel"
tables = ["Custom_CL", "NTANetAnalytics", "Vendor*_CL"]
"#,
    ));
    // Declared: known, and an unknown declared table has no column checks.
    assert!(findings("sentinel", "Custom_CL | where AnyColumn == 1 | take 1").is_empty());
    assert!(findings("sentinel", "VendorFirewall_CL | take 1").is_empty());
    assert!(findings("sentinel", "NTANetAnalytics | take 1").is_empty());
    // Undeclared, built-in or not: a warning.
    assert_eq!(
        findings("sentinel", "SigninLogs | take 1"),
        warning(codes::KQL_TABLE_NOT_DECLARED)
    );
    assert_eq!(
        findings("sentinel", "Other_CL | take 1"),
        warning(codes::KQL_TABLE_NOT_DECLARED)
    );
    // Union legs and join sources are read too; `isfuzzy=true` tolerates absent legs.
    assert_eq!(
        findings("sentinel", "union Custom_CL, Other_CL | take 1"),
        warning(codes::KQL_TABLE_NOT_DECLARED)
    );
    assert!(
        findings(
            "sentinel",
            "union isfuzzy=true Custom_CL, Other_CL | take 1"
        )
        .is_empty()
    );
    assert_eq!(
        findings(
            "sentinel",
            "Custom_CL | join (SigninLogs) on UserPrincipalName"
        ),
        warning(codes::KQL_TABLE_NOT_DECLARED)
    );
    // A near miss of a declared table suggests it.
    let d = analyze_query(&QueryRequest {
        language: LanguageId::Kql,
        platform: Some("sentinel".into()),
        stack: None,
        text: "Custom_C | take 1".into(),
    });
    assert_eq!(d[0].suggestion.as_deref(), Some("Custom_CL"));
    assert_eq!(
        d[0].message,
        "'Custom_C' is not a table the workspace declares for sentinel in visibility.toml"
    );
    // Sentinel's declarations are not Defender's: Defender keeps #111.
    assert!(findings("defender_for_endpoint", "DeviceProcessEvents | take 1").is_empty());

    declare(None);
    assert_eq!(
        findings("sentinel", "Other_CL | take 1"),
        warning(codes::KQL_UNKNOWN_TABLE)
    );
}
