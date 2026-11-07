//! Tables a workspace declares in visibility.toml are known; with
//! declarations, an undeclared table warns (#114). Declared columns are
//! checked, hovered and completed like a documented table's (#146).
//! Declared datasets are process-wide, so this file holds one test.

use opentide_analysis::{
    Catalog, LanguageId, MemoryWorkspace, QueryRequest, analyze_query, codes, completions, hover,
    install_catalog,
};

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

fn declare(text: Option<&str>) {
    install_catalog(&Catalog {
        visibility: text.map(str::to_string),
        ..Catalog::default()
    })
    .unwrap();
}

const SENTINEL: &str = r#"[[logsources]]
name = "Contoso_Audit_CL"
description = "Administrative audit events from the Contoso connector."
system = "sentinel"

[logsources.columns]
TimeGenerated = { type = "datetime" }
Actor_s = { type = "string", description = "UPN of the account that made the change" }
ResultCode_d = { type = "real" }

[[logsources]]
name = "Custom_CL"
description = "Custom."
system = "sentinel"

[[logsources]]
name = "NTANetAnalytics"
description = "Flows."
system = "sentinel"

[[logsources]]
name = "Vendor*_CL"
description = "Vendor tables."
system = "sentinel"

[logsources.columns]
DeviceAction_s = { type = "string", description = "What the vendor device did." }
Severity_d = { type = "real" }

[[logsources]]
name = "VendorProxy_CL"
description = "Vendor proxy."
system = "sentinel"

[logsources.columns]
Severity_d = { type = "string", description = "Severity as the proxy writes it." }
Url_s = { type = "string" }

[[logsources]]
name = "SecurityInciden*"
description = "Incidents."
system = "sentinel"

[logsources.columns]
CustomTriage = { type = "string" }

[[logsources]]
name = "myWorkspaceFunction"
description = "A workspace function, declared like a table."
system = "sentinel"

[[logsources]]
name = "SigninLogs"
description = "Sign-ins."
system = "sentinel"

[logsources.columns]
CustomRisk = { type = "int", description = "Risk from the Contoso pipeline." }
ResultType = { type = "int", description = "Declared as a number." }
"#;

#[test]
fn declared_tables_are_known_and_undeclared_ones_warn_once_a_workspace_declares_any() {
    let warning = |code: &str| vec![(code.to_string(), "Warning".to_string())];
    let error = |code: &str| vec![(code.to_string(), "Error".to_string())];

    // No declarations: #111.
    declare(None);
    assert_eq!(
        findings("sentinel", "Custom_CL | take 1"),
        warning(codes::KQL_UNKNOWN_TABLE)
    );
    assert!(findings("sentinel", "SigninLogs | take 1").is_empty());
    assert_eq!(
        findings("sentinel", "SigninLogs | where ResultType > 5"),
        error(codes::KQL_TYPE_MISMATCH)
    );
    // Without declarations a lower-case name may be a workspace function,
    // unless it ends in `_CL` (#149).
    assert!(findings("sentinel", "myWorkspaceFunction | take 1").is_empty());
    assert!(findings("sentinel", "otherFunction | take 1").is_empty());
    assert_eq!(
        findings("sentinel", "custom_CL | take 1"),
        warning(codes::KQL_UNKNOWN_TABLE)
    );
    assert_eq!(
        findings("defender_for_endpoint", "custom_CL | take 1"),
        error(codes::KQL_UNKNOWN_TABLE)
    );

    // A Splunk sourcetype never makes a KQL table known.
    declare(Some(
        r#"[[logsources]]
name = "Custom_CL"
description = "x"
system = "splunk"
"#,
    ));
    assert_eq!(
        findings("sentinel", "Custom_CL | take 1"),
        warning(codes::KQL_UNKNOWN_TABLE)
    );
    assert!(findings("sentinel", "SigninLogs | take 1").is_empty());

    // The plural list of opentide 0.20.0 declares nothing.
    declare(Some(
        r#"[[logsources]]
description = "x"
system = "sentinel"
tables = ["Custom_CL"]
"#,
    ));
    assert_eq!(
        findings("sentinel", "Custom_CL | take 1"),
        warning(codes::KQL_UNKNOWN_TABLE)
    );

    declare(Some(SENTINEL));
    // Declared by name only: known, and its columns are not checked.
    assert!(findings("sentinel", "Custom_CL | where AnyColumn == 1 | take 1").is_empty());
    assert!(
        findings(
            "sentinel",
            "VendorFirewall_CL | where Anything > 1 | take 1"
        )
        .is_empty()
    );
    assert!(findings("sentinel", "NTANetAnalytics | take 1").is_empty());
    // Columns on a pattern apply to every table it matches: one only the
    // query names, a declared one, and a catalog table. An exact entry's
    // column wins over a pattern's of the same name; the rest merge.
    assert!(
        findings(
            "sentinel",
            "VendorFirewall_CL | where DeviceAction_s == \"deny\" and Severity_d > 1"
        )
        .is_empty()
    );
    let d = analyze_query(&QueryRequest {
        language: LanguageId::Kql,
        platform: Some("sentinel".into()),
        stack: None,
        text: "VendorFirewall_CL | where DeviceActon_s == \"deny\"".into(),
    });
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].code, codes::KQL_UNKNOWN_COLUMN);
    assert_eq!(d[0].suggestion.as_deref(), Some("DeviceAction_s"));
    assert!(
        findings(
            "sentinel",
            "VendorProxy_CL | where DeviceAction_s == \"deny\" and Url_s has \"x\""
        )
        .is_empty()
    );
    assert_eq!(
        findings("sentinel", "VendorProxy_CL | where Severity_d > 1"),
        error(codes::KQL_TYPE_MISMATCH)
    );
    assert_eq!(
        findings("sentinel", "VendorProxy_CL | where DeviceActon_s == \"a\""),
        error(codes::KQL_UNKNOWN_COLUMN)
    );
    assert!(findings("sentinel", "SecurityIncident | where CustomTriage == \"x\"").is_empty());
    assert_eq!(
        findings("sentinel", "SecurityIncident | where CustomTriag == \"x\""),
        error(codes::KQL_UNKNOWN_COLUMN)
    );
    let md = hover(
        &MemoryWorkspace::default(),
        LanguageId::Kql,
        "VendorFirewall_CL | where DeviceAction_s == 1",
        30,
    )
    .unwrap();
    assert!(md.contains("What the vendor device did."), "{md}");
    let md = hover(
        &MemoryWorkspace::default(),
        LanguageId::Kql,
        "VendorProxy_CL | where Severity_d == 1",
        25,
    )
    .unwrap();
    assert!(md.contains("Severity as the proxy writes it."), "{md}");

    // Undeclared and built in: a warning.
    assert_eq!(
        findings("sentinel", "AuditLogs | take 1"),
        warning(codes::KQL_TABLE_NOT_DECLARED)
    );
    // Union legs and join sources are read too; `isfuzzy=true` tolerates absent legs.
    assert_eq!(
        findings("sentinel", "union Custom_CL, AuditLogs | take 1"),
        warning(codes::KQL_TABLE_NOT_DECLARED)
    );
    assert!(
        findings(
            "sentinel",
            "union isfuzzy=true Custom_CL, AuditLogs | take 1"
        )
        .is_empty()
    );
    assert_eq!(
        findings("sentinel", "Custom_CL | join (AuditLogs) on OperationName"),
        warning(codes::KQL_TABLE_NOT_DECLARED)
    );
    // Undeclared and unknown to the catalog: still `kql_unknown_table` at
    // the profile's severity (#147), its help naming the declaration, and a
    // near miss of a declared table suggests it.
    let d = analyze_query(&QueryRequest {
        language: LanguageId::Kql,
        platform: Some("sentinel".into()),
        stack: None,
        text: "Custom_C | take 1".into(),
    });
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].code, codes::KQL_UNKNOWN_TABLE);
    assert_eq!(d[0].severity, opentide_analysis::Severity::Warning);
    assert_eq!(d[0].suggestion.as_deref(), Some("Custom_CL"));
    assert_eq!(
        d[0].message,
        "'Custom_C' is not a table opentide knows; if the workspace holds it, declare it for sentinel in visibility.toml"
    );
    assert_eq!(
        findings("sentinel", "Other_CL | take 1"),
        warning(codes::KQL_UNKNOWN_TABLE)
    );
    // With declarations every source name is checked, whatever its case
    // (#149), except `let` bindings, tabular parameters, functions the
    // engine knows and ASIM parsers.
    assert!(findings("sentinel", "myWorkspaceFunction | take 1").is_empty());
    assert_eq!(
        findings("sentinel", "otherFunction | take 1"),
        warning(codes::KQL_UNKNOWN_TABLE)
    );
    assert_eq!(
        findings("sentinel", "union Custom_CL, otherFunction | take 1"),
        warning(codes::KQL_UNKNOWN_TABLE)
    );
    for query in [
        "let recent = Custom_CL | take 1; recent | take 1",
        "let f = (T:(TimeGenerated:datetime)) { T | take 1 }; f(Custom_CL)",
        "_GetWatchlist('allow') | take 1",
        "_Im_Dns | take 1",
        "imDns | take 1",
        "imMyOwnParser | take 1",
        "_ASim_MyOwnParser | take 1",
    ] {
        assert!(
            findings("sentinel", query).is_empty(),
            "{query}: {:?}",
            findings("sentinel", query)
        );
    }

    // Declared columns are checked as a documented table's: a near miss is
    // an unknown column, an operator the declared type lacks a mismatch.
    assert!(
        findings(
            "sentinel",
            "Contoso_Audit_CL | where Actor_s == \"a\" and ResultCode_d > 1 and TimeGenerated > ago(1h)"
        )
        .is_empty()
    );
    let d = analyze_query(&QueryRequest {
        language: LanguageId::Kql,
        platform: Some("sentinel".into()),
        stack: None,
        text: "Contoso_Audit_CL | where Actor_x == \"a\"".into(),
    });
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].code, codes::KQL_UNKNOWN_COLUMN);
    assert_eq!(d[0].suggestion.as_deref(), Some("Actor_s"));
    assert_eq!(
        findings("sentinel", "Contoso_Audit_CL | where Actor_s > 5"),
        error(codes::KQL_TYPE_MISMATCH)
    );
    // Any other name, and the columns every Log Analytics table has, pass.
    assert!(
        findings(
            "sentinel",
            "Contoso_Audit_CL | where Unrelated == 1 and TenantId == \"x\""
        )
        .is_empty()
    );

    // On a catalog table, declared columns extend it, and a declared column
    // with a catalog column's name replaces its type.
    assert!(
        findings(
            "sentinel",
            "SigninLogs | where CustomRisk > 1 and UserPrincipalName == \"a\""
        )
        .is_empty()
    );
    assert_eq!(
        findings("sentinel", "SigninLogs | where CustomRisc > 1"),
        error(codes::KQL_UNKNOWN_COLUMN)
    );
    assert!(findings("sentinel", "SigninLogs | where ResultType > 5").is_empty());

    // Hover shows the declared type and description; completion offers them.
    let host = MemoryWorkspace::default();
    let query = "Contoso_Audit_CL | where Actor_s == \"a\"";
    let md = hover(&host, LanguageId::Kql, query, 27).unwrap();
    assert!(md.contains("**Actor_s** column (`string`)"), "{md}");
    assert!(
        md.contains("UPN of the account that made the change"),
        "{md}"
    );
    assert!(md.contains("visibility.toml"), "{md}");
    let md = hover(
        &host,
        LanguageId::Kql,
        "SigninLogs | where ResultType == 0",
        22,
    )
    .unwrap();
    assert!(md.contains("(`int`)"), "{md}");
    assert!(md.contains("Declared as a number."), "{md}");
    let md = hover(&host, LanguageId::Kql, query, 3).unwrap();
    assert!(md.contains("Administrative audit events"), "{md}");
    assert!(md.contains("`ResultCode_d` _real_"), "{md}");
    let typed = "Contoso_Audit_CL | where ";
    let items = completions(&host, LanguageId::Kql, typed, typed.len());
    let actor = items
        .iter()
        .find(|i| i.label == "Actor_s")
        .unwrap_or_else(|| panic!("{items:?}"));
    assert_eq!(actor.detail.as_deref(), Some("Contoso_Audit_CL (string)"));

    // Sentinel's declarations are not Defender's: Defender keeps #111.
    assert!(findings("defender_for_endpoint", "DeviceProcessEvents | take 1").is_empty());

    // Defender, opted in: an undeclared catalog table warns; an unknown one
    // stays an error, whose help names the declaration (#147).
    declare(Some(
        r#"[[logsources]]
name = "DeviceProcessEvents"
description = "Processes."
system = "defender_for_endpoint"
"#,
    ));
    assert!(findings("defender_for_endpoint", "DeviceProcessEvents | take 1").is_empty());
    assert_eq!(
        findings("defender_for_endpoint", "DeviceFileEvents | take 1"),
        warning(codes::KQL_TABLE_NOT_DECLARED)
    );
    let d = analyze_query(&QueryRequest {
        language: LanguageId::Kql,
        platform: Some("defender_for_endpoint".into()),
        stack: None,
        text: "Custom_CL | take 1".into(),
    });
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].code, codes::KQL_UNKNOWN_TABLE);
    assert_eq!(d[0].severity, opentide_analysis::Severity::Error);
    assert_eq!(
        d[0].message,
        "unknown table 'Custom_CL'; if the workspace holds it, declare it for defender_for_endpoint in visibility.toml"
    );

    declare(None);
    assert_eq!(
        findings("sentinel", "Contoso_Audit_CL | take 1"),
        warning(codes::KQL_UNKNOWN_TABLE)
    );
    assert_eq!(
        findings("sentinel", "SigninLogs | where ResultType > 5"),
        error(codes::KQL_TYPE_MISMATCH)
    );
}
