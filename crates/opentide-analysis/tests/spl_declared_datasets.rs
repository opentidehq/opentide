//! Splunk indexes, sourcetypes and macros a workspace declares in
//! `visibility.toml` (#115): a declared name passes, an undeclared one warns
//! only in a workspace that declares names of that kind for Splunk.

use opentide_analysis::{AnalyzeRequest, Catalog, MemoryWorkspace, analyze, install_catalog};
use opentide_core::{Diagnostic, LanguageId, Severity, codes};

const SPLUNK: &str = r#"{"opentide": "0.20.0", "platforms": {
    "splunk": {"indexes": ["wineventlog", "edr_*"], "macros": ["wineventlog_security"]},
    "sentinel": {"tables": ["SigninLogs"]}
}}"#;
const SENTINEL_ONLY: &str = r#"{"platforms": {"sentinel": {"tables": ["SigninLogs"]}}}"#;

const RULE: &str = r#"name: Declared Datasets

metadata:
  uuid: 00000000-0000-4000-8003-000000000116
  schema: rule::1.0
  version: 1
  created: "2026-01-01"
  modified: "2026-01-02"
  tlp: clear
  author: analyst
  organisation: opentide

description: |
  A Splunk search on a declared and an undeclared index.
status: STAGING
severity: High
techniques:
  - T1059
detection_model: 00000000-0000-4000-8002-000000000001

response:
  alert_severity: High

configurations:
  splunk:
    enabled: true
    name: Declared Datasets
    status: STAGING
    query: |
      index=wineventlog OR index=firewall sourcetype=pan:traffic
      | stats count by src
    cron_schedule: "0 * * * *"
"#;

fn diagnostics(language: LanguageId, uri: &str, text: &str) -> Vec<Diagnostic> {
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
}

/// The text under each `spl_dataset_not_declared` warning.
fn undeclared(language: LanguageId, uri: &str, text: &str) -> Vec<String> {
    diagnostics(language, uri, text)
        .iter()
        .filter(|d| d.code == codes::SPL_DATASET_NOT_DECLARED)
        .map(|d| {
            assert_eq!(d.severity, Severity::Warning, "{d:?}");
            let line = text.lines().nth(d.range.start.line as usize).unwrap();
            line[d.range.start.character as usize..d.range.end.character as usize].to_string()
        })
        .collect()
}

fn install(datasets: Option<&str>) {
    install_catalog(&Catalog {
        datasets: datasets.map(str::to_string),
        ..Catalog::default()
    })
    .unwrap();
}

// One test: the declared datasets are process-wide.
#[test]
fn declared_splunk_datasets_pass_and_undeclared_ones_warn_when_the_kind_is_declared() {
    let spl = "index=wineventlog OR index=main sourcetype=syslog `wineventlog_security` `sysmon` | stats count by host | `drop_dm_object_name(Processes)`";

    // A workspace that declares nothing gets no warning.
    install(None);
    assert!(undeclared(LanguageId::Spl, "a.spl", spl).is_empty());

    // Declarations for another platform are not an opt-in for Splunk.
    install(Some(SENTINEL_ONLY));
    assert!(undeclared(LanguageId::Spl, "a.spl", spl).is_empty());

    // Indexes and macros are declared, sourcetypes are not: only the first
    // two kinds are checked.
    install(Some(SPLUNK));
    assert_eq!(
        undeclared(LanguageId::Spl, "a.spl", spl),
        ["main", "sysmon"]
    );
    assert!(undeclared(LanguageId::Spl, "b.spl", "index=wineventlog | head 1").is_empty());
    assert!(undeclared(LanguageId::Spl, "c.spl", "index=edr_crowdstrike | head 1").is_empty());
    assert_eq!(
        undeclared(LanguageId::TideYaml, "rule.yaml", RULE),
        ["firewall"]
    );

    install(None);
    assert!(undeclared(LanguageId::TideYaml, "rule.yaml", RULE).is_empty());
}
