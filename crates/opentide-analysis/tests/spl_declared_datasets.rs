//! Splunk sourcetypes a workspace declares in `visibility.toml` (#115,
//! `visibility::1.0`): a declared sourcetype passes, an undeclared one warns
//! only in a workspace with Splunk log sources.

use opentide_analysis::{
    AnalyzeRequest, Catalog, MemoryWorkspace, analyze, completions, hover, install_catalog,
};
use opentide_core::{Diagnostic, LanguageId, Severity, codes};

const SPLUNK: &str = r#"[[logsources]]
name = "WinEventLog:Security"
description = "Domain controller security log."
system = "splunk"

[logsources.columns]
EventCode = { type = "number", description = "The Windows event id." }

[[logsources]]
name = "edr:*"
description = "EDR telemetry."
system = "splunk"

[[logsources]]
name = "pan:threat"
description = "Firewall threats."
system = "splunk"

[logsources.columns]
dest_zone = { type = "string" }

[[logsources]]
name = "SigninLogs"
description = "Test log source."
system = "sentinel"
"#;
const SENTINEL_ONLY: &str = r#"[[logsources]]
name = "SigninLogs"
description = "Test log source."
system = "sentinel"
"#;
/// The 0.20.0 plural lists: no longer part of the format, they declare
/// nothing.
const PLURAL: &str = r#"[[logsources]]
description = "x"
system = "splunk"
indexes = ["wineventlog"]
sourcetypes = ["WinEventLog:Security"]
"#;

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
        visibility: datasets.map(str::to_string),
        ..Catalog::default()
    })
    .unwrap();
}

// One test: the declared datasets are process-wide.
#[test]
fn declared_sourcetypes_pass_and_undeclared_ones_warn_once_splunk_is_declared() {
    let spl = "index=wineventlog sourcetype=syslog OR sourcetype=WinEventLog:Security `sysmon` | stats count by host";

    // A workspace that declares nothing gets no warning.
    install(None);
    assert!(undeclared(LanguageId::Spl, "a.spl", spl).is_empty());

    // Declarations for another platform are not an opt-in for Splunk.
    install(Some(SENTINEL_ONLY));
    assert!(undeclared(LanguageId::Spl, "a.spl", spl).is_empty());

    install(Some(PLURAL));
    assert!(undeclared(LanguageId::Spl, "a.spl", spl).is_empty());

    // Only sourcetypes are checked: indexes and macros are not declarable.
    install(Some(SPLUNK));
    assert_eq!(undeclared(LanguageId::Spl, "a.spl", spl), ["syslog"]);
    assert!(undeclared(LanguageId::Spl, "b.spl", "index=main `sysmon` | head 1").is_empty());
    assert!(
        undeclared(
            LanguageId::Spl,
            "c.spl",
            "sourcetype=EDR:crowdstrike | head 1"
        )
        .is_empty()
    );
    assert_eq!(
        undeclared(LanguageId::TideYaml, "rule.yaml", RULE),
        ["pan:traffic"]
    );

    // Declared columns: hover and completion, for the sourcetypes the search
    // reads; never checked.
    let host = MemoryWorkspace::default();
    let search = "sourcetype=WinEventLog:Security EventCode=4688 | table ";
    let md = hover(&host, LanguageId::Spl, search, 35).unwrap();
    assert!(md.contains("**EventCode** field (`number`)"), "{md}");
    assert!(md.contains("WinEventLog:Security"), "{md}");
    assert!(md.contains("The Windows event id."), "{md}");
    let labels: Vec<String> = completions(&host, LanguageId::Spl, search, search.len())
        .into_iter()
        .map(|i| i.label)
        .collect();
    assert!(labels.iter().any(|l| l == "EventCode"), "{labels:?}");
    assert!(!labels.iter().any(|l| l == "dest_zone"), "{labels:?}");
    assert!(
        undeclared(
            LanguageId::Spl,
            "d.spl",
            "sourcetype=WinEventLog:Security EventCod=1"
        )
        .is_empty()
    );

    install(None);
    assert!(undeclared(LanguageId::TideYaml, "rule.yaml", RULE).is_empty());
    assert!(
        hover(&host, LanguageId::Spl, search, 35).is_none_or(|md| !md.contains("visibility.toml"))
    );
}
