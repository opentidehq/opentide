//! CIM data model checks on SPL (#115): a near miss of a CIM field or data
//! model is an error with a suggestion; a field a site adds, and every field
//! after `drop_dm_object_name`, is not.

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, analyze, analyze_queries};
use opentide_core::{Diagnostic, LanguageId, Severity, codes};
use std::path::PathBuf;

fn read(name: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::read_to_string(root.join("testdata/conformance/cim").join(name)).unwrap()
}

fn diagnostics(language: LanguageId, uri: &str, text: String) -> Vec<Diagnostic> {
    let host = MemoryWorkspace {
        files: vec![(uri.into(), text.clone())],
    };
    analyze(
        &host,
        AnalyzeRequest {
            uri: uri.into(),
            language,
            text,
        },
    )
    .diagnostics
}

/// `(code, text under the range, suggestion)` for the CIM codes.
fn cim(diagnostics: &[Diagnostic], source: &str) -> Vec<(String, String, Option<String>)> {
    diagnostics
        .iter()
        .filter(|d| {
            d.code == codes::SPL_UNKNOWN_DATAMODEL || d.code == codes::SPL_UNKNOWN_DATAMODEL_FIELD
        })
        .map(|d| {
            assert_eq!(d.severity, Severity::Error, "{d:?}");
            assert_eq!(d.range.start.line, d.range.end.line);
            let line = source.lines().nth(d.range.start.line as usize).unwrap();
            let text =
                line[d.range.start.character as usize..d.range.end.character as usize].to_string();
            (d.code.clone(), text, d.suggestion.clone())
        })
        .collect()
}

#[test]
fn raw_spl_reports_near_misses_only() {
    let source = read("datamodel-fields.spl");
    let found = diagnostics(LanguageId::Spl, "datamodel-fields.spl", source.clone());
    assert_eq!(
        cim(&found, &source),
        vec![
            (
                codes::SPL_UNKNOWN_DATAMODEL_FIELD.to_string(),
                "Processes.proces_name".to_string(),
                Some("Processes.process_name".to_string()),
            ),
            (
                codes::SPL_UNKNOWN_DATAMODEL.to_string(),
                "Endpont.Processes".to_string(),
                Some("Endpoint.Processes".to_string()),
            ),
        ]
    );
}

#[test]
fn acceptance_examples_from_the_issue() {
    let typo = "| tstats count from datamodel=Endpoint.Processes by Processes.proces_name";
    let found = diagnostics(LanguageId::Spl, "a.spl", typo.into());
    assert_eq!(
        cim(&found, typo),
        vec![(
            codes::SPL_UNKNOWN_DATAMODEL_FIELD.to_string(),
            "Processes.proces_name".to_string(),
            Some("Processes.process_name".to_string()),
        )]
    );
    let dropped = "| tstats count from datamodel=Endpoint.Processes by Processes.process_name | `drop_dm_object_name(Processes)` | table process_name";
    let found = diagnostics(LanguageId::Spl, "b.spl", dropped.into());
    assert!(cim(&found, dropped).is_empty(), "{found:?}");
}

#[test]
fn tide_splunk_query_block_reports_the_field_in_object_coordinates() {
    let source = read("datamodel-fields.rule.yaml");
    let found = diagnostics(
        LanguageId::TideYaml,
        "datamodel-fields.rule.yaml",
        source.clone(),
    );
    assert_eq!(
        cim(&found, &source),
        vec![(
            codes::SPL_UNKNOWN_DATAMODEL_FIELD.to_string(),
            "Processes.proces_name".to_string(),
            Some("Processes.process_name".to_string()),
        )]
    );
    let host = MemoryWorkspace { files: Vec::new() };
    let reports = analyze_queries(&host, &source);
    let splunk = reports
        .iter()
        .find(|r| r.language == LanguageId::Spl)
        .expect("the splunk query is analyzed");
    assert_eq!(splunk.field_path, ["configurations", "splunk", "query"]);
    assert!(
        splunk
            .diagnostics
            .iter()
            .any(|d| d.code == codes::SPL_UNKNOWN_DATAMODEL_FIELD)
    );
}
