//! The spec's Graylog fixtures (`testdata/conformance/graylog/`, from
//! graylog-1.0): the valid ones get no Graylog error, and no error on their
//! query, and each invalid one gets the code it names, at the field path
//! opentidehq/specifications' reference checker reports.

use opentide_core::{Diagnostic, Severity};
use opentide_tide::{AnalyzeInput, analyze};
use std::path::{Path, PathBuf};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/conformance/graylog")
}

fn yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("fixture dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    files
}

/// Findings on the Graylog block: its codes, and the query's.
fn graylog_findings(path: &Path) -> Vec<Diagnostic> {
    let source = std::fs::read_to_string(path).expect("fixture");
    analyze(AnalyzeInput {
        path: "objects/rules/fixture.yaml",
        source: &source,
        workspace: &[],
        elastic_tenants: &[],
    })
    .diagnostics
    .into_iter()
    .filter(|d| {
        d.code.starts_with("graylog_")
            || d.code.starts_with("lucene_")
            || d.field_path
                .as_ref()
                .is_some_and(|p| p.len() > 2 && p[..3] == ["configurations", "graylog", "query"])
    })
    .collect()
}

#[test]
fn valid_fixtures_have_no_graylog_error() {
    let files = yaml_files(&dir().join("valid"));
    assert_eq!(files.len(), 3);
    for path in files {
        let found = graylog_findings(&path);
        assert!(
            found.iter().all(|d| d.severity != Severity::Error),
            "{}: {found:?}",
            path.display()
        );
        // The aggregation's window is longer than its interval, which is
        // fine on an aggregation: no advisory either.
        assert!(found.is_empty(), "{}: {found:?}", path.display());
    }
}

#[test]
fn invalid_fixtures_report_their_code() {
    let files = yaml_files(&dir().join("invalid"));
    assert_eq!(files.len(), 4);
    for path in files {
        let source = std::fs::read_to_string(&path).expect("fixture");
        let expected = source
            .lines()
            .find_map(|l| l.split_once("Expected constraint code: ").map(|(_, c)| c))
            .and_then(|l| l.split(['.', ' ']).next())
            .expect("an expected code")
            .to_string();
        let found = graylog_findings(&path);
        assert!(
            found
                .iter()
                .any(|d| d.code == expected && d.severity == Severity::Error),
            "{}: expected {expected}, found {found:?}",
            path.display()
        );
        // Nothing but the named code: the rest of each fixture is valid.
        assert!(
            found.iter().all(|d| d.code == expected),
            "{}: {found:?}",
            path.display()
        );
    }
}

#[test]
fn invalid_fixtures_name_the_reference_field_paths() {
    // `validate_graylog_block` in scripts/object_fixtures.py.
    let expected = [
        (
            "rule-graylog-condition.yaml",
            vec!["configurations.graylog.aggregation.condition"],
        ),
        (
            "rule-graylog-event-field.yaml",
            vec!["configurations.graylog.event_fields.family"],
        ),
        (
            "rule-graylog-event-key.yaml",
            vec!["configurations.graylog.event_key"],
        ),
        (
            "rule-graylog-schedule.yaml",
            vec![
                "configurations.graylog.schedule",
                "configurations.graylog.schedule.cron",
                "configurations.graylog.schedule.window",
            ],
        ),
    ];
    for (name, paths) in expected {
        let found: Vec<String> = graylog_findings(&dir().join("invalid").join(name))
            .into_iter()
            .map(|d| d.field_path.unwrap_or_default().join("."))
            .collect();
        assert_eq!(found, paths, "{name}");
    }
}
