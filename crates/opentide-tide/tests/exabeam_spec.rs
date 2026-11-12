//! The Exabeam block (`configurations.exabeam`, platform exabeam-1.0) against
//! the block checker of opentidehq/specifications (`validate_exabeam_block`
//! and `validate_exabeam_searches` in `scripts/object_fixtures.py`), whose
//! errors `scripts/sync_exabeam_conformance.py` records under `blocks` in
//! `testdata/conformance/exabeam/reference.json`: the block cases of
//! `testdata/conformance/exabeam/blocks/` and the spec's fixtures under
//! `objects/`. Every error, code and field path, must be the reference's.
//!
//! Unknown keys are the Tide catalogue's (`schema_validation`), never a
//! constraint code, so the reference's `unknown_field` is left out here; a
//! test below holds the catalogue to reporting them.

use opentide_core::{Diagnostic, Severity, codes};
use opentide_tide::{AnalyzeInput, IndexedObject, analyze, index_object};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/conformance/exabeam")
}

fn diagnostics(path: &str, source: &str, workspace: &[IndexedObject]) -> Vec<Diagnostic> {
    analyze(AnalyzeInput {
        path,
        source,
        workspace,
        elastic_tenants: &[],
    })
    .diagnostics
}

/// `(code, field path)` of each Exabeam error: the block's codes and the
/// language's on the queries.
fn errors(diagnostics: &[Diagnostic]) -> BTreeSet<(String, String)> {
    diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error && d.code.starts_with("exabeam_"))
        .map(|d| {
            (
                d.code.clone(),
                d.field_path.clone().unwrap_or_default().join("."),
            )
        })
        .collect()
}

/// Cases where the engine differs from the reference block checker, with
/// the reason.
const DIFFERENCES: &[&str] = &[
    // A block without `status` reports only the missing field, as on the
    // Sysdig and Bitdefender blocks; that finding is the Tide catalogue's.
    // The reference checker does not look at `status`.
    "blocks/no-status.yaml",
];

#[test]
fn block_errors_match_the_reference_checker() {
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir().join("reference.json")).unwrap())
            .unwrap();
    let blocks = doc["blocks"].as_array().unwrap();
    assert!(blocks.len() >= 50, "{}", blocks.len());
    let mut failures = Vec::new();
    for case in blocks {
        let file = case["file"].as_str().unwrap();
        let source = std::fs::read_to_string(dir().join(file)).unwrap();
        let found = errors(&diagnostics(file, &source, &[]));
        let expected: BTreeSet<(String, String)> = case["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e[0].as_str().unwrap().to_string(),
                    e[1].as_str().unwrap().to_string(),
                )
            })
            .collect();
        if DIFFERENCES.contains(&file) {
            assert!(
                found.is_empty() && !expected.is_empty(),
                "{file}: {found:?}"
            );
            continue;
        }
        if found != expected {
            failures.push(format!(
                "{file}:\n  engine    {found:?}\n  reference {expected:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Each invalid fixture names its code in its first lines.
#[test]
fn spec_fixtures_report_the_code_they_name() {
    for entry in std::fs::read_dir(dir().join("objects/invalid")).unwrap() {
        let path = entry.unwrap().path();
        let source = std::fs::read_to_string(&path).unwrap();
        let code = source
            .lines()
            .find_map(|l| l.strip_prefix("# Expected constraint code: "))
            .unwrap()
            .trim_end_matches('.');
        let found = errors(&diagnostics("objects/rules/x.yaml", &source, &[]));
        assert!(
            found.iter().any(|(c, _)| c == code),
            "{}: {found:?}",
            path.display()
        );
    }
    for entry in std::fs::read_dir(dir().join("objects/valid")).unwrap() {
        let path = entry.unwrap().path();
        let source = std::fs::read_to_string(&path).unwrap();
        let all = diagnostics("objects/rules/x.yaml", &source, &[]);
        let exabeam: Vec<&Diagnostic> = all
            .iter()
            .filter(|d| d.code.starts_with("exabeam_"))
            .collect();
        assert!(exabeam.is_empty(), "{}: {exabeam:?}", path.display());
    }
}

fn rule(name: &str, uuid: &str, block: &str) -> String {
    format!(
        "name: {name}\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.0\ndescription: x\nconfigurations:\n  exabeam:\n    enabled: true\n    schema: platform::exabeam::1.0\n    status: STAGING\n{block}"
    )
}

fn has(diagnostics: &[Diagnostic], code: &str, severity: Severity, path: &str) -> bool {
    diagnostics.iter().any(|d| {
        d.code == code
            && d.severity == severity
            && d.field_path.clone().unwrap_or_default().join(".") == path
    })
}

#[test]
fn advisories() {
    let silent = rule(
        "Silent",
        "00000000-0000-4000-8003-000000000201",
        "    outcome: none\n    sequences:\n      - query: 'activity_type:\"app-login\"'\n",
    );
    let d = diagnostics("objects/rules/silent.yaml", &silent, &[]);
    assert!(
        has(
            &d,
            codes::EXABEAM_OUTCOME_SILENT,
            Severity::Warning,
            "configurations.exabeam.outcome"
        ),
        "{d:?}"
    );
    let mailed = silent.replace(
        "    outcome: none\n",
        "    outcome: none\n    email: {recipients: [soc@example.com]}\n",
    );
    let d = diagnostics("objects/rules/silent.yaml", &mailed, &[]);
    assert!(!d.iter().any(|d| d.code == codes::EXABEAM_OUTCOME_SILENT));

    let window = std::fs::read_to_string(dir().join("blocks/correlation-window.yaml")).unwrap();
    let d = diagnostics("objects/rules/window.yaml", &window, &[]);
    assert!(
        has(
            &d,
            codes::EXABEAM_CORRELATION_WINDOW,
            Severity::Warning,
            "configurations.exabeam.correlation.within"
        ),
        "{d:?}"
    );
    // Ordered sequences need 120 + 1 (any match) + 1 (between) = 122 minutes.
    let wide = |within: &str| {
        let text = window.replace(
            "correlation: {within: 1h}",
            &format!("correlation: {{within: {within}}}"),
        );
        diagnostics("objects/rules/window.yaml", &text, &[])
            .iter()
            .any(|d| d.code == codes::EXABEAM_CORRELATION_WINDOW)
    };
    assert!(wide("2h"), "the longest window alone is not enough");
    assert!(wide("122m"));
    assert!(!wide("123m"));
    assert!(!wide("3h"));
    // Exabeam's guide: a 3- and a 5-minute sequence need more than nine minutes.
    let guide = window
        .replace("within: 2h}", "within: 3m}")
        .replace(
            "      - query: 'activity_type:\"process-create\"'\n",
            "      - query: 'activity_type:\"process-create\"'\n        threshold: {function: count, operator: more_than, value: 1, within: 5m}\n",
        );
    assert_ne!(guide, window);
    for (within, warned) in [("9m", true), ("10m", false)] {
        let text = guide.replace(
            "correlation: {within: 1h}",
            &format!("correlation: {{within: {within}}}"),
        );
        let d = diagnostics("objects/rules/window.yaml", &text, &[]);
        assert_eq!(
            d.iter()
                .any(|d| d.code == codes::EXABEAM_CORRELATION_WINDOW),
            warned,
            "{within}: {d:?}"
        );
    }
}

#[test]
fn a_name_another_enabled_block_resolves_to_is_a_duplicate() {
    let block = "    sequences:\n      - query: 'activity_type:\"app-login\"'\n";
    let mine = rule(
        "Failed logins",
        "00000000-0000-4000-8003-000000000202",
        block,
    );
    let theirs = rule(
        "FAILED LOGINS",
        "00000000-0000-4000-8003-000000000203",
        block,
    );
    let other = index_object("objects/rules/theirs.yaml", &theirs).unwrap();
    let d = diagnostics(
        "objects/rules/mine.yaml",
        &mine,
        std::slice::from_ref(&other),
    );
    assert!(
        has(
            &d,
            codes::EXABEAM_NAME_DUPLICATE,
            Severity::Error,
            "configurations.exabeam.name"
        ),
        "{d:?}"
    );
    // The block's own `name` is the Exabeam rule name.
    let renamed = mine.replace(
        "    sequences:",
        "    name: Failed logins from outside\n    sequences:",
    );
    let d = diagnostics(
        "objects/rules/mine.yaml",
        &renamed,
        std::slice::from_ref(&other),
    );
    assert!(!d.iter().any(|d| d.code == codes::EXABEAM_NAME_DUPLICATE));
    // A disabled block takes no name.
    let disabled = theirs.replace("enabled: true", "enabled: false");
    let other = index_object("objects/rules/theirs.yaml", &disabled).unwrap();
    let d = diagnostics("objects/rules/mine.yaml", &mine, &[other]);
    assert!(!d.iter().any(|d| d.code == codes::EXABEAM_NAME_DUPLICATE));
    // The object itself, indexed, is not a duplicate of itself.
    let me = index_object("objects/rules/mine.yaml", &mine).unwrap();
    let d = diagnostics("objects/rules/mine.yaml", &mine, &[me]);
    assert!(!d.iter().any(|d| d.code == codes::EXABEAM_NAME_DUPLICATE));
    // ... nor when the index spells the path with other separators (Windows).
    let me = index_object("C:\\w\\objects\\rules\\mine.yaml", &mine).unwrap();
    let d = diagnostics("c:\\w\\objects/rules/mine.yaml", &mine, &[me]);
    assert!(!d.iter().any(|d| d.code == codes::EXABEAM_NAME_DUPLICATE));
}

#[test]
fn findings_point_at_their_field() {
    let source = std::fs::read_to_string(dir().join("blocks/schedule-month.yaml")).unwrap();
    let d = diagnostics("objects/rules/x.yaml", &source, &[]);
    let schedule: Vec<&Diagnostic> = d
        .iter()
        .filter(|d| d.code == codes::EXABEAM_SCHEDULE)
        .collect();
    assert_eq!(schedule.len(), 2, "{d:?}");
    let lines: Vec<&str> = source.lines().collect();
    // The recurrence items themselves, not the `schedule` key.
    assert!(lines[schedule[0].range.start.line as usize].contains("days: [1, 32]"));
    assert!(
        lines[schedule[1].range.start.line as usize]
            .trim_start()
            .starts_with("- {every: month, from: '08:00Z', to: '18:00Z'}")
    );
    // A sequence query's language error is on the query.
    let source = std::fs::read_to_string(dir().join("blocks/query-errors.yaml")).unwrap();
    let d = diagnostics("objects/rules/x.yaml", &source, &[]);
    let not_equal = d
        .iter()
        .find(|d| d.code == codes::EXABEAM_NOT_EQUAL)
        .unwrap();
    let line = source
        .lines()
        .nth(not_equal.range.start.line as usize)
        .unwrap();
    assert_eq!(
        &line[not_equal.range.start.character as usize..not_equal.range.end.character as usize],
        "!="
    );
}

#[test]
fn nested_unknown_keys_are_unknown_keys_at_their_path() {
    // exabeam-1.0: an unknown key is never a constraint code; the Tide
    // catalogue reports it at its own path, at the root and inside.
    for (file, path) in [
        (
            "sequence-unknown-key.yaml",
            "configurations.exabeam.sequences.0.condition",
        ),
        (
            "threshold-unknown-key.yaml",
            "configurations.exabeam.sequences.0.threshold.window",
        ),
        (
            "suppression-key.yaml",
            "configurations.exabeam.suppression.until",
        ),
        (
            "correlation-unknown-key.yaml",
            "configurations.exabeam.correlation.order",
        ),
    ] {
        let text = std::fs::read_to_string(dir().join("blocks").join(file)).unwrap();
        let d = diagnostics("objects/rules/x.yaml", &text, &[]);
        assert!(
            !d.iter().any(|d| d.code.starts_with("exabeam_")),
            "{file}: {d:?}"
        );
        // The catalogue's field paths leave list indexes out, on every platform.
        let path: Vec<&str> = path
            .split('.')
            .filter(|p| p.parse::<usize>().is_err())
            .collect();
        assert!(
            d.iter().any(|d| d.code == "schema_validation"
                && d.severity == Severity::Error
                && d.field_path.clone().unwrap_or_default() == path),
            "{file}: {d:?}"
        );
    }
}

#[test]
fn merge_keys_are_resolved_before_the_block_checks() {
    // opentide's loader resolves `<<: *anchor`; so do the block checks.
    let text = rule(
        "Merged",
        "00000000-0000-4000-8003-000000000204",
        "    sequences:\n      - query: 'activity_type:\"app-login\"'\n        threshold:\n          <<: &base {function: count, operator: more_than, value: 3}\n          within: 1h\n",
    );
    let d = diagnostics("objects/rules/merged.yaml", &text, &[]);
    assert!(
        !d.iter().any(|d| d.code.starts_with("exabeam_threshold")),
        "{d:?}"
    );
}
