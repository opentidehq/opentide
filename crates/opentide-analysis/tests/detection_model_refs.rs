//! Conformance (#213): a rule's `detection_model` may name an objective or a
//! signal one declares, as `opentide validate` accepts both. Only a UUID that
//! names neither is an `invalid_ref`, and it is not offered an unrelated
//! objective as a fix.
//!
//! | `detection_model` names       | `opentide validate` | engine          |
//! | ----------------------------- | ------------------- | --------------- |
//! | the objective's UUID          | no finding          | no `invalid_ref` |
//! | a signal of that objective    | no finding          | no `invalid_ref` |
//! | a UUID that exists nowhere    | `invalid_ref`       | `invalid_ref`   |

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, analyze};
use opentide_core::{LanguageId, Severity};
use std::fs;
use std::path::PathBuf;

const CASE: &str = "testdata/conformance/refs/detection-model";

fn workspace() -> MemoryWorkspace {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(CASE);
    let mut files = Vec::new();
    for family in ["objectives", "rules"] {
        for entry in fs::read_dir(root.join("objects").join(family)).unwrap() {
            let path = entry.unwrap().path();
            files.push((
                path.display().to_string(),
                fs::read_to_string(&path).unwrap(),
            ));
        }
    }
    files.sort();
    MemoryWorkspace { files }
}

/// The `invalid_ref` findings on the rule file whose name ends with `file`.
fn invalid_refs(file: &str) -> Vec<opentide_core::Diagnostic> {
    let host = workspace();
    let (uri, text) = host
        .files
        .iter()
        .find(|(path, _)| path.ends_with(file))
        .cloned()
        .unwrap_or_else(|| panic!("missing {file}"));
    analyze(
        &host,
        AnalyzeRequest {
            uri,
            language: LanguageId::TideYaml,
            text,
        },
    )
    .diagnostics
    .into_iter()
    .filter(|d| d.code == "invalid_ref")
    .collect()
}

#[test]
fn detection_model_naming_the_objective_is_not_an_invalid_ref() {
    let found = invalid_refs("rules/via-objective.yaml");
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn detection_model_naming_a_signal_is_not_an_invalid_ref() {
    let found = invalid_refs("rules/via-signal.yaml");
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn detection_model_naming_nothing_is_still_an_invalid_ref() {
    let found = invalid_refs("rules/dangling.yaml");
    let [d] = found.as_slice() else {
        panic!("expected one invalid_ref, got {found:?}")
    };
    assert_eq!(d.severity, Severity::Error);
    assert_eq!(
        d.field_path.as_deref(),
        Some(["detection_model".to_string()].as_slice())
    );
    assert!(
        d.message.contains("is not an indexed objective or signal"),
        "{}",
        d.message
    );
    // Nothing in the workspace is a near miss: no fix that would re-parent the rule.
    assert_eq!(d.suggestion, None);
}
