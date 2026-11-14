//! A workspace's declared datasets apply to its own run only: a query
//! checked on its own after `validate` or `lint` is checked as before.
//! One test in its own binary: the datasets are process-wide.

#![cfg(all(feature = "analysis", feature = "queries"))]

mod common;

use opentide::analysis::{self, LanguageId, QueryRequest};
use opentide::{LintOptions, Options, ValidateOptions, Workspace};

const VISIBILITY: &str = r#"[[logsources]]
name = "SecurityEvent"
description = "Windows security events."
system = "sentinel"
"#;

fn codes() -> Vec<String> {
    analysis::analyze_query(&QueryRequest {
        language: LanguageId::Kql,
        platform: None,
        stack: None,
        text: "DeviceProcessEvents | take 1".to_owned(),
    })
    .into_iter()
    .map(|diagnostic| diagnostic.code)
    .collect()
}

#[test]
fn a_validate_or_lint_run_leaves_the_declared_datasets_as_it_found_them() {
    let dir = common::tide_corpus();
    std::fs::write(
        dir.path().join(".opentide/configurations/visibility.toml"),
        VISIBILITY,
    )
    .unwrap();
    let ws = Workspace::open(dir.path(), &Options::default()).unwrap();
    let before = codes();
    assert!(
        !before.iter().any(|code| code == "kql_table_not_declared"),
        "{before:?}"
    );

    let _ = ws.validate(&ValidateOptions::default());
    assert_eq!(codes(), before, "after validate");

    let _ = ws.lint(&LintOptions::default());
    assert_eq!(codes(), before, "after lint");
}
