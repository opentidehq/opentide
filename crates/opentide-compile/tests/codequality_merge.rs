//! The Code Quality merge GitLab's validate job runs in `after_script`
//! (#1656), run as GitLab runs it: the script is read from the rendered
//! pipeline and run by `bash` in a folder that holds the reports, on the
//! `python3` the job's image has. The cases are 0.28.1's
//! `tests/test_ci/test_codequality_merge.py`, whose module the script
//! replaces.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken case is a failure"
)]

use std::path::Path;
use std::process::Command;

use indexmap::IndexMap;
use opentide_compile::ci::{Options, Provider, render};
use opentide_schema::node::Value;

/// The validate job's `after_script`, as the GitLab pipeline holds it.
fn merge_script() -> String {
    let pipeline = render(&Options {
        provider: Provider::GitLab,
        platforms: vec!["sentinel".into()],
        staging: true,
        inflight: false,
        sharing: false,
        lint_changed: false,
        explorer_pages: false,
        python_version: "3.12".into(),
        opentide_version: "1.0.0".into(),
        default_branch: "main".into(),
        docs_output: "docs".into(),
        rules_folder: "objects/rules".into(),
        credentials: IndexMap::new(),
        sharing_credentials: Vec::new(),
    })
    .unwrap();
    let document = opentide_schema::node::load(&pipeline).unwrap();
    let script = document
        .root()
        .and_then(|root| root.get("validate"))
        .and_then(|job| job.get("after_script"))
        .unwrap();
    let Value::Seq(items) = &script.value else {
        panic!("after_script is not a list: {pipeline}");
    };
    assert_eq!(items.len(), 1, "{pipeline}");
    items[0].value.as_str().unwrap().to_owned()
}

fn issue(fingerprint: &str) -> String {
    format!(
        r#"{{"type": "issue", "check_name": "schema_validation", "description": "message", "severity": "major", "fingerprint": "{fingerprint}", "location": {{"path": "objects/rules/a.yaml", "lines": {{"begin": 1}}}}}}"#
    )
}

/// Runs the merge in `dir`: its stderr, and the fingerprints of the merged
/// report (`None` for an issue without one).
fn merge(dir: &Path) -> (String, Vec<Option<String>>) {
    let done = Command::new("bash")
        .args(["-e", "-c", &merge_script()])
        .current_dir(dir)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&done.stderr).into_owned();
    assert!(done.status.success(), "{stderr}");
    assert!(
        done.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&done.stdout)
    );
    let text = std::fs::read_to_string(dir.join("opentide-reports/codequality.json")).unwrap();
    let merged: serde_json::Value = serde_json::from_str(&text).unwrap();
    let fingerprints = merged
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| {
            issue
                .get("fingerprint")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .collect();
    (stderr, fingerprints)
}

fn reports(validate: Option<&[u8]>, lint: Option<&[u8]>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("opentide-reports");
    std::fs::create_dir(&folder).unwrap();
    for (name, content) in [("validate", validate), ("lint", lint)] {
        if let Some(content) = content {
            std::fs::write(folder.join(format!("{name}.codequality.json")), content).unwrap();
        }
    }
    dir
}

fn some(names: &[&str]) -> Vec<Option<String>> {
    names.iter().map(|name| Some((*name).to_owned())).collect()
}

#[test]
fn both_reports_are_merged_in_order() {
    let validate = format!("[{}]", issue("a"));
    let lint = format!("[{}]", issue("b"));
    let dir = reports(Some(validate.as_bytes()), Some(lint.as_bytes()));
    let (stderr, merged) = merge(dir.path());
    assert_eq!(merged, some(&["a", "b"]));
    assert_eq!(stderr, "");
}

#[test]
fn a_fingerprint_is_kept_once() {
    let validate = format!("[{}, {}]", issue("a"), issue("b"));
    let lint = format!("[{}, {}]", issue("b"), issue("c"));
    let dir = reports(Some(validate.as_bytes()), Some(lint.as_bytes()));
    assert_eq!(merge(dir.path()).1, some(&["a", "b", "c"]));
}

/// `validate` failed or crashed before `lint` ran: the merge request keeps
/// its findings, and the log says why the other report was skipped.
#[test]
fn a_broken_report_still_gives_a_valid_one() {
    let validate = format!("[{}]", issue("a"));
    let cases: [(&str, Option<&[u8]>, &str); 5] = [
        ("missing", None, "No such file or directory"),
        ("empty", Some(b""), "Expecting value"),
        (
            "truncated",
            Some(br#"[{"type": "issue", "finger"#),
            "skipped",
        ),
        (
            "object",
            Some(br#"{"issues": []}"#),
            "is not a Code Quality report",
        ),
        ("not-utf8", Some(b"\xff\xfe[]"), "skipped"),
    ];
    for (case, lint, why) in cases {
        let dir = reports(Some(validate.as_bytes()), lint);
        let (stderr, merged) = merge(dir.path());
        assert_eq!(merged, some(&["a"]), "{case}");
        assert!(
            stderr.contains("opentide-reports/lint.codequality.json") && stderr.contains(why),
            "{case}: {stderr}"
        );
    }
}

#[test]
fn no_report_and_no_folder_write_an_empty_report() {
    let dir = tempfile::tempdir().unwrap();
    let (stderr, merged) = merge(dir.path());
    assert!(merged.is_empty());
    assert_eq!(stderr.matches("skipped").count(), 2, "{stderr}");
}

#[test]
fn items_that_are_not_issues_are_dropped() {
    let validate = format!(r#"[{}, "text", 3, null, {{"type": "issue"}}]"#, issue("a"));
    let dir = reports(Some(validate.as_bytes()), Some(b"[]"));
    assert_eq!(merge(dir.path()).1, vec![Some("a".to_owned()), None]);
}

#[test]
fn a_stale_report_is_replaced() {
    let dir = reports(Some(b"[]"), Some(b"[]"));
    std::fs::write(
        dir.path().join("opentide-reports/codequality.json"),
        "stale",
    )
    .unwrap();
    assert!(merge(dir.path()).1.is_empty());
}
