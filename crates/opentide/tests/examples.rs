//! The examples of `examples/`, each run on a workspace: CI runs them with
//! the tests.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers: a fixture that does not lay out is a failure"
)]

mod common;

#[expect(dead_code, reason = "the example's `main`; the test calls `run`")]
#[path = "../examples/validate.rs"]
mod validate;

#[expect(dead_code, reason = "the example's `main`; the test calls `run`")]
#[path = "../examples/catalog.rs"]
mod catalog;

#[expect(dead_code, reason = "the example's `main`; the test calls `run`")]
#[path = "../examples/deploy_plan.rs"]
mod deploy_plan;

fn text(out: Vec<u8>) -> String {
    String::from_utf8(out).unwrap()
}

#[test]
fn the_validate_example_validates_a_workspace() {
    let dir = common::tide_corpus();
    let mut out = Vec::new();
    let passed = validate::run(dir.path(), &mut out).unwrap();
    let out = text(out);
    assert_eq!(
        passed,
        out.lines().all(|line| !line.contains("error[")),
        "{out}"
    );
    assert!(out.contains("12 objects checked: "), "{out}");
    assert_eq!(
        out.starts_with("queries check off"),
        !opentide::queries::AVAILABLE,
        "{out}"
    );

    std::fs::write(
        dir.path().join("objects/rules/bad.yaml"),
        "name: Bad\nmetadata:\n  uuid: not-a-uuid\n  schema: rule::1.1\n",
    )
    .unwrap();
    let mut out = Vec::new();
    assert!(!validate::run(dir.path(), &mut out).unwrap());
    let out = text(out);
    assert!(
        out.contains("objects/rules/bad.yaml:3: error[invalid_uuid]"),
        "a finding names its file and line: {out}"
    );
}

#[test]
fn the_catalog_example_prints_the_catalogue_and_coverage() {
    let dir = common::tide_corpus();
    let mut out = Vec::new();
    catalog::run(dir.path(), "T1059", &mut out).unwrap();
    let out = text(out);
    let mut lines = out.lines();
    assert_eq!(
        lines.next(),
        Some("1 threats, 1 objectives, 10 rules, 0 files that did not load")
    );
    assert!(lines.next().unwrap().starts_with("platforms enabled: "));
    assert_eq!(
        out.lines().filter(|line| line.starts_with("rule ")).count(),
        10,
        "{out}"
    );
    assert!(out.contains("T1059"), "{out}");
    assert!(out.lines().last().unwrap().starts_with("T1059: "), "{out}");
}

#[test]
fn the_deploy_plan_example_plans_a_deploy() {
    let dir = common::tide_corpus();
    let mut out = Vec::new();
    deploy_plan::run(dir.path(), opentide::Strategy::Preview, &mut out).unwrap();
    let out = text(out);
    assert!(out.contains("summary: {"), "{out}");
    let last = out.lines().last().unwrap();
    let document: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(document["dry_run"], true);
}
