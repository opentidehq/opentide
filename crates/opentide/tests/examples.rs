//! The examples of `examples/`, each run on a workspace: CI runs them with
//! the tests.

#![cfg(feature = "compile")]
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

#[cfg(feature = "connectors")]
#[expect(dead_code, reason = "the example's `main`; the test calls `run`")]
#[path = "../examples/query.rs"]
mod query;

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

/// The query example on a workspace whose SentinelOne tenant is a stand-in
/// (wiremock): its rows, one JSON line each.
#[cfg(feature = "connectors")]
#[test]
fn the_query_example_runs_a_query_on_a_tenant() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let server = runtime.block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/web/api/v2.1/dv/events/pq"))
            .and(header("Authorization", "ApiToken s1-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data": {"status": "FINISHED", "columns": [{"name": "src.process.name"}], "data": [["cmd.exe"], ["pwsh.exe"]]}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
        server
    });
    let dir = tempfile::tempdir().unwrap();
    let platforms = dir.path().join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::create_dir_all(dir.path().join("objects/rules")).unwrap();
    std::fs::write(
        platforms.join("sentinel_one.toml"),
        format!(
            "[platform]\nenabled = true\n\n[[tenants]]\nname = \"soc\"\n[tenants.setup]\n\
             url = \"{}\"\napi_token = \"$S1_TOKEN\"\naccount_id = \"42\"\n",
            server.uri()
        ),
    )
    .unwrap();
    let options =
        opentide::connectors::ConnectOptions::default().environment([("S1_TOKEN", "s1-secret")]);
    let mut out = Vec::new();
    query::run(
        dir.path(),
        "sentinel_one",
        "powerquery",
        "| columns src.process.name",
        &options,
        &mut out,
    )
    .unwrap();
    assert_eq!(
        text(out),
        "{\"src.process.name\":\"cmd.exe\"}\n{\"src.process.name\":\"pwsh.exe\"}\n"
    );

    let error =
        query::run(dir.path(), "splunk", "spl", "x", &options, &mut Vec::new()).unwrap_err();
    assert!(
        error.to_string().contains("configures no splunk tenant"),
        "{error}"
    );
    drop(runtime);
}

/// The Rust page shows the query example's code as it is compiled and run
/// above: the part between its `docs:start` and `docs:end` lines.
#[test]
fn the_rust_page_shows_the_query_example() {
    let example = std::fs::read_to_string(common::repo().join("crates/opentide/examples/query.rs"))
        .unwrap()
        .replace("\r\n", "\n");
    let start = example.find("// docs:start").unwrap();
    let shown = &example[start..example.find("// docs:end").unwrap()];
    let shown = &shown[shown.find('\n').unwrap() + 1..];
    let page = std::fs::read_to_string(common::repo().join("docs/sdk/rust.md"))
        .unwrap()
        .replace("\r\n", "\n");
    assert!(
        page.contains(&format!("```rust ignore\n{shown}```\n")),
        "docs/sdk/rust.md's tenants snippet differs from examples/query.rs:\n{shown}"
    );
}
