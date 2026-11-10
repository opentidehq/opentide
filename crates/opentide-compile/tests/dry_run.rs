//! `deploy --dry-run`'s result over an in-memory workspace: selection by
//! strategy, tenants, deployment state, skipped blocks, refused vendor ids,
//! unset variables and the usage failures.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace here opens"
)]

use std::path::PathBuf;
use std::sync::Arc;

use opentide_compile::Owned;
use opentide_compile::dry_run::{self, Outcome, Request};
use opentide_compile::plan::Scope;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

fn rule(uuid: &str, platform: &str, status: &str, extra: &str) -> String {
    format!(
        "name: Rule {uuid}\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.0\ndescription: d\n\
         configurations:\n  {platform}:\n    status: {status}\n{extra}"
    )
}

fn workspace(files: &[(&str, &str)]) -> Workspace {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    for (path, text) in files {
        fs.write(format!("/ws/{path}"), *text);
    }
    Workspace::open(
        fs as Arc<dyn FileSystem>,
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from("/ws")),
                cwd: PathBuf::from("/ws"),
                ..RootOptions::default()
            },
        },
    )
    .unwrap()
}

fn run(workspace: &Workspace, request: Request, set: &[&str]) -> Outcome {
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let changed = |_: &std::path::Path, _: &str| -> Result<(Scope, Option<String>), String> {
        Err("no git here".to_owned())
    };
    let is_set = |name: &str| set.contains(&name);
    dry_run::run(workspace, &owned, &request, &changed, &is_set)
}

fn all(strategies: &[&str]) -> Request {
    Request {
        strategies: strategies.iter().map(|s| (*s).to_owned()).collect(),
        all: true,
        cwd: PathBuf::from("/ws"),
        ..Request::default()
    }
}

fn text(outcome: &Outcome, key: &str) -> String {
    outcome
        .payload
        .get(key)
        .map(opentide_compile::Json::to_compact)
        .unwrap_or_default()
}

const DEFENDER: &str = "[platform]\nenabled = true\n\n[[tenants]]\nname = \"one\"\n\
    description = \"d\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\nssl = true\n\
    tenant_id = \"$DEFENDER_TENANT\"\nclient_id = \"$DEFENDER_CLIENT\"\n\n[[tenants]]\n\
    name = \"two\"\ndescription = \"d\"\nstrategies = [\"RELEASE\"]\n[tenants.setup]\nssl = true\n";

#[test]
fn a_preview_run_plans_creates_and_updates_from_the_deployment_state() {
    let ws = workspace(&[
        (
            ".opentide/configurations/platforms/defender_for_endpoint.toml",
            DEFENDER,
        ),
        (
            "objects/rules/a.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000a",
                "defender_for_endpoint",
                "STAGING",
                "",
            ),
        ),
        (
            "objects/rules/b.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000b",
                "defender_for_endpoint",
                "STAGING",
                "",
            ),
        ),
        (
            ".opentide/states/deployment/00000000-0000-4000-8000-00000000000b.json",
            "{\"schema\": \"deployment.state::1.0\", \"object_uuid\": \
             \"00000000-0000-4000-8000-00000000000b\", \"platforms\": \
             {\"defender_for_endpoint\": {\"one\": \"42\"}}}",
        ),
    ]);
    let outcome = run(&ws, all(&["preview"]), &["DEFENDER_CLIENT"]);
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(
        text(&outcome, "message"),
        "\"Plan: 1 to create, 1 to update, 0 to disable, 0 to delete\""
    );
    assert_eq!(
        text(&outcome, "tenants"),
        r#"{"defender_for_endpoint":{"one":["00000000-0000-4000-8000-00000000000a","00000000-0000-4000-8000-00000000000b"]}}"#
    );
    assert_eq!(
        text(&outcome, "warnings"),
        r#"["a real deploy would need $DEFENDER_TENANT, which is unset"]"#
    );
    assert_eq!(outcome.outcome_kind, Some("plan"));
    // Defender's preview is the block's model dump; a block its model
    // refuses (no query, alert, ...) is shown as written.
    assert_eq!(
        text(&outcome, "payloads"),
        r#"{"defender_for_endpoint":[{"uuid":"00000000-0000-4000-8000-00000000000a","name":"Rule 00000000-0000-4000-8000-00000000000a","api_request":{"status":"STAGING"}},{"uuid":"00000000-0000-4000-8000-00000000000b","name":"Rule 00000000-0000-4000-8000-00000000000b","api_request":{"status":"STAGING"}}]}"#
    );
}

#[test]
fn blocks_no_run_deploys_are_counted_and_a_release_run_retires() {
    let ws = workspace(&[
        (
            ".opentide/configurations/platforms/defender_for_endpoint.toml",
            DEFENDER,
        ),
        (
            "objects/rules/a.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000a",
                "defender_for_endpoint",
                "PRODUCTION",
                "",
            ),
        ),
        (
            "objects/rules/b.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000b",
                "defender_for_endpoint",
                "DISABLED",
                "",
            ),
        ),
    ]);
    let preview = run(&ws, all(&["PREVIEW"]), &[]);
    assert_eq!(text(&preview, "status"), "\"skipped\"");
    assert_eq!(
        preview.outcome_line.as_deref(),
        Some("No rule has a status PREVIEW deploys · 1 rule in PRODUCTION")
    );
    let release = run(
        &ws,
        Request {
            keep_deprecated: Some(true),
            ..all(&["RELEASE"])
        },
        &[],
    );
    assert_eq!(
        text(&release, "message"),
        "\"Plan: 1 to create, 0 to update, 1 to disable, 0 to delete\""
    );
}

#[test]
fn a_rule_with_a_vendor_id_is_refused_and_fails_the_run() {
    let ws = workspace(&[
        (
            ".opentide/configurations/platforms/defender_for_endpoint.toml",
            DEFENDER,
        ),
        (
            "objects/rules/a.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000a",
                "defender_for_endpoint",
                "STAGING",
                "    rule_id: 7\n",
            ),
        ),
    ]);
    let outcome = run(&ws, all(&["PREVIEW"]), &[]);
    assert_eq!(outcome.exit_code, 1);
    assert!(
        text(&outcome, "message")
            .contains("external_id_in_rule: 1 rule(s) still carry vendor rule ids")
    );
}

#[test]
fn usage_failures_name_the_option() {
    let ws = workspace(&[]);
    let missing = run(&ws, all(&[]), &[]);
    assert_eq!(missing.exit_code, 2);
    assert_eq!(missing.usage.unwrap().code, "usage_missing_option");
    let typo = run(&ws, all(&["PREVEW"]), &[]);
    let usage = typo.usage.unwrap();
    assert_eq!(usage.code, "usage_invalid_choice");
    assert_eq!(usage.suggestion.as_deref(), Some("PREVIEW"));
    let removed = run(
        &ws,
        Request {
            removed_plan: Some("STAGING".into()),
            ..all(&["PREVIEW"])
        },
        &[],
    );
    assert_eq!(removed.usage.unwrap().code, "usage_invalid_value");
}

#[test]
fn a_selection_that_matches_nothing_fails() {
    let ws = workspace(&[(
        "objects/rules/a.yaml",
        &rule(
            "00000000-0000-4000-8000-00000000000a",
            "sentinel",
            "STAGING",
            "",
        ),
    )]);
    let outcome = run(
        &ws,
        Request {
            all: false,
            uuids: vec!["00000000-0000-4000-8000-00000000000A".into(), "nope".into()],
            files: vec!["missing.yaml".into()],
            ..all(&["PREVIEW"])
        },
        &[],
    );
    assert_eq!(outcome.exit_code, 1);
    assert_eq!(
        text(&outcome, "message"),
        "\"No rule file directly in objects/rules matched: missing.yaml, nope\""
    );
}

#[test]
fn without_a_checkout_the_changed_rules_fail_with_the_baselines_message() {
    let ws = workspace(&[]);
    let outcome = run(
        &ws,
        Request {
            all: false,
            ..all(&["PREVIEW"])
        },
        &[],
    );
    assert_eq!(outcome.exit_code, 1);
    assert_eq!(text(&outcome, "message"), "\"no git here\"");
}

const SYSDIG: &str = "[platform]\nenabled = true\n\n[[tenants]]\nname = \"one\"\n\
    description = \"d\"\n[tenants.setup]\nssl = true\nurl = \"https://s.example.org\"\n\
    api_token = \"$SYSDIG_TOKEN\"\n";

#[test]
fn a_block_that_cannot_compile_is_a_diagnostic_of_the_plan() {
    let ws = workspace(&[
        (".opentide/configurations/platforms/sysdig.toml", SYSDIG),
        (
            "objects/rules/bad.yaml",
            &rule(
                "00000000-0000-4000-8000-0000000000b1",
                "sysdig",
                "STAGING",
                "    condition: proc.name = x\n    priority: urgent\n",
            ),
        ),
        (
            "objects/rules/good.yaml",
            &rule(
                "00000000-0000-4000-8000-0000000000b2",
                "sysdig",
                "STAGING",
                "    condition: proc.name = y\n",
            ),
        ),
    ]);
    let outcome = run(&ws, all(&["PREVIEW"]), &["SYSDIG_TOKEN"]);
    assert_eq!(outcome.exit_code, 1);
    assert_eq!(text(&outcome, "status"), "\"failed\"");
    assert_eq!(text(&outcome, "error"), "\"1 rule would fail to deploy\"");
    // `file_path` is the platform's path, `\ws\objects\rules\bad.yaml` on
    // Windows, which JSON writes with each backslash doubled.
    assert_eq!(
        text(&outcome, "diagnostics").replace("\\\\", "/"),
        "[{\"code\":\"compile_failed\",\"severity\":\"error\",\"message\":\"Sysdig cannot \
         compile this rule: 'URGENT'\",\"help\":null,\"path\":\"objects/rules/bad.yaml\",\
         \"file_path\":\"/ws/objects/rules/bad.yaml\",\
         \"platform\":\"sysdig\",\"uuid\":\"00000000-0000-4000-8000-0000000000b1\",\
         \"name\":\"Rule 00000000-0000-4000-8000-0000000000b1\"}]"
    );
    let payloads = text(&outcome, "payloads");
    assert!(
        payloads
            .contains("\"api_request\":{\"name\":\"Rule 00000000-0000-4000-8000-0000000000b2\""),
        "{payloads}"
    );
}
