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
    let changed =
        |_: &std::path::Path, _: &str| -> Result<(Scope, Option<String>), dry_run::ScopeError> {
            Err("no git here".to_owned().into())
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

/// The keys a Microsoft Defender block requires, then `extra`.
fn defender(extra: &str) -> String {
    format!("    query: DeviceEvents\n    schedule:\n      frequency: 1H\n{extra}")
}

const DEFENDER: &str = "[platform]\nenabled = true\n\n[[tenants]]\nname = \"one\"\n\
    description = \"d\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\nssl = true\n\
    tenant_id = \"$DEFENDER_TENANT\"\nclient_id = \"$DEFENDER_CLIENT\"\n\n[[tenants]]\n\
    name = \"two\"\ndescription = \"d\"\nstrategies = [\"RELEASE\"]\n[tenants.setup]\nssl = true\n";

#[test]
fn a_preview_run_plans_an_upsert_of_each_rule_by_its_uuid() {
    let ws = workspace(&[
        (
            ".opentide/configurations/platforms/microsoft_defender.toml",
            DEFENDER,
        ),
        (
            "objects/rules/a.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000a",
                "microsoft_defender",
                "STAGING",
                &defender(""),
            ),
        ),
        (
            "objects/rules/b.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000b",
                "microsoft_defender",
                "STAGING",
                &defender(""),
            ),
        ),
    ]);
    let outcome = run(&ws, all(&["preview"]), &["DEFENDER_CLIENT"]);
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(
        text(&outcome, "message"),
        "\"Plan: 0 to create, 0 to update, 2 to create or update, 0 to disable, 0 to delete\""
    );
    assert_eq!(
        text(&outcome, "tenants"),
        r#"{"microsoft_defender":{"one":["00000000-0000-4000-8000-00000000000a","00000000-0000-4000-8000-00000000000b"]}}"#
    );
    assert_eq!(
        text(&outcome, "warnings"),
        r#"["a real deploy would need $DEFENDER_TENANT, which is unset"]"#
    );
    assert_eq!(outcome.outcome_kind, Some("plan"));
    // Defender keeps no deployment state: a deploy's first request is the
    // PATCH of the rule its uuid names (platform::microsoft_defender::1.0).
    let body = |uuid: &str| {
        format!(
            r#"{{"displayName":"Rule {uuid}","description":"d","status":"enabled","queryCondition":{{"queryText":"DeviceEvents"}},"schedule":{{"frequency":"PT1H"}},"detectionAction":{{"alertTemplate":{{"title":"Rule {uuid}","description":"d","severity":"medium"}}}}}}"#
        )
    };
    let (a, b) = (
        "00000000-0000-4000-8000-00000000000a",
        "00000000-0000-4000-8000-00000000000b",
    );
    let endpoint = "https://graph.microsoft.com/beta/security/rules/detectionRules";
    assert_eq!(
        text(&outcome, "payloads"),
        format!(
            r#"{{"microsoft_defender":[{{"uuid":"{a}","name":"Rule {a}","api_request":[{{"method":"PATCH","url":"{endpoint}/{a}","body":{}}}],"tenant":"one"}},{{"uuid":"{b}","name":"Rule {b}","api_request":[{{"method":"PATCH","url":"{endpoint}/{b}","body":{}}}],"tenant":"one"}}]}}"#,
            body(a),
            body(b)
        )
    );
}

const TWO_STRATEGIES: &str = "[platform]\nenabled = true\n\n[[tenants]]\nname = \"lab\"\n\
    description = \"d\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\nssl = true\n\
    tenant_id = \"$X\"\nclient_id = \"c\"\n\n[[tenants]]\nname = \"prod\"\n\
    description = \"d\"\nstrategies = [\"RELEASE\"]\n[tenants.setup]\nssl = true\n\
    tenant_id = \"$Y\"\nclient_id = \"c\"\n";

#[test]
fn the_unset_variable_warning_counts_only_the_tenants_the_plan_reaches() {
    let ws = workspace(&[
        (
            ".opentide/configurations/platforms/microsoft_defender.toml",
            TWO_STRATEGIES,
        ),
        (
            "objects/rules/a.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000a",
                "microsoft_defender",
                "STAGING",
                &defender(""),
            ),
        ),
    ]);
    // A PREVIEW plan reaches `lab` only: `$Y` is prod's, not this run's.
    let outcome = run(&ws, all(&["preview"]), &[]);
    assert_eq!(
        text(&outcome, "tenants"),
        r#"{"microsoft_defender":{"lab":["00000000-0000-4000-8000-00000000000a"]}}"#
    );
    assert_eq!(
        text(&outcome, "warnings"),
        r#"["a real deploy would need $X, which is unset"]"#
    );
    // A plan that routes no rule needs no variable at all.
    let empty = run(&ws, all(&["release"]), &[]);
    assert!(
        !text(&empty, "warnings").contains("a real deploy would need"),
        "{}",
        text(&empty, "warnings")
    );
}

#[test]
fn a_defender_rules_alert_techniques_are_in_the_dry_runs_request() {
    let ws = workspace(&[
        (
            ".opentide/configurations/platforms/microsoft_defender.toml",
            DEFENDER,
        ),
        (
            "objects/rules/a.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000a",
                "microsoft_defender",
                "STAGING",
                &defender("    alert:\n      techniques: [T1528, T1059.001]\n"),
            ),
        ),
    ]);
    let outcome = run(&ws, all(&["preview"]), &["DEFENDER_CLIENT"]);
    assert_eq!(outcome.exit_code, 0);
    let payloads = text(&outcome, "payloads");
    assert!(
        payloads.contains(
            r#""tactics":[{"tactic":"Execution","techniques":[{"technique":"T1059","subTechniques":["T1059.001"]}]},{"tactic":"CredentialAccess","techniques":[{"technique":"T1528"}]}]"#
        ),
        "{payloads}"
    );
}

#[test]
fn blocks_no_run_deploys_are_counted_and_a_release_run_retires() {
    let ws = workspace(&[
        (
            ".opentide/configurations/platforms/microsoft_defender.toml",
            DEFENDER,
        ),
        (
            "objects/rules/a.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000a",
                "microsoft_defender",
                "PRODUCTION",
                &defender(""),
            ),
        ),
        (
            "objects/rules/b.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000b",
                "microsoft_defender",
                "DISABLED",
                &defender(""),
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
        "\"Plan: 0 to create, 0 to update, 1 to create or update, 1 to disable, 0 to delete\""
    );
}

/// Under `--platform`, the blocks a status kept out are that platform's
/// only: another platform's PRODUCTION block is not "not in the plan" of a
/// PREVIEW run of this one (#1662, D11).
#[test]
fn a_platform_run_counts_only_its_own_blocks_as_left_out() {
    let ws = workspace(&[
        (
            ".opentide/configurations/platforms/microsoft_defender.toml",
            DEFENDER,
        ),
        (
            ".opentide/configurations/platforms/sentinel.toml",
            "[platform]\nenabled = true\n",
        ),
        (
            "objects/rules/a.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000a",
                "microsoft_defender",
                "STAGING",
                &defender(""),
            ),
        ),
        (
            "objects/rules/b.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000b",
                "sentinel",
                "PRODUCTION",
                "",
            ),
        ),
    ]);
    let all_platforms = run(&ws, all(&["PREVIEW"]), &[]);
    assert!(
        text(&all_platforms, "detail").contains("not in the plan: 1 rule in PRODUCTION"),
        "{}",
        text(&all_platforms, "detail")
    );
    let defender = run(
        &ws,
        Request {
            platform: Some("microsoft_defender".to_owned()),
            ..all(&["PREVIEW"])
        },
        &[],
    );
    assert_eq!(text(&defender, "detail"), "");
    assert_eq!(text(&defender, "skipped"), "");
}

#[test]
fn a_rule_with_a_vendor_id_is_refused_and_fails_the_run() {
    let ws = workspace(&[
        (
            ".opentide/configurations/platforms/microsoft_defender.toml",
            DEFENDER,
        ),
        (
            "objects/rules/a.yaml",
            &rule(
                "00000000-0000-4000-8000-00000000000a",
                "microsoft_defender",
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
fn a_selected_rule_without_a_status_fails_the_plan_and_keeps_the_scope() {
    let ws = workspace(&[(
        "objects/rules/a.yaml",
        "name: A\nmetadata:\n  uuid: 00000000-0000-4000-8000-00000000000a\n  schema: rule::1.0\n\
         description: d\nconfigurations:\n  sentinel:\n    query: x\n",
    )]);
    let selected = Request {
        all: false,
        uuids: vec!["00000000-0000-4000-8000-00000000000a".into()],
        ..all(&["PREVIEW"])
    };
    let outcome = run(&ws, selected, &[]);
    assert_eq!(outcome.exit_code, 1);
    assert_eq!(
        text(&outcome, "message"),
        "\"\\\"A\\\" (00000000-0000-4000-8000-00000000000a): configurations.sentinel.status is \
         required for deployment\""
    );
    let keys: Vec<&String> = outcome.payload.keys().collect();
    assert_eq!(keys, ["status", "message", "scope"]);
    assert_eq!(text(&outcome, "scope"), "\"selected\"");
    // Without a selection, no scope.
    let outcome = run(&ws, all(&["PREVIEW"]), &[]);
    assert_eq!(outcome.exit_code, 1);
    assert!(!outcome.payload.contains_key("scope"));
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
         compile this rule: unknown priority \\\"URGENT\\\" (expected EMERGENCY, ALERT, \
         CRITICAL, ERROR, WARNING, NOTICE, INFORMATIONAL or DEBUG)\",\"help\":null,\"path\":\"objects/rules/bad.yaml\",\
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

#[test]
fn a_scope_failure_stops_the_run_with_its_own_exit_code() {
    let ws = workspace(&[(
        "objects/rules/a.yaml",
        &rule(
            "00000000-0000-4000-8000-00000000000a",
            "microsoft_defender",
            "STAGING",
            &defender(""),
        ),
    )]);
    let owned = Owned::new(&Vocabularies::bundled(), &ws.configuration().resolved);
    let run_with = |exit_code: i32| {
        let changed = move |_: &std::path::Path,
                            _: &str|
              -> Result<(Scope, Option<String>), dry_run::ScopeError> {
            Err(dry_run::ScopeError {
                message: "OPENTIDE_PUSH_BASE=x is not an ancestor of HEAD (y)".to_owned(),
                exit_code,
            })
        };
        let request = Request {
            strategies: vec!["preview".to_owned()],
            cwd: PathBuf::from("/ws"),
            ..Request::default()
        };
        dry_run::run(&ws, &owned, &request, &changed, &|_: &str| false).exit_code
    };
    assert_eq!(run_with(2), 2);
    assert_eq!(run_with(1), 1);
}
