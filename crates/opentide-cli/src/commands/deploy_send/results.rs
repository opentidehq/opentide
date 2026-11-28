//! `deploy`'s refusals and failures, built as a [`CommandResult`], print the
//! document, the outcome line and the CI job summary their `_`-keys printed
//! (#1949): each case holds the keys the run used to build, key for key,
//! next to the typed result that replaced them.

use super::*;
use crate::json::document_text;
use crate::render::summary::deploy_summary;

fn key(name: &str, value: Json) -> (String, Json) {
    (name.to_owned(), value)
}

/// The `--json` document of `typed`, once it is checked to be what `old`
/// (the run's keys in order, `_`-keys included) printed: the document key
/// for key, the warnings, the outcome line, a bare exit, and the CI job
/// summary.
fn same(old: &[(String, Json)], typed: &CommandResult) -> String {
    let before = CommandResult::from_fields(old).report(COMMAND);
    let after = typed.clone().report(COMMAND);
    let text = |report: &Report| document_text(&report.outcome.document(0), false);
    assert_eq!(text(&after), text(&before));
    assert_eq!(after.warnings, before.warnings);
    let outcome_line = old.iter().find_map(|(name, value)| match value {
        Json::Str(line) if name == "_outcome" => Some(line.clone()),
        _ => None,
    });
    assert_eq!(after.outcome_line, outcome_line);
    let bare_exit = old.iter().any(|(name, _)| name == "_bare_exit");
    assert_eq!(after.bare_exit, bare_exit);
    let old_json = Json::Object(
        old.iter()
            .filter(|(name, _)| !name.starts_with('_'))
            .cloned()
            .collect(),
    );
    assert_eq!(
        deploy_summary(&typed.to_json(), None, Some(false)),
        deploy_summary(&old_json, None, Some(false))
    );
    text(&after)
}

#[test]
fn a_usage_refusal_names_its_argument_and_suggestion() {
    let message = "--strategy: «PREVEW» is not a strategy 😀";
    let old = vec![
        key("status", Json::str("failed")),
        key("message", Json::str(message)),
        key("_exit_code", Json::Int(2)),
        key("_failure_code", Json::str(code::USAGE_INVALID_CHOICE)),
        key("_failure_argument", Json::str("--strategy")),
        key("_failure_suggestion", Json::str("PREVIEW")),
    ];
    let mut typed = usage(message, code::USAGE_INVALID_CHOICE, Some("--strategy"));
    typed.failure.suggestion = Some("PREVIEW".to_owned());
    assert_eq!(
        same(&old, &typed),
        "{\"ok\":false,\"status\":\"failed\",\"message\":\"--strategy: «PREVEW» is not a \
         strategy 😀\",\"error\":\"--strategy: «PREVEW» is not a strategy 😀\",\
         \"schema_version\":1,\"command\":\"deploy\",\"duration_ms\":0,\"exit_code\":2,\
         \"summary\":{},\"next_actions\":[],\"failure\":{\"code\":\"usage_invalid_choice\",\
         \"message\":\"--strategy: «PREVEW» is not a strategy 😀\",\"argument\":\
         \"--strategy\",\"suggestion\":\"PREVIEW\",\"crash_log\":null}}\n"
    );
    let old = vec![
        key("status", Json::str("failed")),
        key("message", Json::str("é")),
        key("_exit_code", Json::Int(2)),
        key("_failure_code", Json::str("usage_error")),
    ];
    same(&old, &usage("é", "usage_error", None));
}

#[test]
fn a_failed_run_exits_1() {
    let old = vec![
        key("status", Json::str("failed")),
        key("message", Json::str("rules/é.yaml: problème 😀")),
        key("_exit_code", Json::Int(1)),
    ];
    same(&old, &failed("rules/é.yaml: problème 😀"));
}

#[test]
fn a_workspace_that_does_not_open_keeps_its_code_and_diagnostics() {
    let diagnostics = Json::Array(vec![Json::object([
        ("file", Json::str("é/😀.toml")),
        ("line", Json::Int(3)),
    ])]);
    let old = vec![
        key("status", Json::str("failed")),
        key("message", Json::str("é/😀.toml does not parse")),
        key("diagnostics", diagnostics.clone()),
        key("_exit_code", Json::Int(1)),
        key("_failure_code", Json::str("config_parse")),
    ];
    let typed = refusal(
        "config_parse".to_owned(),
        "é/😀.toml does not parse",
        Some(diagnostics),
    );
    same(&old, &typed);
    let old = vec![
        key("status", Json::str("failed")),
        key("message", Json::str("no workspace 😀")),
        key("_exit_code", Json::Int(1)),
        key("_failure_code", Json::str("workspace_not_found")),
    ];
    let typed = refusal("workspace_not_found".to_owned(), "no workspace 😀", None);
    same(&old, &typed);
}

#[test]
fn rules_no_file_holds_fail_the_run() {
    let unmatched = vec!["é.yaml".to_owned(), "😀".to_owned()];
    let old = vec![
        key("status", Json::str("failed")),
        key(
            "message",
            Json::str("No rule file directly in règles matched: é.yaml, 😀"),
        ),
        key("scope", Json::str("selected")),
        key(
            "unmatched",
            Json::Array(vec![Json::str("é.yaml"), Json::str("😀")]),
        ),
        key("dry_run", Json::Bool(false)),
        key("_exit_code", Json::Int(1)),
    ];
    same(&old, &unmatched_files("règles", &unmatched));
}

#[test]
fn nothing_to_deploy_is_skipped_unless_planning_refused_a_rule() {
    for refused in [false, true] {
        let mut old = vec![
            key("platform", Json::str("sentinel_é")),
            key(
                "status",
                Json::str(if refused { "failed" } else { "skipped" }),
            ),
            key(
                "message",
                Json::str(if refused {
                    "Rien 😀; planning reported rule errors"
                } else {
                    "Rien 😀"
                }),
            ),
            key("deployed", Json::Array(Vec::new())),
            key("dry_run", Json::Bool(false)),
            key("plan", Json::Object(Object::new())),
        ];
        if refused {
            old.push(key("_exit_code", Json::Int(1)));
        }
        let typed = nothing("Rien 😀", refused, ("platform", Json::str("sentinel_é")));
        let document = same(&old, &typed);
        if !refused {
            assert_eq!(
                document,
                "{\"platform\":\"sentinel_é\",\"deployed\":[],\"dry_run\":false,\"plan\":{},\
                 \"ok\":true,\"status\":\"skipped\",\"message\":\"Rien 😀\",\
                 \"schema_version\":1,\"command\":\"deploy\",\"duration_ms\":0,\
                 \"exit_code\":0,\"summary\":{},\"next_actions\":[],\"failure\":null}\n"
            );
        }
    }
}

#[test]
fn platforms_without_tenants_fail_unless_skipped() {
    let detail = "sentinel has no tenants configured in é.toml 😀";
    let missing = Json::object([("sentinel", Json::str("é.toml"))]);
    let plan = Json::object([("sentinel", Json::Array(vec![Json::str("ü")]))]);
    for (kind, status, message) in [
        (
            Tenantless::Skipped,
            "skipped",
            format!("Skipped deploy: {detail}"),
        ),
        (
            Tenantless::Refused,
            "failed",
            format!("Planning refused rules; {detail}"),
        ),
        (
            Tenantless::Failed,
            "failed",
            format!("Cannot deploy: {detail}"),
        ),
    ] {
        let mut old = vec![
            key("status", Json::str(status)),
            key("message", Json::str(&message)),
            key("advice", Json::str("add a [[tenants]] entry in é.toml")),
            key("missing_tenants", missing.clone()),
            key("deployed", Json::Array(Vec::new())),
            key("dry_run", Json::Bool(false)),
            key("plan", plan.clone()),
        ];
        if kind != Tenantless::Skipped {
            old.push(key("_exit_code", Json::Int(1)));
        }
        let typed = no_tenants(
            kind,
            detail,
            "add a [[tenants]] entry in é.toml",
            missing.clone(),
            plan.clone(),
        );
        same(&old, &typed);
    }
}

#[test]
fn a_stopped_promotion_fails_and_an_invalid_target_exits_bare() {
    use super::super::deploy_promote::{Stop, stopped};
    let old = vec![
        key("status", Json::str("failed")),
        key(
            "message",
            Json::str("é.yaml: cannot promote its statuses 😀"),
        ),
        key("_exit_code", Json::Int(1)),
    ];
    let typed = stopped(&Stop::Failed(
        "é.yaml: cannot promote its statuses 😀".to_owned(),
    ));
    same(&old, &typed);
    let old = vec![
        key("status", Json::str("failed")),
        key("message", Json::str("Invalid promotion target")),
        key("_exit_code", Json::Int(1)),
        key("_bare_exit", Json::Bool(true)),
    ];
    same(&old, &stopped(&Stop::Exit));
}

#[test]
fn a_promotion_that_cannot_be_put_back_fails_the_run() {
    let settled = || Settled {
        warnings: vec!["é.yaml was deleted during the deploy 😀".to_owned()],
        failures: vec![("règles/b.yaml".to_owned(), "refusé 😀".to_owned())],
    };
    let line = "Could not undo the status promotion of règles/b.yaml, which no tenant \
                received: refusé 😀";
    let entry = Json::object([
        ("path", Json::str("règles/b.yaml")),
        ("error", Json::str(line)),
    ]);
    // A run that completed: failed now, its message and error the line.
    let before = vec![
        key("message", Json::str("Deployed 1 rule 😀")),
        key("status", Json::str("completed")),
        key("deployed", Json::Array(vec![Json::str("sentinel")])),
        key("_exit_code", Json::Int(0)),
        key("results", Json::Array(Vec::new())),
    ];
    let old = vec![
        key("message", Json::str(line)),
        key("status", Json::str("failed")),
        key("deployed", Json::Array(vec![Json::str("sentinel")])),
        key("_exit_code", Json::Int(1)),
        key("results", Json::Array(Vec::new())),
        key("failures", Json::Array(vec![entry.clone()])),
        key("error", Json::str(line)),
    ];
    let mut typed = CommandResult::from_fields(&before);
    let mut warnings = Vec::new();
    settled().apply(&mut typed, &mut warnings);
    assert_eq!(warnings, ["é.yaml was deleted during the deploy 😀"]);
    let document = same(&old, &typed);
    let failure = format!("{{\"path\":\"règles/b.yaml\",\"error\":\"{line}\"}}");
    assert_eq!(
        document,
        format!(
            "{{\"deployed\":[\"sentinel\"],\"results\":[],\"failures\":[{failure}],\
             \"error\":\"{line}\",\"ok\":false,\"status\":\"failed\",\"message\":\"{line}\",\
             \"schema_version\":1,\"command\":\"deploy\",\"duration_ms\":0,\"exit_code\":1,\
             \"summary\":{{}},\"next_actions\":[],\"failure\":{{\"code\":\"command_failed\",\
             \"message\":\"{line}\",\"argument\":null,\"suggestion\":null,\"crash_log\":null}}}}\n"
        )
    );
    // A run that failed already: its message and error kept, the failure
    // added to its own.
    let own = Json::object([("id", Json::str("ü")), ("error", Json::str("é"))]);
    let before = vec![
        key("status", Json::str("failed")),
        key("message", Json::str("Échec 😀")),
        key("_exit_code", Json::Int(1)),
        key("error", Json::str("Échec 😀")),
        key("failures", Json::Array(vec![own.clone()])),
        key("_failure_code", Json::str(crate::commands::ISSUES_FOUND)),
    ];
    let old = vec![
        key("status", Json::str("failed")),
        key("message", Json::str("Échec 😀")),
        key("_exit_code", Json::Int(1)),
        key("error", Json::str("Échec 😀")),
        key("failures", Json::Array(vec![own, entry])),
        key("_failure_code", Json::str(crate::commands::ISSUES_FOUND)),
    ];
    let mut typed = CommandResult::from_fields(&before);
    settled().apply(&mut typed, &mut Vec::new());
    same(&old, &typed);
}
