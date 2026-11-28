//! `deploy`'s results, built as a [`CommandResult`], print the document, the
//! outcome line and the CI job summary their `_`-keys printed (#1949): each
//! case asserts the typed fields, the keys in order and the document of the
//! result a run builds, with non-ASCII text throughout.

use super::planning::Settled;
use super::*;
use crate::commands::result::FailureDetail;
use crate::json::document_text;
use crate::render::summary::deploy_summary;

fn key(name: &str, value: Json) -> (String, Json) {
    (name.to_owned(), value)
}

/// The keys of a result's data, in order.
fn keys(result: &CommandResult) -> Vec<&str> {
    result.data.keys().map(String::as_str).collect()
}

/// The `--json` document of `typed`, once it is checked to carry what a
/// deploy result carries: no outcome line and no bare exit unless it says
/// so, and a CI job summary that opens with the glyph of its status and its
/// message.
fn printed(typed: &CommandResult, glyph: &str) -> String {
    let report = typed.clone().report(COMMAND);
    assert_eq!(report.outcome_line, None);
    assert_eq!(report.warnings, typed.warnings);
    assert_eq!(report.bare_exit, typed.bare_exit);
    assert_eq!(report.outcome.status, typed.status);
    assert_eq!(report.outcome.exit_code, typed.exit);
    assert_eq!(report.outcome.summary, typed.summary);
    // The summary is Markdown: it escapes the underscores.
    let message = report.outcome.message.replace('_', "\\_");
    let summary = deploy_summary(&typed.to_json(), None, Some(false));
    assert!(
        summary.starts_with(&format!("### {glyph} opentide deploy\n\n{message}\n")),
        "{summary}"
    );
    document_text(&report.outcome.document(0), false)
}

#[test]
fn a_usage_refusal_names_its_argument_and_suggestion() {
    let message = "--strategy: «PREVEW» is not a strategy 😀";
    let mut typed = usage(message, code::USAGE_INVALID_CHOICE, Some("--strategy"));
    typed.failure.suggestion = Some("PREVIEW".to_owned());
    assert_eq!(typed.status, Status::Failed);
    assert_eq!(typed.exit, ExitCode::Usage);
    assert!(typed.data.is_empty());
    assert_eq!(
        printed(&typed, "✗"),
        "{\"ok\":false,\"status\":\"failed\",\"message\":\"--strategy: «PREVEW» is not a \
         strategy 😀\",\"error\":\"--strategy: «PREVEW» is not a strategy 😀\",\
         \"schema_version\":1,\"command\":\"deploy\",\"duration_ms\":0,\"exit_code\":2,\
         \"summary\":{},\"next_actions\":[],\"failure\":{\"code\":\"usage_invalid_choice\",\
         \"message\":\"--strategy: «PREVEW» is not a strategy 😀\",\"argument\":\
         \"--strategy\",\"suggestion\":\"PREVIEW\",\"crash_log\":null}}\n"
    );
    let typed = usage("é", "usage_error", None);
    assert_eq!(typed.exit, ExitCode::Usage);
    assert_eq!(
        printed(&typed, "✗"),
        "{\"ok\":false,\"status\":\"failed\",\"message\":\"é\",\"error\":\"é\",\
         \"schema_version\":1,\"command\":\"deploy\",\"duration_ms\":0,\"exit_code\":2,\
         \"summary\":{},\"next_actions\":[],\"failure\":{\"code\":\"usage_error\",\
         \"message\":\"é\",\"argument\":null,\"suggestion\":null,\"crash_log\":null}}\n"
    );
}

#[test]
fn a_failed_run_exits_1() {
    let typed = failed("rules/é.yaml: problème 😀");
    assert_eq!(typed.status, Status::Failed);
    assert_eq!(typed.exit, ExitCode::Failure);
    assert!(typed.data.is_empty());
    assert_eq!(
        printed(&typed, "✗"),
        "{\"ok\":false,\"status\":\"failed\",\"message\":\"rules/é.yaml: problème 😀\",\
         \"error\":\"rules/é.yaml: problème 😀\",\"schema_version\":1,\"command\":\
         \"deploy\",\"duration_ms\":0,\"exit_code\":1,\"summary\":{},\"next_actions\":[],\
         \"failure\":{\"code\":\"command_failed\",\"message\":\"rules/é.yaml: problème 😀\",\
         \"argument\":null,\"suggestion\":null,\"crash_log\":null}}\n"
    );
}

#[test]
fn a_workspace_that_does_not_open_keeps_its_code_and_diagnostics() {
    let diagnostics = Json::Array(vec![Json::object([
        ("file", Json::str("é/😀.toml")),
        ("line", Json::Int(3)),
    ])]);
    let typed = refusal(
        "config_parse".to_owned(),
        "é/😀.toml does not parse",
        Some(diagnostics.clone()),
    );
    assert_eq!(typed.failure.code.as_deref(), Some("config_parse"));
    assert_eq!(typed.exit, ExitCode::Failure);
    assert_eq!(keys(&typed), ["diagnostics"]);
    assert_eq!(typed.get("diagnostics"), Some(&diagnostics));
    assert_eq!(
        printed(&typed, "✗"),
        "{\"diagnostics\":[{\"file\":\"é/😀.toml\",\"line\":3}],\"ok\":false,\
         \"status\":\"failed\",\"message\":\"é/😀.toml does not parse\",\"error\":\
         \"é/😀.toml does not parse\",\"schema_version\":1,\"command\":\"deploy\",\
         \"duration_ms\":0,\"exit_code\":1,\"summary\":{},\"next_actions\":[],\"failure\":\
         {\"code\":\"config_parse\",\"message\":\"é/😀.toml does not parse\",\"argument\":\
         null,\"suggestion\":null,\"crash_log\":null}}\n"
    );
    let typed = refusal("workspace_not_found".to_owned(), "no workspace 😀", None);
    assert_eq!(typed.failure.code.as_deref(), Some("workspace_not_found"));
    assert!(typed.data.is_empty());
    printed(&typed, "✗");
}

#[test]
fn rules_no_file_holds_fail_the_run() {
    let unmatched = vec!["é.yaml".to_owned(), "😀".to_owned()];
    let typed = unmatched_files("règles", &unmatched);
    assert_eq!(typed.status, Status::Failed);
    assert_eq!(typed.exit, ExitCode::Failure);
    assert_eq!(
        typed.message.as_deref(),
        Some("No rule file directly in règles matched: é.yaml, 😀")
    );
    assert_eq!(keys(&typed), ["scope", "unmatched", "dry_run"]);
    assert_eq!(typed.get("scope"), Some(&Json::str("selected")));
    assert_eq!(
        typed.get("unmatched"),
        Some(&Json::Array(vec![Json::str("é.yaml"), Json::str("😀")]))
    );
    assert_eq!(typed.get("dry_run"), Some(&Json::Bool(false)));
    assert_eq!(
        printed(&typed, "✗"),
        "{\"scope\":\"selected\",\"unmatched\":[\"é.yaml\",\"😀\"],\"dry_run\":false,\
         \"ok\":false,\"status\":\"failed\",\"message\":\"No rule file directly in règles \
         matched: é.yaml, 😀\",\"error\":\"No rule file directly in règles matched: \
         é.yaml, 😀\",\"schema_version\":1,\"command\":\"deploy\",\"duration_ms\":0,\
         \"exit_code\":1,\"summary\":{},\"next_actions\":[],\"failure\":{\"code\":\
         \"command_failed\",\"message\":\"No rule file directly in règles matched: \
         é.yaml, 😀\",\"argument\":null,\"suggestion\":null,\"crash_log\":null}}\n"
    );
}

#[test]
fn nothing_to_deploy_is_skipped_unless_planning_refused_a_rule() {
    for refused in [false, true] {
        let typed = nothing("Rien 😀", refused, ("platform", Json::str("sentinel_é")));
        assert_eq!(keys(&typed), ["platform", "deployed", "dry_run", "plan"]);
        assert_eq!(typed.get("platform"), Some(&Json::str("sentinel_é")));
        assert_eq!(typed.get("deployed"), Some(&Json::Array(Vec::new())));
        assert_eq!(typed.get("dry_run"), Some(&Json::Bool(false)));
        assert_eq!(typed.get("plan"), Some(&Json::Object(Object::new())));
        if refused {
            assert_eq!(typed.status, Status::Failed);
            assert_eq!(typed.exit, ExitCode::Failure);
            assert_eq!(
                typed.message.as_deref(),
                Some("Rien 😀; planning reported rule errors")
            );
            printed(&typed, "✗");
        } else {
            assert_eq!(typed.status, Status::Skipped);
            assert_eq!(typed.exit, ExitCode::Success);
            assert_eq!(
                printed(&typed, "–"),
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
            Status::Skipped,
            format!("Skipped deploy: {detail}"),
        ),
        (
            Tenantless::Refused,
            Status::Failed,
            format!("Planning refused rules; {detail}"),
        ),
        (
            Tenantless::Failed,
            Status::Failed,
            format!("Cannot deploy: {detail}"),
        ),
    ] {
        let typed = no_tenants(
            kind,
            detail,
            "add a [[tenants]] entry in é.toml",
            missing.clone(),
            plan.clone(),
        );
        assert_eq!(typed.status, status);
        assert_eq!(typed.message.as_deref(), Some(message.as_str()));
        assert_eq!(
            typed.exit,
            if kind == Tenantless::Skipped {
                ExitCode::Success
            } else {
                ExitCode::Failure
            }
        );
        assert_eq!(
            keys(&typed),
            ["advice", "missing_tenants", "deployed", "dry_run", "plan"]
        );
        assert_eq!(
            typed.get("advice"),
            Some(&Json::str("add a [[tenants]] entry in é.toml"))
        );
        assert_eq!(typed.get("missing_tenants"), Some(&missing));
        assert_eq!(typed.get("plan"), Some(&plan));
        printed(
            &typed,
            if kind == Tenantless::Skipped {
                "–"
            } else {
                "✗"
            },
        );
    }
}

#[test]
fn a_stopped_promotion_fails_and_an_invalid_target_exits_bare() {
    use super::super::deploy_promote::{Stop, stopped};
    let typed = stopped(&Stop::Failed(
        "é.yaml: cannot promote its statuses 😀".to_owned(),
    ));
    assert_eq!(typed.status, Status::Failed);
    assert_eq!(typed.exit, ExitCode::Failure);
    assert!(!typed.bare_exit);
    assert_eq!(
        typed.message.as_deref(),
        Some("é.yaml: cannot promote its statuses 😀")
    );
    assert!(typed.data.is_empty());
    printed(&typed, "✗");
    let typed = stopped(&Stop::Exit);
    assert_eq!(typed.status, Status::Failed);
    assert_eq!(typed.exit, ExitCode::Failure);
    assert!(typed.bare_exit);
    assert_eq!(typed.message.as_deref(), Some("Invalid promotion target"));
    printed(&typed, "✗");
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
    let mut typed = CommandResult {
        message: Some("Deployed 1 rule 😀".to_owned()),
        data: Object::from([
            key("deployed", Json::Array(vec![Json::str("sentinel")])),
            key("results", Json::Array(Vec::new())),
        ]),
        ..CommandResult::default()
    };
    let mut warnings = Vec::new();
    settled().apply(&mut typed, &mut warnings);
    assert_eq!(warnings, ["é.yaml was deleted during the deploy 😀"]);
    assert_eq!(typed.status, Status::Failed);
    assert_eq!(typed.exit, ExitCode::Failure);
    assert_eq!(typed.message.as_deref(), Some(line));
    assert_eq!(keys(&typed), ["deployed", "results", "failures", "error"]);
    assert_eq!(typed.get("error"), Some(&Json::str(line)));
    let document = printed(&typed, "✗");
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
    let mut typed = CommandResult {
        status: Status::Failed,
        message: Some("Échec 😀".to_owned()),
        exit: ExitCode::Failure,
        failure: FailureDetail {
            code: Some(crate::commands::ISSUES_FOUND.to_owned()),
            ..FailureDetail::default()
        },
        data: Object::from([
            key("error", Json::str("Échec 😀")),
            key("failures", Json::Array(vec![own.clone()])),
        ]),
        ..CommandResult::default()
    };
    settled().apply(&mut typed, &mut Vec::new());
    assert_eq!(typed.message.as_deref(), Some("Échec 😀"));
    assert_eq!(typed.get("error"), Some(&Json::str("Échec 😀")));
    assert_eq!(keys(&typed), ["error", "failures"]);
    assert_eq!(typed.get("failures"), Some(&Json::Array(vec![own, entry])));
    assert_eq!(
        typed.failure.code.as_deref(),
        Some(crate::commands::ISSUES_FOUND)
    );
    printed(&typed, "✗");
}

/// A run's shared parts, with non-ASCII data.
fn ran() -> Ran {
    Ran {
        deployed: vec!["sentinel_é".to_owned()],
        plan: Json::object([("sentinel_é", Json::Array(vec![Json::str("ü😀")]))]),
        strategies: Json::Array(vec![Json::str("PRODUCTION")]),
        changes: Json::Array(vec![Json::object([("id", Json::str("ü😀"))])]),
        results: Json::Array(vec![Json::object([
            ("id", Json::str("ü😀")),
            ("status", Json::str("failed")),
        ])]),
        summary: Object::from([
            ("create".to_owned(), Json::Int(1)),
            ("seconds".to_owned(), Json::Float(0.25)),
            ("platforms".to_owned(), Json::Int(1)),
            ("tenants".to_owned(), Json::Int(1)),
        ]),
    }
}

fn failure_entries() -> Vec<(String, Json)> {
    vec![
        (
            "règle ü😀 on lé: refusée".to_owned(),
            Json::object([("id", Json::str("ü😀")), ("error", Json::str("refusée"))]),
        ),
        (
            "tenant lé: 401".to_owned(),
            Json::object([("tenant", Json::str("lé")), ("error", Json::str("401"))]),
        ),
    ]
}

fn entries() -> Json {
    Json::Array(
        failure_entries()
            .into_iter()
            .map(|(_, entry)| entry)
            .collect(),
    )
}

#[test]
fn a_run_a_platform_stopped_fails_naming_the_rule_it_stopped_on() {
    let message = "Deployment to sentinel_é failed: refusé 😀";
    // The stop came on no rule.
    let typed = ran().stopped(message.to_owned(), None, failure_entries());
    assert_eq!(typed.status, Status::Failed);
    assert_eq!(typed.exit, ExitCode::Failure);
    assert_eq!(typed.message.as_deref(), Some(message));
    assert_eq!(typed.failure.code, None);
    assert_eq!(typed.summary, ran().summary);
    assert_eq!(
        keys(&typed),
        [
            "deployed",
            "dry_run",
            "plan",
            "strategies",
            "changes",
            "results",
            "failures"
        ]
    );
    assert_eq!(typed.get("failures"), Some(&entries()));
    assert_eq!(typed.get("plan"), Some(&ran().plan));
    printed(&typed, "✗");
    // The stop came on a rule: the outcome message, its error and
    // `issues_found`.
    let outcome = "Failed: 1 rule ✗ 😀";
    let error = "Deployment to sentinel_é failed on Règle: refusé 😀";
    let typed = ran().stopped(
        message.to_owned(),
        Some((outcome.to_owned(), error.to_owned())),
        failure_entries(),
    );
    assert_eq!(typed.message.as_deref(), Some(outcome));
    assert_eq!(
        typed.failure.code.as_deref(),
        Some(crate::commands::ISSUES_FOUND)
    );
    assert_eq!(
        keys(&typed),
        [
            "deployed",
            "dry_run",
            "plan",
            "strategies",
            "changes",
            "results",
            "error",
            "failures"
        ]
    );
    assert_eq!(typed.get("error"), Some(&Json::str(error)));
    assert_eq!(
        printed(&typed, "✗"),
        "{\"deployed\":[\"sentinel_é\"],\"dry_run\":false,\"plan\":{\"sentinel_é\":\
         [\"ü😀\"]},\"strategies\":[\"PRODUCTION\"],\"changes\":[{\"id\":\"ü😀\"}],\
         \"results\":[{\"id\":\"ü😀\",\"status\":\"failed\"}],\"error\":\"Deployment to \
         sentinel_é failed on Règle: refusé 😀\",\"failures\":[{\"id\":\"ü😀\",\"error\":\
         \"refusée\"},{\"tenant\":\"lé\",\"error\":\"401\"}],\"ok\":false,\"status\":\
         \"failed\",\"message\":\"Failed: 1 rule ✗ 😀\",\"schema_version\":1,\"command\":\
         \"deploy\",\"duration_ms\":0,\"exit_code\":1,\"summary\":{\"create\":1,\
         \"seconds\":0.25,\"platforms\":1,\"tenants\":1},\"next_actions\":[],\"failure\":\
         {\"code\":\"issues_found\",\"message\":\"Deployment to sentinel_é failed on \
         Règle: refusé 😀\",\"argument\":null,\"suggestion\":null,\"crash_log\":null}}\n"
    );
}

#[test]
fn a_run_that_ended_completes_or_fails_with_its_first_failure() {
    for (failed, rule_failed, failures, warned) in [
        (false, false, Vec::new(), false),
        (false, false, Vec::new(), true),
        (true, true, failure_entries(), true),
        (true, false, failure_entries(), false),
    ] {
        let message = if failed {
            "Échec 😀"
        } else {
            "Deployed 1 rule ✓ 😀"
        };
        let first_error = failures
            .first()
            .map(|(first, _)| format!("{first}{}", more_failures(failures.len())));
        let typed = ran().ended(&Ending {
            message: message.to_owned(),
            failed,
            rule_failed,
            failures,
            warned,
        });
        assert_eq!(
            typed.status,
            if failed {
                Status::Failed
            } else {
                Status::Completed
            }
        );
        assert_eq!(
            typed.exit,
            if failed {
                ExitCode::Failure
            } else {
                ExitCode::Success
            }
        );
        assert_eq!(typed.message.as_deref(), Some(message));
        assert_eq!(typed.summary, ran().summary);
        assert_eq!(
            typed.failure.code.as_deref(),
            (failed && rule_failed).then_some(crate::commands::ISSUES_FOUND)
        );
        assert_eq!(
            typed.warnings,
            if warned {
                vec!["Some rules reported deployment warnings".to_owned()]
            } else {
                Vec::new()
            }
        );
        let mut expected = vec!["deployed", "dry_run", "plan", "changes", "results"];
        if let Some(error) = &first_error {
            expected.extend(["error", "failures"]);
            assert_eq!(typed.get("error"), Some(&Json::str(error)));
            assert_eq!(typed.get("failures"), Some(&entries()));
        }
        expected.push("strategies");
        assert_eq!(keys(&typed), expected);
        let glyph = match (failed, warned) {
            (true, _) => "✗",
            (false, true) => "!",
            (false, false) => "✓",
        };
        let document = printed(&typed, glyph);
        if !failed && !warned {
            assert_eq!(
                document,
                "{\"deployed\":[\"sentinel_é\"],\"dry_run\":false,\"plan\":{\"sentinel_é\":\
                 [\"ü😀\"]},\"changes\":[{\"id\":\"ü😀\"}],\"results\":[{\"id\":\"ü😀\",\
                 \"status\":\"failed\"}],\"strategies\":[\"PRODUCTION\"],\"ok\":true,\
                 \"status\":\"completed\",\"message\":\"Deployed 1 rule ✓ 😀\",\
                 \"schema_version\":1,\"command\":\"deploy\",\"duration_ms\":0,\
                 \"exit_code\":0,\"summary\":{\"create\":1,\"seconds\":0.25,\"platforms\":1,\
                 \"tenants\":1},\"next_actions\":[],\"failure\":null}\n"
            );
        }
    }
}
