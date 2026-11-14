//! What a Google SecOps deploy, live check and search do when the instance
//! refuses, loses or half-answers a request: each failure is the rule's
//! (with its code and a message that says what was and was not written), or
//! the tenant's, as `deployer.py` reports it. The Chronicle API and the token
//! endpoint are a wiremock server; no real credential is used.
#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::time::Duration;

use opentide_compile::google_secops::RunState;
use opentide_connectors::connector::{
    DeployRequest, Deployer, LiveValidator, Operation, QueryRequest, QueryRunner, TenantContext,
    TimeWindow,
};
use opentide_connectors::credentials::Mode;
use opentide_connectors::google_secops::deploy::{
    Action, RuleDeploy, RuleOutcome, StateChange, deploy_rule,
};
use opentide_connectors::google_secops::{GoogleSecops, Instance};
use opentide_connectors::{ConnectorError, Environment, HttpClient, HttpSettings, Tenant};
use opentide_schema::objects::platform::google_secops::assemble::AssembledRule;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockBuilder, MockServer, ResponseTemplate, Times};

const ID: &str = "ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1";
const RESOURCE: &str = "projects/acme/locations/eu/instances/i-1";
const TEXT: &str =
    "rule r {\n  events:\n    $e.metadata.event_type = \"X\"\n  condition:\n    $e\n}\n";
const VERIFY: &str = ":verifyRuleText";
/// The access token the stand-in issues; it must never reach a message.
const TOKEN: &str = "ya29.never-in-a-message";

/// A request to `/v1/<instance><suffix>`.
fn on(verb: &str, suffix: &str) -> MockBuilder {
    Mock::given(method(verb)).and(path(format!("/v1/{RESOURCE}{suffix}")))
}

/// `PATCH <suffix>?updateMask=<mask>`.
fn patch(suffix: &str, mask: &str) -> MockBuilder {
    on("PATCH", suffix).and(query_param("updateMask", mask))
}

/// Answers `mock` with `reply`, `times` times.
async fn serve(
    server: &MockServer,
    mock: MockBuilder,
    reply: ResponseTemplate,
    times: impl Into<Times>,
) {
    mock.respond_with(reply).expect(times).mount(server).await;
}

fn answer(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(body)
}

fn ok() -> ResponseTemplate {
    answer(200, json!({}))
}

fn verified() -> ResponseTemplate {
    answer(200, json!({"success": true}))
}

fn google_error(status: u16, code: &str, message: &str) -> ResponseTemplate {
    answer(
        status,
        json!({"error": {"status": code, "message": message}}),
    )
}

fn rule_path() -> String {
    format!("/rules/{ID}")
}

fn deployment() -> String {
    format!("/rules/{ID}/deployment")
}

/// The server, its token endpoint mounted.
async fn server() -> MockServer {
    let server = MockServer::start().await;
    let token = answer(200, json!({"access_token": TOKEN, "expires_in": 3600}));
    let mock = Mock::given(method("POST")).and(path("/token"));
    serve(&server, mock, token, ..).await;
    server
}

/// Runs `body` with the tenant at `server` (its `setup` extended by `extra`,
/// reached with `settings`) and the connector.
async fn with_tenant<T>(
    server: &MockServer,
    extra: &str,
    settings: &HttpSettings,
    body: impl AsyncFnOnce(TenantContext<'_>, &GoogleSecops) -> T,
) -> T {
    let directory = tempfile::tempdir().unwrap();
    let adc = directory.path().join("adc.json");
    let document = json!({"type": "authorized_user", "client_id": "c", "client_secret": "s",
        "refresh_token": "r", "token_uri": format!("{}/token", server.uri())});
    std::fs::write(&adc, document.to_string()).unwrap();
    let setup: toml::Table = toml::from_str(&format!(
        "project = \"acme\"\nlocation = \"eu\"\ninstance = \"i-1\"\nendpoint = \"{}\"\n{extra}",
        server.uri()
    ))
    .unwrap();
    let env = Environment::from_pairs([("GOOGLE_APPLICATION_CREDENTIALS", adc.to_str().unwrap())]);
    let tenant = Tenant::from_setup(
        "google_secops",
        "secops-eu",
        &setup,
        &env,
        Mode::Required,
        settings,
    );
    let tenant = tenant.unwrap();
    let http = HttpClient::new(&tenant.label, settings, &env, None).unwrap();
    let cancel = CancellationToken::new();
    let connector = GoogleSecops::new(env);
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    body(cx, &connector).await
}

fn rule(action: Action) -> RuleDeploy {
    let assembled = AssembledRule {
        name: "r".into(),
        text: TEXT.into(),
        sections: Vec::new(),
    };
    RuleDeploy {
        action,
        assembled,
        run_state: RunState::disabled(),
        run_frequency: None,
        disabling: false,
        retiring: false,
        scope: None,
        delete: false,
        recreate_refusal: None,
    }
}

async fn deploy_with(
    server: &MockServer,
    settings: &HttpSettings,
    rule: &RuleDeploy,
) -> Result<RuleOutcome, ConnectorError> {
    with_tenant(server, "", settings, async |cx, connector| {
        let authorizer = connector.authorizer(cx.tenant).unwrap();
        deploy_rule(cx, &authorizer, &server.uri(), RESOURCE, rule).await
    })
    .await
}

async fn deploy(server: &MockServer, rule: &RuleDeploy) -> RuleOutcome {
    deploy_with(server, &HttpSettings::default(), rule)
        .await
        .unwrap()
}

/// The failures' codes, then the warnings'.
fn codes(outcome: &RuleOutcome) -> (Vec<&str>, Vec<&str>) {
    (
        outcome.failures.iter().map(|f| f.code.as_str()).collect(),
        outcome.warnings.iter().map(|w| w.code).collect(),
    )
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

#[test]
fn a_create_google_refuses_or_cannot_confirm_records_no_rule() {
    runtime().block_on(async {
        // verifyRuleText refused outright: the request's own words, nothing created.
        let server = server().await;
        serve(
            &server,
            on("POST", VERIFY),
            google_error(400, "INVALID_ARGUMENT", "too long"),
            1,
        )
        .await;
        serve(&server, on("POST", "/rules"), ok(), 0).await;
        let outcome = deploy(&server, &rule(Action::Create)).await;
        assert_eq!(outcome.state, StateChange::Keep);
        assert_eq!(codes(&outcome).0, ["google_secops_request_failed"]);
        assert_eq!(outcome.failures[0].message, "INVALID_ARGUMENT: too long");
        server.verify().await;

        // Compiled, but neither success nor a diagnostic: the rule fails.
        let server = self::server().await;
        serve(&server, on("POST", VERIFY), ok(), ..).await;
        let outcome = deploy(&server, &rule(Action::Create)).await;
        let expected =
            "Google SecOps does not compile rule r: verifyRuleText did not report success";
        assert_eq!(outcome.failures[0].message, expected);

        // A frequency Google does not allow: nothing is written.
        let server = self::server().await;
        let daily = answer(
            200,
            json!({"success": true, "allowedRunFrequencies": ["DAILY"]}),
        );
        serve(&server, on("POST", VERIFY), daily, ..).await;
        serve(&server, on("POST", "/rules"), ok(), 0).await;
        let mut hourly = rule(Action::Create);
        hourly.run_frequency = Some("HOURLY".to_owned());
        let outcome = deploy(&server, &hourly).await;
        assert_eq!(
            codes(&outcome).0,
            ["google_secops_run_frequency_not_allowed"]
        );
        assert!(
            outcome.failures[0]
                .message
                .ends_with("(DAILY); nothing was written")
        );
        server.verify().await;

        // A 2xx whose body is not JSON names no id; a 4xx is the request's failure.
        for (reply, code, shown) in [
            (
                ResponseTemplate::new(200).set_body_string("<html>ok</html>"),
                "google_secops_create_no_id",
                "answered a body that is not JSON",
            ),
            (
                google_error(409, "ALREADY_EXISTS", "rule exists"),
                "google_secops_request_failed",
                "ALREADY_EXISTS: rule exists",
            ),
        ] {
            let server = self::server().await;
            serve(&server, on("POST", VERIFY), verified(), ..).await;
            serve(&server, on("POST", "/rules"), reply, 1).await;
            let outcome = deploy(&server, &rule(Action::Create)).await;
            assert_eq!(outcome.state, StateChange::Keep);
            assert_eq!(codes(&outcome).0, [code]);
            assert!(
                outcome.failures[0].message.contains(shown),
                "{:?}",
                outcome.failures
            );
            server.verify().await;
        }
    });
}

#[test]
fn a_create_that_times_out_is_never_resent() {
    runtime().block_on(async {
        let server = server().await;
        serve(&server, on("POST", VERIFY), verified(), ..).await;
        let slow = ok().set_delay(Duration::from_secs(5));
        serve(&server, on("POST", "/rules"), slow, 1).await;
        let timeout = Duration::from_millis(300);
        let settings = HttpSettings {
            timeout,
            ..HttpSettings::default()
        };
        let outcome = deploy_with(&server, &settings, &rule(Action::Create))
            .await
            .unwrap();
        assert_eq!(outcome.state, StateChange::Keep);
        assert_eq!(codes(&outcome).0, ["google_secops_create_unconfirmed"]);
        let message = &outcome.failures[0].message;
        assert!(message.contains("got no answer"), "{message}");
        assert!(
            message.contains("Deploy does not send it again"),
            "{message}"
        );
        server.verify().await;
    });
}

#[test]
fn a_created_rule_is_recorded_even_when_its_run_state_fails() {
    runtime().block_on(async {
        let server = server().await;
        serve(&server, on("POST", VERIFY), verified(), ..).await;
        let created = answer(200, json!({"name": format!("{RESOURCE}/rules/{ID}")}));
        serve(&server, on("POST", "/rules"), created, 1).await;
        let refused = google_error(400, "FAILED_PRECONDITION", "quota");
        serve(&server, on("PATCH", &deployment()), refused, 1).await;
        let outcome = deploy(&server, &rule(Action::Create)).await;
        assert_eq!(outcome.state, StateChange::Record(ID.to_owned()));
        assert_eq!(codes(&outcome).0, ["google_secops_deployment_failed"]);
        assert!(
            outcome.failures[0]
                .message
                .contains("the next deploy repairs it")
        );
        server.verify().await;
    });
}

#[test]
fn credentials_the_instance_refuses_stop_the_tenant_without_the_token() {
    runtime().block_on(async {
        let server = server().await;
        let denied = google_error(403, "PERMISSION_DENIED", "caller lacks chronicle.rules");
        serve(&server, on("POST", VERIFY), denied, 1).await;
        let settings = HttpSettings::default();
        let error = deploy_with(&server, &settings, &rule(Action::Create))
            .await
            .unwrap_err();
        let ConnectorError::Authentication { message, .. } = &error else {
            panic!("{error:?}")
        };
        assert!(message.starts_with("google_secops_tenant_unauthorized: tenant secops-eu"));
        assert!(
            message.contains("(HTTP 403 PERMISSION_DENIED): caller lacks"),
            "{message}"
        );
        assert!(!format!("{error} {error:?}").contains(TOKEN));
    });
}

#[test]
fn a_bound_rule_that_is_gone_is_created_again_or_forgotten() {
    runtime().block_on(async {
        // Retiring: forgotten, nothing created.
        let server = server().await;
        serve(
            &server,
            on("GET", &rule_path()),
            google_error(404, "NOT_FOUND", "no"),
            ..,
        )
        .await;
        serve(&server, on("POST", VERIFY), verified(), 0).await;
        let mut disabling = rule(Action::Update(ID.to_owned()));
        disabling.retiring = true;
        let outcome = deploy(&server, &disabling).await;
        assert_eq!(outcome.state, StateChange::Forget);
        assert_eq!(codes(&outcome).1, ["google_secops_rule_missing"]);

        // Not retiring, but deployment state cannot take a new id: the refusal.
        let mut refused = rule(Action::Update(ID.to_owned()));
        refused.recreate_refusal = Some(("state_ignored".into(), "state is ignored".into()));
        let outcome = deploy(&server, &refused).await;
        let recreated = (vec!["state_ignored"], vec!["google_secops_rule_recreated"]);
        assert_eq!(codes(&outcome), recreated);
        assert_eq!(outcome.state, StateChange::Keep);
        server.verify().await;

        // A read that fails otherwise is the rule's failure.
        let server = self::server().await;
        serve(
            &server,
            on("GET", &rule_path()),
            google_error(500, "INTERNAL", "backend"),
            ..,
        )
        .await;
        let outcome = deploy(&server, &rule(Action::Update(ID.to_owned()))).await;
        assert_eq!(outcome.failures[0].message, "INTERNAL: backend");
    });
}

/// A bound, archived rule with the text `text` and another scope; Google
/// reports it paused and its compilation failed.
async fn bound_rule(server: &MockServer, text: &str) {
    let scope = format!("{RESOURCE}/dataAccessScopes/old");
    let remote = json!({"text": text, "etag": "e1", "compilationState": "FAILED", "scope": scope});
    serve(server, on("GET", &rule_path()), answer(200, remote), ..).await;
    let state = json!({"archived": true, "enabled": true, "executionState": "PAUSED"});
    serve(server, on("GET", &deployment()), answer(200, state), ..).await;
}

#[test]
fn an_update_writes_only_what_changed_and_reports_what_failed() {
    runtime().block_on(async {
        // The text is unchanged: no verify, no text update; the unarchive and
        // the scope are written, the run state is refused.
        let server = server().await;
        bound_rule(&server, TEXT).await;
        serve(&server, on("POST", VERIFY), verified(), 0).await;
        serve(&server, patch(&deployment(), "archived"), ok(), 1).await;
        serve(&server, patch(&rule_path(), "scope"), ok(), 1).await;
        let later = google_error(500, "INTERNAL", "later");
        serve(&server, patch(&deployment(), "enabled"), later, 1).await;
        let outcome = deploy(&server, &rule(Action::Update(ID.to_owned()))).await;
        let (failures, warnings) = codes(&outcome);
        assert_eq!(failures, ["google_secops_deployment_failed"]);
        let health = [
            "google_secops_rule_execution_limited",
            "google_secops_rule_compilation_failed",
        ];
        assert_eq!(warnings, health);
        assert!(
            outcome.warnings[0]
                .detail
                .contains("PAUSED: it is not run at all")
        );
        server.verify().await;

        // A changed text whose etag went stale: a conflict, nothing more written.
        let server = self::server().await;
        bound_rule(&server, "rule old {}").await;
        serve(&server, on("POST", VERIFY), verified(), 1).await;
        serve(&server, patch(&deployment(), "archived"), ok(), 1).await;
        serve(
            &server,
            patch(&rule_path(), "text"),
            google_error(409, "ABORTED", "etag"),
            1,
        )
        .await;
        serve(&server, patch(&rule_path(), "scope"), ok(), 0).await;
        let outcome = deploy(&server, &rule(Action::Update(ID.to_owned()))).await;
        assert_eq!(codes(&outcome).0, ["google_secops_rule_conflict"]);
        assert!(
            outcome.failures[0]
                .message
                .contains("(etag mismatch); nothing was written")
        );
        server.verify().await;

        // The unarchive refused: neither the scope nor the run state is set.
        let server = self::server().await;
        bound_rule(&server, TEXT).await;
        let locked = google_error(400, "FAILED_PRECONDITION", "locked");
        serve(&server, on("PATCH", &deployment()), locked, 1).await;
        serve(&server, on("PATCH", &rule_path()), ok(), 0).await;
        let outcome = deploy(&server, &rule(Action::Update(ID.to_owned()))).await;
        assert_eq!(codes(&outcome).0, ["google_secops_deployment_failed"]);
        server.verify().await;
    });
}

#[test]
fn a_disablement_disables_the_rule_even_when_its_new_text_does_not_compile() {
    runtime().block_on(async {
        let server = server().await;
        serve(
            &server,
            on("GET", &rule_path()),
            answer(200, json!({"text": "rule old {}"})),
            ..,
        )
        .await;
        let enabled = answer(200, json!({"enabled": true, "alerting": true}));
        serve(&server, on("GET", &deployment()), enabled, ..).await;
        let error =
            json!({"message": "bad field", "severity": "ERROR", "position": {"startLine": 1}});
        let diagnostics = answer(200, json!({"compilationDiagnostics": [error]}));
        serve(&server, on("POST", VERIFY), diagnostics, 1).await;
        serve(&server, on("PATCH", &rule_path()), ok(), 0).await;
        serve(&server, patch(&deployment(), "enabled,alerting"), ok(), 1).await;
        let mut disabling = rule(Action::Update(ID.to_owned()));
        disabling.disabling = true;
        disabling.retiring = true;
        let outcome = deploy(&server, &disabling).await;
        assert_eq!(codes(&outcome).0, ["google_secops_verify_failed"]);
        assert!(outcome.failures[0].message.contains("bad field"));
        server.verify().await;
    });
}

#[test]
fn a_deletion_archives_when_google_refuses_the_delete() {
    runtime().block_on(async {
        let mut deleting = rule(Action::Delete(ID.to_owned()));
        deleting.delete = true;
        // Refused (a 4xx but 401/403/404/429): disabled and archived instead,
        // the binding kept.
        let server = server().await;
        let refused = google_error(400, "FAILED_PRECONDITION", "rule has detections");
        serve(&server, on("DELETE", &rule_path()), refused, 1).await;
        serve(
            &server,
            on("GET", &deployment()),
            answer(200, json!({"enabled": true})),
            ..,
        )
        .await;
        serve(&server, patch(&deployment(), "enabled,alerting"), ok(), 1).await;
        serve(&server, patch(&deployment(), "archived"), ok(), 1).await;
        let outcome = deploy(&server, &deleting).await;
        assert_eq!(outcome.state, StateChange::Keep);
        assert_eq!(codes(&outcome).1, ["google_secops_delete_refused"]);
        assert!(
            outcome.warnings[0]
                .detail
                .contains("HTTP 400 FAILED_PRECONDITION: rule has")
        );
        server.verify().await;

        // Deleted or already gone: forgotten. A 5xx: the rule fails, its id kept.
        for (status, state, failures) in [
            (200, StateChange::Forget, vec![]),
            (404, StateChange::Forget, vec![]),
            (500, StateChange::Keep, vec!["google_secops_request_failed"]),
        ] {
            let server = self::server().await;
            serve(
                &server,
                on("DELETE", &rule_path()),
                google_error(status, "X", "m"),
                1,
            )
            .await;
            let outcome = deploy(&server, &deleting).await;
            assert_eq!(
                (outcome.state.clone(), codes(&outcome).0),
                (state, failures)
            );
            server.verify().await;
        }

        // Archiving a rule that is gone forgets it; one already archived is
        // left as it is.
        let archiving = rule(Action::Delete(ID.to_owned()));
        for (reply, state) in [
            (google_error(404, "NOT_FOUND", "gone"), StateChange::Forget),
            (answer(200, json!({"archived": true})), StateChange::Keep),
        ] {
            let server = self::server().await;
            serve(&server, on("GET", &deployment()), reply, 1).await;
            serve(&server, on("PATCH", &deployment()), ok(), 0).await;
            let outcome = deploy(&server, &archiving).await;
            assert_eq!(outcome.state, state);
            assert!(outcome.failures.is_empty());
            server.verify().await;
        }
    });
}

#[test]
fn the_framework_traits_turn_a_refusal_into_an_error_with_googles_words() {
    runtime().block_on(async {
        let server = server().await;
        let error = json!({"message": "unknown function", "severity": "ERROR"});
        let diagnostics = answer(200, json!({"compilationDiagnostics": [error]}));
        serve(&server, on("POST", VERIFY), diagnostics, ..).await;
        let refused = google_error(400, "INVALID_ARGUMENT", "bad query");
        serve(&server, on("GET", ":udmSearch"), refused, 1).await;
        let window = TimeWindow::check(jiff::Timestamp::from_second(1_800_000_000).unwrap());
        let request = QueryRequest::new(TEXT, "yaral", window);
        let create = DeployRequest {
            rule_id: String::new(),
            operation: Operation::Create,
            body: serde_json::to_vec(&json!({"text": TEXT})).unwrap(),
        };
        let settings = HttpSettings::default();
        let [check, search, deploy] = with_tenant(&server, "", &settings, async |cx, connector| {
            [
                connector.validate(cx, &request).await.unwrap_err(),
                connector.run(cx, &request).await.unwrap_err(),
                connector.deploy(cx, &create).await.unwrap_err(),
            ]
        })
        .await;
        // Each is a refusal: the tenant's words in the detail, the token nowhere.
        let refusal = |error: &ConnectorError| {
            assert!(!format!("{error:?}").contains(TOKEN));
            match error {
                ConnectorError::Refused {
                    message, detail, ..
                } => (message.clone(), detail.clone()),
                other => panic!("{other:?}"),
            }
        };
        let (message, detail) = refusal(&check);
        assert_eq!(
            message,
            "Google SecOps tenant secops-eu does not compile the rule"
        );
        assert!(detail.unwrap().contains("unknown function"));
        let searched = refusal(&search);
        let expected = "Google SecOps refused the search on secops-eu (INVALID_ARGUMENT)";
        assert_eq!(
            searched,
            (expected.to_owned(), Some("bad query".to_owned()))
        );
        let (message, _) = refusal(&deploy);
        assert!(
            message.starts_with("google_secops_verify_failed: "),
            "{message}"
        );
        server.verify().await;
    });
}

#[test]
fn the_deployer_trait_records_the_created_id_and_forgets_a_retired_one() {
    runtime().block_on(async {
        let server = server().await;
        serve(&server, on("POST", VERIFY), verified(), 1).await;
        let created = answer(200, json!({"name": format!("{RESOURCE}/rules/{ID}")}));
        serve(&server, on("POST", "/rules"), created, 1).await;
        serve(
            &server,
            on("GET", &deployment()),
            google_error(404, "NOT_FOUND", "gone"),
            1,
        )
        .await;
        serve(&server, on("PATCH", &deployment()), ok(), 1).await;
        let request = |operation, rule_id: &str| DeployRequest {
            rule_id: rule_id.to_owned(),
            operation,
            body: serde_json::to_vec(&json!({"text": TEXT})).unwrap(),
        };
        let settings = HttpSettings::default();
        let scoped = "data_access_scope = \"soc\"";
        with_tenant(&server, scoped, &settings, async |cx, connector| {
            let created = connector
                .deploy(cx, &request(Operation::Create, ""))
                .await
                .unwrap();
            assert_eq!(created.remote_id.as_deref(), Some(ID));
            let deleted = connector
                .deploy(cx, &request(Operation::Delete, ID))
                .await
                .unwrap();
            assert_eq!(
                (deleted.remote_id, deleted.operation),
                (None, Operation::Delete)
            );
            let scope = Instance::of(cx.tenant).unwrap().scope(cx.tenant);
            assert_eq!(scope, Some(format!("{RESOURCE}/dataAccessScopes/soc")));
        })
        .await;
        server.verify().await;
    });
}

#[test]
fn an_instance_without_an_endpoint_is_reached_at_its_locations_default() {
    let env = Environment::default();
    for extra in ["", "endpoint = \"\""] {
        let setup = format!("project = \"acme\"\nlocation = \"eu\"\ninstance = \"i-1\"\n{extra}");
        let setup: toml::Table = toml::from_str(&setup).unwrap();
        let settings = HttpSettings::default();
        let tenant = Tenant::from_setup(
            "google_secops",
            "t",
            &setup,
            &env,
            Mode::Required,
            &settings,
        );
        let tenant = tenant.unwrap();
        let instance = Instance::of(&tenant).unwrap();
        assert_eq!(instance.endpoint, "https://eu-chronicle.googleapis.com");
        assert_eq!(instance.resource, RESOURCE);
        assert_eq!(instance.scope(&tenant), None);
    }
}
