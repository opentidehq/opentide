//! Exabeam against a stand-in tenant (wiremock): the token, the name check
//! before a create, every create, update, disable and delete with the
//! bodies of `tests/fixtures/exabeam/*.api.json`, what each failure does to
//! the rule and to the tenant, `429`s, and Search for `opentide query` and
//! `validate query --live`. Ported from 0.28.0's
//! `tests/test_platforms/test_exabeam_{deployer,runner}.py`.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use opentide_compile::Json;
use opentide_connectors::connector::{
    DeployRequest, Operation, QueryRequest, TenantContext, TimeWindow,
};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::exabeam::{
    self, Action, Exabeam, Pacer, RuleDeploy, RuleOutcome, Session, StateChange, deploy_rule,
};
use opentide_connectors::{ConnectorError, Environment, HttpClient, Platform, Tenant};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const FIRST_ID: &str = "016dbc1d-a727-43df-a143-9546dcc81a5a";
const NAME: &str = "Password spraying from outside the network";
const RULES: &str = "/correlation-rules/v2/rules";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/exabeam")
}

/// The `body` of a fixture request.
fn golden(name: &str) -> Json {
    let text = std::fs::read_to_string(fixtures().join(name)).unwrap();
    let request: Json = serde_json::from_str(&text).unwrap();
    request.get("body").unwrap().clone()
}

fn as_json(value: &Json) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}

/// A stand-in tenant and what a call needs.
struct Stand {
    server: MockServer,
    tenant: Tenant,
    http: HttpClient,
    cancel: CancellationToken,
    pacer: Arc<Pacer>,
}

impl Stand {
    async fn start() -> Self {
        Self::start_with("").await
    }

    /// A tenant with `extra` setup lines (TOML).
    async fn start_with(extra: &str) -> Self {
        let server = MockServer::start().await;
        let setup = format!(
            "ssl = true\nregion = \"eu\"\nclient_id = \"$EXABEAM_CLIENT_ID\"\n\
             client_secret = \"$EXABEAM_CLIENT_SECRET\"\napi_url = \"{}/\"\n{extra}",
            server.uri()
        );
        let setup: toml::Table = toml::from_str(&setup).unwrap();
        let env = Environment::default()
            .with("EXABEAM_CLIENT_ID", "client-id")
            .with("EXABEAM_CLIENT_SECRET", "client-secret");
        let tenant = Tenant::from_setup(
            "exabeam",
            "exabeam-eu",
            &setup,
            &env,
            Resolve::Required,
            &exabeam::http_defaults(),
        )
        .unwrap();
        let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
        Self {
            server,
            tenant,
            http,
            cancel: CancellationToken::new(),
            pacer: Arc::new(Pacer::default()),
        }
    }

    fn cx(&self) -> TenantContext<'_> {
        TenantContext {
            tenant: &self.tenant,
            http: &self.http,
            cancel: &self.cancel,
        }
    }

    fn session(&self) -> Session<'_> {
        Session::new(self.cx(), Arc::clone(&self.pacer)).unwrap()
    }

    /// Answers the token endpoint with `t1`.
    async fn token(&self) {
        Mock::given(method("POST"))
            .and(path(exabeam::TOKEN_PATH))
            .and(body_partial_json(serde_json::json!({
                "client_id": "client-id",
                "client_secret": "client-secret",
                "grant_type": "client_credentials",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "t1", "token_type": "Bearer", "expires_in": 14400
            })))
            .mount(&self.server)
            .await;
    }

    async fn on(&self, verb: &str, route: &str, answer: ResponseTemplate) {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(answer)
            .mount(&self.server)
            .await;
    }

    async fn requests(&self) -> Vec<Request> {
        self.server.received_requests().await.unwrap_or_default()
    }

    /// `METHOD path` of every request, in order.
    async fn routes(&self) -> Vec<String> {
        self.requests()
            .await
            .iter()
            .map(|request| format!("{} {}", request.method, request.url.path()))
            .collect()
    }

    /// The JSON body of the `index`th request.
    async fn sent(&self, index: usize) -> serde_json::Value {
        serde_json::from_slice(&self.requests().await[index].body).unwrap()
    }
}

fn rule(action: Action, body: Json) -> RuleDeploy {
    let name = body
        .get("name")
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned();
    let disable = body.get("enabled") == Some(&Json::Bool(false));
    RuleDeploy {
        action,
        body,
        name,
        disable,
        recreate_refusal: None,
    }
}

fn create_rule() -> RuleDeploy {
    rule(
        Action::Create,
        golden("rule-exabeam-threshold-1.0.create.api.json"),
    )
}

fn update_rule() -> RuleDeploy {
    rule(
        Action::Update(FIRST_ID.to_owned()),
        golden("rule-exabeam-threshold-1.0.update.api.json"),
    )
}

fn created() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": FIRST_ID, "name": NAME}))
}

fn failure_code(outcome: &RuleOutcome) -> Option<&str> {
    outcome
        .failure
        .as_ref()
        .map(|failure| failure.code.as_str())
}

fn warnings(outcome: &RuleOutcome) -> Vec<&str> {
    outcome
        .warnings
        .iter()
        .map(|warning| warning.code.as_str())
        .collect()
}

#[tokio::test]
async fn create_checks_the_name_sends_the_golden_and_records_the_id() {
    let stand = Stand::start().await;
    stand.token().await;
    Mock::given(method("GET"))
        .and(path(RULES))
        .and(query_param("nameContains", NAME))
        .and(header("Authorization", "Bearer t1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&stand.server)
        .await;
    stand.on("POST", RULES, created()).await;
    let outcome = deploy_rule(&stand.session(), &create_rule()).await.unwrap();
    assert_eq!(
        stand.routes().await,
        [
            "POST /auth/v1/token",
            &format!("GET {RULES}"),
            &format!("POST {RULES}")
        ]
    );
    assert_eq!(
        stand.sent(2).await,
        as_json(&golden("rule-exabeam-threshold-1.0.create.api.json"))
    );
    assert_eq!(outcome.state, StateChange::Record(FIRST_ID.to_owned()));
    assert_eq!(
        outcome.done,
        Some(("exabeam_rule_created", FIRST_ID.to_owned()))
    );
    assert_eq!(outcome.failure, None);
}

#[tokio::test]
async fn update_and_disable_send_the_whole_body_and_keep_the_binding() {
    for (golden_name, done) in [
        (
            "rule-exabeam-threshold-1.0.update.api.json",
            "exabeam_rule_updated",
        ),
        (
            "rule-exabeam-threshold-1.0.disable.api.json",
            "exabeam_rule_disabled",
        ),
    ] {
        let stand = Stand::start().await;
        stand.token().await;
        stand
            .on(
                "PUT",
                &format!("{RULES}/{FIRST_ID}"),
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": FIRST_ID})),
            )
            .await;
        let deploy = rule(Action::Update(FIRST_ID.to_owned()), golden(golden_name));
        let outcome = deploy_rule(&stand.session(), &deploy).await.unwrap();
        assert_eq!(stand.sent(1).await, as_json(&golden(golden_name)));
        assert_eq!(outcome.state, StateChange::Keep);
        assert_eq!(outcome.done, Some((done, FIRST_ID.to_owned())));
        assert!(outcome.failure.is_none() && outcome.warnings.is_empty());
    }
}

#[tokio::test]
async fn deletion_deletes_and_forgets_even_a_rule_already_gone() {
    for status in [204, 404] {
        let stand = Stand::start().await;
        stand.token().await;
        stand
            .on(
                "DELETE",
                &format!("{RULES}/{FIRST_ID}"),
                ResponseTemplate::new(status),
            )
            .await;
        let deploy = rule(Action::Delete(FIRST_ID.to_owned()), Json::Null);
        let outcome = deploy_rule(&stand.session(), &deploy).await.unwrap();
        assert_eq!(outcome.state, StateChange::Forget, "{status}");
        assert!(outcome.failure.is_none());
    }
}

#[tokio::test]
async fn a_failed_delete_keeps_the_binding() {
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "DELETE",
            &format!("{RULES}/{FIRST_ID}"),
            ResponseTemplate::new(500).set_body_json(serde_json::json!({"message": "boom"})),
        )
        .await;
    let deploy = rule(Action::Delete(FIRST_ID.to_owned()), Json::Null);
    let outcome = deploy_rule(&stand.session(), &deploy).await.unwrap();
    assert_eq!(outcome.state, StateChange::Keep);
    assert_eq!(failure_code(&outcome), Some("exabeam_request_failed"));
}

#[tokio::test]
async fn an_update_of_a_rule_gone_creates_it_again() {
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "PUT",
            &format!("{RULES}/{FIRST_ID}"),
            ResponseTemplate::new(404),
        )
        .await;
    stand
        .on(
            "GET",
            RULES,
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"rules": []})),
        )
        .await;
    stand.on("POST", RULES, created()).await;
    let outcome = deploy_rule(&stand.session(), &update_rule()).await.unwrap();
    assert_eq!(
        stand.routes().await[1..],
        [
            format!("PUT {RULES}/{FIRST_ID}"),
            format!("GET {RULES}"),
            format!("POST {RULES}")
        ]
    );
    assert_eq!(outcome.state, StateChange::Record(FIRST_ID.to_owned()));
    assert_eq!(warnings(&outcome), ["exabeam_rule_recreated"]);
    // Deployment state that cannot take the new id refuses the create.
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "PUT",
            &format!("{RULES}/{FIRST_ID}"),
            ResponseTemplate::new(404),
        )
        .await;
    let mut refused = update_rule();
    refused.recreate_refusal = Some((
        "deployment_state_ignored".to_owned(),
        ".opentide/states/deployment/ is ignored".to_owned(),
    ));
    let outcome = deploy_rule(&stand.session(), &refused).await.unwrap();
    assert_eq!(failure_code(&outcome), Some("deployment_state_ignored"));
    assert_eq!(stand.routes().await.len(), 2);
}

#[tokio::test]
async fn disabling_a_rule_gone_forgets_it() {
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "PUT",
            &format!("{RULES}/{FIRST_ID}"),
            ResponseTemplate::new(404),
        )
        .await;
    let deploy = rule(
        Action::Update(FIRST_ID.to_owned()),
        golden("rule-exabeam-threshold-1.0.disable.api.json"),
    );
    let outcome = deploy_rule(&stand.session(), &deploy).await.unwrap();
    assert_eq!(outcome.state, StateChange::Forget);
    assert_eq!(warnings(&outcome), ["exabeam_rule_missing"]);
    assert!(outcome.failure.is_none());
}

#[tokio::test]
async fn an_existing_name_is_never_adopted_but_a_longer_one_is_no_conflict() {
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "GET",
            RULES,
            ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "a", "name": NAME.to_uppercase()},
                {"id": "b", "name": format!("{NAME} (copy)")},
            ])),
        )
        .await;
    stand.on("POST", RULES, created()).await;
    let outcome = deploy_rule(&stand.session(), &create_rule()).await.unwrap();
    assert_eq!(failure_code(&outcome), Some("exabeam_name_conflict"));
    let failure = outcome.failure.unwrap();
    assert!(failure.message.contains("(id a)"), "{}", failure.message);
    assert_eq!(failure.fields, [("existing_id", "a".to_owned())]);
    assert_eq!(outcome.state, StateChange::Keep);
    assert!(!stand.routes().await.contains(&format!("POST {RULES}")));

    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "GET",
            RULES,
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"items": [
                {"id": "b", "name": format!("{NAME} (copy)")},
            ]})),
        )
        .await;
    stand.on("POST", RULES, created()).await;
    let outcome = deploy_rule(&stand.session(), &create_rule()).await.unwrap();
    assert_eq!(outcome.state, StateChange::Record(FIRST_ID.to_owned()));
}

#[tokio::test]
async fn a_name_check_answer_of_another_shape_refuses_the_create() {
    for answer in [
        ResponseTemplate::new(200).set_body_json(serde_json::json!({"rules": [], "items": []})),
        ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})),
        ResponseTemplate::new(200).set_body_string("<html></html>"),
        ResponseTemplate::new(500).set_body_json(serde_json::json!({"message": "boom"})),
    ] {
        let stand = Stand::start().await;
        stand.token().await;
        stand.on("GET", RULES, answer).await;
        stand.on("POST", RULES, created()).await;
        let outcome = deploy_rule(&stand.session(), &create_rule()).await.unwrap();
        assert_eq!(failure_code(&outcome), Some("exabeam_request_failed"));
        assert!(!stand.routes().await.contains(&format!("POST {RULES}")));
    }
}

#[tokio::test]
async fn creates_that_cannot_be_bound() {
    for (answer, code) in [
        (
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "17"})),
            "exabeam_create_no_id",
        ),
        (
            ResponseTemplate::new(201).set_body_string("created"),
            "exabeam_create_no_id",
        ),
        (
            ResponseTemplate::new(200).set_body_json(serde_json::json!({})),
            "exabeam_create_no_id",
        ),
        (
            ResponseTemplate::new(502).set_body_string("bad gateway"),
            "exabeam_create_unconfirmed",
        ),
        (
            ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "errors": [{"code": "INVALID_QUERY", "message": "bad", "fields": ["query"]}],
                "traceId": "trace-1",
            })),
            "exabeam_request_rejected",
        ),
        (
            ResponseTemplate::new(422).set_body_json(serde_json::json!({"message": "no"})),
            "exabeam_request_failed",
        ),
    ] {
        let stand = Stand::start().await;
        stand.token().await;
        stand
            .on(
                "GET",
                RULES,
                ResponseTemplate::new(200).set_body_json(serde_json::json!([])),
            )
            .await;
        stand.on("POST", RULES, answer).await;
        let outcome = deploy_rule(&stand.session(), &create_rule()).await.unwrap();
        assert_eq!(failure_code(&outcome), Some(code));
        assert_eq!(outcome.state, StateChange::Keep, "{code}");
        let posts = stand
            .routes()
            .await
            .iter()
            .filter(|route| *route == &format!("POST {RULES}"))
            .count();
        assert_eq!(posts, 1, "a create is never sent again");
        if code == "exabeam_request_rejected" {
            let failure = outcome.failure.unwrap();
            assert!(
                failure
                    .message
                    .contains("INVALID_QUERY: bad (fields: query)")
            );
            assert!(failure.fields.contains(&("trace_id", "trace-1".to_owned())));
        }
    }
}

#[tokio::test]
async fn a_create_with_no_answer_is_unconfirmed_and_not_sent_again() {
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "GET",
            RULES,
            ResponseTemplate::new(200).set_body_json(serde_json::json!([])),
        )
        .await;
    stand
        .on("POST", RULES, created().set_delay(Duration::from_secs(5)))
        .await;
    let session = stand.session();
    let deploy = create_rule();
    // The run is cancelled while the create waits for its answer.
    let cancel = stand.cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        cancel.cancel();
    });
    let outcome = deploy_rule(&session, &deploy).await.unwrap();
    assert_eq!(failure_code(&outcome), Some("exabeam_create_unconfirmed"));
    let failure = outcome.failure.unwrap();
    assert!(
        failure.message.contains("got no answer"),
        "{}",
        failure.message
    );
}

#[tokio::test]
async fn a_retained_schedule_and_an_auto_disabled_rule_are_reported() {
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "PUT",
            &format!("{RULES}/{FIRST_ID}"),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": FIRST_ID,
                "autoDisabled": true,
                "scheduleConfig": {"recurrences": [{"recurrenceType": "DAILY"}]},
            })),
        )
        .await;
    let outcome = deploy_rule(&stand.session(), &update_rule()).await.unwrap();
    assert_eq!(
        warnings(&outcome),
        ["exabeam_schedule_retained", "exabeam_rule_auto_disabled"]
    );
    assert!(outcome.failure.is_none());
}

#[tokio::test]
async fn a_rejected_update_fails_and_keeps_the_binding() {
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "PUT",
            &format!("{RULES}/{FIRST_ID}"),
            ResponseTemplate::new(400).set_body_json(serde_json::json!({"message": "bad"})),
        )
        .await;
    let outcome = deploy_rule(&stand.session(), &update_rule()).await.unwrap();
    assert_eq!(failure_code(&outcome), Some("exabeam_request_rejected"));
    assert_eq!(outcome.state, StateChange::Keep);
}

#[tokio::test]
async fn a_name_longer_than_128_is_never_sent() {
    let stand = Stand::start().await;
    let mut deploy = create_rule();
    deploy.name = "x".repeat(129);
    let outcome = deploy_rule(&stand.session(), &deploy).await.unwrap();
    assert_eq!(failure_code(&outcome), Some("exabeam_name_length"));
    assert!(stand.routes().await.is_empty());
}

#[tokio::test]
async fn one_token_serves_the_run_and_an_expired_one_is_renewed_once() {
    let stand = Stand::start().await;
    Mock::given(method("POST"))
        .and(path(exabeam::TOKEN_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"access_token": "t1"})),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&stand.server)
        .await;
    Mock::given(method("POST"))
        .and(path(exabeam::TOKEN_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"access_token": "t2"})),
        )
        .with_priority(2)
        .mount(&stand.server)
        .await;
    Mock::given(method("PUT"))
        .and(header("Authorization", "Bearer t1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": FIRST_ID})))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&stand.server)
        .await;
    Mock::given(method("PUT"))
        .and(header("Authorization", "Bearer t1"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({"message": "Jwt is expired"})),
        )
        .with_priority(2)
        .mount(&stand.server)
        .await;
    Mock::given(method("PUT"))
        .and(header("Authorization", "Bearer t2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": FIRST_ID})))
        .mount(&stand.server)
        .await;
    let session = stand.session();
    deploy_rule(&session, &update_rule()).await.unwrap();
    let outcome = deploy_rule(&session, &update_rule()).await.unwrap();
    assert!(outcome.failure.is_none());
    let routes = stand.routes().await;
    let put = format!("PUT {RULES}/{FIRST_ID}");
    assert_eq!(
        routes,
        [
            "POST /auth/v1/token",
            put.as_str(),
            put.as_str(),
            "POST /auth/v1/token",
            put.as_str()
        ]
    );
    let last = stand.requests().await.last().cloned().unwrap();
    assert_eq!(
        last.headers.get("authorization").unwrap().to_str().unwrap(),
        "Bearer t2"
    );
}

#[tokio::test]
async fn a_second_expired_token_stops_the_tenant() {
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "PUT",
            &format!("{RULES}/{FIRST_ID}"),
            ResponseTemplate::new(401).set_body_string("token expired"),
        )
        .await;
    let failure = deploy_rule(&stand.session(), &update_rule())
        .await
        .unwrap_err();
    assert_eq!(failure.code, exabeam::UNAUTHORIZED);
    assert!(
        failure.message.contains("HTTP 401 ("),
        "{}",
        failure.message
    );
    assert!(
        failure.message.contains("token expired"),
        "{}",
        failure.message
    );
    assert_eq!(stand.routes().await.len(), 4);
}

#[tokio::test]
async fn a_refusing_tenant_stops() {
    for (status, code) in [
        (403, exabeam::UNAUTHORIZED),
        (409, exabeam::FEATURE_UNAVAILABLE),
    ] {
        let stand = Stand::start().await;
        stand.token().await;
        stand
            .on(
                "GET",
                RULES,
                ResponseTemplate::new(status)
                    .set_body_json(serde_json::json!({"message": "Feature is not enabled"})),
            )
            .await;
        let failure = deploy_rule(&stand.session(), &create_rule())
            .await
            .unwrap_err();
        assert_eq!(failure.code, code);
        assert!(
            failure
                .message
                .starts_with(&format!("{code}: tenant exabeam-eu ")),
            "{}",
            failure.message
        );
        assert!(failure.error.is_none());
    }
}

#[tokio::test]
async fn a_refused_or_failing_token_stops_the_tenant() {
    for (status, code) in [
        (401, exabeam::UNAUTHORIZED),
        (400, exabeam::UNAUTHORIZED),
        (500, exabeam::UNREACHABLE),
    ] {
        let stand = Stand::start().await;
        stand
            .on(
                "POST",
                exabeam::TOKEN_PATH,
                ResponseTemplate::new(status).set_body_string("no"),
            )
            .await;
        let failure = deploy_rule(&stand.session(), &create_rule())
            .await
            .unwrap_err();
        assert_eq!(failure.code, code, "{status}");
        assert_eq!(stand.routes().await, ["POST /auth/v1/token"]);
    }
    for body in [
        serde_json::json!({"token_type": "Bearer"}),
        serde_json::json!({"access_token": ""}),
    ] {
        let stand = Stand::start().await;
        stand
            .on(
                "POST",
                exabeam::TOKEN_PATH,
                ResponseTemplate::new(200).set_body_json(body),
            )
            .await;
        let failure = deploy_rule(&stand.session(), &create_rule())
            .await
            .unwrap_err();
        assert_eq!(failure.code, exabeam::UNREACHABLE);
        assert!(
            failure.message.contains("no access_token"),
            "{}",
            failure.message
        );
    }
    let stand = Stand::start().await;
    stand
        .on(
            "POST",
            exabeam::TOKEN_PATH,
            ResponseTemplate::new(200).set_body_string("<html/>"),
        )
        .await;
    let failure = deploy_rule(&stand.session(), &create_rule())
        .await
        .unwrap_err();
    assert!(failure.message.contains("not JSON"), "{}", failure.message);
}

#[tokio::test]
async fn an_unreachable_tenant_stops() {
    let stand = Stand::start().await;
    let address = stand.server.address().to_owned();
    drop(stand.server);
    // Nothing listens there any more.
    let server = MockServer::start().await;
    let _ = server;
    let setup: toml::Table = toml::from_str(&format!(
        "region = \"eu\"\nclient_id = \"$A\"\nclient_secret = \"$B\"\napi_url = \"http://{address}\"\n"
    ))
    .unwrap();
    let env = Environment::default().with("A", "a").with("B", "b");
    let tenant = Tenant::from_setup(
        "exabeam",
        "exabeam-eu",
        &setup,
        &env,
        Resolve::Required,
        &exabeam::http_defaults(),
    )
    .unwrap();
    let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let session = Session::new(cx, Arc::new(Pacer::default())).unwrap();
    let failure = deploy_rule(&session, &create_rule()).await.unwrap_err();
    assert_eq!(failure.code, exabeam::UNREACHABLE);
    assert!(
        failure.message.contains("no token for GET"),
        "{}",
        failure.message
    );
}

#[tokio::test]
async fn a_429_waits_and_resends_the_same_request() {
    let stand = Stand::start().await;
    Mock::given(method("POST"))
        .and(path(exabeam::TOKEN_PATH))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&stand.server)
        .await;
    stand.token().await;
    stand
        .on(
            "PUT",
            &format!("{RULES}/{FIRST_ID}"),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({})),
        )
        .await;
    let outcome = deploy_rule(&stand.session(), &update_rule()).await.unwrap();
    assert!(outcome.failure.is_none());
    assert_eq!(
        stand.routes().await[..2],
        ["POST /auth/v1/token", "POST /auth/v1/token"]
    );
}

#[tokio::test]
async fn a_long_or_endless_rate_limit_fails_the_rule() {
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "PUT",
            &format!("{RULES}/{FIRST_ID}"),
            ResponseTemplate::new(429).insert_header("Retry-After", "301"),
        )
        .await;
    let outcome = deploy_rule(&stand.session(), &update_rule()).await.unwrap();
    let failure = outcome.failure.unwrap();
    assert_eq!(failure.code, "exabeam_request_failed");
    assert!(
        failure.message.contains("more than 300s"),
        "{}",
        failure.message
    );

    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "PUT",
            &format!("{RULES}/{FIRST_ID}"),
            ResponseTemplate::new(429).insert_header("Retry-After", "0"),
        )
        .await;
    let outcome = deploy_rule(&stand.session(), &update_rule()).await.unwrap();
    let failure = outcome.failure.unwrap();
    assert!(
        failure
            .message
            .contains("still rate limited after 10 waits"),
        "{}",
        failure.message
    );
    assert_eq!(stand.routes().await.len(), 12);
}

#[tokio::test]
async fn an_unset_credential_fails_before_any_call() {
    let stand = Stand::start().await;
    let setup: toml::Table = toml::from_str(
        "region = \"eu\"\nclient_id = \"$UNSET_ID\"\nclient_secret = \"$UNSET_SECRET\"\n",
    )
    .unwrap();
    let tenant = Tenant::from_setup(
        "exabeam",
        "exabeam-eu",
        &setup,
        &Environment::default(),
        Resolve::Counting,
        &exabeam::http_defaults(),
    )
    .unwrap();
    let cx = TenantContext {
        tenant: &tenant,
        http: &stand.http,
        cancel: &stand.cancel,
    };
    let error = Session::new(cx, Arc::new(Pacer::default())).unwrap_err();
    assert!(matches!(error, ConnectorError::MissingCredential { .. }));
    assert!(stand.routes().await.is_empty());
}

#[tokio::test]
async fn the_region_names_the_api_host() {
    let server = MockServer::start().await;
    let _ = server;
    let setup: toml::Table =
        toml::from_str("region = \"us-east\"\nclient_id = \"$A\"\nclient_secret = \"$B\"\n")
            .unwrap();
    let env = Environment::default().with("A", "a").with("B", "b");
    let tenant = Tenant::from_setup(
        "exabeam",
        "t",
        &setup,
        &env,
        Resolve::Required,
        &exabeam::http_defaults(),
    )
    .unwrap();
    let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    assert_eq!(
        exabeam::base_url(cx).unwrap(),
        "https://api.us-east.exabeam.cloud"
    );
    let stand = Stand::start().await;
    assert_eq!(stand.session().base(), stand.server.uri());
}

// ---------------------------------------------------------------------------
// Search.
// ---------------------------------------------------------------------------

fn window() -> TimeWindow {
    TimeWindow {
        start: "2026-11-11T11:00:00Z".parse().unwrap(),
        end: "2026-11-11T12:00:00Z".parse().unwrap(),
    }
}

#[tokio::test]
async fn a_query_runs_through_search() {
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "POST",
            "/search/v2/events",
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "rows": [{"user": "a", "host": {"name": "h1"}}, {"user": "b"}, {"user": "c"}],
                "totalRows": 40,
            })),
        )
        .await;
    let mut request = QueryRequest::new("SELECT user, host WHERE x", "exabeam", window());
    request.limit = 2;
    let outcome = Exabeam::with_pacer(Arc::clone(&stand.pacer))
        .query_runner()
        .unwrap()
        .run(stand.cx(), &request)
        .await
        .unwrap();
    assert_eq!(outcome.rows.len(), 2);
    assert!(outcome.truncated);
    assert!(outcome.rows[0].contains_key("host.name"));
    assert_eq!(outcome.language.as_deref(), Some("exabeam"));
    assert!(outcome.warnings.is_empty());
    assert_eq!(
        stand.sent(1).await,
        serde_json::json!({
            "filter": "SELECT user, host WHERE x",
            "fields": ["user", "host"],
            "startTime": "2026-11-11T11:00:00Z",
            "endTime": "2026-11-11T12:00:00Z",
            "limit": 3,
        })
    );
    // At most 3,000 rows a search.
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "POST",
            "/search/v2/events",
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"rows": []})),
        )
        .await;
    let mut request = QueryRequest::new("x", "exabeam", window());
    request.limit = 5000;
    let outcome = exabeam::run_query(&stand.session(), &request)
        .await
        .unwrap();
    assert!(!outcome.truncated);
    assert_eq!(
        outcome.warnings,
        ["Exabeam returns at most 3,000 rows per search"]
    );
    assert_eq!(stand.sent(1).await["limit"], 3000);
    assert_eq!(stand.sent(1).await["fields"], serde_json::json!(["*"]));
}

#[tokio::test]
async fn the_live_check_reads_200_400_and_anything_else() {
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "POST",
            "/search/v2/events",
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"rows": [{"a": 1}]})),
        )
        .await;
    let request = QueryRequest::new(" activity_type:\"app-login\" ", "exabeam", window());
    let check = Exabeam::with_pacer(Arc::clone(&stand.pacer))
        .live_validator()
        .unwrap()
        .validate(stand.cx(), &request)
        .await
        .unwrap();
    assert_eq!(check.result.unwrap().rows.len(), 1);
    assert_eq!(stand.sent(1).await["limit"], 1);
    assert_eq!(stand.sent(1).await["filter"], "activity_type:\"app-login\"");

    for (answer, message) in [
        (
            ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "errors": [{"code": "BAD_FILTER", "message": "unexpected token"}]
            })),
            "Exabeam refused the query on exabeam-eu: BAD_FILTER: unexpected token",
        ),
        (
            ResponseTemplate::new(500).set_body_json(serde_json::json!({"message": "down"})),
            "Exabeam answered HTTP 500 to the search on exabeam-eu: down",
        ),
        (
            ResponseTemplate::new(200).set_body_string("<html/>"),
            "Exabeam did not answer the search with JSON on exabeam-eu",
        ),
        (
            ResponseTemplate::new(429).insert_header("Retry-After", "900"),
            "Exabeam could not run the search on exabeam-eu: rate limited",
        ),
    ] {
        let stand = Stand::start().await;
        stand.token().await;
        stand.on("POST", "/search/v2/events", answer).await;
        let error = exabeam::check_query(&stand.session(), &request)
            .await
            .unwrap_err();
        assert!(matches!(error, ConnectorError::Refused { .. }), "{error:?}");
        assert!(error.text().starts_with(message), "{}", error.text());
    }
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on("POST", "/search/v2/events", ResponseTemplate::new(403))
        .await;
    let error = exabeam::check_query(&stand.session(), &request)
        .await
        .unwrap_err();
    assert!(
        matches!(error, ConnectorError::Authentication { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn the_platform_deploys_through_the_generic_interface() {
    let stand = Stand::start().await;
    stand.token().await;
    stand
        .on(
            "GET",
            RULES,
            ResponseTemplate::new(200).set_body_json(serde_json::json!([])),
        )
        .await;
    stand.on("POST", RULES, created()).await;
    stand
        .on(
            "PUT",
            &format!("{RULES}/{FIRST_ID}"),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({})),
        )
        .await;
    stand
        .on(
            "DELETE",
            &format!("{RULES}/{FIRST_ID}"),
            ResponseTemplate::new(204),
        )
        .await;
    let platform = Exabeam::with_pacer(Arc::clone(&stand.pacer));
    assert_eq!(platform.id(), "exabeam");
    let deployer = platform.deployer().unwrap();
    let body = serde_json::to_vec(&golden("rule-exabeam-threshold-1.0.create.api.json")).unwrap();
    let mut request = DeployRequest {
        rule_id: String::new(),
        operation: Operation::Create,
        body: body.clone(),
    };
    let outcome = deployer.deploy(stand.cx(), &request).await.unwrap();
    assert_eq!(outcome.remote_id.as_deref(), Some(FIRST_ID));
    request.rule_id = FIRST_ID.to_owned();
    request.operation = Operation::Disable;
    let outcome = deployer.deploy(stand.cx(), &request).await.unwrap();
    assert_eq!(outcome.remote_id.as_deref(), Some(FIRST_ID));
    request.operation = Operation::Delete;
    let outcome = deployer.deploy(stand.cx(), &request).await.unwrap();
    assert_eq!(outcome.remote_id, None);
    // One token for the run, across the three calls.
    let tokens = stand
        .routes()
        .await
        .iter()
        .filter(|route| route.ends_with("/auth/v1/token"))
        .count();
    assert_eq!(tokens, 1);
    // A rule failure is an error through this interface.
    request.operation = Operation::Create;
    request.body = b"{\"name\": \"x\"}".to_vec();
    let stand2 = Stand::start().await;
    stand2.token().await;
    stand2
        .on(
            "GET",
            RULES,
            ResponseTemplate::new(200).set_body_json(serde_json::json!([{"id": "z", "name": "x"}])),
        )
        .await;
    let error = deployer.deploy(stand2.cx(), &request).await.unwrap_err();
    assert!(
        error.text().starts_with("exabeam_name_conflict: "),
        "{}",
        error.text()
    );
    request.body = b"not json".to_vec();
    assert!(deployer.deploy(stand2.cx(), &request).await.is_err());
}
