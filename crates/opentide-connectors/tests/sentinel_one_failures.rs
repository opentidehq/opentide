//! What SentinelOne's deploy and query calls report when the console refuses
//! or half-answers them (`_http_errors`): the error kind, the console's own
//! words, and never the API token. The console is a wiremock server.
#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use opentide_connectors::connector::{
    DeployError, DeployRequest, DeployScope, Deployer, Operation, QueryRequest, TenantContext,
    TimeWindow,
};
use opentide_connectors::credentials::Mode;
use opentide_connectors::runtime::block_on;
use opentide_connectors::sentinel_one::{
    self, QUERY_PATH, QueryValidation, RULES_PATH, SentinelOne, SentinelOneError,
};
use opentide_connectors::{ConnectorError, Environment, HttpClient, Tenant};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// *work* on the process's runtime.
fn wait<F: Future>(work: F) -> F::Output {
    block_on(work).unwrap()
}

const TOKEN: &str = "s1-token-never-in-a-message";

/// Runs `body` with a tenant whose console is `api`.
fn with_tenant<T>(api: &MockServer, body: impl FnOnce(TenantContext<'_>) -> T) -> T {
    let setup: opentide_core::json::Object = toml::from_str(&format!(
        "url = \"{}\"\napi_token = \"$S1_TOKEN\"\naccount_id = 4242\nsite_id = 0\n",
        api.uri()
    ))
    .unwrap();
    let env = Environment::from_pairs([("S1_TOKEN", TOKEN)]);
    let settings = sentinel_one::http_settings();
    let tenant = Tenant::from_setup(
        sentinel_one::PLATFORM,
        "s1",
        &setup,
        &env,
        Mode::Required,
        &settings,
    )
    .unwrap();
    let http = HttpClient::new(&tenant.label, &settings, &env, None).unwrap();
    let cancel = CancellationToken::new();
    body(TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    })
}

/// A server that answers every `verb` to `route` with `reply`.
fn server(verb: &str, route: &str, reply: ResponseTemplate) -> MockServer {
    wait(async {
        let api = MockServer::start().await;
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(reply)
            .mount(&api)
            .await;
        api
    })
}

fn deploy(
    api: &MockServer,
    operation: Operation,
    rule_id: &str,
    body: &[u8],
) -> Result<Option<String>, DeployError> {
    let request = DeployRequest::new(rule_id.to_owned(), operation, body.to_vec());
    with_tenant(api, |cx| wait(SentinelOne.deploy(cx, &request))).map(|outcome| outcome.remote_id)
}

/// The console's refusal: its message, which names no secret, after its
/// code, scope and status are checked.
fn reason(error: &DeployError, code: &str, scope: DeployScope, status: Option<u16>) -> String {
    assert_eq!(error.failure.code, code, "{error:?}");
    assert_eq!(error.scope, scope, "{error:?}");
    assert_eq!(error.failure.status, status, "{error:?}");
    assert_eq!(error.failure.field("platform"), Some("sentinel_one"));
    assert!(!format!("{error} {error:?}").contains(TOKEN));
    error.failure.message.clone()
}

#[test]
fn the_deployer_reports_each_refusal_in_the_consoles_words() {
    let rule = br#"{"data": {"name": "r"}}"#;
    for (status, body, expected, code, scope, kept) in [
        (
            400,
            json!({"errors": ["bad"]}),
            "SentinelOne refused the rule (HTTP 400)",
            "sentinel_one_rule_invalid",
            DeployScope::Rule,
            Some(400),
        ),
        (
            401,
            json!({"errors": ["token"]}),
            "SentinelOne refused the API token (HTTP 401)",
            "sentinel_one_unauthorized",
            DeployScope::Tenant,
            Some(401),
        ),
        (
            500,
            json!({"errors": [{"code": 5}]}),
            "Unforeseen error with code [500]: {\"errors\":[{\"code\":5}]}",
            "sentinel_one_request_failed",
            DeployScope::Rule,
            Some(500),
        ),
        (
            200,
            json!({"data": {}}),
            "SentinelOne answered without the rule's id",
            "tenant_answer_invalid",
            DeployScope::Rule,
            None,
        ),
    ] {
        let api = server(
            "POST",
            RULES_PATH,
            ResponseTemplate::new(status).set_body_json(body),
        );
        let error = deploy(&api, Operation::Create, "", rule).unwrap_err();
        let reason = reason(&error, code, scope, kept);
        assert!(reason.starts_with(expected), "{status}: {reason}");
    }
    // A rule that is gone says how to clear its deployment state.
    let api = server(
        "PUT",
        &format!("{RULES_PATH}/77"),
        ResponseTemplate::new(404),
    );
    let error = deploy(&api, Operation::Update, "77", rule).unwrap_err();
    let gone = reason(
        &error,
        "sentinel_one_rule_not_found",
        DeployScope::Rule,
        Some(404),
    );
    assert!(gone.contains("remove its sentinel_one entry"));
}

#[test]
fn the_deployer_creates_replaces_and_deletes_by_the_recorded_id() {
    let created = ResponseTemplate::new(200).set_body_json(json!({"data": {"id": " 9001 "}}));
    let api = server("POST", RULES_PATH, created);
    assert_eq!(
        deploy(&api, Operation::Create, "", b"{}")
            .unwrap()
            .as_deref(),
        Some("9001")
    );
    let replaced = ResponseTemplate::new(200).set_body_json(json!({"data": {"id": 9001}}));
    let api = server("PUT", &format!("{RULES_PATH}/9001"), replaced);
    assert_eq!(
        deploy(&api, Operation::Disable, "9001", b"{}")
            .unwrap()
            .as_deref(),
        Some("9001")
    );
    let api = server("DELETE", RULES_PATH, ResponseTemplate::new(200));
    assert_eq!(deploy(&api, Operation::Delete, "9001", b"").unwrap(), None);
    let deletes = wait(api.received_requests()).unwrap();
    let [delete] = deletes.as_slice() else {
        panic!("{deletes:?}")
    };
    let filter: serde_json::Value = serde_json::from_slice(&delete.body).unwrap();
    assert_eq!(filter["filter"]["ids"], json!([9001]), "{filter}");
    // Nothing is sent for an id that is not a number or a body that is not JSON.
    let api = server("DELETE", RULES_PATH, ResponseTemplate::new(200));
    let error = deploy(&api, Operation::Delete, "ru-1", b"").unwrap_err();
    assert_eq!(
        reason(&error, "deployment_id_invalid", DeployScope::Rule, None),
        "deployment id \"ru-1\" is not a number"
    );
    let error = deploy(&api, Operation::Create, "", b"{not json")
        .unwrap_err()
        .into_connector();
    let ConnectorError::Setup { message, .. } = &error else {
        panic!("{error:?}")
    };
    assert!(
        message.starts_with("the compiled rule is not JSON"),
        "{message}"
    );
    assert!(wait(api.received_requests()).unwrap().is_empty());
}

#[test]
fn a_query_check_the_console_cannot_run_is_refused_or_unforeseen() {
    let now = jiff::Timestamp::from_second(1_800_000_000).unwrap();
    let refused = ResponseTemplate::new(400)
        .set_body_json(json!({"errors": [{"detail": "unknown field src.x"}]}));
    let api = server("POST", QUERY_PATH, refused);
    let outcome = with_tenant(&api, |cx| {
        wait(SentinelOne.validate_query(cx, "src.x = 1", now))
    });
    assert_eq!(
        outcome.unwrap(),
        QueryValidation::Refused("unknown field src.x".into())
    );

    let api = server(
        "POST",
        QUERY_PATH,
        ResponseTemplate::new(500).set_body_string("down"),
    );
    let outcome = with_tenant(&api, |cx| {
        wait(SentinelOne.validate_query(cx, "src.x = 1", now))
    });
    let Err(SentinelOneError::Unforeseen { status, context }) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!((status, context.as_str()), (500, "down"));
}

#[test]
fn a_powerquery_answered_without_json_or_without_an_id_is_refused() {
    let window = TimeWindow::check(jiff::Timestamp::from_second(1_800_000_000).unwrap());
    let request = QueryRequest::new("src.x = 1", "powerquery", window);
    for (reply, expected) in [
        (
            ResponseTemplate::new(200).set_body_string("<html><title>Gateway</title></html>"),
            "SentinelOne did not answer the PowerQuery on s1 with JSON",
        ),
        (
            ResponseTemplate::new(200).set_body_json(json!({"data": {"status": "RUNNING"}})),
            "SentinelOne returned no query id on s1",
        ),
    ] {
        let api = server("POST", QUERY_PATH, reply);
        let error = with_tenant(&api, |cx| wait(SentinelOne.run(cx, &request))).unwrap_err();
        let ConnectorError::Refused { message, .. } = &error else {
            panic!("{error:?}")
        };
        assert_eq!(message, expected);
    }
}

#[test]
fn a_2xx_json_answer_an_error_quotes_never_shows_the_token() {
    // The console echoes the request's `Authorization` in a 2xx JSON answer
    // the connector cannot use: each error quoting it shows `***`.
    let echo = |status: u16| {
        move |request: &wiremock::Request| {
            let seen = request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            ResponseTemplate::new(status).set_body_json(json!({"data": {"seen": seen}}))
        }
    };
    let api = wait(async {
        let api = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(RULES_PATH))
            .respond_with(echo(200))
            .mount(&api)
            .await;
        Mock::given(method("POST"))
            .and(path(QUERY_PATH))
            .respond_with(echo(201))
            .mount(&api)
            .await;
        api
    });
    let created = deploy(&api, Operation::Create, "r1", br#"{"data": {}}"#).unwrap_err();
    let shown = format!("{created} {created:?} {}", created.failure.message);
    assert!(shown.contains("ApiToken ***"), "{shown}");
    assert!(!shown.contains(TOKEN), "{shown}");
    let now = jiff::Timestamp::from_second(1_800_000_000).unwrap();
    let checked = with_tenant(&api, |cx| {
        wait(SentinelOne.validate_query(cx, "src.x = 1", now))
    });
    let Err(SentinelOneError::Unforeseen { status, context }) = checked else {
        panic!("{checked:?}")
    };
    assert_eq!(status, 201);
    assert!(context.contains("ApiToken ***"), "{context}");
    assert!(!context.contains(TOKEN), "{context}");
}

/// A PowerQuery answered 401 is the API token's refusal, not the query's:
/// `validate query --live` fails the tenant on it (#1658, E8). Any other
/// refusal stays the query's.
#[test]
fn a_powerquery_answered_401_is_the_tokens_refusal() {
    let window = TimeWindow::check(jiff::Timestamp::from_second(1_800_000_000).unwrap());
    let request = QueryRequest::new("src.x = 1", "powerquery", window);
    let reply = ResponseTemplate::new(401)
        .set_body_json(json!({"errors": [{"title": "Authentication Failed"}]}));
    let api = server("POST", QUERY_PATH, reply);
    let error = with_tenant(&api, |cx| wait(SentinelOne.run(cx, &request))).unwrap_err();
    let ConnectorError::Authentication { message, .. } = &error else {
        panic!("{error:?}")
    };
    assert_eq!(
        message,
        "SentinelOne refused the API token on s1 (HTTP 401): Authentication Failed"
    );
    let reply = ResponseTemplate::new(400)
        .set_body_json(json!({"errors": [{"detail": "unknown field src.x"}]}));
    let api = server("POST", QUERY_PATH, reply);
    let error = with_tenant(&api, |cx| wait(SentinelOne.run(cx, &request))).unwrap_err();
    assert!(matches!(error, ConnectorError::Refused { .. }), "{error:?}");
}
