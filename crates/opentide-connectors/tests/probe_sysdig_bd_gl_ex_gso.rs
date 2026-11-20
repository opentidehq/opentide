//! `Prober::probe` (`opentide doctor --live`, #1658) of Sysdig, Graylog,
//! Exabeam and Google SecOps, and Bitdefender's lack of one. Each tenant is a
//! wiremock server (or a closed loopback port) with literal test credentials;
//! no real host is contacted and no Bitdefender variable is read.
#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use opentide_connectors::connector::{DeployError, Platform, TenantContext};
use opentide_connectors::credentials::Mode;
use opentide_connectors::{
    Environment, HttpClient, HttpSettings, Tenant, exabeam, graylog, sysdig,
};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A literal credential no tenant knows; it must never reach a message.
const SECRET: &str = "stand-in-credential-0123456789";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

/// What the platform's probe said for the tenant `setup` describes, reached
/// with `settings`.
async fn probe(
    platform: &dyn Platform,
    name: &str,
    setup: &str,
    env: &Environment,
    settings: &HttpSettings,
) -> Result<(), DeployError> {
    let setup: toml::Table = toml::from_str(setup).unwrap();
    let tenant =
        Tenant::from_setup(platform.id(), name, &setup, env, Mode::Counting, settings).unwrap();
    let http = HttpClient::new(&tenant.label, &tenant.http, env, None).unwrap();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    platform.prober().unwrap().probe(cx).await
}

/// The code a failed probe carries, and that no message holds the secret.
fn code(result: Result<(), DeployError>) -> &'static str {
    let error = result.unwrap_err();
    assert!(!error.to_string().contains(SECRET), "{error}");
    error.failure.code
}

/// `(method, path)` of each request the server took, in order.
async fn taken(server: &MockServer) -> Vec<(String, String)> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| (request.method.to_string(), request.url.path().to_owned()))
        .collect()
}

fn pair(verb: &str, route: &str) -> (String, String) {
    (verb.to_owned(), route.to_owned())
}

fn closed() -> String {
    "http://127.0.0.1:1".to_owned()
}

async fn answering(server: &MockServer, verb: &str, route: &str, status: u16) {
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(ResponseTemplate::new(status).set_body_json(json!({})))
        .mount(server)
        .await;
}

// ---- Sysdig: no sign-in, `GET /api/v2/policies` ----

fn sysdig_probe(url: &str) -> impl std::future::Future<Output = Result<(), DeployError>> {
    let setup = format!("url = \"{url}\"\napi_token = \"$SYSDIG_TEST_TOKEN\"\n");
    let env = Environment::default().with("SYSDIG_TEST_TOKEN", SECRET);
    async move {
        probe(
            &sysdig::Sysdig,
            "soc",
            &setup,
            &env,
            &sysdig::http_defaults(),
        )
        .await
    }
}

#[test]
fn sysdig_reads_the_policies_and_writes_nothing() {
    runtime().block_on(async {
        let server = MockServer::start().await;
        answering(&server, "GET", "/api/v2/policies", 200).await;
        sysdig_probe(&server.uri()).await.unwrap();
        assert_eq!(taken(&server).await, [pair("GET", "/api/v2/policies")]);
    });
}

#[test]
fn sysdig_refusing_the_token_is_authentication_failed_and_a_5xx_is_tenant_refused() {
    runtime().block_on(async {
        for (status, expected) in [
            (401, "authentication_failed"),
            (403, "authentication_failed"),
            (500, "tenant_refused"),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/v2/policies"))
                .respond_with(ResponseTemplate::new(status).set_body_string("leaked-answer-text"))
                .mount(&server)
                .await;
            let failed = sysdig_probe(&server.uri()).await.unwrap_err();
            assert_eq!(failed.failure.code, expected, "HTTP {status}");
            // The answer's body is not quoted.
            assert!(
                !failed.to_string().contains("leaked-answer-text"),
                "{failed}"
            );
        }
    });
}

#[test]
fn sysdig_on_a_closed_port_is_unreachable() {
    runtime().block_on(async {
        assert_eq!(code(sysdig_probe(&closed()).await), "tenant_unreachable");
    });
}

#[test]
fn sysdig_with_an_unset_variable_sends_nothing() {
    runtime().block_on(async {
        let server = MockServer::start().await;
        let setup = format!(
            "url = \"{}\"\napi_token = \"$SYSDIG_TEST_UNSET\"\n",
            server.uri()
        );
        let result = probe(
            &sysdig::Sysdig,
            "soc",
            &setup,
            &Environment::default(),
            &sysdig::http_defaults(),
        )
        .await;
        assert_eq!(code(result), "credential_unset");
        assert!(taken(&server).await.is_empty());
    });
}

// ---- Graylog: no sign-in, `GET /api/system` ----

fn graylog_probe(url: &str) -> impl std::future::Future<Output = Result<(), DeployError>> {
    let setup = format!("url = \"{url}\"\ntoken = \"$GRAYLOG_TEST_TOKEN\"\n");
    let env = Environment::default().with("GRAYLOG_TEST_TOKEN", SECRET);
    async move {
        probe(
            &graylog::Graylog::new(),
            "prod",
            &setup,
            &env,
            &graylog::http_defaults(),
        )
        .await
    }
}

#[test]
fn graylog_reads_the_system_and_judges_only_the_status() {
    runtime().block_on(async {
        // The answer holds no version: a deploy would refuse it, a probe
        // only asks whether the tenant answers with these credentials.
        let server = MockServer::start().await;
        answering(&server, "GET", "/api/system", 200).await;
        graylog_probe(&server.uri()).await.unwrap();
        assert_eq!(taken(&server).await, [pair("GET", "/api/system")]);
    });
}

#[test]
fn graylog_refusing_the_token_fails_authentication_and_a_5xx_is_refused() {
    runtime().block_on(async {
        for (status, expected) in [
            (401, "authentication_failed"),
            (403, "authentication_failed"),
            (500, "tenant_refused"),
        ] {
            let server = MockServer::start().await;
            answering(&server, "GET", "/api/system", status).await;
            assert_eq!(
                code(graylog_probe(&server.uri()).await),
                expected,
                "{status}"
            );
        }
    });
}

#[test]
fn graylog_on_a_closed_port_is_unreachable() {
    runtime().block_on(async {
        assert_eq!(code(graylog_probe(&closed()).await), "tenant_unreachable");
    });
}

// ---- Exabeam: client-credentials sign-in, then `GET /correlation-rules/v2/rules` ----

const TOKEN_PATH: &str = "/auth/v1/token";
const RULES_PATH: &str = "/correlation-rules/v2/rules";

fn exabeam_probe(url: &str) -> impl std::future::Future<Output = Result<(), DeployError>> {
    let setup = format!(
        "region = \"eu\"\napi_url = \"{url}\"\nclient_id = \"$EXABEAM_TEST_ID\"\n\
         client_secret = \"$EXABEAM_TEST_SECRET\"\n"
    );
    let env = Environment::default()
        .with("EXABEAM_TEST_ID", "client-id")
        .with("EXABEAM_TEST_SECRET", SECRET);
    async move {
        probe(
            &exabeam::Exabeam::new(),
            "eu",
            &setup,
            &env,
            &exabeam::http_defaults(),
        )
        .await
    }
}

async fn exabeam_token(server: &MockServer, status: u16) {
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(status).set_body_json(
            json!({"access_token": "stand-in-bearer-0123456789", "expires_in": 3600}),
        ))
        .mount(server)
        .await;
}

#[test]
fn exabeam_signs_in_then_lists_rules_and_writes_nothing() {
    runtime().block_on(async {
        let server = MockServer::start().await;
        exabeam_token(&server, 200).await;
        answering(&server, "GET", RULES_PATH, 200).await;
        exabeam_probe(&server.uri()).await.unwrap();
        // One sign-in, first; then the one read.
        assert_eq!(
            taken(&server).await,
            [pair("POST", TOKEN_PATH), pair("GET", RULES_PATH)]
        );
    });
}

#[test]
fn exabeam_refusing_the_sign_in_fails_before_any_read() {
    runtime().block_on(async {
        let server = MockServer::start().await;
        exabeam_token(&server, 401).await;
        answering(&server, "GET", RULES_PATH, 200).await;
        assert_eq!(
            code(exabeam_probe(&server.uri()).await),
            "authentication_failed"
        );
        assert_eq!(taken(&server).await, [pair("POST", TOKEN_PATH)]);
    });
}

#[test]
fn exabeam_refusing_the_read_is_authentication_or_refused() {
    runtime().block_on(async {
        for (status, expected) in [
            (401, "authentication_failed"),
            (403, "authentication_failed"),
            (409, "tenant_refused"),
            (500, "tenant_refused"),
        ] {
            let server = MockServer::start().await;
            exabeam_token(&server, 200).await;
            answering(&server, "GET", RULES_PATH, status).await;
            assert_eq!(
                code(exabeam_probe(&server.uri()).await),
                expected,
                "{status}"
            );
        }
    });
}

#[test]
fn exabeam_on_a_closed_port_is_unreachable() {
    runtime().block_on(async {
        assert_eq!(code(exabeam_probe(&closed()).await), "tenant_unreachable");
    });
}

// ---- Google SecOps: ADC sign-in, then `GET rules?pageSize=1` ----

const RESOURCE: &str = "projects/acme/locations/eu/instances/i-1";

/// The tenant at `api`, its Application Default Credentials a file whose
/// token endpoint is `token_uri`.
async fn secops_probe(api: &str, token_uri: &str) -> Result<(), DeployError> {
    let directory = tempfile::tempdir().unwrap();
    let adc = directory.path().join("adc.json");
    let document = json!({"type": "authorized_user", "client_id": "c", "client_secret": SECRET,
        "refresh_token": "stand-in-refresh-0123456789", "token_uri": token_uri});
    std::fs::write(&adc, document.to_string()).unwrap();
    let setup = format!(
        "project = \"acme\"\nlocation = \"eu\"\ninstance = \"i-1\"\nendpoint = \"{api}\"\n"
    );
    let env = Environment::from_pairs([("GOOGLE_APPLICATION_CREDENTIALS", adc.to_str().unwrap())]);
    let connector = opentide_connectors::google_secops::GoogleSecops::new(env.clone());
    probe(
        &connector,
        "secops-eu",
        &setup,
        &env,
        &opentide_connectors::google_secops::http_defaults(),
    )
    .await
}

async fn secops_server(token_status: u16, rules_status: u16) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(token_status)
                .set_body_json(json!({"access_token": "ya29.stand-in", "expires_in": 3600})),
        )
        .mount(&server)
        .await;
    answering(
        &server,
        "GET",
        &format!("/v1/{RESOURCE}/rules"),
        rules_status,
    )
    .await;
    server
}

#[test]
fn google_secops_signs_in_then_lists_one_rule_and_writes_nothing() {
    runtime().block_on(async {
        let server = secops_server(200, 200).await;
        let token = format!("{}/token", server.uri());
        secops_probe(&server.uri(), &token).await.unwrap();
        assert_eq!(
            taken(&server).await,
            [
                pair("POST", "/token"),
                pair("GET", &format!("/v1/{RESOURCE}/rules"))
            ]
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests[1].url.query(), Some("pageSize=1"));
    });
}

#[test]
fn google_secops_refusing_the_sign_in_fails_before_any_read() {
    runtime().block_on(async {
        let server = secops_server(401, 200).await;
        let token = format!("{}/token", server.uri());
        let result = secops_probe(&server.uri(), &token).await;
        assert_eq!(code(result), "authentication_failed");
        assert_eq!(taken(&server).await, [pair("POST", "/token")]);
    });
}

#[test]
fn google_secops_refusing_the_read_is_authentication_or_refused() {
    runtime().block_on(async {
        for (status, expected) in [
            (401, "authentication_failed"),
            (403, "authentication_failed"),
            (500, "tenant_refused"),
        ] {
            let server = secops_server(200, status).await;
            let token = format!("{}/token", server.uri());
            let result = secops_probe(&server.uri(), &token).await;
            assert_eq!(code(result), expected, "{status}");
        }
    });
}

#[test]
fn google_secops_on_a_closed_port_is_unreachable() {
    runtime().block_on(async {
        let server = secops_server(200, 200).await;
        let token = format!("{}/token", server.uri());
        let result = secops_probe(&closed(), &token).await;
        assert_eq!(code(result), "tenant_unreachable");
    });
}

// ---- Bitdefender: no Prober ----

#[test]
fn bitdefender_has_no_prober_because_its_client_speaks_no_read() {
    // GravityZone's client sends createCustomRule, updateCustomRule and
    // deleteCustomRule only; a probe would have to invent a request, or pass
    // without one. doctor reports the platform as not checked instead.
    assert!(
        opentide_connectors::bitdefender::Bitdefender
            .prober()
            .is_none()
    );
}
