//! `opentide doctor --live`'s connectivity probes (#1658) of Splunk,
//! SentinelOne, CrowdStrike and HarfangLab, against stand-ins only: a
//! hand-written cassette replayed by the replaying proxy for the platforms
//! whose host is fixed (Splunk's `https://<url>:<port>`, CrowdStrike's
//! cloud), a wiremock server on the loopback for the others. A refused
//! connection is a loopback port nothing listens on. No real tenant is
//! contacted.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod support;

use std::time::Duration;

use opentide_cassette::cassette::{Request, Response};
use opentide_cassette::{Body, Cassette, Interaction};
use opentide_connectors::connector::{DeployError, TenantContext};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::runtime::block_on;
use opentide_connectors::{
    Environment, HttpClient, HttpSettings, Platform, Registry, Tenant, crowdstrike, harfanglab,
    sentinel_one, splunk,
};
use support::Replayed;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "stand-in-token-0123456789";

/// The probe of *platform* on the context *cx*, through the registry as
/// `opentide doctor --live` reaches it.
async fn probe(platform: &str, cx: TenantContext<'_>) -> Result<(), DeployError> {
    let registry = opentide_connectors::builtin();
    let platform: &dyn Platform = registry.get(platform).unwrap();
    platform.prober().unwrap().probe(cx).await
}

fn code(result: Result<(), DeployError>) -> &'static str {
    result.unwrap_err().failure.code
}

fn request(method: &str, url: &str, headers: &[(&str, &str)], body: &str) -> Request {
    Request {
        method: method.to_owned(),
        url: url.to_owned(),
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        body: Body::Text(body.to_owned()),
    }
}

fn answer(status: u16, content_type: &str, body: &str) -> Response {
    Response {
        status,
        headers: vec![("content-type".to_owned(), content_type.to_owned())],
        body: Body::Text(body.to_owned()),
    }
}

/// A tenant of *platform* and its client, on the environment *env*.
fn tenant(
    platform: &str,
    setup: &str,
    env: &Environment,
    proxy: Option<&str>,
) -> (Tenant, HttpClient) {
    let setup: toml::Table = toml::from_str(setup).unwrap();
    let tenant = Tenant::from_setup(
        platform,
        "lab",
        &setup,
        env,
        Resolve::Required,
        &opentide_connectors::http_settings(platform, Duration::from_secs(120)),
    )
    .unwrap();
    let http = HttpClient::new(&tenant.label, &tenant.http, env, proxy).unwrap();
    (tenant, http)
}

fn cx<'a>(
    tenant: &'a Tenant,
    http: &'a HttpClient,
    cancel: &'a CancellationToken,
) -> TenantContext<'a> {
    TenantContext {
        tenant,
        http,
        cancel,
    }
}

// ---- HarfangLab: a token, one read of the Sigma rules ----

const HARFANGLAB: &str = r#"
url = "URL"
api_token = "$HARFANGLAB_API_TOKEN"
"#;

fn harfanglab_at(url: &str) -> (Tenant, HttpClient) {
    let env = Environment::from_pairs([("HARFANGLAB_API_TOKEN", TOKEN)]);
    tenant(
        harfanglab::PLATFORM,
        &HARFANGLAB.replace("URL", url),
        &env,
        None,
    )
}

async fn sigma(server: &MockServer, status: u16) {
    Mock::given(method("GET"))
        .and(path("/api/data/threat_intelligence/SigmaRule/"))
        .and(query_param("limit", "1"))
        .and(header("authorization", format!("Token {TOKEN}").as_str()))
        .respond_with(ResponseTemplate::new(status).set_body_string("{\"results\": []}"))
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn harfanglab_answering_the_read_is_reached() {
    let server = MockServer::start().await;
    sigma(&server, 200).await;
    let (tenant, http) = harfanglab_at(&server.uri());
    let cancel = CancellationToken::new();
    probe(harfanglab::PLATFORM, cx(&tenant, &http, &cancel))
        .await
        .unwrap();
    // One read: no write was sent.
    let seen = server.received_requests().await.unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].method.as_str(), "GET");
}

#[tokio::test]
async fn harfanglab_refusing_the_token_is_authentication_failed() {
    for status in [401, 403] {
        let server = MockServer::start().await;
        sigma(&server, status).await;
        let (tenant, http) = harfanglab_at(&server.uri());
        let cancel = CancellationToken::new();
        let failed = probe(harfanglab::PLATFORM, cx(&tenant, &http, &cancel)).await;
        let failed = failed.unwrap_err();
        assert_eq!(failed.failure.code, "authentication_failed", "{status}");
        // The message names the tenant and never the token.
        assert!(failed.to_string().contains("'lab'"), "{failed}");
        assert!(!failed.to_string().contains(TOKEN), "{failed}");
    }
}

#[tokio::test]
async fn harfanglab_answering_a_server_error_is_refused() {
    let server = MockServer::start().await;
    sigma(&server, 500).await;
    let (tenant, http) = harfanglab_at(&server.uri());
    let cancel = CancellationToken::new();
    assert_eq!(
        code(probe(harfanglab::PLATFORM, cx(&tenant, &http, &cancel)).await),
        "tenant_refused"
    );
}

#[tokio::test]
async fn harfanglab_that_does_not_answer_in_time_is_a_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;
    let env = Environment::from_pairs([("HARFANGLAB_API_TOKEN", TOKEN)]);
    let setup: toml::Table = toml::from_str(&HARFANGLAB.replace("URL", &server.uri())).unwrap();
    let settings = HttpSettings {
        timeout: Duration::from_secs(1),
        ..opentide_connectors::http_settings(harfanglab::PLATFORM, Duration::from_secs(1))
    };
    let tenant = Tenant::from_setup(
        harfanglab::PLATFORM,
        "lab",
        &setup,
        &env,
        Resolve::Required,
        &settings,
    )
    .unwrap();
    let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
    let cancel = CancellationToken::new();
    assert_eq!(
        code(probe(harfanglab::PLATFORM, cx(&tenant, &http, &cancel)).await),
        "tenant_timeout"
    );
}

#[tokio::test]
async fn a_tenant_nothing_listens_for_is_unreachable() {
    for (platform, setup) in [
        (
            harfanglab::PLATFORM,
            HARFANGLAB.replace("URL", "http://127.0.0.1:1"),
        ),
        (
            sentinel_one::PLATFORM,
            SENTINEL_ONE.replace("URL", "http://127.0.0.1:1"),
        ),
        // Splunk's address is always https://<url>:<port>.
        (splunk::PLATFORM, SPLUNK_LOOPBACK.to_owned()),
    ] {
        let env = Environment::from_pairs([
            ("HARFANGLAB_API_TOKEN", TOKEN),
            ("SENTINEL_ONE_API_TOKEN", TOKEN),
            ("SPLUNK_TOKEN", TOKEN),
        ]);
        let (tenant, http) = tenant(platform, &setup, &env, None);
        let cancel = CancellationToken::new();
        assert_eq!(
            code(probe(platform, cx(&tenant, &http, &cancel)).await),
            "tenant_unreachable",
            "{platform}"
        );
    }
}

#[tokio::test]
async fn a_credential_that_is_not_set_is_credential_unset_before_any_request() {
    let server = MockServer::start().await;
    let env = Environment::default();
    let setup: toml::Table = toml::from_str(&HARFANGLAB.replace("URL", &server.uri())).unwrap();
    // `Resolve::Counting` leaves an unset variable for the connector to name.
    let tenant = Tenant::from_setup(
        harfanglab::PLATFORM,
        "lab",
        &setup,
        &env,
        Resolve::Counting,
        &HttpSettings::default(),
    )
    .unwrap();
    let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
    let cancel = CancellationToken::new();
    assert_eq!(
        code(probe(harfanglab::PLATFORM, cx(&tenant, &http, &cancel)).await),
        "credential_unset"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

// ---- SentinelOne: an API token, one read of the STAR rules ----

const SENTINEL_ONE: &str = r#"
url = "URL"
api_token = "$SENTINEL_ONE_API_TOKEN"
account_id = "1234567890"
"#;

async fn star_rules(server: &MockServer, status: u16) {
    Mock::given(method("GET"))
        .and(path("/web/api/v2.1/cloud-detection/rules"))
        .and(query_param("limit", "1"))
        .and(query_param("accountIds", "1234567890"))
        .and(header(
            "authorization",
            format!("ApiToken {TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(status).set_body_string("{\"data\": []}"))
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn sentinel_one_answering_the_read_is_reached() {
    let server = MockServer::start().await;
    star_rules(&server, 200).await;
    let env = Environment::from_pairs([("SENTINEL_ONE_API_TOKEN", TOKEN)]);
    let (tenant, http) = tenant(
        sentinel_one::PLATFORM,
        &SENTINEL_ONE.replace("URL", &server.uri()),
        &env,
        None,
    );
    let cancel = CancellationToken::new();
    probe(sentinel_one::PLATFORM, cx(&tenant, &http, &cancel))
        .await
        .unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn sentinel_one_refusing_the_token_is_authentication_failed() {
    let server = MockServer::start().await;
    star_rules(&server, 401).await;
    let env = Environment::from_pairs([("SENTINEL_ONE_API_TOKEN", TOKEN)]);
    let (tenant, http) = tenant(
        sentinel_one::PLATFORM,
        &SENTINEL_ONE.replace("URL", &server.uri()),
        &env,
        None,
    );
    let cancel = CancellationToken::new();
    let failed = probe(sentinel_one::PLATFORM, cx(&tenant, &http, &cancel)).await;
    let failed = failed.unwrap_err();
    assert_eq!(failed.failure.code, "authentication_failed");
    assert!(!failed.to_string().contains(TOKEN), "{failed}");
}

// ---- Splunk: a token, one read of server/info on https://<url>:<port> ----

const SPLUNK: &str = r#"
ssl = true
url = "splunk.invalid"
port = 8089
app = "search"
token = "$SPLUNK_TOKEN"
"#;

/// A tenant on the loopback's closed port 1: https://127.0.0.1:1.
const SPLUNK_LOOPBACK: &str = r#"
ssl = false
url = "127.0.0.1"
port = 1
token = "$SPLUNK_TOKEN"
"#;

fn splunk_replay(status: u16) -> Replayed {
    let info = request(
        "GET",
        "https://splunk.invalid:8089/services/server/info",
        &[("authorization", "Splunk REDACTED")],
        "",
    );
    let cassette = Cassette::new(
        "probe",
        vec![],
        vec![Interaction {
            request: info,
            response: answer(
                status,
                "text/xml",
                "<feed xmlns=\"http://www.w3.org/2005/Atom\"/>",
            ),
        }],
    );
    Replayed::start_with(
        cassette,
        splunk::PLATFORM,
        SPLUNK,
        "SPLUNK_TOKEN",
        &splunk::http_settings(Duration::from_secs(120)),
    )
}

#[test]
fn splunk_answering_server_info_is_reached() {
    let replayed = splunk_replay(200);
    block_on(probe(splunk::PLATFORM, replayed.cx()))
        .unwrap()
        .unwrap();
    assert!(replayed.verify().is_empty(), "{:?}", replayed.verify());
    assert_eq!(replayed.proxy.requests().len(), 1);
}

#[test]
fn splunk_refusing_the_token_is_authentication_failed() {
    let replayed = splunk_replay(401);
    let failed = block_on(probe(splunk::PLATFORM, replayed.cx())).unwrap();
    assert_eq!(code(failed), "authentication_failed");
}

// ---- CrowdStrike: the OAuth2 token first, then one read ----

const CROWDSTRIKE: &str = r#"
ssl = true
api = "EU-1"
client_id = "opentide-client"
client_secret = "$CROWDSTRIKE_CLIENT_SECRET"
"#;

const API: &str = "https://api.eu-1.crowdstrike.com";

fn token_call(status: u16) -> Interaction {
    Interaction {
        request: request(
            "POST",
            &format!("{API}/oauth2/token"),
            &[("content-type", "application/x-www-form-urlencoded")],
            "client_id=opentide-client&client_secret=REDACTED",
        ),
        response: answer(
            status,
            "application/json",
            r#"{"access_token": "REDACTED", "token_type": "REDACTED", "expires_in": 1799}"#,
        ),
    }
}

fn rules_call(status: u16) -> Interaction {
    Interaction {
        request: request(
            "GET",
            &format!("{API}/correlation-rules/queries/rules/v1?limit=1"),
            &[
                ("accept", "application/json"),
                ("authorization", "Bearer REDACTED"),
                ("content-type", "application/json"),
            ],
            "",
        ),
        response: answer(status, "application/json", r#"{"resources": []}"#),
    }
}

fn crowdstrike_replay(interactions: Vec<Interaction>) -> Replayed {
    Replayed::start_with(
        Cassette::new("probe", vec![], interactions),
        crowdstrike::PLATFORM,
        CROWDSTRIKE,
        "CROWDSTRIKE_CLIENT_SECRET",
        &crowdstrike::http_defaults(),
    )
}

fn methods(replayed: &Replayed) -> Vec<String> {
    replayed
        .proxy
        .requests()
        .into_iter()
        .map(|sent| {
            format!(
                "{} {}",
                sent.method,
                sent.url.rsplit('/').next().unwrap_or("")
            )
        })
        .collect()
}

#[test]
fn crowdstrike_signs_in_first_and_then_reads() {
    let replayed = crowdstrike_replay(vec![token_call(201), rules_call(200)]);
    block_on(probe(crowdstrike::PLATFORM, replayed.cx()))
        .unwrap()
        .unwrap();
    assert!(replayed.verify().is_empty(), "{:?}", replayed.verify());
    assert_eq!(methods(&replayed), ["POST token", "GET v1?limit=1"]);
}

#[test]
fn crowdstrike_whose_token_endpoint_refuses_the_client_is_authentication_failed() {
    let replayed = crowdstrike_replay(vec![token_call(401)]);
    let failed = block_on(probe(crowdstrike::PLATFORM, replayed.cx())).unwrap();
    assert_eq!(code(failed), "authentication_failed");
    // The read was never sent without a token.
    assert_eq!(methods(&replayed), ["POST token"]);
}

#[test]
fn crowdstrike_token_endpoint_statuses_are_told_apart() {
    // Only 400, 401 and 403 are the credentials' fault; a rate limit or a
    // failing endpoint is not (#1658, D5).
    for (status, expected) in [
        (400, "authentication_failed"),
        (403, "authentication_failed"),
        (429, "tenant_refused"),
        (500, "tenant_refused"),
        (503, "tenant_gateway"),
    ] {
        let replayed = crowdstrike_replay(vec![token_call(status)]);
        let failed = block_on(probe(crowdstrike::PLATFORM, replayed.cx())).unwrap();
        assert_eq!(code(failed), expected, "token endpoint answered {status}");
        // Nothing was read without a token, and the sign-in was not repeated.
        assert_eq!(methods(&replayed), ["POST token"], "{status}");
    }
}

#[test]
fn crowdstrike_refusing_the_token_on_the_read_is_authentication_failed() {
    // The 401 rule: one new sign-in and one resend, then the refusal.
    let replayed = crowdstrike_replay(vec![
        token_call(201),
        rules_call(401),
        token_call(201),
        rules_call(401),
    ]);
    let failed = block_on(probe(crowdstrike::PLATFORM, replayed.cx())).unwrap();
    assert_eq!(code(failed), "authentication_failed");
    assert_eq!(methods(&replayed).len(), 4);
}

#[test]
fn crowdstrike_behind_a_proxy_nothing_listens_for_is_unreachable() {
    let env = Environment::from_pairs([("CROWDSTRIKE_CLIENT_SECRET", TOKEN)]);
    let (tenant, http) = tenant(
        crowdstrike::PLATFORM,
        CROWDSTRIKE,
        &env,
        Some("http://127.0.0.1:1"),
    );
    let cancel = CancellationToken::new();
    let failed = block_on(probe(crowdstrike::PLATFORM, cx(&tenant, &http, &cancel))).unwrap();
    assert_eq!(code(failed), "tenant_unreachable");
}

#[test]
fn the_four_platforms_have_a_prober() {
    let registry: Registry = opentide_connectors::builtin();
    for id in ["splunk", "sentinel_one", "crowdstrike", "harfanglab"] {
        assert!(registry.get(id).unwrap().prober().is_some(), "{id}");
    }
}
