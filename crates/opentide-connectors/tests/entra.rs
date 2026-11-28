//! Entra ID's client-credentials sign-in (`opentide_connectors::entra`)
//! against a stand-in identity platform (wiremock): the one request it
//! sends, the secret intact on the wire and absent everywhere else, Entra's
//! refusals, each tenant's own client and token.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::sync::{Arc, Mutex};

use opentide_connectors::connector::TenantContext;
use opentide_connectors::credentials::Mode;
use opentide_connectors::entra::{self, CredentialNames};
use opentide_connectors::token::TokenCache;
use opentide_connectors::{
    ConnectorError, Environment, HttpClient, HttpSettings, Tenant, microsoft_defender, sentinel,
};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// A client secret with every character a form must escape, and the `~` and
/// `.` Entra's generated secrets hold.
const SECRET: &str = "aB3~Q8_x.y+z/w=v&u%t s~9";
const TENANT_ID: &str = "11111111-2222-4333-8444-555555555555";

const NAMES: CredentialNames = sentinel::CREDENTIALS;
const ARM: &str = sentinel::ARM_SCOPE;

struct Stand {
    tenant: Tenant,
    http: HttpClient,
    cancel: CancellationToken,
}

impl Stand {
    fn new(name: &str, tenant_id: &str, secret: &str, proxy: Option<&str>) -> Self {
        Self::with_settings(name, tenant_id, secret, proxy, &HttpSettings::default())
    }

    /// A Sentinel tenant on *settings* (its retry policy).
    fn with_settings(
        name: &str,
        tenant_id: &str,
        secret: &str,
        proxy: Option<&str>,
        settings: &HttpSettings,
    ) -> Self {
        let setup: opentide_core::json::Object = toml::from_str(
            "azure_tenant_id = \"$TENANT_ID\"\nazure_client_id = \"app-id\"\n\
             azure_client_secret = \"$SECRET\"\n",
        )
        .unwrap();
        let env = Environment::default()
            .with("TENANT_ID", tenant_id)
            .with("SECRET", secret);
        let tenant = Tenant::from_setup(
            sentinel::PLATFORM,
            name,
            &setup,
            &env,
            Mode::Required,
            settings,
        )
        .unwrap();
        let http = HttpClient::new(&tenant.label, &tenant.http, &env, proxy).unwrap();
        Self {
            tenant,
            http,
            cancel: CancellationToken::new(),
        }
    }

    fn cx(&self) -> TenantContext<'_> {
        TenantContext {
            tenant: &self.tenant,
            http: &self.http,
            cancel: &self.cancel,
        }
    }
}

fn token_path(tenant_id: &str) -> String {
    format!("/{tenant_id}/oauth2/v2.0/token")
}

async fn issuing(server: &MockServer, tenant_id: &str, body: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path(token_path(tenant_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// *cx*'s token for *scope* from *tokens*, signing in at *authority*.
async fn token(
    tokens: &TokenCache,
    cx: TenantContext<'_>,
    authority: &str,
    scope: &'static str,
) -> String {
    tokens
        .token(&cx.tenant.label, scope, || {
            entra::sign_in_at(cx, authority, NAMES, scope)
        })
        .await
        .unwrap()
        .expose()
        .to_owned()
}

fn form(request: &Request) -> Vec<(String, String)> {
    url::form_urlencoded::parse(&request.body)
        .into_owned()
        .collect()
}

/// Requirements 1 and 4: one form POST to the v2.0 token endpoint with
/// exactly the four fields, the secret decoding back to itself; no
/// discovery, no MSAL headers, no `client_info`.
#[tokio::test]
async fn the_sign_in_is_one_client_credentials_post() {
    logs();
    let server = MockServer::start().await;
    issuing(
        &server,
        TENANT_ID,
        serde_json::json!({"access_token": "tok", "expires_in": "3599", "token_type": "Bearer"}),
    )
    .await;
    let stand = Stand::new("prod", TENANT_ID, SECRET, None);
    let issued = entra::sign_in_at(stand.cx(), &server.uri(), NAMES, ARM)
        .await
        .unwrap();
    assert_eq!(issued.token.expose(), "tok");
    // expires_in written as text (requirement 5).
    assert_eq!(issued.lifetime, Some(std::time::Duration::from_secs(3599)));
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "no discovery GET");
    let request = &received[0];
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.url.path(), token_path(TENANT_ID));
    assert_eq!(request.url.query(), None);
    assert_eq!(
        request.headers.get("content-type").unwrap(),
        "application/x-www-form-urlencoded"
    );
    for (name, _) in &request.headers {
        let name = name.as_str();
        assert!(
            !name.starts_with("x-client-")
                && !name.starts_with("x-ms-")
                && name != "client-request-id"
                && name != "return-client-request-id",
            "{name}"
        );
    }
    assert_eq!(
        form(request),
        [
            ("grant_type".to_owned(), "client_credentials".to_owned()),
            ("client_id".to_owned(), "app-id".to_owned()),
            ("client_secret".to_owned(), SECRET.to_owned()),
            (
                "scope".to_owned(),
                "https://management.azure.com/.default".to_owned()
            ),
        ]
    );
}

/// Requirements 2 and 3: each platform's resource scope and secret names.
#[test]
fn each_resource_has_its_scope_and_each_platform_its_names() {
    assert_eq!(sentinel::ARM_SCOPE, "https://management.azure.com/.default");
    assert_eq!(sentinel::LOGS_SCOPE, "https://api.loganalytics.io/.default");
    assert_eq!(
        microsoft_defender::SCOPE,
        "https://graph.microsoft.com/.default"
    );
    assert_eq!(
        sentinel::CREDENTIALS,
        CredentialNames {
            tenant_id: "azure_tenant_id",
            client_id: "azure_client_id",
            client_secret: "azure_client_secret",
        }
    );
    assert_eq!(
        microsoft_defender::CREDENTIALS,
        CredentialNames {
            tenant_id: "tenant_id",
            client_id: "client_id",
            client_secret: "client_secret",
        }
    );
}

/// Requirement 2: one token per tenant and scope; the ARM token is never
/// the Log Analytics one.
#[tokio::test]
async fn a_token_serves_only_its_scope() {
    logs();
    let server = MockServer::start().await;
    let issued = Arc::new(Mutex::new(0));
    let counter = Arc::clone(&issued);
    Mock::given(method("POST"))
        .and(path(token_path(TENANT_ID)))
        .respond_with(move |request: &Request| {
            *counter.lock().unwrap() += 1;
            let scope = form(request)
                .into_iter()
                .find(|(name, _)| name == "scope")
                .unwrap()
                .1;
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"access_token": format!("for {scope}"), "expires_in": 3599}),
            )
        })
        .mount(&server)
        .await;
    let stand = Stand::new("prod", TENANT_ID, SECRET, None);
    let tokens = TokenCache::new();
    let uri = server.uri();
    assert_eq!(
        token(&tokens, stand.cx(), &uri, ARM).await,
        format!("for {ARM}")
    );
    assert_eq!(
        token(&tokens, stand.cx(), &uri, sentinel::LOGS_SCOPE).await,
        format!("for {}", sentinel::LOGS_SCOPE)
    );
    assert_eq!(
        token(&tokens, stand.cx(), &uri, ARM).await,
        format!("for {ARM}")
    );
    assert_eq!(*issued.lock().unwrap(), 2);
}

/// Collects every tracing event's message and fields.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<String>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Logs {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Fields<'a>(&'a mut String);
        impl tracing::field::Visit for Fields<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={value:?} ", field.name()));
            }
        }
        event.record(&mut Fields(&mut self.0.lock().unwrap()));
    }
}

/// The log of every test of this file: installed as the global subscriber
/// by the first test to start, before any sign-in, so no event is missed
/// (a thread's own default can miss a callsite another test's thread
/// registered first).
fn logs() -> &'static Logs {
    use tracing_subscriber::layer::SubscriberExt as _;
    static LOGS: std::sync::OnceLock<Logs> = std::sync::OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Logs::default();
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(logs.clone()))
            .unwrap();
        logs
    })
}

/// Requirement 7: a wrong tenant id, a wrong secret and an expired secret
/// are authentication failures naming the platform and the tenant, with
/// Entra's description; the secret is in no error, no `Debug` and no log.
#[tokio::test]
async fn entra_refusals_name_the_tenant_and_never_the_secret() {
    let logs = logs();
    let refusals = [
        (
            400,
            "invalid_request",
            "AADSTS90002: Tenant '11111111-2222-4333-8444-555555555555' not found.",
        ),
        (
            401,
            "invalid_client",
            "AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in \
             the request is the client secret value, not the client secret ID.",
        ),
        (
            401,
            "invalid_client",
            "AADSTS7000222: The provided client secret keys for app 'app-id' are expired.",
        ),
        (
            400,
            "invalid_client",
            "AADSTS7000215: Invalid client secret provided.",
        ),
    ];
    for (status, error, description) in refusals {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(token_path(TENANT_ID)))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "error": error,
                    "error_description": description,
                    "error_codes": [7_000_215],
                })),
            )
            .mount(&server)
            .await;
        let stand = Stand::new("prod", TENANT_ID, SECRET, None);
        let refused = entra::sign_in_at(stand.cx(), &server.uri(), NAMES, ARM)
            .await
            .unwrap_err();
        let ConnectorError::Authentication {
            platform,
            tenant,
            message,
            ..
        } = &refused
        else {
            panic!("not an authentication failure: {refused:?}");
        };
        assert_eq!((platform.as_str(), tenant.as_str()), ("sentinel", "prod"));
        assert!(message.contains(description), "{message}");
        for shown in [refused.to_string(), format!("{refused:?}"), refused.text()] {
            assert!(shown.contains("prod"), "{shown}");
            assert!(!shown.contains(SECRET), "{shown}");
        }
    }
    // An answer that echoed the secret: not repeated.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path(TENANT_ID)))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_client",
            "error_description": format!("bad secret {SECRET}"),
        })))
        .mount(&server)
        .await;
    let stand = Stand::new("prod", TENANT_ID, SECRET, None);
    let refused = entra::sign_in_at(stand.cx(), &server.uri(), NAMES, ARM)
        .await
        .unwrap_err();
    assert!(matches!(refused, ConnectorError::Authentication { .. }));
    assert!(!format!("{refused} {refused:?}").contains(SECRET));
    // The same echo in an answer that is no refusal: not repeated either.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path(TENANT_ID)))
        .respond_with(ResponseTemplate::new(500).set_body_string(format!("oops {SECRET}")))
        .mount(&server)
        .await;
    let failed = entra::sign_in_at(stand.cx(), &server.uri(), NAMES, ARM)
        .await
        .unwrap_err();
    assert!(!matches!(failed, ConnectorError::Authentication { .. }));
    let shown = format!("{failed} {failed:?} {}", failed.text());
    assert!(shown.contains("oops ***"), "{shown}");
    assert!(!shown.contains(SECRET), "{shown}");
    assert!(!format!("{:?}", stand.tenant).contains(SECRET));
    // The log is not empty: each sign-in is a debug event naming the
    // tenant and the scope, and none of its fields holds the secret.
    let logged = logs.0.lock().unwrap().clone();
    assert!(
        logged.matches("signing in to Entra ID").count() >= 6,
        "{logged}"
    );
    assert!(logged.contains("tenant=prod"), "{logged}");
    assert!(logged.contains(&format!("scope=\"{ARM}\"")), "{logged}");
    for leaked in [
        SECRET.to_owned(),
        SECRET.replace(' ', "+"),
        url::form_urlencoded::byte_serialize(SECRET.as_bytes()).collect(),
    ] {
        assert!(!logged.contains(&leaked), "{logged}");
    }
}

/// Requirement 7, the other side: an answer without a token that is no
/// refusal of the credentials (a rate limit or an outage the retries did not
/// outlast, a proxy's page, a `400` without OAuth's `error`) is a service
/// error naming Entra ID and the status, never an authentication failure.
#[tokio::test]
async fn answers_that_are_no_refusal_name_entra_and_the_status() {
    logs();
    let html = "<html><head><title>Proxy Error</title></head></html>";
    let cases: [(u16, &str, &str); 4] = [
        (
            429,
            r#"{"error":"temporarily_unavailable","error_description":"AADSTS50196: throttled"}"#,
            "Entra ID answered HTTP 429 and issued no token: AADSTS50196: throttled",
        ),
        (
            500,
            html,
            "Entra ID answered HTTP 500 and issued no token: HTTP 500 with an HTML page titled \"Proxy Error\"",
        ),
        (
            400,
            html,
            "Entra ID answered HTTP 400 and issued no token: HTTP 400 with an HTML page",
        ),
        (
            200,
            r#"{"token_type":"Bearer"}"#,
            "Entra ID answered HTTP 200 and issued no token: no access token",
        ),
    ];
    for (status, body, expected) in cases {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(token_path(TENANT_ID)))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Retry-After", "0")
                    .set_body_string(body),
            )
            .mount(&server)
            .await;
        let stand = Stand::with_settings(
            "prod",
            TENANT_ID,
            SECRET,
            None,
            &sentinel::http_settings(std::time::Duration::from_secs(10)),
        );
        let failed = entra::sign_in_at(stand.cx(), &server.uri(), NAMES, ARM)
            .await
            .unwrap_err();
        let ConnectorError::Answer { tenant, reason, .. } = &failed else {
            panic!("HTTP {status}: not a service error: {failed:?}");
        };
        assert_eq!(tenant, "prod");
        assert!(reason.starts_with(expected), "{reason}");
        // A 429 is retried (the token POST is idempotent); the others are not.
        let sent = server.received_requests().await.unwrap().len();
        assert_eq!(sent, if status == 429 { 4 } else { 1 }, "HTTP {status}");
    }
}

/// A `503` from the identity platform is retried; one that lasts is a
/// gateway error naming Entra ID, the status and the tenant.
#[tokio::test]
async fn a_503_is_retried_and_one_that_lasts_is_a_service_error() {
    logs();
    let settings = sentinel::http_settings(std::time::Duration::from_secs(10));
    // Once, then a token: two POSTs, one token.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path(TENANT_ID)))
        .respond_with(ResponseTemplate::new(503).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    issuing(
        &server,
        TENANT_ID,
        serde_json::json!({"access_token": "tok", "expires_in": 3599}),
    )
    .await;
    let stand = Stand::with_settings("prod", TENANT_ID, SECRET, None, &settings);
    let tokens = TokenCache::new();
    assert_eq!(token(&tokens, stand.cx(), &server.uri(), ARM).await, "tok");
    assert_eq!(token(&tokens, stand.cx(), &server.uri(), ARM).await, "tok");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    // Every time: the retries run out, and the error says who and what.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path(TENANT_ID)))
        .respond_with(ResponseTemplate::new(503).insert_header("Retry-After", "0"))
        .mount(&server)
        .await;
    let failed = entra::sign_in_at(stand.cx(), &server.uri(), NAMES, ARM)
        .await
        .unwrap_err();
    let ConnectorError::Gateway {
        platform,
        tenant,
        message,
        status,
    } = &failed
    else {
        panic!("not a gateway error: {failed:?}");
    };
    assert_eq!(
        (platform.as_str(), tenant.as_str(), *status),
        ("sentinel", "prod", 503)
    );
    assert!(
        message.starts_with("Entra ID answered HTTP 503 when tenant prod signed in"),
        "{message}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
}

/// Requirement 8: the sign-in goes through the tenant's own client, so its
/// proxy applies to the identity platform too.
#[tokio::test]
async fn the_sign_in_uses_the_tenants_proxy() {
    logs();
    let proxy = MockServer::start().await;
    issuing(
        &proxy,
        TENANT_ID,
        serde_json::json!({"access_token": "tok", "expires_in": 3599}),
    )
    .await;
    let stand = Stand::new("prod", TENANT_ID, SECRET, Some(&proxy.uri()));
    let issued = entra::sign_in_at(stand.cx(), "http://login.example.invalid", NAMES, ARM)
        .await
        .unwrap();
    assert_eq!(issued.token.expose(), "tok");
    let received = proxy.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].url.host_str(), Some("login.example.invalid"));
}

/// Requirement 9: tenants signing in at once, each with its own secret,
/// each get their own token.
#[tokio::test]
async fn tenants_signing_in_at_once_get_their_own_tokens() {
    logs();
    let server = MockServer::start().await;
    let (a, b) = (
        "aaaaaaaa-0000-4000-8000-000000000000",
        "bbbbbbbb-0000-4000-8000-000000000000",
    );
    for (tenant_id, secret) in [(a, "secret-a"), (b, "secret-b")] {
        Mock::given(method("POST"))
            .and(path(token_path(tenant_id)))
            .and(wiremock::matchers::body_string_contains(format!(
                "client_secret={secret}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(50))
                    .set_body_json(serde_json::json!({"access_token": format!("token-{secret}"), "expires_in": 3599})),
            )
            .mount(&server)
            .await;
    }
    let (first, second) = (
        Stand::new("first", a, "secret-a", None),
        Stand::new("second", b, "secret-b", None),
    );
    let tokens = TokenCache::new();
    let uri = server.uri();
    let (one, two) = tokio::join!(
        token(&tokens, first.cx(), &uri, ARM),
        token(&tokens, second.cx(), &uri, ARM)
    );
    assert_eq!(
        (one.as_str(), two.as_str()),
        ("token-secret-a", "token-secret-b")
    );
    let (one, two) = tokio::join!(
        token(&tokens, first.cx(), &uri, ARM),
        token(&tokens, second.cx(), &uri, ARM)
    );
    assert_eq!(
        (one.as_str(), two.as_str()),
        ("token-secret-a", "token-secret-b")
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

/// Requirement 7 (second review, N1): a proxy or server that echoes the
/// form it was sent echoes the secret form-encoded. No form of it reaches
/// an error, its `Debug` or the log, nor part of one through an excerpt
/// cut in the middle of it.
#[tokio::test]
async fn an_echoed_form_body_never_shows_the_secret_in_any_encoding() {
    let logs = logs();
    let form_encoded: String = url::form_urlencoded::byte_serialize(SECRET.as_bytes()).collect();
    let leaks = [
        SECRET.to_owned(),
        form_encoded.clone(),
        form_encoded.replace('+', "%20"),
        // Python's `quote_plus`, which leaves `~` as it is.
        "aB3~Q8_x.y%2Bz%2Fw%3Dv%26u%25t+s~9".to_owned(),
        "aB3~Q8_x.y%2Bz%2Fw%3Dv%26u%25t%20s~9".to_owned(),
        "aB3~Q8_x.y%2bz%2fw%3dv%26u%25t+s~9".to_owned(),
        // What an excerpt cut inside the secret would keep.
        "aB3~Q8".to_owned(),
        "aB3%7EQ8".to_owned(),
    ];
    // (status, type, the answer): `{}` is the form as it arrived.
    let echoes: [(u16, &str, &str); 5] = [
        (500, "text/plain", "upstream failed for {}"),
        (502, "text/plain", "bad gateway, request was {}"),
        (400, "text/plain", "cannot parse {}"),
        // An excerpt that ends in the middle of the secret.
        (400, "text/plain", "PAD{}"),
        (
            400,
            "application/json",
            r#"{"error":"invalid_request","error_description":"AADSTS900144: in {}"}"#,
        ),
    ];
    for (status, kind, wrap) in echoes {
        let server = MockServer::start().await;
        let wrap = wrap.to_owned();
        Mock::given(method("POST"))
            .and(path(token_path(TENANT_ID)))
            .respond_with(move |request: &Request| {
                let sent = String::from_utf8_lossy(&request.body).into_owned();
                // The secret's value starts 190 bytes in: a 200-byte
                // excerpt of the raw body would cut it after 10.
                let at = sent.find("client_secret=").unwrap() + "client_secret=".len();
                let body = wrap
                    .replace("PAD", &"x".repeat(190 - at))
                    .replace("{}", &sent);
                ResponseTemplate::new(status)
                    .insert_header("Retry-After", "0")
                    .set_body_raw(body, kind)
            })
            .mount(&server)
            .await;
        let stand = Stand::with_settings(
            "prod",
            TENANT_ID,
            SECRET,
            None,
            &sentinel::http_settings(std::time::Duration::from_secs(10)),
        );
        let failed = entra::sign_in_at(stand.cx(), &server.uri(), NAMES, ARM)
            .await
            .unwrap_err();
        let shown = format!("{failed}\n{failed:?}\n{}", failed.text());
        assert!(shown.contains("prod"), "HTTP {status}: {shown}");
        if kind == "text/plain" {
            assert!(
                shown.contains("client_secret=***"),
                "HTTP {status}: {shown}"
            );
        }
        for leak in &leaks {
            assert!(
                !shown.contains(leak.as_str()),
                "HTTP {status}: {leak} in {shown}"
            );
        }
    }
    let logged = logs.0.lock().unwrap().clone();
    for leak in &leaks {
        assert!(!logged.contains(leak.as_str()), "{leak} in {logged}");
    }
}
