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
    ConnectorError, Environment, HttpClient, HttpSettings, Tenant, defender, sentinel,
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
        let setup: toml::Table = toml::from_str(
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
            &HttpSettings::default(),
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
    assert_eq!(defender::SCOPE, "https://graph.microsoft.com/.default");
    assert_eq!(
        sentinel::CREDENTIALS,
        CredentialNames {
            tenant_id: "azure_tenant_id",
            client_id: "azure_client_id",
            client_secret: "azure_client_secret",
        }
    );
    assert_eq!(
        defender::CREDENTIALS,
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

/// Requirement 7: a wrong tenant id, a wrong secret and an expired secret
/// are authentication failures naming the platform and the tenant, with
/// Entra's description; the secret is in no error, no `Debug` and no log.
#[tokio::test]
async fn entra_refusals_name_the_tenant_and_never_the_secret() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let logs = Logs::default();
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(logs.clone()));
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
        .respond_with(ResponseTemplate::new(401).set_body_json(
            serde_json::json!({"error_description": format!("bad secret {SECRET}")}),
        ))
        .mount(&server)
        .await;
    let stand = Stand::new("prod", TENANT_ID, SECRET, None);
    let refused = entra::sign_in_at(stand.cx(), &server.uri(), NAMES, ARM)
        .await
        .unwrap_err();
    assert!(!format!("{refused} {refused:?}").contains(SECRET));
    assert!(!format!("{:?}", stand.tenant).contains(SECRET));
    let logged = logs.0.lock().unwrap().clone();
    assert!(!logged.contains(SECRET), "{logged}");
    assert!(!logged.contains(&SECRET.replace(' ', "+")), "{logged}");
}

/// Requirement 8: the sign-in goes through the tenant's own client, so its
/// proxy applies to the identity platform too.
#[tokio::test]
async fn the_sign_in_uses_the_tenants_proxy() {
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
