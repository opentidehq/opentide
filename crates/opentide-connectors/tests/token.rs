//! The token cache's rule for a platform's `401`, against a stand-in token
//! endpoint and API (wiremock): one new sign-in and one resend, never a
//! loop; a `403` returned as it is; each tenant its own token.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::time::Duration;

use opentide_compile::json::Json;
use opentide_connectors::connector::TenantContext;
use opentide_connectors::credentials::Mode;
use opentide_connectors::token::{Issued, TokenCache, lifetime};
use opentide_connectors::transport::Method;
use opentide_connectors::{ConnectorError, Environment, HttpClient, HttpSettings, Secret, Tenant};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{body_string, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const SECRET: &str = "s3cr3t+/=&%~ x";

struct Stand {
    server: MockServer,
    tenant: Tenant,
    http: HttpClient,
    cancel: CancellationToken,
}

impl Stand {
    async fn start(name: &str, secret: &str) -> Self {
        let server = MockServer::start().await;
        let setup: opentide_core::json::Object =
            toml::from_str("client_secret = \"$SECRET\"\n").unwrap();
        let env = Environment::default().with("SECRET", secret);
        let tenant = Tenant::from_setup(
            "stand",
            name,
            &setup,
            &env,
            Mode::Required,
            &HttpSettings::default(),
        )
        .unwrap();
        let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
        Self {
            server,
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

    /// Issues `t1`, `t2`, … for an hour each.
    async fn issuing(&self) {
        let issued = std::sync::atomic::AtomicUsize::new(0);
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(move |_: &Request| {
                let n = issued.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"access_token": format!("t{n}"), "expires_in": 3600}),
                )
            })
            .mount(&self.server)
            .await;
    }

    async fn count(&self, route: &str) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| request.url.path() == route)
            .count()
    }
}

/// Signs in to the stand-in token endpoint with the tenant's secret.
async fn sign_in(cx: TenantContext<'_>, base: &str) -> Result<Issued, ConnectorError> {
    let secret = cx.tenant.secret("client_secret")?;
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_secret", secret.expose())
        .finish();
    let request = cx
        .http
        .request(Method::POST, &format!("{base}/token"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form)
        .build()
        .unwrap();
    let answer = opentide_connectors::answer::Answer::fetch(cx.http, request, cx.cancel).await?;
    let body = answer.json().unwrap_or(Json::Null);
    Ok(Issued {
        token: Secret::new(
            body.get("access_token")
                .and_then(Json::as_str)
                .unwrap_or_default(),
        ),
        lifetime: lifetime(body.get("expires_in")),
    })
}

/// A `POST` to the stand-in API with *tokens*' token.
async fn post(stand: &Stand, tokens: &TokenCache) -> Result<u16, ConnectorError> {
    let base = stand.server.uri();
    let cx = stand.cx();
    tokens
        .send(
            cx,
            "api",
            || sign_in(cx, &base),
            |token| {
                cx.http
                    .request(Method::POST, &format!("{base}/rules"))
                    .header("Authorization", format!("Bearer {}", token.expose()))
                    .body(b"{\"rule\": 1}".to_vec())
            },
            &stand.cancel,
        )
        .await
        .map(|answer| answer.status)
}

#[tokio::test]
async fn a_token_serves_every_call_until_it_is_due() {
    let stand = Stand::start("a", SECRET).await;
    stand.issuing().await;
    Mock::given(method("POST"))
        .and(path("/rules"))
        .and(header("authorization", "Bearer t1"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&stand.server)
        .await;
    let tokens = TokenCache::new();
    assert_eq!(post(&stand, &tokens).await.unwrap(), 200);
    assert_eq!(post(&stand, &tokens).await.unwrap(), 200);
    assert_eq!(stand.count("/token").await, 1);
    assert_eq!(stand.count("/rules").await, 2);
}

#[tokio::test]
async fn a_401_signs_in_again_once_and_resends_the_post_once() {
    let stand = Stand::start("a", SECRET).await;
    stand.issuing().await;
    Mock::given(method("POST"))
        .and(path("/rules"))
        .and(header("authorization", "Bearer t1"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&stand.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rules"))
        .and(header("authorization", "Bearer t2"))
        .and(body_string("{\"rule\": 1}"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&stand.server)
        .await;
    let tokens = TokenCache::new();
    assert_eq!(post(&stand, &tokens).await.unwrap(), 201);
    assert_eq!(stand.count("/token").await, 2);
    assert_eq!(stand.count("/rules").await, 2);
    // The new token is the one kept.
    assert_eq!(post(&stand, &tokens).await.unwrap(), 201);
    assert_eq!(stand.count("/token").await, 2);
}

#[tokio::test]
async fn a_second_401_is_an_authentication_failure_and_no_loop() {
    let stand = Stand::start("lab", SECRET).await;
    stand.issuing().await;
    Mock::given(method("POST"))
        .and(path("/rules"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&stand.server)
        .await;
    let tokens = TokenCache::new();
    let error = post(&stand, &tokens).await.unwrap_err();
    let ConnectorError::Authentication {
        platform, tenant, ..
    } = &error
    else {
        panic!("not an authentication failure: {error:?}");
    };
    assert_eq!((platform.as_str(), tenant.as_str()), ("stand", "lab"));
    assert!(error.to_string().contains("lab"), "{error}");
    assert_eq!(stand.count("/token").await, 2);
    assert_eq!(stand.count("/rules").await, 2);
    for shown in [
        error.to_string(),
        format!("{error:?}"),
        format!("{tokens:?}"),
    ] {
        assert!(
            !shown.contains(SECRET) && !shown.contains("t1") && !shown.contains("t2"),
            "{shown}"
        );
    }
}

#[tokio::test]
async fn a_second_401_keeps_what_the_api_said_with_no_token() {
    let stand = Stand::start("lab", SECRET).await;
    stand.issuing().await;
    Mock::given(method("POST"))
        .and(path("/rules"))
        .respond_with(|request: &Request| {
            let bearer = request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            ResponseTemplate::new(401).set_body_string(format!(
                "{{\"error\":{{\"code\":\"InvalidAuthenticationToken\",\"seen\":\"{bearer}\"}}}}"
            ))
        })
        .mount(&stand.server)
        .await;
    let error = post(&stand, &TokenCache::new()).await.unwrap_err();
    let ConnectorError::Authentication {
        detail: Some(detail),
        ..
    } = &error
    else {
        panic!("no detail: {error:?}");
    };
    assert!(detail.contains("InvalidAuthenticationToken"), "{detail}");
    assert!(detail.contains("Bearer ***"), "{detail}");
    for shown in [detail.clone(), error.text(), format!("{error:?}")] {
        assert!(
            !shown.contains("t1") && !shown.contains("t2") && !shown.contains(SECRET),
            "{shown}"
        );
    }
}

#[tokio::test]
async fn calls_answered_401_at_once_sign_in_again_once() {
    let stand = Stand::start("a", SECRET).await;
    stand.issuing().await;
    Mock::given(method("POST"))
        .and(path("/rules"))
        .and(header("authorization", "Bearer t1"))
        .respond_with(ResponseTemplate::new(401).set_delay(Duration::from_millis(30)))
        .mount(&stand.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rules"))
        .and(header("authorization", "Bearer t2"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&stand.server)
        .await;
    let tokens = TokenCache::new();
    let all = tokio::join!(
        post(&stand, &tokens),
        post(&stand, &tokens),
        post(&stand, &tokens)
    );
    assert_eq!(
        (all.0.unwrap(), all.1.unwrap(), all.2.unwrap()),
        (201, 201, 201)
    );
    // One first sign-in shared, one new sign-in after the 401s shared:
    // no call forgot the token another had just signed in for.
    assert_eq!(stand.count("/token").await, 2);
    assert_eq!(stand.count("/rules").await, 6);
}

/// [`post`], marked `X-Call: <call>` so the stand-in API can tell calls apart.
async fn post_as(stand: &Stand, tokens: &TokenCache, call: &str) -> Result<u16, ConnectorError> {
    let base = stand.server.uri();
    let cx = stand.cx();
    tokens
        .send(
            cx,
            "api",
            || sign_in(cx, &base),
            |token| {
                cx.http
                    .request(Method::POST, &format!("{base}/rules"))
                    .header("Authorization", format!("Bearer {}", token.expose()))
                    .header("X-Call", call)
                    .body(b"{\"rule\": 1}".to_vec())
            },
            &stand.cancel,
        )
        .await
        .map(|answer| answer.status)
}

#[tokio::test]
async fn a_late_401_on_the_old_token_keeps_the_token_signed_in_since() {
    let stand = Stand::start("a", SECRET).await;
    stand.issuing().await;
    // Both calls start with t1. A's 401 comes at once: A signs in for t2
    // and replays. B's 401 on t1 comes only after that.
    Mock::given(method("POST"))
        .and(path("/rules"))
        .and(header("authorization", "Bearer t1"))
        .and(header("x-call", "a"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&stand.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rules"))
        .and(header("authorization", "Bearer t1"))
        .and(header("x-call", "b"))
        .respond_with(ResponseTemplate::new(401).set_delay(Duration::from_millis(400)))
        .mount(&stand.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rules"))
        .and(header("authorization", "Bearer t2"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&stand.server)
        .await;
    let tokens = TokenCache::new();
    let (a, b) = tokio::join!(post_as(&stand, &tokens, "a"), post_as(&stand, &tokens, "b"));
    assert_eq!((a.unwrap(), b.unwrap()), (201, 201));
    // B's 401 forgot only t1, which A had already replaced: no third
    // sign-in, and B replayed with A's t2.
    assert_eq!(stand.count("/token").await, 2);
    let sent: Vec<(String, String)> = stand
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() == "/rules")
        .map(|request| {
            let read = |name: &str| {
                request
                    .headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            };
            (read("x-call"), read("authorization"))
        })
        .collect();
    let of_b: Vec<&str> = sent
        .iter()
        .filter(|(call, _)| call == "b")
        .map(|(_, bearer)| bearer.as_str())
        .collect();
    assert_eq!(of_b, ["Bearer t1", "Bearer t2"]);
}

#[tokio::test]
async fn a_403_is_the_answer_and_no_new_sign_in() {
    let stand = Stand::start("a", SECRET).await;
    stand.issuing().await;
    Mock::given(method("POST"))
        .and(path("/rules"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&stand.server)
        .await;
    let tokens = TokenCache::new();
    assert_eq!(post(&stand, &tokens).await.unwrap(), 403);
    assert_eq!(stand.count("/token").await, 1);
    assert_eq!(stand.count("/rules").await, 1);
}

#[tokio::test]
async fn tenants_signing_in_at_once_each_get_their_own_token() {
    let (a, b) = (
        Stand::start("a", "secret-of-a").await,
        Stand::start("b", "secret-of-b").await,
    );
    for (stand, secret) in [(&a, "secret-of-a"), (&b, "secret-of-b")] {
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string(format!("client_secret={secret}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(50))
                    .set_body_json(serde_json::json!({"access_token": format!("token-{secret}"), "expires_in": 3600})),
            )
            .mount(&stand.server)
            .await;
        Mock::given(method("POST"))
            .and(path("/rules"))
            .and(header(
                "authorization",
                format!("Bearer token-{secret}").as_str(),
            ))
            .respond_with(ResponseTemplate::new(200))
            .mount(&stand.server)
            .await;
    }
    // One cache for both tenants, as one platform keeps them.
    let tokens = TokenCache::new();
    let (first, second) = tokio::join!(post(&a, &tokens), post(&b, &tokens));
    assert_eq!((first.unwrap(), second.unwrap()), (200, 200));
    let (first, second) = tokio::join!(post(&a, &tokens), post(&b, &tokens));
    assert_eq!((first.unwrap(), second.unwrap()), (200, 200));
    assert_eq!((a.count("/token").await, b.count("/token").await), (1, 1));
}

#[tokio::test]
async fn the_secret_reaches_the_token_endpoint_intact() {
    let stand = Stand::start("a", SECRET).await;
    stand.issuing().await;
    Mock::given(method("POST"))
        .and(path("/rules"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&stand.server)
        .await;
    post(&stand, &TokenCache::new()).await.unwrap();
    let received = stand.server.received_requests().await.unwrap();
    let form: Vec<(String, String)> = url::form_urlencoded::parse(&received[0].body)
        .into_owned()
        .collect();
    assert_eq!(form, [("client_secret".to_owned(), SECRET.to_owned())]);
}
