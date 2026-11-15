//! What an API says back about a request's credential is masked in every cut
//! of the answer: the credential the request sent, echoed in a body, never
//! reaches an error's detail, whole or straddling the cut.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::time::Duration;

use opentide_connectors::answer::{Answer, Credentials, exchange};
use opentide_connectors::connector::TenantContext;
use opentide_connectors::credentials::Mode;
use opentide_connectors::transport::Method;
use opentide_connectors::{Environment, HttpClient, HttpSettings, Tenant};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const SECRET: &str = "tok-0123456789abcdefghij";

/// The API echoes the request's `Authorization` header after *padding*
/// characters, so that the secret straddles any cut made inside it.
async fn answer_echoing(padding: usize) -> Answer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rules"))
        .respond_with(move |request: &Request| {
            let seen = request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            ResponseTemplate::new(500)
                .insert_header("content-type", "text/plain")
                .set_body_string(format!("{}{seen}", "x".repeat(padding)))
        })
        .mount(&server)
        .await;
    let setup = toml::Table::new();
    let env = Environment::default();
    let tenant = Tenant::from_setup(
        "stand",
        "lab",
        &setup,
        &env,
        Mode::Required,
        &HttpSettings::default(),
    )
    .unwrap();
    let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let builder = http
        .request(Method::GET, &format!("{}/rules", server.uri()))
        .header("Authorization", format!("Bearer {SECRET}"));
    exchange(cx, builder).await.unwrap()
}

#[tokio::test]
async fn a_credential_straddling_the_cut_is_masked_before_the_cut() {
    // "Bearer " is 7 characters: the secret begins at 493 and ends at 517,
    // across the 500th.
    let answer = answer_echoing(486).await;
    let head = answer.text_head(500);
    assert!(!head.contains("tok-"), "{head}");
    assert!(head.ends_with("Bearer ***"), "{head}");
    assert!(!answer.text().contains(SECRET));
}

#[tokio::test]
async fn the_description_of_an_answer_that_is_not_json_has_no_credential() {
    let answer = answer_echoing(0).await;
    let detail = answer.not_json_detail().unwrap();
    assert!(detail.contains("Bearer ***"), "{detail}");
    assert!(!detail.contains(SECRET), "{detail}");
}

#[test]
fn a_successful_json_answer_is_kept_and_an_error_is_masked() {
    let mut request = opentide_connectors::transport::Request::new(
        Method::POST,
        "https://example.test/token".parse().unwrap(),
    );
    request.headers_mut().insert(
        "content-type",
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    request.set_body(Some(b"client_secret=secret-of-a".to_vec()));
    let credentials = Credentials::of(&request);
    let issued = br#"{"access_token":"token-secret-of-a"}"#.to_vec();
    let kept = Answer::new(200, None, issued.clone(), Duration::ZERO, &credentials);
    assert_eq!(kept.body, issued);
    let refused = Answer::new(400, None, issued, Duration::ZERO, &credentials);
    assert_eq!(refused.text(), r#"{"access_token":"token-***"}"#);
    let page = Answer::new(
        200,
        None,
        b"<p>secret-of-a</p>".to_vec(),
        Duration::ZERO,
        &credentials,
    );
    assert_eq!(page.text(), "<p>***</p>");
}

#[test]
fn a_body_that_echoes_no_credential_is_kept_as_it_is() {
    let credentials = Credentials::default();
    let body = b"\xff not utf-8 \xfe".to_vec();
    assert_eq!(credentials.mask(body.clone()), body);
    assert_eq!(
        Answer::new(200, None, body.clone(), Duration::ZERO, &credentials).body,
        body
    );
}
