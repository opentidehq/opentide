//! The connectors' HTTP client follows a redirect only on the tenant's
//! origin (#1142): reqwest strips `Authorization` on a hop to another host,
//! but not a platform's own credential header (Carbon Black's
//! `X-Auth-Token`, Bitdefender's `X-API-Key`), so such a hop is not taken.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use opentide_connectors::runtime::block_on;
use opentide_connectors::transport::{Method, follows_redirect};
use opentide_connectors::{Environment, HttpClient, HttpSettings, TenantLabel};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// `GET {from}/start` with Carbon Black's credential header: the answer's
/// status.
fn get_with_token(from: &MockServer) -> u16 {
    let label = TenantLabel::new("carbon_black_cloud", "lab");
    let client = HttpClient::new(
        &label,
        &HttpSettings::default(),
        &Environment::default(),
        None,
    )
    .unwrap();
    let request = client
        .request(Method::GET, &format!("{}/start", from.uri()))
        .header("X-Auth-Token", "secret-key/secret-id")
        .build()
        .unwrap();
    block_on(async {
        let response = client
            .send(request, &CancellationToken::new())
            .await
            .unwrap();
        response.status().as_u16()
    })
    .unwrap()
}

#[test]
fn a_redirect_to_another_origin_is_not_followed() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (tenant, elsewhere) = runtime.block_on(async {
        let tenant = MockServer::start().await;
        let elsewhere = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/stolen", elsewhere.uri())),
            )
            .mount(&tenant)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&elsewhere)
            .await;
        (tenant, elsewhere)
    });
    assert_eq!(get_with_token(&tenant), 302, "the redirect is the answer");
    let received = runtime.block_on(elsewhere.received_requests()).unwrap();
    assert!(received.is_empty(), "the other host received {received:?}");
}

#[test]
fn a_redirect_on_the_same_origin_is_followed() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let tenant = runtime.block_on(async {
        let tenant = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(ResponseTemplate::new(307).insert_header("Location", "/moved"))
            .mount(&tenant)
            .await;
        Mock::given(method("GET"))
            .and(path("/moved"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&tenant)
            .await;
        tenant
    });
    assert_eq!(get_with_token(&tenant), 200);
    runtime.block_on(tenant.verify());
}

#[test]
fn which_hops_are_followed() {
    let url = |text: &str| url::Url::parse(text).unwrap();
    let from = url("https://defense.conferdeploy.net/appservices/v6/orgs/x");
    assert!(follows_redirect(
        &from,
        &url("https://defense.conferdeploy.net/other")
    ));
    assert!(follows_redirect(
        &from,
        &url("https://DEFENSE.conferdeploy.net:443/a")
    ));
    for to in [
        "https://evil.example/",
        "http://defense.conferdeploy.net/a",
        "https://defense.conferdeploy.net:8443/a",
        "https://defense.conferdeploy.net.evil.example/a",
    ] {
        assert!(!follows_redirect(&from, &url(to)), "{to}");
    }
    // An upgrade to https on the same host is followed; nothing else from http.
    let plain = url("http://graylog.lab/api");
    assert!(follows_redirect(&plain, &url("https://graylog.lab/api")));
    assert!(!follows_redirect(&plain, &url("https://other.lab/api")));
    assert!(!follows_redirect(
        &plain,
        &url("https://graylog.lab:9000/api")
    ));
}
