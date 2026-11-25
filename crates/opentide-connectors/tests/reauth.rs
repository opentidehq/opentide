//! The `401` rule and token renewal on the real Entra ID connectors, over
//! hand-written replays built from the recorded cassettes
//! (`tests/cassettes/{sentinel,defender}/`): Sentinel's ARM and Log
//! Analytics calls and Microsoft Defender's Graph calls each sign in
//! again once and resend once after a `401`, fail on a second `401` naming
//! the tenant, and a Defender token is renewed five minutes before it
//! expires rather than kept for the run.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod support;

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use opentide_cassette::cassette::{Request, Response};
use opentide_cassette::{Body, Cassette, Interaction};
use opentide_compile::json::Json;
use opentide_connectors::ConnectorError;
use opentide_connectors::connector::QueryRequest;
use opentide_connectors::defender::{self, Defender, DefenderError};
use opentide_connectors::runtime::block_on;
use opentide_connectors::sentinel::{self, Sentinel};
use opentide_connectors::token::{Clock, TokenCache};
use support::{Replayed, cassette, fixture, items, text, window};

const SENTINEL: &str = r#"
ssl = true
resource_group = "soc-rg"
workspace_name = "soc workspace"
workspace_id = "11111111-2222-4333-8444-555555555555"
azure_tenant_id = "contoso-tenant-id"
azure_subscription_id = "sub-0001"
azure_client_id = "opentide-app-id"
azure_client_secret = "$AZURE_CLIENT_SECRET"
"#;

const DEFENDER: &str = r#"
tenant_id = "contoso-tenant-id"
client_id = "opentide-app-id"
client_secret = "$DEFENDER_CLIENT_SECRET"
"#;

/// What an API answers a token it no longer takes.
fn unauthorized() -> Response {
    Response {
        status: 401,
        headers: vec![("content-type".into(), "application/json".into())],
        body: Body::Text(
            r#"{"error":{"code":"InvalidAuthenticationToken","message":"Lifetime validation failed, the token is expired."}}"#
                .into(),
        ),
    }
}

/// The recorded *sign_in* and *call* of *scenario*, played as: sign in,
/// the call answered `401`, sign in again, the call answered as recorded
/// (or `401` again when *twice*).
fn refused_once(scenario: &str, sign_in: usize, call: usize, twice: bool) -> Cassette {
    let recorded = cassette(scenario);
    let token = recorded.interactions[sign_in].clone();
    let answered = recorded.interactions[call].clone();
    assert!(token.request.url.ends_with("/oauth2/v2.0/token"));
    let refused = Interaction {
        request: answered.request.clone(),
        response: unauthorized(),
    };
    let last = if twice { refused.clone() } else { answered };
    Cassette::new(scenario, vec![], vec![token.clone(), refused, token, last])
}

/// The requests the replay received, in order.
fn sent(tenant: &Replayed) -> Vec<Request> {
    tenant.proxy.requests()
}

fn sign_ins(requests: &[Request]) -> usize {
    requests
        .iter()
        .filter(|request| request.url.ends_with("/oauth2/v2.0/token"))
        .count()
}

/// Exactly sign-in, call, sign-in, call, the call's two copies the same.
fn assert_signed_in_twice_and_resent_once(tenant: &Replayed) {
    assert_eq!(tenant.verify(), Vec::new());
    let requests = sent(tenant);
    assert_eq!(requests.len(), 4, "{requests:#?}");
    assert_eq!(sign_ins(&requests), 2);
    assert!(sign_ins(&requests[..1]) == 1 && sign_ins(&requests[2..3]) == 1);
    let (first, again) = (&requests[1], &requests[3]);
    assert_eq!(
        (&first.method, &first.url, first.body.bytes()),
        (&again.method, &again.url, again.body.bytes())
    );
}

fn sentinel_tenant(replay: Cassette) -> Replayed {
    Replayed::start_with(
        replay,
        sentinel::PLATFORM,
        SENTINEL,
        "AZURE_CLIENT_SECRET",
        &sentinel::http_settings(Duration::from_secs(60)),
    )
}

fn defender_tenant(replay: Cassette) -> Replayed {
    Replayed::start_with(
        replay,
        defender::PLATFORM,
        DEFENDER,
        "DEFENDER_CLIENT_SECRET",
        &defender::http_settings(),
    )
}

/// An authentication failure of the replayed tenant, saying it refused a
/// new token too and keeping what the API said.
fn assert_refused_twice(error: &ConnectorError) {
    let ConnectorError::Authentication {
        tenant,
        message,
        detail,
        ..
    } = error
    else {
        panic!("not an authentication failure: {error:?}");
    };
    assert_eq!(tenant, "replayed");
    assert!(
        message.contains("tenant replayed refused a new token too (HTTP 401)"),
        "{message}"
    );
    assert!(
        detail
            .as_deref()
            .is_some_and(|detail| detail.contains("InvalidAuthenticationToken")),
        "{detail:?}"
    );
}

fn sentinel_rule() -> (String, Json) {
    let inputs = fixture("sentinel");
    let deploy = inputs.get("deploy").unwrap();
    (
        text(deploy.get("rule_id").unwrap()).to_owned(),
        deploy.get("rule").unwrap().clone(),
    )
}

/// Sentinel's ARM `PUT` (interaction 2 of `sentinel/deploy`; 1 is the
/// sign-in, 0 MSAL's discovery).
#[test]
fn sentinel_arm_signs_in_again_once_after_a_401() {
    let (rule_id, rule) = sentinel_rule();
    let tenant = sentinel_tenant(refused_once("sentinel/deploy", 1, 2, false));
    let answer = block_on(async {
        Sentinel::new()
            .create_or_update(tenant.cx(), &rule_id, &rule)
            .await
    })
    .unwrap();
    assert!(matches!(answer, Ok(Ok(_))), "{answer:?}");
    assert_signed_in_twice_and_resent_once(&tenant);

    let tenant = sentinel_tenant(refused_once("sentinel/deploy", 1, 2, true));
    let answer = block_on(async {
        Sentinel::new()
            .create_or_update(tenant.cx(), &rule_id, &rule)
            .await
    })
    .unwrap();
    assert_refused_twice(&answer.unwrap_err());
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(sent(&tenant).len(), 4, "no third sign-in, no loop");
}

/// An API that answers `401` twice and echoes the bearer token it was sent
/// at the end of a long body: the token starts before the 300th character
/// of the answer and ends after it.
#[test]
fn a_token_echoed_across_the_cut_of_the_401_detail_is_masked_whole() {
    const TOKEN: &str = "REDACTED";
    let (rule_id, rule) = sentinel_rule();
    let mut replay = refused_once("sentinel/deploy", 1, 2, true);
    let signed_in = &replay.interactions[0].response.body.bytes();
    assert!(
        String::from_utf8_lossy(signed_in).contains(TOKEN),
        "the recorded sign-in no longer issues the token this test looks for"
    );
    let echo = format!("{}{TOKEN} and more after it", "x".repeat(296));
    for interaction in &mut replay.interactions {
        if interaction.response.status == 401 {
            interaction.response.body = Body::Text(echo.clone());
        }
    }
    let tenant = sentinel_tenant(replay);
    let answer = block_on(async {
        Sentinel::new()
            .create_or_update(tenant.cx(), &rule_id, &rule)
            .await
    })
    .unwrap();
    let error = answer.unwrap_err();
    let ConnectorError::Authentication { detail, .. } = &error else {
        panic!("not an authentication failure: {error:?}");
    };
    let detail = detail.as_deref().unwrap_or_default();
    assert!(
        !detail.contains("RED") && !detail.contains("DACTED"),
        "a part of the token is in the detail: {detail}"
    );
    assert_eq!(detail, format!("{}***", "x".repeat(296)));
}

fn sentinel_query() -> QueryRequest {
    let inputs = fixture("sentinel");
    let query = inputs.get("query").unwrap();
    let item = &items(query.get("queries").unwrap())[0];
    let mut request = QueryRequest::new(
        text(item.get("text").unwrap()),
        "kql",
        window(query.get("window").unwrap()),
    );
    request.limit = usize::try_from(match item.get("limit").unwrap() {
        Json::Int(limit) => *limit,
        _ => 100,
    })
    .unwrap();
    request
}

/// Sentinel's Log Analytics query `POST` (interaction 2 of
/// `sentinel/query`): a `POST` is resent too, as a `401` means the query
/// never ran.
#[test]
fn sentinel_log_analytics_signs_in_again_once_after_a_401() {
    let request = sentinel_query();
    let tenant = sentinel_tenant(refused_once("sentinel/query", 1, 2, false));
    let outcome = block_on(async { Sentinel::new().run(tenant.cx(), &request).await }).unwrap();
    assert!(outcome.is_ok(), "{outcome:?}");
    assert_signed_in_twice_and_resent_once(&tenant);

    let tenant = sentinel_tenant(refused_once("sentinel/query", 1, 2, true));
    let outcome = block_on(async { Sentinel::new().run(tenant.cx(), &request).await }).unwrap();
    assert_refused_twice(&outcome.unwrap_err());
    assert_eq!(sent(&tenant).len(), 4, "no third sign-in, no loop");
}

fn defender_rule() -> Json {
    let inputs = fixture("defender");
    inputs.get("deploy").unwrap().get("rule").unwrap().clone()
}

/// Defender's Graph `PATCH` of rule 42 (interaction 3 of
/// `defender/deploy`; 0 is the sign-in).
#[test]
fn defender_graph_signs_in_again_once_after_a_401() {
    let rule = defender_rule();
    let tenant = defender_tenant(refused_once("defender/deploy", 0, 3, false));
    let updated =
        block_on(async { Defender::new().update_rule(tenant.cx(), &rule, "42").await }).unwrap();
    assert!(updated.is_ok(), "{updated:?}");
    assert_signed_in_twice_and_resent_once(&tenant);

    let tenant = defender_tenant(refused_once("defender/deploy", 0, 3, true));
    let updated =
        block_on(async { Defender::new().update_rule(tenant.cx(), &rule, "42").await }).unwrap();
    let Err(DefenderError::Authentication { detail }) = &updated else {
        panic!("not an authentication failure: {updated:?}");
    };
    assert!(
        detail.contains("tenant replayed refused a new token too (HTTP 401)")
            && detail.contains("InvalidAuthenticationToken"),
        "{detail}"
    );
    let error = updated.unwrap_err().into_connector("replayed");
    assert!(
        matches!(&error, ConnectorError::Authentication { tenant, .. } if tenant == "replayed"),
        "{error:?}"
    );
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(sent(&tenant).len(), 4, "no third sign-in, no loop");
}

/// A clock the test moves.
fn clock() -> (Clock, Arc<Mutex<Instant>>) {
    let at = Arc::new(Mutex::new(Instant::now()));
    let read = Arc::clone(&at);
    (
        Arc::new(move || *read.lock().unwrap_or_else(PoisonError::into_inner)),
        at,
    )
}

/// Defender keeps its token until five minutes before `expires_in` (3599 s
/// in the recording), then signs in again: the token is not kept for the
/// whole run, as it was before the shared cache.
#[test]
fn defender_renews_its_token_five_minutes_before_it_expires() {
    let recorded = cassette("defender/deploy");
    let (token, patch) = (
        recorded.interactions[0].clone(),
        recorded.interactions[3].clone(),
    );
    assert!(
        token
            .response
            .body
            .bytes()
            .windows(18)
            .any(|w| w == b"\"expires_in\": 3599"),
        "the recorded lifetime"
    );
    let replay = Cassette::new(
        "defender/deploy",
        vec![],
        vec![token.clone(), patch.clone(), patch.clone(), token, patch],
    );
    let tenant = defender_tenant(replay);
    let (now, at) = clock();
    let connector = Defender::with_tokens(Arc::new(TokenCache::with_clock(now)));
    let rule = defender_rule();
    let advance = |seconds: u64| {
        *at.lock().unwrap_or_else(PoisonError::into_inner) += Duration::from_secs(seconds);
    };
    block_on(async {
        connector
            .update_rule(tenant.cx(), &rule, "42")
            .await
            .unwrap();
        // One second before the token is due: no sign-in.
        advance(3599 - 300 - 1);
        connector
            .update_rule(tenant.cx(), &rule, "42")
            .await
            .unwrap();
        // Due: a new sign-in before the call.
        advance(1);
        connector
            .update_rule(tenant.cx(), &rule, "42")
            .await
            .unwrap();
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    // The replay may pass a repeated sign-in over; the requests say it was
    // sent.
    let requests = sent(&tenant);
    let shape: Vec<bool> = requests
        .iter()
        .map(|request| request.url.ends_with("/oauth2/v2.0/token"))
        .collect();
    assert_eq!(shape, [true, false, false, true, false], "{requests:#?}");
}
