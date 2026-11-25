//! Microsoft Defender against the cassettes recorded from the Python
//! client (`tests/cassettes/defender/`, `cargo xtask cassettes record
//! defender/<scenario>`): every request the connector sends must be the
//! Python client's, in order (a JSON body as the same data), and the answers must read as
//! Python reads them.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod support;

use opentide_cassette::cassette::Body;
use opentide_compile::json::Json;
use opentide_connectors::ConnectorError;
use opentide_connectors::connector::QueryRequest;
use opentide_connectors::defender::{self, Defender, DefenderError};
use opentide_connectors::runtime::block_on;
use support::{Replayed, fixture, items, text, window};

const SETUP: &str = r#"
tenant_id = "contoso-tenant-id"
client_id = "opentide-app-id"
client_secret = "$DEFENDER_CLIENT_SECRET"
"#;

fn replay(scenario: &str) -> Replayed {
    Replayed::start(
        scenario,
        defender::PLATFORM,
        SETUP,
        "DEFENDER_CLIENT_SECRET",
        &defender::http_settings(),
    )
}

fn deploy(tenant: &Replayed, rule: &Json) -> Vec<String> {
    let connector = Defender::new();
    let cx = tenant.cx();
    block_on(async {
        let mut seen = Vec::new();
        let created = connector.create_rule(cx, rule).await.unwrap();
        seen.push(format!(
            "created {} partial {}",
            created.id, created.partial
        ));
        let id = created.id.to_string();
        connector.update_rule(cx, rule, &id).await.unwrap();
        seen.push(format!("updated {id}"));
        match connector.update_rule(cx, rule, "99").await {
            Err(DefenderError::Refused { message, context }) => {
                seen.push(format!("{message} | {}", context.unwrap_or_default()));
            }
            other => panic!("{other:?}"),
        }
        connector.delete_rule(cx, &id).await.unwrap();
        seen.push(format!("deleted {id}"));
        seen
    })
    .unwrap()
}

#[test]
fn defender_deploy_sends_what_the_python_client_sent() {
    let inputs = fixture("defender");
    let rule = inputs.get("deploy").unwrap().get("rule").unwrap();
    assert_eq!(
        &defender::safer_configuration(rule),
        inputs.get("deploy").unwrap().get("safer").unwrap()
    );
    let tenant = replay("defender/deploy");
    let seen = deploy(&tenant, rule);
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(
        seen,
        [
            "created 42 partial true",
            "updated 42",
            "Failed to update detection rule with id 99 in tenant replayed \
             (https://graph.microsoft.com/beta/security/rules/detectionRules/99) - Error Code 404 \
             | (empty body, HTTP 404)",
            "deleted 42",
        ]
    );
}

/// The same steps through the `Deployer`, as `opentide deploy` sends them:
/// the compiled rule as the body, the stored id addressing an update or a
/// delete. The requests are the recording's; the safer configuration is a
/// raised warning; Graph's refusal keeps its answer as the detail and fails
/// the rule, never the tenant.
#[test]
fn defender_the_deployer_sends_what_the_python_client_sent() {
    use opentide_connectors::connector::{DeployRequest, DeployScope, Deployer, Operation};
    let inputs = fixture("defender");
    let rule = inputs.get("deploy").unwrap().get("rule").unwrap();
    let body = rule.to_compact().into_bytes();
    let tenant = replay("defender/deploy");
    let connector = Defender::new();
    let cx = tenant.cx();
    let (created, updated, refused, deleted) = block_on(async {
        let created = connector
            .deploy(
                cx,
                &DeployRequest::new("u1", Operation::Create, body.clone()),
            )
            .await
            .unwrap();
        let id = created.remote_id.clone().unwrap();
        let updated = connector
            .deploy(
                cx,
                &DeployRequest::new(id.clone(), Operation::Update, body.clone()),
            )
            .await
            .unwrap();
        let refused = connector
            .deploy(
                cx,
                &DeployRequest::new("99", Operation::Update, body.clone()),
            )
            .await
            .unwrap_err();
        let deleted = connector
            .deploy(cx, &DeployRequest::delete(id))
            .await
            .unwrap();
        (created, updated, refused, deleted)
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(created.remote_id.as_deref(), Some("42"));
    assert_eq!(created.warnings.len(), 1);
    assert_eq!(created.warnings[0].code, defender::PARTIAL_DEPLOYMENT);
    assert!(created.warnings[0].raised);
    assert_eq!(updated.remote_id.as_deref(), Some("42"));
    assert_eq!(deleted.remote_id, None);
    assert_eq!(refused.scope, DeployScope::Rule);
    assert_eq!(refused.failure.code, "tenant_refused");
    assert_eq!(
        refused.failure.field("detail"),
        Some("(empty body, HTTP 404)")
    );
}

#[test]
fn defender_a_single_byte_off_fails() {
    // The same rule, its title one character longer: the create's body differs.
    let inputs = fixture("defender");
    let mut rule = inputs.get("deploy").unwrap().get("rule").unwrap().clone();
    if let Json::Object(top) = &mut rule {
        top.insert(
            "displayName".into(),
            Json::Str("Encoded PowerShell — Ünïcodé".into()),
        );
    }
    let tenant = replay("defender/deploy");
    let connector = Defender::new();
    let _ = block_on(async { connector.create_rule(tenant.cx(), &rule).await });
    let mismatches = tenant.verify();
    assert_eq!(
        mismatches.first().map(|m| m.index),
        Some(1),
        "{mismatches:?}"
    );
    assert!(mismatches[0].detail.starts_with("bodies differ at byte "));

    // A recorded body one byte off is refused too.
    let mut altered = support::cassette("defender/deploy");
    let Body::Text(body) = &mut altered.interactions[0].request.body else {
        panic!("the token request has a text body")
    };
    *body = body.replace("grant_type", "grant_typf");
    let tenant = Replayed::start_with(
        altered,
        defender::PLATFORM,
        SETUP,
        "DEFENDER_CLIENT_SECRET",
        &defender::http_settings(),
    );
    let _ = block_on(async { Defender::new().token(tenant.cx()).await });
    assert_eq!(tenant.verify()[0].index, 0);
}

#[test]
fn defender_query_sends_what_the_python_runner_sent() {
    let inputs = fixture("defender");
    let query = inputs.get("query").unwrap();
    let window = window(query.get("window").unwrap());
    let tenant = replay("defender/query");
    let connector = Defender::new();
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for item in items(query.get("queries").unwrap()) {
            let mut request = QueryRequest::new(text(item.get("text").unwrap()), "kql", window);
            request.limit = usize::try_from(match item.get("limit").unwrap() {
                Json::Int(limit) => *limit,
                _ => 100,
            })
            .unwrap();
            outcomes.push(connector.run(tenant.cx(), &request, window.end).await);
        }
        outcomes
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    let first = outcomes[0].as_ref().unwrap();
    assert_eq!(
        first
            .columns
            .iter()
            .map(|c| (c.name.as_str(), c.kind.as_deref()))
            .collect::<Vec<_>>(),
        [
            ("Timestamp", Some("DateTime")),
            ("DeviceId", Some("String")),
            ("DeviceName", Some("String")),
            ("ReportId", Some("Int64"))
        ]
    );
    assert_eq!(first.rows.len(), 1);
    assert!(first.truncated);
    assert_eq!(
        first.sent.as_deref(),
        Some("DeviceProcessEvents\n| where FileName =~ 'powershell.exe'\n| take 2")
    );
    // The 403 is the app registration's, not the query's: an
    // authentication failure, which `validate query --live` reports as the
    // tenant's (#1658, E8); the others are the query's refusals.
    let refusals: Vec<String> = outcomes[1..]
        .iter()
        .map(|outcome| match outcome {
            Err(refused @ ConnectorError::Refused { .. }) => refused.text(),
            Err(ConnectorError::Authentication { message, .. }) => format!("auth: {message}"),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        refusals,
        [
            "Graph refused the hunting query on replayed (HTTP 400): Syntax error near 'whre'",
            "auth: Graph refused the hunting query on replayed (HTTP 403): the app registration \
             needs ThreatHunting.Read.All: Insufficient privileges to complete the operation.",
            "Graph refused the hunting query on replayed (HTTP 502): HTTP 502 with an HTML page \
             titled \"502 Bad Gateway\": HTTP 502 Bad Gateway is what a gateway or proxy in front \
             of the tenant answers when the tenant does not answer it in time, so the url and \
             port are not at fault when other requests to the same address succeed",
        ]
    );
}

#[test]
fn defender_query_refuses_a_window_past_retention_without_a_request() {
    let inputs = fixture("defender");
    let window = window(inputs.get("query").unwrap().get("window").unwrap());
    let tenant = replay("defender/query");
    let now = window
        .end
        .checked_add(jiff::SignedDuration::from_hours(24 * 40))
        .unwrap();
    let outcome = block_on(async {
        Defender::new()
            .run(tenant.cx(), &QueryRequest::new("T", "kql", window), now)
            .await
    })
    .unwrap();
    match outcome {
        Err(ConnectorError::Refused { message, .. }) => assert_eq!(
            message,
            "advanced hunting keeps 30 days of data: start the window after 2026-11-06T08:00:00.000Z"
        ),
        other => panic!("{other:?}"),
    }
    let mismatches = tenant.verify();
    assert!(
        mismatches
            .iter()
            .all(|m| m.detail.ends_with("was recorded and never sent")),
        "{mismatches:?}"
    );
}

#[test]
fn defender_validate_checks_one_row_and_the_custom_detection_columns() {
    let inputs = fixture("defender");
    let validate = inputs.get("validate").unwrap();
    let window = window(validate.get("window").unwrap());
    let tenant = replay("defender/validate");
    let connector = Defender::new();
    let errors = block_on(async {
        let mut errors = Vec::new();
        for query in items(validate.get("queries").unwrap()) {
            let check = connector
                .check(
                    tenant.cx(),
                    &QueryRequest::new(text(query), "kql", window),
                    window.end,
                )
                .await
                .unwrap();
            assert_eq!(check.result.as_ref().unwrap().rows.len(), 1);
            errors.push(check.errors);
        }
        errors
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(
        errors,
        [
            Vec::<String>::new(),
            vec!["the query's output lacks DeviceId; ReportId".to_owned()]
        ]
    );
}

/// The cassette `defender/deploy`'s sign-in, then one page of the rules
/// whose `@odata.nextLink` is *link*.
fn listing_linking_to(link: &str) -> opentide_cassette::Cassette {
    let full = support::cassette("defender/deploy");
    let mut page = full.interactions[5].clone();
    page.request.method = "GET".into();
    page.request.url = defender::DETECTION_RULES_ENDPOINT.into();
    page.response.status = 200;
    page.response.headers = vec![("content-type".into(), "application/json".into())];
    page.response.body = Body::Text(
        serde_json::json!({"value": [{"id": "42"}], "@odata.nextLink": link}).to_string(),
    );
    opentide_cassette::Cassette::new(
        &full.scenario,
        full.recorded_from,
        vec![full.interactions[0].clone(), page],
    )
}

fn list_through(link: &str) -> (Result<Vec<Json>, DefenderError>, Replayed) {
    let tenant = Replayed::start_with(
        listing_linking_to(link),
        defender::PLATFORM,
        SETUP,
        "DEFENDER_CLIENT_SECRET",
        &defender::http_settings(),
    );
    let listed = block_on(async { Defender::new().list_rules(tenant.cx()).await }).unwrap();
    (listed, tenant)
}

/// #1142: an `@odata.nextLink` to another host is not followed, so Graph's
/// bearer token never reaches it; the listing fails and says why.
#[test]
fn defender_a_next_link_to_another_host_receives_no_token() {
    let (listed, tenant) = list_through("https://evil.example/loop");
    let error = listed.unwrap_err();
    assert!(
        matches!(
            error,
            DefenderError::Connector(ConnectorError::Answer { .. })
        ),
        "{error:?}"
    );
    assert!(
        error
            .to_string()
            .contains("points to https://evil.example, not to https://graph.microsoft.com"),
        "{error}"
    );
    assert_eq!(tenant.verify(), Vec::new(), "nothing sent to evil.example");
}

/// #1142: an `@odata.nextLink` back to the page itself ends the listing
/// with an error, never an endless loop.
#[test]
fn defender_a_next_link_that_loops_is_not_followed() {
    let (listed, tenant) = list_through(defender::DETECTION_RULES_ENDPOINT);
    let error = listed.unwrap_err().to_string();
    assert!(error.contains("repeats one already followed"), "{error}");
    assert_eq!(tenant.verify(), Vec::new());
}

/// #1142: a page of the rules that is not JSON is an error naming its
/// content type, never an empty listing.
#[test]
fn defender_a_list_page_that_is_not_json_is_an_error() {
    let full = support::cassette("defender/deploy");
    let mut page = full.interactions[5].clone();
    page.request.method = "GET".into();
    page.request.url = defender::DETECTION_RULES_ENDPOINT.into();
    page.response.status = 200;
    page.response.headers = vec![("content-type".into(), "text/plain".into())];
    page.response.body = Body::Text("maintenance".into());
    let tenant = Replayed::start_with(
        opentide_cassette::Cassette::new(
            &full.scenario,
            full.recorded_from,
            vec![full.interactions[0].clone(), page],
        ),
        defender::PLATFORM,
        SETUP,
        "DEFENDER_CLIENT_SECRET",
        &defender::http_settings(),
    );
    let listed = block_on(async { Defender::new().list_rules(tenant.cx()).await }).unwrap();
    let error = listed.unwrap_err().to_string();
    assert!(
        error.ends_with(
            "listing the detection rules: the page is not JSON (Content-Type text/plain): HTTP \
             200 with a body that is not JSON (\"maintenance\")"
        ),
        "{error}"
    );
    assert_eq!(tenant.verify(), Vec::new());
}

/// The error the Deployer now returns for a token Entra ID does not issue
/// fails the tenant (its other rules would fail the same way), with Entra
/// ID's answer as the detail.
#[test]
fn defender_a_refused_sign_in_fails_the_tenant() {
    use opentide_connectors::connector::{DeployError, DeployScope};
    let refused = DefenderError::Authentication {
        detail: "AADSTS7000215: Invalid client secret".into(),
    };
    let failure = DeployError::from(refused.into_connector("soc"));
    assert_eq!(failure.scope, DeployScope::Tenant);
    assert_eq!(failure.failure.code, "authentication_failed");
    assert_eq!(
        failure.failure.field("detail"),
        Some("AADSTS7000215: Invalid client secret")
    );
}

/// A sign-in Entra ID answers without a token, and without refusing the
/// credentials (a proxy's 403 page), still fails the tenant through the
/// Deployer, as `opentide deploy` stops it: no rule can deploy without a
/// token, and nothing but the sign-in is sent.
#[test]
fn defender_a_sign_in_without_a_token_fails_the_tenant() {
    use opentide_connectors::connector::{DeployRequest, DeployScope, Deployer};
    let mut cassette = support::cassette("defender/deploy");
    let mut signed = cassette.interactions[0].clone();
    signed.response.status = 403;
    signed.response.body = Body::Text("<html><title>Forbidden</title></html>".into());
    cassette.interactions = vec![signed];
    let tenant = Replayed::start_with(
        cassette,
        defender::PLATFORM,
        SETUP,
        "DEFENDER_CLIENT_SECRET",
        &defender::http_settings(),
    );
    let request = DeployRequest::delete("42");
    let error = block_on(async { Defender::new().deploy(tenant.cx(), &request).await })
        .unwrap()
        .unwrap_err();
    assert_eq!(error.scope, DeployScope::Tenant, "{error:?}");
    assert!(
        error.failure.message.contains("Entra ID answered HTTP 403"),
        "{error:?}"
    );
    assert_eq!(tenant.verify(), Vec::new());
}
