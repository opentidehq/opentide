//! Microsoft Defender against recorded cassettes: advanced hunting
//! (`defender/query`, `defender/validate`, recorded from the Python client),
//! whose every request must be the Python client's, in order; and the Graph
//! beta deploy (`golden/deploy-defender-continues`, recorded from the Rust
//! command line against `tests/cassettes/defender/tenant.py`), replayed
//! through the connector: `PATCH` then `POST` on a `404`, one more `PATCH`
//! after a `409`, a DISABLEMENT's `404` creating nothing, a DELETE's `404`
//! and a refusal, every rule addressed as `opentide-<uuid>` (#1886); and a
//! `409` whose `PATCH` finds no rule, another rule holding the name.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod support;

use opentide_cassette::cassette::Body;
use opentide_compile::json::Json;
use opentide_connectors::ConnectorError;
use opentide_connectors::connector::QueryRequest;
use opentide_connectors::microsoft_defender::{self, DefenderError, MicrosoftDefender};
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
        microsoft_defender::PLATFORM,
        SETUP,
        "DEFENDER_CLIENT_SECRET",
        &microsoft_defender::http_settings(),
    )
}

#[test]
fn defender_query_sends_what_the_python_runner_sent() {
    let inputs = fixture("defender");
    let query = inputs.get("query").unwrap();
    let window = window(query.get("window").unwrap());
    let tenant = replay("defender/query");
    let connector = MicrosoftDefender::new();
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
        MicrosoftDefender::new()
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
    let connector = MicrosoftDefender::new();
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

/// The cassette `defender/query`'s sign-in, then one page of the rules
/// whose `@odata.nextLink` is *link*.
fn listing_linking_to(link: &str) -> opentide_cassette::Cassette {
    let full = support::cassette("defender/query");
    let mut page = full.interactions[1].clone();
    page.request.method = "GET".into();
    page.request.url = microsoft_defender::DETECTION_RULES_ENDPOINT.into();
    page.request.body = Body::Text(String::new());
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
        microsoft_defender::PLATFORM,
        SETUP,
        "DEFENDER_CLIENT_SECRET",
        &microsoft_defender::http_settings(),
    );
    let listed =
        block_on(async { MicrosoftDefender::new().list_rules(tenant.cx()).await }).unwrap();
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
    let (listed, tenant) = list_through(microsoft_defender::DETECTION_RULES_ENDPOINT);
    let error = listed.unwrap_err().to_string();
    assert!(error.contains("repeats one already followed"), "{error}");
    assert_eq!(tenant.verify(), Vec::new());
}

/// #1142: a page of the rules that is not JSON is an error naming its
/// content type, never an empty listing.
#[test]
fn defender_a_list_page_that_is_not_json_is_an_error() {
    let full = support::cassette("defender/query");
    let mut page = full.interactions[1].clone();
    page.request.method = "GET".into();
    page.request.url = microsoft_defender::DETECTION_RULES_ENDPOINT.into();
    page.request.body = Body::Text(String::new());
    page.response.status = 200;
    page.response.headers = vec![("content-type".into(), "text/plain".into())];
    page.response.body = Body::Text("maintenance".into());
    let tenant = Replayed::start_with(
        opentide_cassette::Cassette::new(
            &full.scenario,
            full.recorded_from,
            vec![full.interactions[0].clone(), page],
        ),
        microsoft_defender::PLATFORM,
        SETUP,
        "DEFENDER_CLIENT_SECRET",
        &microsoft_defender::http_settings(),
    );
    let listed =
        block_on(async { MicrosoftDefender::new().list_rules(tenant.cx()).await }).unwrap();
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
    let mut cassette = support::cassette("defender/query");
    let mut signed = cassette.interactions[0].clone();
    signed.response.status = 403;
    signed.response.body = Body::Text("<html><title>Forbidden</title></html>".into());
    cassette.interactions = vec![signed];
    let tenant = Replayed::start_with(
        cassette,
        microsoft_defender::PLATFORM,
        SETUP,
        "DEFENDER_CLIENT_SECRET",
        &microsoft_defender::http_settings(),
    );
    let request = DeployRequest::delete("42");
    let error = block_on(async { MicrosoftDefender::new().deploy(tenant.cx(), &request).await })
        .unwrap()
        .unwrap_err();
    assert_eq!(error.scope, DeployScope::Tenant, "{error:?}");
    assert!(
        error.failure.message.contains("Entra ID answered HTTP 403"),
        "{error:?}"
    );
    assert_eq!(tenant.verify(), Vec::new());
}

/// The tenant of the golden deploy (`deploy-tenants`' `lab`).
const GOLDEN_SETUP: &str = r#"
tenant_id = "00000000-0000-4000-8000-00000000de1d"
client_id = "00000000-0000-4000-8000-00000000c11d"
client_secret = "$DEFENDER_CLIENT_SECRET"
"#;

/// The body the golden deploy sent in its `PATCH` of rule `id` (its
/// first), read back from the cassette.
fn recorded_body(cassette: &opentide_cassette::Cassette, id: &str) -> Json {
    let patch = cassette
        .interactions
        .iter()
        .find(|interaction| {
            interaction.request.method == "PATCH" && interaction.request.url.ends_with(id)
        })
        .unwrap();
    serde_json::from_slice(&patch.request.body.bytes()).unwrap()
}

fn rule(number: &str) -> String {
    format!("00000000-0000-4000-8047-0000000000{number}")
}

/// The Defender rule id of [`rule`] *number*: `opentide-<uuid>`.
fn rule_id(number: &str) -> String {
    opentide_compile::microsoft_defender::rule_id_of(&rule(number))
}

/// RFC 0021's deploy, replayed through the connector from the golden
/// deploy's cassette: every call is the one the command line made, and
/// each answer reads as microsoft-defender-1.0 says.
#[test]
fn microsoft_defender_deploy_follows_the_spec_through_every_answer() {
    use opentide_connectors::connector::{DeployRequest, Deployer, Operation};
    use opentide_connectors::microsoft_defender::{RULE_ABSENT, Sent};
    let cassette = support::cassette("golden/deploy-defender-continues");
    let bodies: Vec<Json> = ["d1", "d2", "d3", "d4", "d6"]
        .iter()
        .map(|number| recorded_body(&cassette, &rule(number)))
        .collect();
    let tenant = Replayed::start_with(
        cassette,
        microsoft_defender::PLATFORM,
        GOLDEN_SETUP,
        "DEFENDER_CLIENT_SECRET",
        &microsoft_defender::http_settings(),
    );
    let connector = MicrosoftDefender::new();
    let cx = tenant.cx();
    let request = |id: &str, operation: Operation, body: &Json| {
        // An upper-case uuid addresses the same rule. Each uuid begins
        // with a digit, which Graph refuses as an id (#1886): the requests
        // name `opentide-<uuid>`.
        DeployRequest::new(id.to_uppercase(), operation, body.to_compact().into_bytes())
    };
    block_on(async {
        // PATCH 404, then POST with `opentide-<uuid>` as id: created.
        let created = connector
            .deploy(cx, &request(&rule("d1"), Operation::Update, &bodies[0]))
            .await
            .unwrap();
        assert_eq!(created.operation, Operation::Create);
        assert_eq!(created.remote_id.as_deref(), Some(rule_id("d1").as_str()));
        assert_eq!(created.events[0].name, "microsoft_defender_rule_created");
        assert_eq!(
            created.events[0].fields,
            [("rule_id".to_owned(), rule_id("d1"))]
        );
        // PATCH 200: updated, in one call.
        assert_eq!(
            connector
                .upsert(cx, &rule_id("d2"), &bodies[1])
                .await
                .unwrap(),
            Sent::Updated
        );
        // PATCH 404, POST 409 (created meanwhile), PATCH 200: updated.
        assert_eq!(
            connector
                .upsert(cx, &rule_id("d3"), &bodies[2])
                .await
                .unwrap(),
            Sent::Updated
        );
        // A DISABLEMENT's PATCH 404: nothing created, a warning.
        let absent = connector
            .deploy(cx, &request(&rule("d4"), Operation::Disable, &bodies[3]))
            .await
            .unwrap();
        assert_eq!(absent.remote_id, None);
        assert_eq!(absent.warnings[0].code, RULE_ABSENT);
        assert!(absent.warnings[0].raised);
        // A DELETE's 404: a failure whose status says the rule is gone.
        let gone = connector
            .deploy(cx, &DeployRequest::delete(rule("d5")))
            .await
            .unwrap_err();
        assert_eq!(gone.failure.status, Some(404));
        // A refusal fails the rule, with Graph's message.
        let refused = connector
            .upsert(cx, &rule_id("d6"), &bodies[4])
            .await
            .unwrap_err();
        assert_eq!(refused.failure.status, Some(400));
        assert_eq!(refused.failure.code, "tenant_refused");
        assert!(
            refused
                .failure
                .message
                .contains("The query is not valid for a custom detection."),
            "{refused:?}"
        );
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
}

/// The create body is the update body with `id` first: the `POST` the
/// golden deploy recorded is the `PATCH` before it, plus the id,
/// `opentide-<uuid>` (#1886).
#[test]
fn microsoft_defender_creates_with_the_opentide_rule_id() {
    let cassette = support::cassette("golden/deploy-defender-continues");
    let patch = recorded_body(&cassette, &rule("d1"));
    let post = cassette
        .interactions
        .iter()
        .find(|interaction| {
            interaction.request.method == "POST"
                && interaction.request.url.ends_with("detectionRules")
        })
        .unwrap();
    let post: Json = serde_json::from_slice(&post.request.body.bytes()).unwrap();
    assert_eq!(
        post,
        opentide_compile::microsoft_defender::create_body(&rule_id("d1"), &patch)
    );
    assert_eq!(
        post.get("id").and_then(Json::as_str),
        Some("opentide-00000000-0000-4000-8047-0000000000d1")
    );
    assert_eq!(
        post.as_object().unwrap().keys().next().map(String::as_str),
        Some("id")
    );
}

/// #1886: a create Graph refuses with `409` while no rule has the id (the
/// `PATCH` after it answers `404` again) is another rule holding the
/// display name, one an earlier opentide release or a person created:
/// `microsoft_defender_rule_conflict`, which says to delete or rename it.
#[test]
fn microsoft_defender_a_name_held_by_another_rule_is_a_conflict() {
    use opentide_connectors::connector::{DeployRequest, Deployer, Operation};
    let recorded = support::cassette("golden/deploy-defender-continues");
    let find = |method: &str, status: u16| {
        recorded
            .interactions
            .iter()
            .find(|interaction| {
                interaction.request.method == method
                    && interaction.response.status == status
                    && (interaction.request.url.ends_with(&rule_id("d3")) || method == "POST")
            })
            .unwrap()
            .clone()
    };
    // d3's PATCH 404 and POST 409, then a PATCH that finds no rule either.
    let patch = find("PATCH", 404);
    let mut post = find("POST", 409);
    post.response.headers = vec![("content-type".into(), "application/json".into())];
    post.response.body = Body::Text(
        r#"{"error":{"code":"Conflict","message":"A detection rule with this name, title, or rule ID already exists."}}"#
            .into(),
    );
    let cassette = opentide_cassette::Cassette::new(
        &recorded.scenario,
        recorded.recorded_from.clone(),
        vec![recorded.interactions[0].clone(), patch.clone(), post, patch],
    );
    let body = recorded_body(&recorded, &rule_id("d3"));
    let tenant = Replayed::start_with(
        cassette,
        microsoft_defender::PLATFORM,
        GOLDEN_SETUP,
        "DEFENDER_CLIENT_SECRET",
        &microsoft_defender::http_settings(),
    );
    let request = DeployRequest::new(
        rule("d3"),
        Operation::Update,
        body.to_compact().into_bytes(),
    );
    let failed = block_on(async { MicrosoftDefender::new().deploy(tenant.cx(), &request).await })
        .unwrap()
        .unwrap_err();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(failed.failure.code, microsoft_defender::RULE_CONFLICT);
    assert_eq!(failed.failure.code, "microsoft_defender_rule_conflict");
    assert_eq!(failed.failure.status, Some(409));
    let message = &failed.failure.message;
    for said in [
        "Graph refused to create detection rule opentide-00000000-0000-4000-8047-0000000000d3",
        "A detection rule with this name, title, or rule ID already exists.",
        "an earlier opentide release",
        "delete or rename that rule in the Defender portal",
    ] {
        assert!(message.contains(said), "{said}: {message}");
    }
}
