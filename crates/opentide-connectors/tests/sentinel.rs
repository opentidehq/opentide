//! Sentinel against the cassettes recorded from the Python client (ARM over
//! requests, azure-identity's `ClientSecretCredential` through MSAL, and
//! azure-monitor-query; `tests/cassettes/sentinel/`, `cargo xtask cassettes
//! record sentinel/<scenario>`): every request the connector sends must be
//! the Python client's, in order, by the matcher's rules: MSAL's discovery
//! `GET`, its identity headers and its `client_info` field are not sent
//! (opentide-cassette's `replay`), and the answers must read as Python read
//! them.

mod support;

use std::time::Duration;

use opentide_compile::json::Json;
use opentide_connectors::ConnectorError;
use opentide_connectors::connector::QueryRequest;
use opentide_connectors::runtime::block_on;
use opentide_connectors::sentinel::{self, Sentinel};
use support::{Replayed, fixture, items, text, window};

const SETUP: &str = r#"
ssl = true
resource_group = "soc-rg"
workspace_name = "soc workspace"
workspace_id = "11111111-2222-4333-8444-555555555555"
azure_tenant_id = "contoso-tenant-id"
azure_subscription_id = "sub-0001"
azure_client_id = "opentide-app-id"
azure_client_secret = "$AZURE_CLIENT_SECRET"
"#;

fn replay(scenario: &str) -> Replayed {
    Replayed::start(
        scenario,
        sentinel::PLATFORM,
        SETUP,
        "AZURE_CLIENT_SECRET",
        &sentinel::http_settings(Duration::from_secs(60)),
    )
}

fn connector() -> Sentinel {
    Sentinel::new()
}

#[test]
fn sentinel_deploy_sends_what_the_python_client_sent() {
    let inputs = fixture("sentinel");
    let deploy = inputs.get("deploy").unwrap();
    let rule_id = text(deploy.get("rule_id").unwrap());
    let rule = deploy.get("rule").unwrap();
    let tenant = replay("sentinel/deploy");
    let connector = connector();
    let cx = tenant.cx();
    let seen = block_on(async {
        let mut seen = Vec::new();
        for label in ["create", "replace"] {
            let answer = connector
                .create_or_update(cx, rule_id, rule)
                .await
                .unwrap()
                .unwrap();
            seen.push(format!(
                "{label} {}",
                answer
                    .get("name")
                    .and_then(Json::as_str)
                    .unwrap_or_default()
            ));
        }
        let listed = connector.list(cx).await.unwrap().unwrap();
        seen.push(format!("list {}", listed.len()));
        connector.delete(cx, rule_id).await.unwrap().unwrap();
        seen.push("delete".into());
        let missing = connector.delete(cx, rule_id).await.unwrap().unwrap_err();
        seen.push(format!("{} | {}", missing.status, missing));
        seen
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    // ARM's error code is redacted in the cassette ("code" names a secret): the
    // recorder wrote the bearer's own replay value, so the error masks it.
    assert_eq!(
        seen,
        [
            "create 00000000-0000-4000-8003-000000000001",
            "replace 00000000-0000-4000-8003-000000000001",
            "list 1",
            "delete",
            "404 | DELETE https://management.azure.com/subscriptions/sub-0001/resourceGroups/soc-rg/\
             providers/Microsoft.OperationalInsights/workspaces/soc%20workspace/providers/\
             Microsoft.SecurityInsights/alertRules/00000000-0000-4000-8003-000000000001 failed \
             with HTTP 404 ***: Alert rule with id '00000000-0000-4000-8003-000000000001' was \
             not found.",
        ]
    );
}

#[test]
fn sentinel_a_single_field_off_fails() {
    // The sign-in alone (no discovery, no MSAL headers, no client_info):
    // it matches, and the ARM call recorded next was never sent.
    let tenant = replay("sentinel/deploy");
    let _ = block_on(async { connector().token(tenant.cx(), sentinel::ARM_SCOPE).await });
    let mismatches = tenant.verify();
    assert_eq!(
        mismatches.first().map(|m| m.index),
        Some(1),
        "{mismatches:?}"
    );
    assert!(
        mismatches[0]
            .detail
            .ends_with("was recorded and never sent"),
        "{mismatches:?}"
    );
    // A token for another scope: the token request's form differs.
    let tenant = replay("sentinel/deploy");
    let _ = block_on(async { connector().token(tenant.cx(), sentinel::LOGS_SCOPE).await });
    let mismatches = tenant.verify();
    assert_eq!(
        mismatches.first().map(|m| m.index),
        Some(0),
        "{mismatches:?}"
    );
    assert!(
        mismatches[0].detail.starts_with("bodies differ"),
        "{mismatches:?}"
    );
}

fn cells(row: &opentide_compile::json::Object) -> String {
    row.iter()
        .map(|(key, value)| match value {
            Json::Str(text) => format!("{key}={text}"),
            Json::Int(number) => format!("{key}={number}"),
            other => format!("{key}={other:?}"),
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn sentinel_query_sends_what_the_python_runner_sent() {
    let inputs = fixture("sentinel");
    let query = inputs.get("query").unwrap();
    let window = window(query.get("window").unwrap());
    let tenant = replay("sentinel/query");
    let connector = connector();
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for item in items(query.get("queries").unwrap()) {
            let mut request = QueryRequest::new(text(item.get("text").unwrap()), "kql", window);
            request.limit = usize::try_from(match item.get("limit").unwrap() {
                Json::Int(limit) => *limit,
                _ => 100,
            })
            .unwrap();
            outcomes.push(connector.run(tenant.cx(), &request).await);
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
            ("TimeGenerated", Some("datetime")),
            ("Computer", Some("string")),
            ("EventID", Some("int"))
        ]
    );
    assert_eq!(
        first.rows.iter().map(cells).collect::<Vec<_>>(),
        [
            "TimeGenerated=2026-10-27T07:51:00.000Z,Computer=ws-1.contoso.example,EventID=4689",
            "TimeGenerated=2026-10-27T07:52:00.000Z,Computer=ws-2.contoso.example,EventID=4690",
        ]
    );
    assert!(first.truncated && !first.partial);
    assert_eq!(
        first.sent.as_deref(),
        Some(
            "SecurityEvent\n| where EventID == 4688\n| project TimeGenerated, Computer, EventID\n| take 3"
        )
    );
    let partial = outcomes[1].as_ref().unwrap();
    assert!(partial.partial && !partial.truncated);
    assert_eq!(partial.rows.len(), 2);
    assert_eq!(
        partial.warnings,
        ["partial result: Response size too large"]
    );
    assert_eq!(partial.sent, None);
    let tables = outcomes[2].as_ref().unwrap();
    assert_eq!(tables.rows.len(), 3);
    assert_eq!(
        tables.warnings,
        ["the query returned 2 tables; showing the first"]
    );
    let refusals: Vec<String> = outcomes[3..]
        .iter()
        .map(|outcome| match outcome {
            Err(error @ ConnectorError::Refused { .. }) => error.text(),
            other => panic!("{other:?}"),
        })
        .collect();
    // The 403's code is redacted in the cassette ("code" names a secret): the
    // recorder wrote the bearer's own replay value, so the error masks it.
    assert_eq!(
        refusals,
        [
            "Log Analytics refused the query on replayed: Query could not be parsed at 'whre' on \
             line [1,22]",
            "Log Analytics refused the query on replayed: ***: The provided credentials \
             have insufficient access to perform the requested operation",
        ]
    );
}

#[test]
fn sentinel_validate_searches_one_row() {
    let inputs = fixture("sentinel");
    let validate = inputs.get("validate").unwrap();
    let window = window(validate.get("window").unwrap());
    let tenant = replay("sentinel/validate");
    let connector = connector();
    let checks = block_on(async {
        let mut checks = Vec::new();
        for query in items(validate.get("queries").unwrap()) {
            checks.push(
                connector
                    .check(tenant.cx(), &QueryRequest::new(text(query), "kql", window))
                    .await
                    .unwrap(),
            );
        }
        checks
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    for check in &checks {
        assert_eq!(check.result.as_ref().unwrap().rows.len(), 1);
        assert!(check.errors.is_empty());
    }
}

/// The cassette `sentinel/deploy`'s sign-in and first list page, the page's
/// `nextLink` set to *link*.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failed set-up is a failure"
)]
fn listing_linking_to(link: &str) -> opentide_cassette::Cassette {
    let full = support::cassette("sentinel/deploy");
    let mut page = full.interactions[4].clone();
    let mut body: serde_json::Value = serde_json::from_slice(&page.response.body.bytes()).unwrap();
    body["nextLink"] = serde_json::Value::String(link.to_owned());
    page.response.body = opentide_cassette::cassette::Body::Text(body.to_string());
    let interactions = vec![
        full.interactions[0].clone(),
        full.interactions[1].clone(),
        page,
    ];
    opentide_cassette::Cassette::new(&full.scenario, full.recorded_from, interactions)
}

#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failed set-up is a failure"
)]
fn list_through(
    cassette: opentide_cassette::Cassette,
) -> (Result<usize, ConnectorError>, Replayed) {
    let tenant = Replayed::start_with(
        cassette,
        sentinel::PLATFORM,
        SETUP,
        "AZURE_CLIENT_SECRET",
        &sentinel::http_settings(Duration::from_secs(60)),
    );
    let listed = block_on(async { connector().list(tenant.cx()).await })
        .unwrap()
        .map(|rules| rules.unwrap().len());
    (listed, tenant)
}

/// #1142: a `nextLink` to another host is not followed, so ARM's bearer
/// token never reaches it; the listing fails and says why.
#[test]
fn sentinel_a_next_link_to_another_host_receives_no_token() {
    let (listed, tenant) = list_through(listing_linking_to("https://evil.example/loop"));
    let error = listed.unwrap_err();
    assert!(matches!(error, ConnectorError::Answer { .. }), "{error:?}");
    assert_eq!(
        error.to_string(),
        "sentinel tenant 'replayed' at https://management.azure.com: listing the analytics rules: \
         the next-page link points to https://evil.example, not to https://management.azure.com, \
         where the listing started; it is not followed, so the tenant's token is not sent there"
    );
    // The sign-in and the one page, and nothing sent to evil.example.
    assert_eq!(tenant.verify(), Vec::new());
}

/// #1142: a `nextLink` back to the page itself ends the listing with an
/// error, never an endless loop.
#[test]
fn sentinel_a_next_link_that_loops_is_not_followed() {
    let first = "https://management.azure.com/subscriptions/sub-0001/resourceGroups/soc-rg/\
                 providers/Microsoft.OperationalInsights/workspaces/soc%20workspace/providers/\
                 Microsoft.SecurityInsights/alertRules?api-version=2025-10-01-preview";
    let (listed, tenant) = list_through(listing_linking_to(first));
    let error = listed.unwrap_err().to_string();
    assert!(
        error.ends_with(
            "the next-page link repeats one already followed; the listing would never end"
        ),
        "{error}"
    );
    assert_eq!(tenant.verify(), Vec::new());
}
