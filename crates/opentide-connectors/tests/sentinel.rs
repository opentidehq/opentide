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

/// #1142: a list page that is not JSON (a sign-in or gateway page served
/// with 200) is an error naming its content type, never an empty page.
#[test]
fn sentinel_a_list_page_that_is_not_json_is_an_error() {
    let full = support::cassette("sentinel/deploy");
    let mut page = full.interactions[4].clone();
    page.response.headers = vec![("content-type".into(), "text/html".into())];
    page.response.body = opentide_cassette::cassette::Body::Text(
        "<html><head><title>Sign in</title></head></html>".into(),
    );
    let (listed, tenant) = list_from(opentide_cassette::Cassette::new(
        &full.scenario,
        full.recorded_from,
        vec![
            full.interactions[0].clone(),
            full.interactions[1].clone(),
            page,
        ],
    ));
    let error = listed.unwrap_err();
    assert!(matches!(error, ConnectorError::Answer { .. }), "{error:?}");
    assert!(
        error.to_string().ends_with(
            "listing the analytics rules: the page is not JSON (Content-Type text/html): HTTP \
             200 with an HTML page titled \"Sign in\""
        ),
        "{error}"
    );
    assert_eq!(tenant.verify(), Vec::new());
}

/// `Sentinel::list` on a tenant the cassette serves.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failed set-up is a failure"
)]
fn list_from(cassette: opentide_cassette::Cassette) -> (Result<usize, ConnectorError>, Replayed) {
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

/// #1142: a rule write ARM answers with a redirect the client cannot follow
/// (a 307 without `Location`) is a failure, not a rule written.
#[test]
fn sentinel_a_redirect_answer_is_not_a_rule_written() {
    let inputs = fixture("sentinel");
    let deploy = inputs.get("deploy").unwrap();
    let rule_id = text(deploy.get("rule_id").unwrap());
    let rule = deploy.get("rule").unwrap();
    let full = support::cassette("sentinel/deploy");
    let mut created = full.interactions[2].clone();
    created.response.status = 307;
    created
        .response
        .headers
        .retain(|(name, _)| name != "location");
    let cassette = opentide_cassette::Cassette::new(
        &full.scenario,
        full.recorded_from,
        vec![
            full.interactions[0].clone(),
            full.interactions[1].clone(),
            created,
        ],
    );
    let tenant = Replayed::start_with(
        cassette,
        sentinel::PLATFORM,
        SETUP,
        "AZURE_CLIENT_SECRET",
        &sentinel::http_settings(Duration::from_secs(60)),
    );
    let answer = block_on(async {
        connector()
            .create_or_update(tenant.cx(), rule_id, rule)
            .await
    })
    .unwrap()
    .unwrap();
    let error = answer.unwrap_err();
    assert_eq!(error.status, 307, "{error}");
    assert_eq!(tenant.verify(), Vec::new());
}

/// OT-3: `deploy` reads the rule it writes before it writes it. A cassette of
/// the sign-in, each `GET` the connector sends (*reads*: status and body)
/// and, when the rule is written, the recorded `PUT` of *sent*.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failed set-up is a failure"
)]
fn deploy_reading(
    reads: &[(u16, Option<serde_json::Value>)],
    sent: &serde_json::Value,
    writes: bool,
) -> (
    Result<
        opentide_connectors::connector::DeployOutcome,
        opentide_connectors::connector::DeployError,
    >,
    Replayed,
) {
    use opentide_connectors::connector::{DeployRequest, Deployer, Operation};
    let inputs = fixture("sentinel");
    let rule_id = text(inputs.get("deploy").unwrap().get("rule_id").unwrap());
    let full = support::cassette("sentinel/deploy");
    let mut interactions = vec![full.interactions[0].clone(), full.interactions[1].clone()];
    for (status, body) in reads {
        let mut read = full.interactions[6].clone();
        read.request.method = "GET".into();
        read.response.status = *status;
        read.response.body = opentide_cassette::cassette::Body::Text(
            body.as_ref().map(ToString::to_string).unwrap_or_default(),
        );
        interactions.push(read);
    }
    if writes {
        let mut write = full.interactions[2].clone();
        write.request.body = opentide_cassette::cassette::Body::Text(sent.to_string());
        interactions.push(write);
    }
    let tenant = Replayed::start_with(
        opentide_cassette::Cassette::new(&full.scenario, full.recorded_from, interactions),
        sentinel::PLATFORM,
        SETUP,
        "AZURE_CLIENT_SECRET",
        &sentinel::http_settings(Duration::from_secs(60)),
    );
    let request = DeployRequest::new(
        rule_id.to_owned(),
        Operation::Update,
        sent.to_string().into_bytes(),
    );
    let done = block_on(async { connector().deploy(tenant.cx(), &request).await }).unwrap();
    (done, tenant)
}

/// The rule the fixture deploys, as sent.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failed set-up is a failure"
)]
fn sent_rule() -> serde_json::Value {
    let inputs = fixture("sentinel");
    serde_json::from_str(
        &inputs
            .get("deploy")
            .unwrap()
            .get("rule")
            .unwrap()
            .to_compact(),
    )
    .unwrap()
}

/// The rule as the cassette's `PUT` answered it: what was sent, with the
/// members ARM adds (`name`, `etag`).
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failed set-up is a failure"
)]
fn held_rule() -> serde_json::Value {
    let full = support::cassette("sentinel/deploy");
    serde_json::from_slice(&full.interactions[2].response.body.bytes()).unwrap()
}

fn event_of(done: &opentide_connectors::connector::DeployOutcome) -> Vec<&str> {
    done.events
        .iter()
        .map(|event| event.name.as_str())
        .collect()
}

/// *edit* applied to a copy of the cassette's rule.
fn edited(edit: impl Fn(&mut serde_json::Value)) -> serde_json::Value {
    let mut rule = held_rule();
    edit(&mut rule);
    rule
}

#[test]
fn sentinel_a_rule_the_workspace_lacks_is_created() {
    let (done, tenant) = deploy_reading(&[(404, None)], &sent_rule(), true);
    assert_eq!(event_of(&done.unwrap()), ["sentinel_rule_created"]);
    assert_eq!(tenant.verify(), Vec::new());
}

#[test]
fn sentinel_a_rule_the_workspace_holds_as_sent_is_unchanged_and_not_written() {
    // No `PUT` is in the cassette: one sent would be a mismatch.
    let (done, tenant) = deploy_reading(&[(200, Some(held_rule()))], &sent_rule(), false);
    let done = done.unwrap();
    assert!(done.unchanged(), "{done:?}");
    assert_eq!(event_of(&done), ["rule_unchanged"]);
    assert_eq!(tenant.verify(), Vec::new());
}

#[test]
fn sentinel_a_field_that_differs_is_updated() {
    for (field, value) in [
        ("severity", serde_json::json!("Low")),
        ("tactics", serde_json::json!(["Execution", "Persistence"])),
        ("enabled", serde_json::json!(false)),
        ("query", serde_json::json!("SecurityEvent | take 1")),
    ] {
        let held = edited(|rule| rule["properties"][field] = value.clone());
        let (done, tenant) = deploy_reading(&[(200, Some(held))], &sent_rule(), true);
        assert_eq!(
            event_of(&done.unwrap()),
            ["sentinel_rule_updated"],
            "{field}"
        );
        assert_eq!(tenant.verify(), Vec::new(), "{field}");
    }
}

#[test]
fn sentinel_a_disabled_rule_held_enabled_is_updated() {
    let mut sent = sent_rule();
    sent["properties"]["enabled"] = false.into();
    let (done, tenant) = deploy_reading(&[(200, Some(held_rule()))], &sent, true);
    assert_eq!(event_of(&done.unwrap()), ["sentinel_rule_updated"]);
    assert_eq!(tenant.verify(), Vec::new());
}

#[test]
fn sentinel_what_arm_writes_itself_is_not_a_difference() {
    let held = edited(|rule| {
        rule["etag"] = "\"another\"".into();
        rule["id"] = "/subscriptions/x/alertRules/y".into();
        rule["type"] = "Microsoft.SecurityInsights/alertRules".into();
        rule["systemData"] = serde_json::json!({"lastModifiedBy": "someone"});
        rule["properties"]["lastModifiedUtc"] = "2026-01-01T00:00:00Z".into();
        // Members ARM answers empty for what nobody set.
        rule["properties"]["alertRuleTemplateName"] = serde_json::Value::Null;
        rule["properties"]["customDetails"] = serde_json::Value::Null;
        rule["properties"]["entityMappings"] = serde_json::json!([]);
        rule["properties"]["alertDetailsOverride"] = serde_json::json!({});
    });
    let (done, tenant) = deploy_reading(&[(200, Some(held))], &sent_rule(), false);
    assert!(done.unwrap().unchanged());
    assert_eq!(tenant.verify(), Vec::new());
}

#[test]
fn sentinel_an_empty_container_sent_is_a_missing_or_null_member_held() {
    let mut sent = sent_rule();
    sent["properties"]["alertDetailsOverride"] = serde_json::json!({});
    sent["properties"]["customDetails"] = serde_json::json!({});
    sent["properties"]["entityMappings"] = serde_json::json!([]);
    // Missing on the tenant, and `null` there.
    for held in [
        held_rule(),
        edited(|rule| {
            rule["properties"]["alertDetailsOverride"] = serde_json::Value::Null;
            rule["properties"]["customDetails"] = serde_json::Value::Null;
            rule["properties"]["entityMappings"] = serde_json::Value::Null;
        }),
    ] {
        let (done, tenant) = deploy_reading(&[(200, Some(held))], &sent, false);
        assert!(done.unwrap().unchanged());
        assert_eq!(tenant.verify(), Vec::new());
    }
}

#[test]
fn sentinel_a_duration_is_the_same_in_arms_form_and_opentides() {
    // ARM answers `PT1H`; opentide sends `PT01H00M00S`.
    let mut sent = sent_rule();
    for key in ["queryFrequency", "queryPeriod", "suppressionDuration"] {
        sent["properties"][key] = "PT01H00M00S".into();
    }
    let held = edited(|rule| {
        for key in ["queryFrequency", "queryPeriod", "suppressionDuration"] {
            rule["properties"][key] = "PT1H".into();
        }
    });
    let (done, tenant) = deploy_reading(&[(200, Some(held))], &sent, false);
    assert!(done.unwrap().unchanged());
    assert_eq!(tenant.verify(), Vec::new());
    // Another length is a difference.
    let held = edited(|rule| rule["properties"]["queryPeriod"] = "PT2H".into());
    let (done, tenant) = deploy_reading(&[(200, Some(held))], &sent, true);
    assert_eq!(event_of(&done.unwrap()), ["sentinel_rule_updated"]);
    assert_eq!(tenant.verify(), Vec::new());
    // The lookback of incident grouping is read the same way.
    let mut sent = sent_rule();
    let grouping = |lookback: &str| {
        serde_json::json!({"createIncident": true, "groupingConfiguration":
            {"enabled": true, "lookbackDuration": lookback}})
    };
    sent["properties"]["incidentConfiguration"] = grouping("PT05H00M00S");
    let held = edited(|rule| rule["properties"]["incidentConfiguration"] = grouping("PT5H"));
    let (done, tenant) = deploy_reading(&[(200, Some(held))], &sent, false);
    assert!(done.unwrap().unchanged());
    assert_eq!(tenant.verify(), Vec::new());
}

/// A member opentide no longer sends keeps its value on the workspace until
/// a write replaces the rule, so the rule is written, never `unchanged`.
#[test]
fn sentinel_a_member_no_longer_sent_is_a_difference() {
    let grouping = |extra: serde_json::Value| {
        let mut configuration = serde_json::json!({"enabled": false});
        if let Some(extra) = extra.as_object() {
            for (key, value) in extra {
                configuration[key] = value.clone();
            }
        }
        serde_json::json!({"createIncident": true, "groupingConfiguration": configuration})
    };
    type Edit = Box<dyn Fn(&mut serde_json::Value)>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "alert title",
            Box::new(|r| {
                r["properties"]["alertDetailsOverride"] =
                    serde_json::json!({"alertDisplayNameFormat": "{{Computer}}"});
            }),
        ),
        (
            "alert description",
            Box::new(|r| {
                r["properties"]["alertDetailsOverride"] =
                    serde_json::json!({"alertDescriptionFormat": "{{Account}}"});
            }),
        ),
        (
            "a custom detail",
            Box::new(|r| {
                r["properties"]["customDetails"] = serde_json::json!({"Host": "Computer"});
            }),
        ),
        (
            "entities",
            Box::new(|r| {
                r["properties"]["entityMappings"] = serde_json::json!([
                    {"entityType": "Host", "fieldMappings": [
                        {"identifier": "HostName", "columnName": "Computer"}]}
                ]);
            }),
        ),
        (
            "the template link",
            Box::new(|r| {
                r["properties"]["alertRuleTemplateName"] =
                    "11111111-2222-4333-8444-555555555555".into();
            }),
        ),
        (
            "group by entities",
            Box::new(move |r| {
                r["properties"]["incidentConfiguration"] =
                    grouping(serde_json::json!({"groupByEntities": ["Host"]}));
            }),
        ),
    ];
    for (removed, edit) in &cases {
        let mut held = held_rule();
        edit(&mut held);
        let (done, tenant) = deploy_reading(&[(200, Some(held))], &sent_rule(), true);
        assert_eq!(
            event_of(&done.unwrap()),
            ["sentinel_rule_updated"],
            "{removed}"
        );
        assert_eq!(tenant.verify(), Vec::new(), "{removed}");
    }
    // A member of the rule as it is held, taken from what is sent.
    for (removed, keys) in [
        ("the trigger", &["triggerOperator", "triggerThreshold"][..]),
        ("a sub-technique", &["subTechniques"][..]),
    ] {
        let mut sent = sent_rule();
        for key in keys {
            sent["properties"].as_object_mut().unwrap().remove(*key);
        }
        // The trigger held is not ARM's default (`GreaterThan`, `0`).
        let held = edited(|rule| rule["properties"]["triggerThreshold"] = 3.into());
        let (done, tenant) = deploy_reading(&[(200, Some(held))], &sent, true);
        assert_eq!(
            event_of(&done.unwrap()),
            ["sentinel_rule_updated"],
            "{removed}"
        );
        assert_eq!(tenant.verify(), Vec::new(), "{removed}");
    }
}

/// ARM answers a Scheduled rule with a trigger (`GreaterThan`, `0`) even when
/// the rule sends none, so that is not a difference.
#[test]
fn sentinel_the_triggers_defaults_are_not_a_difference() {
    let mut sent = sent_rule();
    for key in ["triggerOperator", "triggerThreshold"] {
        sent["properties"].as_object_mut().unwrap().remove(key);
    }
    let held = edited(|rule| {
        rule["properties"]["triggerOperator"] = "GreaterThan".into();
        rule["properties"]["triggerThreshold"] = 0.into();
    });
    let (done, tenant) = deploy_reading(&[(200, Some(held))], &sent, false);
    assert!(done.unwrap().unchanged());
    assert_eq!(tenant.verify(), Vec::new());
    // Another operator is a difference.
    let held = edited(|rule| {
        rule["properties"]["triggerOperator"] = "LessThan".into();
        rule["properties"]["triggerThreshold"] = 0.into();
    });
    let (done, tenant) = deploy_reading(&[(200, Some(held))], &sent, true);
    assert_eq!(event_of(&done.unwrap()), ["sentinel_rule_updated"]);
    assert_eq!(tenant.verify(), Vec::new());
}

/// A `customDetails` key named like a duration is no duration: `PT1H` and
/// `PT01H00M00S` there are two values.
#[test]
fn sentinel_a_duration_is_read_only_where_a_rule_has_one() {
    let mut sent = sent_rule();
    sent["properties"]["customDetails"] = serde_json::json!({"queryPeriod": "PT01H00M00S"});
    let held = edited(|rule| {
        rule["properties"]["customDetails"] = serde_json::json!({"queryPeriod": "PT1H"});
    });
    let (done, tenant) = deploy_reading(&[(200, Some(held))], &sent, true);
    assert_eq!(event_of(&done.unwrap()), ["sentinel_rule_updated"]);
    assert_eq!(tenant.verify(), Vec::new());
}

#[test]
fn sentinel_a_throttled_read_is_retried() {
    let (done, tenant) = deploy_reading(
        &[(429, None), (200, Some(held_rule()))],
        &sent_rule(),
        false,
    );
    assert!(done.unwrap().unchanged());
    assert_eq!(tenant.verify(), Vec::new());
}

#[test]
fn sentinel_a_failed_read_fails_the_rule_and_writes_nothing() {
    // A 403, which is not retried; the cassette has no `PUT`.
    let body = serde_json::json!({"error": {"code": "AuthorizationFailed", "message": "no"}});
    let (done, tenant) = deploy_reading(&[(403, Some(body))], &sent_rule(), false);
    let error = done.unwrap_err();
    assert!(error.to_string().contains("403"), "{error}");
    assert_eq!(tenant.verify(), Vec::new());
}

#[test]
fn sentinel_a_read_answered_with_a_page_fails_the_rule_and_writes_nothing() {
    let (answer, tenant) = {
        use opentide_connectors::connector::{DeployRequest, Deployer, Operation};
        let full = support::cassette("sentinel/deploy");
        let mut read = full.interactions[6].clone();
        read.request.method = "GET".into();
        read.response.status = 200;
        read.response.body =
            opentide_cassette::cassette::Body::Text("<html><title>Gateway</title></html>".into());
        let tenant = Replayed::start_with(
            opentide_cassette::Cassette::new(
                &full.scenario,
                full.recorded_from,
                vec![
                    full.interactions[0].clone(),
                    full.interactions[1].clone(),
                    read,
                ],
            ),
            sentinel::PLATFORM,
            SETUP,
            "AZURE_CLIENT_SECRET",
            &sentinel::http_settings(Duration::from_secs(60)),
        );
        let request = DeployRequest::new(
            "00000000-0000-4000-8003-000000000001".to_owned(),
            Operation::Update,
            sent_rule().to_string().into_bytes(),
        );
        (
            block_on(async { connector().deploy(tenant.cx(), &request).await }).unwrap(),
            tenant,
        )
    };
    assert!(answer.is_err(), "{answer:?}");
    assert_eq!(tenant.verify(), Vec::new());
}
