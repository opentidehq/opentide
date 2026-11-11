//! SentinelOne against the cassettes recorded from the Python client
//! (`tests/cassettes/sentinel_one/`, `cargo xtask cassettes record
//! sentinel_one/<scenario>`): every request the connector sends must be the
//! Python client's, byte for byte and in order.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod support;

use opentide_compile::json::Json;
use opentide_connectors::runtime::block_on;
use opentide_connectors::search::{SearchError, SearchRequest};
use opentide_connectors::sentinel_one::{self, QueryValidation, SentinelOne, SentinelOneError};
use support::{Replayed, fixture, items, text, window};

const SETUP: &str = r#"
url = "https://s1.invalid"
api_token = "$S1_API_TOKEN"
account_id = 4242
site_id = 77
"#;

fn replay(scenario: &str) -> Replayed {
    Replayed::start(
        scenario,
        sentinel_one::PLATFORM,
        SETUP,
        "S1_API_TOKEN",
        &sentinel_one::http_settings(),
    )
}

fn limit(item: &Json) -> usize {
    match item.get("limit") {
        Some(Json::Int(limit)) => usize::try_from(*limit).unwrap(),
        _ => 100,
    }
}

#[test]
fn sentinel_one_deploy_sends_what_the_python_client_sent() {
    let inputs = fixture("sentinel_one");
    let deploy = inputs.get("deploy").unwrap();
    let rules = items(deploy.get("rules").unwrap());
    let validate = inputs.get("validate").unwrap();
    let now = window(validate.get("window").unwrap()).end;
    let tenant = replay("sentinel_one/deploy");
    let connector = SentinelOne;
    let cx = tenant.cx();
    let seen = block_on(async {
        let first = connector
            .create_update_rule(cx, &rules[0], None)
            .await
            .unwrap();
        let second = connector
            .create_update_rule(cx, &rules[1], None)
            .await
            .unwrap();
        let updated = connector
            .create_update_rule(cx, &rules[0], Some(first))
            .await
            .unwrap();
        let missing = connector.create_update_rule(cx, &rules[0], Some(999)).await;
        assert!(
            matches!(missing, Err(SentinelOneError::NotFound { .. })),
            "{missing:?}"
        );
        connector.disable_rule(cx, first).await.unwrap();
        connector.delete_rule(cx, first).await.unwrap();
        let mut validations = Vec::new();
        for query in items(deploy.get("validations").unwrap()) {
            validations.push(
                connector
                    .validate_query(cx, text(query), now)
                    .await
                    .unwrap(),
            );
        }
        (first, second, updated, validations)
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(
        seen,
        (
            1_900_000_000_000_000_001,
            1_900_000_000_000_000_002,
            1_900_000_000_000_000_001,
            vec![
                QueryValidation::Ran,
                QueryValidation::Refused("Syntax error at 3".into())
            ]
        )
    );
}

#[test]
fn sentinel_one_a_single_byte_off_fails() {
    let inputs = fixture("sentinel_one");
    let mut rule = items(inputs.get("deploy").unwrap().get("rules").unwrap())[0].clone();
    if let Json::Object(top) = &mut rule
        && let Some(Json::Object(data)) = top.get_mut("data")
    {
        data.insert("severity".into(), Json::Str("Higi".into()));
    }
    let tenant = replay("sentinel_one/deploy");
    let _ = block_on(async {
        SentinelOne
            .create_update_rule(tenant.cx(), &rule, None)
            .await
    });
    let mismatches = tenant.verify();
    assert_eq!(mismatches[0].index, 0, "{mismatches:?}");
    assert!(mismatches[0].detail.starts_with("bodies differ at byte "));
}

#[test]
fn sentinel_one_query_polls_as_the_python_runner_does() {
    let inputs = fixture("sentinel_one");
    let query = inputs.get("query").unwrap();
    let window = window(query.get("window").unwrap());
    let tenant = replay("sentinel_one/query");
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for item in items(query.get("queries").unwrap()) {
            let mut request = SearchRequest::new(text(item.get("text").unwrap()), window);
            request.limit = limit(item);
            outcomes.push(SentinelOne.run(tenant.cx(), &request).await);
        }
        outcomes
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    let polled = outcomes[0].as_ref().unwrap();
    assert_eq!(polled.vendor_query_id.as_deref(), Some("pq-1"));
    assert!(polled.truncated);
    assert_eq!(
        polled.rows,
        [serde_json::from_str::<Json>(
            r#"{"src.process.name": "cmd.exe", "endpoint.name": "ws-1"}"#
        )
        .unwrap()]
    );
    assert_eq!(
        polled.warnings,
        ["Add a filter on event.type to speed up the query"]
    );
    let finished = outcomes[1].as_ref().unwrap();
    assert_eq!(finished.rows.len(), 2);
    assert_eq!(finished.sent, None);
    let refusals: Vec<String> = outcomes[2..]
        .iter()
        .map(|outcome| match outcome {
            Err(refused @ SearchError::Refused { .. }) => refused.text(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        refusals,
        [
            "SentinelOne refused the PowerQuery on replayed (HTTP 400): Syntax error at 3",
            "the PowerQuery ended failed: out of memory",
        ]
    );
}

#[test]
fn sentinel_one_query_gives_up_at_the_timeout() {
    let inputs = fixture("sentinel_one");
    let query = inputs.get("query").unwrap();
    let first = &items(query.get("queries").unwrap())[0];
    let mut request = SearchRequest::new(
        text(first.get("text").unwrap()),
        window(query.get("window").unwrap()),
    );
    request.limit = limit(first);
    request.timeout = std::time::Duration::from_millis(300);
    let tenant = replay("sentinel_one/query");
    let outcome = block_on(async { SentinelOne.run(tenant.cx(), &request).await }).unwrap();
    match outcome {
        Err(SearchError::TimedOut {
            message, timeout, ..
        }) => {
            assert_eq!(
                message,
                "the PowerQuery did not finish within 0.3s on replayed"
            );
            assert!((timeout - 0.3).abs() < f64::EPSILON);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn sentinel_one_validate_checks_one_row_over_the_minute() {
    let inputs = fixture("sentinel_one");
    let validate = inputs.get("validate").unwrap();
    let window = window(validate.get("window").unwrap());
    let tenant = replay("sentinel_one/validate");
    let rows = block_on(async {
        let mut rows = Vec::new();
        for query in items(validate.get("queries").unwrap()) {
            let checked = SentinelOne
                .check(tenant.cx(), &SearchRequest::new(text(query), window))
                .await
                .unwrap();
            rows.push((checked.rows.len(), checked.truncated, checked.sent));
        }
        rows
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(
        rows,
        [
            (
                1,
                true,
                Some("EventType = \"Process Create\"\n| limit 2".to_owned())
            ),
            (
                1,
                true,
                Some("src.process.name = 'cmd.exe'\n| limit 2".to_owned())
            ),
        ]
    );
}
