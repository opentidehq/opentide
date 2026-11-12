//! Carbon Black Cloud against the cassettes recorded from the Python client
//! (cbc_sdk; `tests/cassettes/carbon_black/`, `cargo xtask cassettes record
//! carbon_black/<scenario>`): every request the connector sends must be the
//! Python client's, byte for byte and in order, and the answers must read as
//! Python read them (the outcomes `client.py` printed).

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod support;

use std::time::Duration;

use opentide_compile::json::Json;
use opentide_connectors::ConnectorError;
use opentide_connectors::carbon_black::{self, CarbonBlack, ReportChange, ReportDeploy};
use opentide_connectors::connector::QueryRequest;
use opentide_connectors::runtime::block_on;
use support::{Replayed, fixture, items, text, window};

const SETUP: &str = r#"
ssl = true
url = "https://cbc.invalid"
org_key = "ORGKEY01"
token = "$CBC_TOKEN"
watchlist = "opentide"
"#;

fn replay(scenario: &str) -> Replayed {
    Replayed::start(
        scenario,
        carbon_black::PLATFORM,
        SETUP,
        "CBC_TOKEN",
        &carbon_black::http_settings(Duration::from_secs(120)),
    )
}

/// What `_deploy_to_org` works out for one step of `client.py`: tags are
/// the status and the block's own (the rules have no detection model).
fn plan(step: &Json, now: i64) -> ReportDeploy {
    let status = text(step.get("status").unwrap());
    let name = text(step.get("name").unwrap()).trim().to_owned();
    let mut tags = vec![status.to_owned()];
    if let Some(Json::Array(extra)) = step.get("tags") {
        tags.extend(extra.iter().map(|tag| text(tag).to_owned()));
    }
    let severity = match text(step.get("alert_severity").unwrap()) {
        "High" => 8,
        other => panic!("{other}"),
    };
    ReportDeploy {
        uuid: text(step.get("uuid").unwrap()).to_owned(),
        description: text(step.get("description").unwrap()).trim().to_owned(),
        query: text(step.get("query").unwrap()).to_owned(),
        deployment: !matches!(status, "DISABLED" | "REMOVED"),
        tags,
        severity,
        watchlist: text(step.get("watchlist").unwrap()).to_owned(),
        report: step
            .get("report")
            .and_then(Json::as_str)
            .map_or_else(|| name.clone(), str::to_owned),
        name,
        now,
    }
}

#[test]
fn carbon_black_deploy_sends_what_the_python_deployer_sent() {
    let inputs = fixture("carbon_black");
    let Json::Int(now) = inputs.get("now").unwrap() else {
        panic!("now is a number")
    };
    let tenant = replay("carbon_black/deploy");
    let connector = CarbonBlack;
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for step in items(inputs.get("deploy").unwrap()) {
            outcomes.push(
                connector
                    .deploy_report(tenant.cx(), &plan(step, *now))
                    .await,
            );
        }
        outcomes
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    let changes: Vec<Option<ReportChange>> = outcomes[..5]
        .iter()
        .map(|outcome| outcome.as_ref().ok().copied())
        .collect();
    assert_eq!(
        changes,
        [
            Some(ReportChange::Created),
            Some(ReportChange::Updated),
            Some(ReportChange::Updated),
            Some(ReportChange::IocRemoved),
            Some(ReportChange::Deleted),
        ]
    );
    match &outcomes[5] {
        Err(error @ ConnectorError::Refused { .. }) => assert_eq!(
            error.text(),
            "The CBC Deployer cannot create a detection in a nonexistent Watchlist: absent. \
             Create it on the console before retriggering deployment."
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn carbon_black_a_single_byte_off_fails() {
    let inputs = fixture("carbon_black");
    // The report stamped one second later: the create's body differs.
    let step = plan(&items(inputs.get("deploy").unwrap())[0], 1_793_088_001);
    let tenant = replay("carbon_black/deploy");
    let _ = block_on(async { CarbonBlack.deploy_report(tenant.cx(), &step).await });
    let mismatches = tenant.verify();
    assert_eq!(
        mismatches.first().map(|m| m.index),
        Some(3),
        "{mismatches:?}"
    );
    assert!(mismatches[0].detail.starts_with("bodies differ at byte "));
}

#[test]
fn carbon_black_query_sends_what_the_python_runner_sent() {
    let inputs = fixture("carbon_black");
    let query = inputs.get("query").unwrap();
    let window = window(query.get("window").unwrap());
    let tenant = replay("carbon_black/query");
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for item in items(query.get("queries").unwrap()) {
            let mut request = QueryRequest::new(text(item.get("text").unwrap()), "lucene", window);
            request.limit = usize::try_from(match item.get("limit").unwrap() {
                Json::Int(limit) => *limit,
                _ => 100,
            })
            .unwrap();
            outcomes.push(CarbonBlack.run(tenant.cx(), &request).await);
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
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        [
            "process_name",
            "process_pid",
            "device_name",
            "device_timestamp",
            "process_guid",
            "backend_timestamp",
            "process_hash",
            "parent.name",
            "parent.pid"
        ]
    );
    assert_eq!(first.rows.len(), 2);
    assert!(first.truncated);
    assert_eq!(first.rows[1].get("parent.pid"), Some(&Json::Int(102)));
    let empty = outcomes[1].as_ref().unwrap();
    assert!(empty.rows.is_empty() && empty.columns.is_empty() && !empty.truncated);
    let refusals: Vec<String> = outcomes[2..]
        .iter()
        .map(|outcome| match outcome {
            Err(error @ ConnectorError::Refused { .. }) => error.text(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        refusals,
        [
            "Carbon Black Cloud refused the query on replayed: Invalid query: {'time_range': \
             {'start': '2026-10-26T08:00:00.000Z', 'end': '2026-10-27T08:00:00.000Z'}, 'query': \
             'process_name:(cmd.exe', 'sort': None}: unbalanced parenthesis",
            "Carbon Black Cloud refused the query on replayed: Received error code 403 from API: \
             {\"error_code\": \"FORBIDDEN\", \"message\": \"Access denied to process search\"}",
        ]
    );
}

#[test]
fn carbon_black_validate_asks_search_validation() {
    let inputs = fixture("carbon_black");
    let validate = inputs.get("validate").unwrap();
    let window = window(validate.get("window").unwrap());
    let tenant = replay("carbon_black/validate");
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for query in items(validate.get("queries").unwrap()) {
            let request = QueryRequest::new(text(query), "lucene", window).for_check();
            outcomes.push(CarbonBlack.check(tenant.cx(), &request).await);
        }
        outcomes
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert!(outcomes[0].is_ok());
    match &outcomes[1] {
        Err(error @ ConnectorError::Refused { .. }) => assert_eq!(
            error.text(),
            "Carbon Black Cloud refused the query on replayed: ensure each term has a value, and \
             escape slashes, colons and spaces"
        ),
        other => panic!("{other:?}"),
    }
}
