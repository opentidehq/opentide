//! CrowdStrike against the cassettes the Python client recorded
//! (`tests/cassettes/crowdstrike/`): the deployer and the CQL runner send
//! the Python client's requests, in order (a JSON body as the same data), and read the
//! answers as it does (the outcomes `client.py` printed when it recorded).

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod cassette_support;

use std::time::Duration;

use cassette_support::{json, replay, rows, tenant, window};
use opentide_compile::Json;
use opentide_compile::json::Object;
use opentide_connectors::ConnectorError;
use opentide_connectors::connector::{
    DEFAULT_LIMIT, DEFAULT_QUERY_TIMEOUT, DeployRequest, Operation, QueryRequest, TenantContext,
};
use opentide_connectors::crowdstrike::{self, Crowdstrike};
use opentide_connectors::runtime::block_on;
use opentide_connectors::{Platform, Registry};
use tokio_util::sync::CancellationToken;

const SECRET: (&str, &str) = ("CROWDSTRIKE_CLIENT_SECRET", "cs-test-secret-only");

const SETUP: &str = r#"
ssl = true
api = "EU-1"
client_id = "opentide-client"
client_secret = "$CROWDSTRIKE_CLIENT_SECRET"
customer_id = "0123456789ABCDEF-12"
"#;

/// The correlation rule `client.py` deploys (`DetectionRule`, `null`s left
/// out), in its dataclass's key order.
fn rule(name: &str, status: &str) -> Object {
    let object = |pairs: Vec<(&str, Json)>| {
        Json::Object(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    };
    let Json::Object(body) = object(vec![
        ("name", name.into()),
        (
            "description",
            "Encoded PowerShell — Ünïcode \"quoted\"".into(),
        ),
        ("customer_id", "0123456789abcdef".into()),
        ("severity", Json::Int(70)),
        (
            "search",
            object(vec![
                ("outcome", "detection".into()),
                (
                    "filter",
                    "#event_simpleName=ProcessRollup2 CommandLine=/-enc/i\n| groupBy([aid])".into(),
                ),
                ("lookback", "1h0m".into()),
                ("trigger_mode", "summary".into()),
            ]),
        ),
        (
            "operation",
            object(vec![
                (
                    "schedule",
                    object(vec![("definition", "@every 1h0m".into())]),
                ),
                ("start_on", "2025-04-15T19:00:00Z".into()),
            ]),
        ),
        ("status", status.into()),
        ("tactic", "TA0002".into()),
        (
            "comment",
            "Updated by opentide Crowdstrike Deployer - Author(s) : Amine, Zoé".into(),
        ),
    ]) else {
        unreachable!()
    };
    body
}

/// A create's body.
fn create(name: &str) -> Vec<u8> {
    serde_json::to_vec(&Json::Object(rule(name, "active"))).unwrap()
}

/// An update's body: the one-rule list with the id last.
fn update(id: &str, name: &str, status: &str) -> Vec<u8> {
    let mut body = rule(name, status);
    body.insert("id".into(), id.into());
    serde_json::to_vec(&Json::Array(vec![Json::Object(body)])).unwrap()
}

fn registry() -> Registry {
    let mut registry = Registry::new();
    registry.register(Box::new(Crowdstrike::new())).unwrap();
    registry
}

fn refusal(error: &ConnectorError) -> (String, Option<String>) {
    match error {
        ConnectorError::Refused {
            message, detail, ..
        }
        | ConnectorError::QueryTimedOut {
            message, detail, ..
        } => (message.clone(), detail.clone()),
        other => panic!("not a refusal: {other}"),
    }
}

#[test]
fn crowdstrike_deploys_as_the_python_client_does() {
    let replay = replay("crowdstrike/deploy", &[SECRET]);
    let (tenant, http) = tenant(
        &replay,
        "crowdstrike",
        "falcon",
        SETUP,
        &crowdstrike::http_defaults(),
    );
    let registry = registry();
    let platform = registry.get("crowdstrike").unwrap();
    assert!(platform.live_validator().is_none(), "no live validation");
    let deployer = platform.deployer().unwrap();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let deploy = |operation, rule_id: &str, body: Vec<u8>| {
        let request = DeployRequest {
            rule_id: rule_id.to_owned(),
            operation,
            body,
        };
        block_on(async { deployer.deploy(cx, &request).await }).unwrap()
    };
    // One token for the run: the rules after the first reuse it.
    let created = deploy(Operation::Create, "", create("Encoded PowerShell")).unwrap();
    assert_eq!(created.remote_id.as_deref(), Some("cs-rule-1"));
    let tuned = "Encoded PowerShell (tuned)";
    let updated = deploy(
        Operation::Update,
        "cs-rule-1",
        update("cs-rule-1", tuned, "active"),
    )
    .unwrap();
    assert_eq!(updated.remote_id.as_deref(), Some("cs-rule-1"));
    deploy(
        Operation::Disable,
        "cs-rule-1",
        update("cs-rule-1", tuned, "inactive"),
    )
    .unwrap();
    let deleted = deploy(Operation::Delete, "cs-rule-1", Vec::new()).unwrap();
    assert_eq!(deleted.remote_id, None);

    let refused = deploy(Operation::Create, "", create("Rejected rule")).unwrap_err();
    assert_eq!(
        refusal(&refused).0,
        "Was not able to create rule against tenant falcon - Error Code 400"
    );
    assert!(
        refusal(&refused)
            .1
            .unwrap()
            .contains("search.filter: invalid query")
    );
    let refused = deploy(
        Operation::Update,
        "cs-rule-1",
        update("cs-rule-1", "Rejected rule", "active"),
    )
    .unwrap_err();
    assert_eq!(
        refusal(&refused).0,
        "Was not able to update rule with id cs-rule-1 against tenant falcon - Error Code 400"
    );
    let refused = deploy(Operation::Delete, "cs-rule-missing", Vec::new()).unwrap_err();
    assert_eq!(
        refusal(&refused).0,
        "Was not able to delete rule with ID cs-rule-missing against tenant falcon - Error Code 404"
    );
    assert_eq!(refused.failure_code(), "command_failed");
    assert_eq!(replay.proxy.verify(), Vec::new());
}

#[test]
fn crowdstrike_a_body_one_byte_off_fails_the_replay() {
    let replay = replay("crowdstrike/deploy", &[SECRET]);
    let (tenant, http) = tenant(
        &replay,
        "crowdstrike",
        "falcon",
        SETUP,
        &crowdstrike::http_defaults(),
    );
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let request = DeployRequest {
        rule_id: String::new(),
        operation: Operation::Create,
        body: create("Encoded PowerShelL"),
    };
    let platform = Crowdstrike::new();
    let _ = block_on(async { platform.deployer().unwrap().deploy(cx, &request).await });
    let mismatches = replay.proxy.verify();
    assert_eq!(
        mismatches.first().map(|m| m.index),
        Some(1),
        "{mismatches:?}"
    );
}

fn query(text: &str, limit: usize, index: &[&str], timeout: Duration) -> QueryRequest {
    QueryRequest {
        text: text.to_owned(),
        language: "cql".to_owned(),
        window: window(),
        limit,
        index: index.iter().map(|name| (*name).to_owned()).collect(),
        data_view: None,
        timeout,
    }
}

#[test]
fn crowdstrike_runs_and_stops_query_jobs_as_the_python_runner_does() {
    let replay = replay("crowdstrike/query", &[SECRET]);
    let (tenant, http) = tenant(
        &replay,
        "crowdstrike",
        "falcon",
        SETUP,
        &crowdstrike::http_defaults(),
    );
    let registry = registry();
    let runner = registry.get("crowdstrike").unwrap().query_runner().unwrap();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let run = |request: QueryRequest| block_on(async { runner.run(cx, &request).await }).unwrap();

    // Polled until done, cut to its limit of 1.
    let first = run(query(
        "#event_simpleName=ProcessRollup2",
        1,
        &[],
        DEFAULT_QUERY_TIMEOUT,
    ))
    .unwrap();
    let columns: Vec<&str> = first.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(columns, ["ComputerName", "aid.id", "aid.cid", "@timestamp"]);
    assert_eq!(
        rows(&first.rows),
        json(
            r#"[{"ComputerName": "ws-01", "aid.id": "a1", "aid.cid": "c1", "@timestamp": 1761465600000}]"#
        )
    );
    assert!(first.truncated);
    assert_eq!(first.warnings, ["the search hit a limit", "plain warning"]);
    assert_eq!(first.vendor_query_id.as_deref(), Some("search-all-job-1"));
    assert_eq!(
        first.sent.as_deref(),
        Some("#event_simpleName=ProcessRollup2\n| head(limit=2)")
    );
    assert_eq!(first.language.as_deref(), Some("cql"));

    // Its own head, sent as written (trimmed); every event that is an object.
    let second = run(query(
        "  #event_simpleName=DnsRequest | head(limit=5)  ",
        DEFAULT_LIMIT,
        &["investigate_view"],
        DEFAULT_QUERY_TIMEOUT,
    ))
    .unwrap();
    assert_eq!(
        rows(&second.rows),
        json(
            r#"[{"ComputerName": "ws-01", "aid.id": "a1", "aid.cid": "c1", "@timestamp": 1761465600000},
                {"ComputerName": "ws-02", "aid.id": "a2", "UserName": "Ünïcode", "tags": ["x", 1]}]"#
        )
    );
    assert_eq!(second.columns.len(), 6);
    assert!(!second.truncated);
    assert_eq!(second.sent, None);

    // Outlives its timeout: stopped with a DELETE.
    let slow = run(query("x", DEFAULT_LIMIT, &["slow_view"], Duration::ZERO)).unwrap_err();
    assert!(matches!(slow, ConnectorError::QueryTimedOut { .. }));
    assert_eq!(
        refusal(&slow),
        (
            "the search did not finish within 0s on falcon".to_owned(),
            Some("narrow the window or raise --timeout".to_owned())
        )
    );
    // Cancelled by the tenant: stopped too.
    let cancelled = run(query(
        "x",
        DEFAULT_LIMIT,
        &["cancelled_view"],
        DEFAULT_QUERY_TIMEOUT,
    ))
    .unwrap_err();
    assert_eq!(
        refusal(&cancelled),
        ("the search was cancelled on falcon".to_owned(), None)
    );
    // A 403 names the scope; nothing to stop.
    let forbidden = run(query(
        "x",
        DEFAULT_LIMIT,
        &["forbidden_view"],
        DEFAULT_QUERY_TIMEOUT,
    ))
    .unwrap_err();
    assert_eq!(
        refusal(&forbidden),
        (
            "Next-Gen SIEM could not start the search on falcon (HTTP 403)".to_owned(),
            Some("the API client needs the NGSIEM: Read scope".to_owned())
        )
    );
    // Two repositories: refused before any request.
    let two = run(query(
        "x",
        DEFAULT_LIMIT,
        &["a", "b"],
        DEFAULT_QUERY_TIMEOUT,
    ))
    .unwrap_err();
    assert_eq!(
        refusal(&two),
        (
            "a Next-Gen SIEM search reads one repository: pass --index once".to_owned(),
            Some("got a, b".to_owned())
        )
    );
    assert_eq!(replay.proxy.verify(), Vec::new());
}

#[test]
fn crowdstrike_stops_the_search_a_cancelled_run_stops_waiting_for() {
    // The run is cancelled while the job polls: the job is still stopped
    // (the DELETE goes out on a token of its own), and the run reports the
    // cancellation. Recorded: the second search, cut after its first poll.
    let replay = replay("crowdstrike/query", &[SECRET]);
    let (tenant, http) = tenant(
        &replay,
        "crowdstrike",
        "falcon",
        SETUP,
        &crowdstrike::http_defaults(),
    );
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let runner = Crowdstrike::new();
    let request = query(
        "#event_simpleName=ProcessRollup2",
        1,
        &[],
        DEFAULT_QUERY_TIMEOUT,
    );
    let trigger = cancel.clone();
    let outcome = block_on(async {
        let run = opentide_connectors::connector::QueryRunner::run(&runner, cx, &request);
        tokio::pin!(run);
        // Cancel between the first poll and the second (0.5 s apart).
        tokio::select! {
            outcome = &mut run => outcome,
            () = tokio::time::sleep(Duration::from_millis(250)) => {
                trigger.cancel();
                run.await
            }
        }
    })
    .unwrap();
    assert!(
        matches!(outcome, Err(ConnectorError::Cancelled)),
        "{outcome:?}"
    );
    // The oracle's run polled again; this one stopped instead: the
    // DELETE is the fourth request, and nothing after it was sent.
    let mismatches = replay.proxy.verify();
    assert_eq!(mismatches[0].index, 3, "{mismatches:?}");
    assert!(mismatches[0].detail.contains("DELETE"), "{}", mismatches[0]);
    assert!(
        mismatches[1..]
            .iter()
            .all(|mismatch| mismatch.detail.ends_with("was recorded and never sent")),
        "{mismatches:?}"
    );
}
