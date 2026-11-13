//! Splunk against the cassettes recorded from the Python client (Splunk's SDK on
//! opentide's urllib handler; `tests/cassettes/splunk/`, `cargo xtask
//! cassettes record splunk/<scenario>`): every request the connector sends
//! must be the Python client's, in order (a JSON body as the same data), and the answers
//! must read as Python read them (the outcomes `client.py` printed).

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod support;

use std::time::Duration;

use opentide_cassette::cassette::Body;
use opentide_compile::json::{Json, Object};
use opentide_connectors::ConnectorError;
use opentide_connectors::connector::QueryRequest;
use opentide_connectors::runtime::block_on;
use opentide_connectors::splunk::{self, PARSER_TIMEOUT_WARNING, Splunk};
use support::{Replayed, fixture, items, text, window};

const SETUP: &str = r#"
ssl = true
url = "splunk.invalid"
port = 8089
app = "search"
token = "$SPLUNK_TOKEN"
"#;

fn replay(scenario: &str) -> Replayed {
    Replayed::start(
        scenario,
        splunk::PLATFORM,
        SETUP,
        "SPLUNK_TOKEN",
        &splunk::http_settings(Duration::from_secs(120)),
    )
}

/// The settings `_apply_saved_search` sends for one step of `client.py`:
/// the rule's, its actions', then `search`.
fn settings(step: &Json) -> Object {
    let mut settings = step.get("mdr_config").unwrap().as_object().unwrap().clone();
    for (key, value) in step.get("actions_config").unwrap().as_object().unwrap() {
        settings.insert(key.clone(), value.clone());
    }
    settings.insert("search".into(), step.get("query").unwrap().clone());
    settings
}

#[test]
fn splunk_deploy_sends_what_the_python_deployer_sent() {
    let inputs = fixture("splunk");
    let tenant = replay("splunk/deploy");
    let connector = Splunk::new();
    let done = block_on(async {
        let mut done = Vec::new();
        for step in items(inputs.get("deploy").unwrap()) {
            let deletion = text(step.get("status").unwrap()) == "REMOVED";
            done.push(
                connector
                    .apply_saved_search(
                        tenant.cx(),
                        text(step.get("name").unwrap()),
                        &settings(step),
                        deletion,
                    )
                    .await
                    .unwrap(),
            );
        }
        done
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    // client.py: create true, update true, delete null, absent null.
    assert_eq!(done, [Some(true), Some(true), None, None]);
}

#[test]
fn splunk_a_single_byte_off_fails() {
    let inputs = fixture("splunk");
    let step = &items(inputs.get("deploy").unwrap())[0];
    let mut altered = settings(step);
    altered.insert(
        "description".into(),
        Json::Str("Simulated Splunk rule!".into()),
    );
    let tenant = replay("splunk/deploy");
    let _ = block_on(async {
        Splunk::new()
            .apply_saved_search(tenant.cx(), "Splunk SPL Rule", &altered, false)
            .await
    });
    let mismatches = tenant.verify();
    assert_eq!(
        mismatches.first().map(|m| m.index),
        Some(2),
        "{mismatches:?}"
    );

    // A recorded request one byte off is refused too.
    let mut cassette = support::cassette("splunk/deploy");
    let Body::Text(body) = &mut cassette.interactions[1].request.body else {
        panic!("the create has a form body")
    };
    *body = body.replace("name=Splunk", "name=Splunl");
    let tenant = Replayed::start_with(
        cassette,
        splunk::PLATFORM,
        SETUP,
        "SPLUNK_TOKEN",
        &splunk::http_settings(Duration::from_secs(120)),
    );
    let _ = block_on(async {
        Splunk::new()
            .apply_saved_search(tenant.cx(), "Splunk SPL Rule", &settings(step), false)
            .await
    });
    assert_eq!(tenant.verify()[0].index, 1);
}

fn row_text(row: &Object) -> String {
    row.iter()
        .map(|(key, value)| format!("{key}={}", value.as_str().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn splunk_query_sends_what_the_python_runner_sent() {
    let inputs = fixture("splunk");
    let query = inputs.get("query").unwrap();
    let window = window(query.get("window").unwrap());
    let tenant = replay("splunk/query");
    let connector = Splunk::new();
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for item in items(query.get("queries").unwrap()) {
            let mut request = QueryRequest::new(text(item.get("text").unwrap()), "spl", window);
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
    let shown: Vec<String> = outcomes
        .iter()
        .map(|outcome| match outcome {
            Ok(result) => format!(
                "columns {} rows [{}] truncated {} warnings {:?} sent {:?}",
                result
                    .columns
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                result
                    .rows
                    .iter()
                    .map(row_text)
                    .collect::<Vec<_>>()
                    .join(" | "),
                result.truncated,
                result.warnings,
                result.sent
            ),
            Err(error @ ConnectorError::Refused { .. }) => format!("refused {}", error.text()),
            Err(ConnectorError::Gateway { message, .. }) => format!("gateway {message}"),
            Err(other) => panic!("{other:?}"),
        })
        .collect();
    let gateway = shown[6].clone();
    assert_eq!(
        shown,
        [
            "columns _time,host,count rows [_time=2026-10-27T07:51:00.000+00:00,host=ws-1,count=1 \
             | _time=2026-10-27T07:52:00.000+00:00,host=ws-2,count=2] truncated true warnings [] \
             sent Some(\"search index=main sourcetype=WinEventLog:Security EventCode=4688\")",
            "columns _time,host,count rows [_time=2026-10-27T07:51:00.000+00:00,host=ws-1,count=1 \
             | _time=2026-10-27T07:52:00.000+00:00,host=ws-2,count=2 \
             | _time=2026-10-27T07:53:00.000+00:00,host=ws-3,count=3] truncated false warnings [] \
             sent None",
            "columns _time,host rows [] truncated false warnings [\"Search filters specified using \
             splunk_server/splunk_server_group do not match any search peer.\"] sent None",
            "refused Splunk refused the search on replayed: Error in 'lookup' command: The lookup \
             table 'x' does not exist.",
            "refused Splunk refused the search on replayed (HTTP 400): Unknown search command \
             'badcommand'.",
            "columns host,b,a rows [host=ws-1,b=1 | a=x,host=ws-2] truncated false warnings [] \
             sent Some(\"search index=main nofields\")",
            gateway.as_str(),
        ]
    );
    assert!(
        gateway.starts_with(
            "gateway Splunk at https://splunk.invalid:8089 answered with an HTML page (HTTP 502), \
             not its REST API (page title: '502 Bad Gateway'). HTTP 502 Bad Gateway is what a \
             gateway or proxy in front of the tenant answers when the tenant does not answer it \
             in time, so the url and port are not at fault when other requests to the same \
             address succeed. The request went through the proxy http://127.0.0.1:"
        ),
        "{gateway}"
    );
    assert!(gateway.ends_with(
        ". The request may be too slow for the gateway: make the query cheaper, or raise the \
         gateway's timeout."
    ));
}

#[test]
fn splunk_validate_parses_without_a_search() {
    let inputs = fixture("splunk");
    let validate = inputs.get("validate").unwrap();
    let window = window(validate.get("window").unwrap());
    let tenant = replay("splunk/validate");
    let connector = Splunk::new();
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for query in items(validate.get("queries").unwrap()) {
            let request = QueryRequest::new(text(query), "spl", window).for_check();
            outcomes.push(connector.check(tenant.cx(), &request).await);
        }
        outcomes
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(outcomes[0].as_ref().unwrap().warnings, Vec::<String>::new());
    assert_eq!(outcomes[1].as_ref().unwrap().warnings, Vec::<String>::new());
    match &outcomes[2] {
        Err(error @ ConnectorError::Refused { .. }) => assert_eq!(
            error.text(),
            "Splunk refused the query on replayed: Unknown search command 'badcommand'."
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        outcomes[3].as_ref().unwrap().warnings,
        [PARSER_TIMEOUT_WARNING]
    );
    match &outcomes[4] {
        Err(ConnectorError::Gateway {
            message, status, ..
        }) => {
            assert_eq!(*status, 504);
            assert!(message.starts_with(
                "Splunk at https://splunk.invalid:8089 answered with an HTML page (HTTP 504), \
                 not its REST API (page title: '504 Gateway Time-out')."
            ));
        }
        other => panic!("{other:?}"),
    }
}
