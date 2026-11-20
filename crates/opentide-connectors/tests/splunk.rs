//! Splunk against its cassettes (`tests/cassettes/splunk/`): `query` and
//! `validate` recorded from the Python client (Splunk's SDK on opentide's
//! urllib handler), `deploy` from the Rust connector since opentide stopped
//! sending what Python sent (#1657; `examples/splunk_client.rs`). Every
//! request the connector sends must be the recorded one, in order (a JSON
//! body as the same data), and the answers must read as they were read
//! then (the outcomes the client printed).

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

/// The body `opentide deploy` sends for one step of the fixture (written by
/// `cargo run -p opentide-connectors --example splunk_client -- fixture`):
/// the saved search's settings (the rule's, its actions', then `search`),
/// or, for a retirement, the description that names the rule.
fn settings(step: &Json) -> Object {
    step.get("body").unwrap().as_object().unwrap().clone()
}

/// Whether *interaction* is the listing of the saved searches that name a
/// rule, which only `Deployer::deploy` sends (#1657).
fn listing(interaction: &opentide_cassette::Interaction) -> bool {
    interaction.request.method == "GET" && interaction.request.url.contains("saved/searches?")
}

/// The recording without its listings: the writes and deletes alone, as
/// [`Splunk::apply_saved_search`] sends them.
fn writes_alone() -> Replayed {
    let recorded = support::cassette("splunk/deploy");
    let interactions = recorded
        .interactions
        .iter()
        .filter(|interaction| !listing(interaction))
        .cloned()
        .collect();
    Replayed::start_with(
        opentide_cassette::Cassette::new(
            &recorded.scenario,
            recorded.recorded_from.clone(),
            interactions,
        ),
        splunk::PLATFORM,
        SETUP,
        "SPLUNK_TOKEN",
        &splunk::http_settings(Duration::from_secs(120)),
    )
}

/// The recording as a deploy of an unchanged rule sends it: the second
/// step's two updates (interactions 6 and 7) are not sent, because the
/// lookup before them (interaction 5) already answers every setting the
/// step sends, the marked description and the empty `alert.managedBy`
/// among them (#1711). Its listing for a rename's cleanup is still sent.
fn unchanged_second_step(listings: bool) -> Replayed {
    let recorded = support::cassette("splunk/deploy");
    let interactions = recorded
        .interactions
        .iter()
        .enumerate()
        .filter(|(index, interaction)| {
            !matches!(index, 6 | 7) && (listings || !listing(interaction))
        })
        .map(|(_, interaction)| interaction.clone())
        .collect();
    Replayed::start_with(
        opentide_cassette::Cassette::new(
            &recorded.scenario,
            recorded.recorded_from.clone(),
            interactions,
        ),
        splunk::PLATFORM,
        SETUP,
        "SPLUNK_TOKEN",
        &splunk::http_settings(Duration::from_secs(120)),
    )
}

/// The recording whose second lookup (interaction 5) answers a
/// `cron_schedule` the step does not send, as a saved search someone changed
/// in Splunk, without its listings: the second step finds it, sees the
/// setting differ, and updates it with the recorded two writes.
fn changed_second_step() -> Replayed {
    let mut recorded = support::cassette("splunk/deploy");
    let Body::Text(answer) = &mut recorded.interactions[5].response.body else {
        panic!("the lookup's answer is text");
    };
    let held = "<s:key name=\"cron_schedule\">0 * * * *</s:key>";
    assert!(answer.contains(held), "{answer}");
    *answer = answer.replace(held, "<s:key name=\"cron_schedule\">30 * * * *</s:key>");
    let interactions = recorded
        .interactions
        .iter()
        .filter(|interaction| !listing(interaction))
        .cloned()
        .collect();
    Replayed::start_with(
        opentide_cassette::Cassette::new(
            &recorded.scenario,
            recorded.recorded_from.clone(),
            interactions,
        ),
        splunk::PLATFORM,
        SETUP,
        "SPLUNK_TOKEN",
        &splunk::http_settings(Duration::from_secs(120)),
    )
}

/// Every step of the fixture through `apply_saved_search` against *tenant*.
fn apply_every_step(tenant: &Replayed) -> Vec<Option<bool>> {
    let inputs = fixture("splunk");
    let connector = Splunk::new();
    block_on(async {
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
    .unwrap()
}

/// The steps' saved search written through `apply_saved_search`: created
/// (looked up, 404; created; its settings in two updates), found as the
/// step has it (nothing written, #1711), deleted, then already absent.
#[test]
fn splunk_saved_search_writes_are_the_recorded_ones() {
    let tenant = unchanged_second_step(false);
    let done = apply_every_step(&tenant);
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(done, [Some(true), Some(false), None, None]);
}

/// A saved search the tenant has with a setting that differs from the
/// step's is updated (#1711): the lookup, then both of the update's writes
/// as recorded (the settings, then those Splunk takes only once the others
/// are set). Without this nothing would run `update_saved_search` on a
/// saved search found.
#[test]
fn splunk_a_saved_search_that_differs_is_updated() {
    let tenant = changed_second_step();
    let done = apply_every_step(&tenant);
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(done, [Some(true), Some(true), None, None]);
}

/// The recording through `Deployer::deploy`, as `opentide deploy` sends
/// it (the scenario's client, `examples/splunk_client.rs`): each step's
/// body as the request, a retirement as a delete. After each write and
/// each delete, one listing of the saved searches that name the rule
/// (#1657) finds only the one written, so nothing else is deleted; only
/// the delete of a saved search the tenant had warns.
#[test]
fn splunk_the_deployer_sends_what_was_recorded() {
    use opentide_connectors::connector::{DeployRequest, Deployer, Operation};
    let inputs = fixture("splunk");
    let recorded = support::cassette("splunk/deploy");
    assert_eq!(
        recorded
            .interactions
            .iter()
            .filter(|found| listing(found))
            .count(),
        4,
        "one listing after each step"
    );
    // The second step finds the saved search as the step has it: its two
    // updates are not sent (#1711), but its rename-cleanup listing still is.
    let tenant = unchanged_second_step(true);
    let connector = Splunk::new();
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for step in items(inputs.get("deploy").unwrap()) {
            let deletion = text(step.get("status").unwrap()) == "REMOVED";
            let request = DeployRequest::new(
                text(step.get("name").unwrap()).to_owned(),
                if deletion {
                    Operation::Delete
                } else {
                    Operation::Update
                },
                Json::Object(settings(step)).to_compact().into_bytes(),
            );
            outcomes.push(connector.deploy(tenant.cx(), &request).await.unwrap());
        }
        outcomes
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    let warned: Vec<Vec<(String, String)>> = outcomes
        .iter()
        .map(|outcome| {
            outcome
                .warnings
                .iter()
                .map(|warning| (warning.code.clone(), warning.message.clone()))
                .collect()
        })
        .collect();
    let deleted = text(items(inputs.get("deploy").unwrap())[2].get("name").unwrap()).to_owned();
    assert_eq!(
        warned,
        [
            vec![],
            vec![],
            vec![("splunk_alert_deleted".to_owned(), deleted)],
            vec![]
        ]
    );
    assert_eq!(
        outcomes
            .iter()
            .map(|outcome| outcome.remote_id.is_some())
            .collect::<Vec<_>>(),
        [true, true, false, false]
    );
    assert_eq!(
        outcomes
            .iter()
            .map(opentide_connectors::connector::DeployOutcome::unchanged)
            .collect::<Vec<_>>(),
        [false, true, false, false],
        "only the rule the tenant already held is unchanged"
    );
}

/// Every tracing event's level and message, from the first test that asks.
#[derive(Clone, Default)]
struct Logs(std::sync::Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Logs {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Message<'a>(&'a mut String);
        impl tracing::field::Visit for Message<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0.push_str(&format!("{value:?}"));
                }
            }
        }
        let mut message = String::new();
        event.record(&mut Message(&mut message));
        self.0
            .lock()
            .unwrap()
            .push((*event.metadata().level(), message));
    }
}

/// The global subscriber, installed once, before any request.
fn logs() -> &'static Logs {
    use tracing_subscriber::layer::SubscriberExt as _;
    static LOGS: std::sync::OnceLock<Logs> = std::sync::OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Logs::default();
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(logs.clone()))
            .unwrap();
        logs
    })
}

/// A saved search the tenant does not have yet is created: the `404` of
/// the lookup before it is the normal path, logged at debug, never as a
/// warning or an error.
#[test]
fn splunk_creating_an_absent_saved_search_logs_no_warning() {
    let logs = logs();
    let inputs = fixture("splunk");
    let step = &items(inputs.get("deploy").unwrap())[0];
    let tenant = writes_alone();
    let written = block_on(async {
        Splunk::new()
            .apply_saved_search(
                tenant.cx(),
                text(step.get("name").unwrap()),
                &settings(step),
                false,
            )
            .await
    })
    .unwrap()
    .unwrap();
    assert_eq!(written, Some(true), "the recording's first step creates it");
    // The log is the process's: other tests' events are in it too, so this
    // reads the 404s alone (no other recording answers one).
    let events: Vec<_> = logs
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, message)| message.contains("404"))
        .cloned()
        .collect();
    let loud: Vec<_> = events
        .iter()
        .filter(|(level, _)| *level <= tracing::Level::WARN)
        .collect();
    assert!(loud.is_empty(), "{loud:?}");
    assert!(
        events
            .iter()
            .any(|(level, message)| *level == tracing::Level::DEBUG && message.contains("404")),
        "{events:?}"
    );
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
    let tenant = writes_alone();
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
             not its REST API (page title: \"502 Bad Gateway\"). HTTP 502 Bad Gateway is what a \
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
                 not its REST API (page title: \"504 Gateway Time-out\")."
            ));
        }
        other => panic!("{other:?}"),
    }
}
