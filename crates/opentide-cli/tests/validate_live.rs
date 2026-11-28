//! `validate query --live`'s flow on the platforms whose checks search the
//! last minute (UC-4.6, #979): Microsoft Defender, SentinelOne and
//! Sentinel. A golden case cannot replay them (a run's window ends now), so
//! each runs here with the time fixed, against its connector's cassette
//! recorded from the Python client (`tests/cassettes/<platform>/validate.json`):
//! the rules of a workspace, through the deploy plan, the tenant's batch and
//! the connector, send exactly the requests opentide 0.23.0 sent, and the result
//! reads as opentide 0.23.0's.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::io::Write as _;
use std::path::Path;

use opentide_cassette::{Cassette, Mode, Proxy, Redaction};
use opentide_cli::commands::result::ExitCode;
use opentide_cli::commands::validate_live::{Context, Live, run};
use opentide_cli::commands::validate_query::Args;
use opentide_cli::env::Env;
use opentide_cli::json::Json;
use opentide_connectors::connector::{
    BoxFuture, LiveCheck, LiveValidator, Platform, QueryRequest, TenantContext,
};
use opentide_connectors::{ConnectorError, Registry};

/// The credential the replayed tenant gets; redacted, as the recording's was.
const SECRET: &str = "replayed-credential-value";

/// The end of the connectors' recorded check windows.
fn now() -> jiff::Timestamp {
    "2026-10-27T08:00:00Z".parse().unwrap()
}

fn repo() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A rule file of one platform block.
fn rule(name: &str, uuid: &str, block: &str) -> String {
    format!(
        "name: {name}\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.0\n  version: 1\n  created: \
         2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: {name}.\nresponse:\n  \
         alert_severity: High\nconfigurations:\n{block}"
    )
}

/// A workspace whose `platform` has one tenant, `lab`, of `setup`, and the
/// rules `rules` (file name, text), checked in file order.
fn workspace(platform: &str, setup: &str, rules: &[(&str, String)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let platforms = dir.path().join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::write(
        platforms.join(format!("{platform}.toml")),
        format!(
            "[platform]\nenabled = true\nname = \"Stand-in\"\n\n[[tenants]]\nname = \
             \"lab\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\n{setup}"
        ),
    )
    .unwrap();
    let rules_dir = dir.path().join("objects/rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    for (file, text) in rules {
        std::fs::write(rules_dir.join(file), text).unwrap();
    }
    dir
}

/// Runs `validate query --live --platform platform` in `ws`, the network
/// the proxy replaying `scenario`, `variable` set to [`SECRET`].
fn live(
    ws: &Path,
    platform: &str,
    scenario: &str,
    variable: &str,
    registry: &Registry,
) -> (Live, Vec<opentide_cassette::Mismatch>) {
    let text =
        std::fs::read_to_string(repo().join(format!("tests/cassettes/{scenario}.json"))).unwrap();
    let proxy = Proxy::start(
        Mode::Replay {
            cassette: Cassette::parse(&text).unwrap(),
        },
        Redaction::new([SECRET.to_owned()]),
    )
    .unwrap();
    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(proxy.ca_pem().as_bytes()).unwrap();
    let env = Env::from_pairs(
        proxy
            .client_env(ca.path().to_str().unwrap())
            .into_iter()
            .chain([(variable.to_owned(), SECRET.to_owned())]),
    );
    let args = Args {
        platform: Some(platform.to_owned()),
        live: true,
        ..Args::default()
    };
    let never = || false;
    let result = run(
        &args,
        &Context {
            repo: Some(ws.to_str().unwrap()),
            env: &env,
            cwd: ws,
            proxy: None,
            interrupted: &never,
            now: now(),
            registry,
            debug: false,
        },
    );
    (result, proxy.verify())
}

/// The result's value at `key`: one of its own keys, `status`, `message`
/// or `warnings`.
fn value(live: &Live, key: &str) -> Json {
    live.result_json()
        .get(key)
        .cloned()
        .unwrap_or_else(|| panic!("no {key} in {:?}", live.result))
}

/// Whether the result has its own key `key`.
fn has(live: &Live, key: &str) -> bool {
    live.result.data.iter().any(|(name, _)| name == key)
}

/// The result's `failure.code`.
fn failure_code(live: &Live) -> Option<&str> {
    live.result.failure.code.as_deref()
}

/// Microsoft Defender whose check counts its data's retention from the
/// recording's time, not today's.
struct DefenderAt(opentide_connectors::microsoft_defender::MicrosoftDefender);

impl LiveValidator for DefenderAt {
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        Box::pin(self.0.check(cx, request, now()))
    }
}

impl Platform for DefenderAt {
    fn id(&self) -> &'static str {
        "microsoft_defender"
    }

    fn live_validator(&self) -> Option<&dyn LiveValidator> {
        Some(self)
    }
}

#[test]
fn defender_rules_are_checked_with_their_custom_detection_columns() {
    let ws = workspace(
        "microsoft_defender",
        "tenant_id = \"contoso-tenant-id\"\nclient_id = \"opentide-app-id\"\nclient_secret = \
         \"$DEFENDER_CLIENT_SECRET\"\n",
        &[
            (
                "a-columns.yaml",
                rule(
                    "Defender columns rule",
                    "00000000-0000-4000-8046-000000000101",
                    "  microsoft_defender:\n    status: STAGING\n    query: |\n      \
                     DeviceProcessEvents\n      | project Timestamp, DeviceId, ReportId\n",
                ),
            ),
            (
                "b-no-columns.yaml",
                rule(
                    "Defender rule without columns",
                    "00000000-0000-4000-8046-000000000102",
                    "  microsoft_defender:\n    status: STAGING\n    query: |\n      \
                     DeviceProcessEvents\n      | project Timestamp, DeviceName\n",
                ),
            ),
        ],
    );
    let mut registry = Registry::new();
    registry
        .register(Box::new(DefenderAt(
            opentide_connectors::microsoft_defender::MicrosoftDefender::new(),
        )))
        .unwrap();
    let (live, mismatches) = live(
        ws.path(),
        "microsoft_defender",
        "defender/validate",
        "DEFENDER_CLIENT_SECRET",
        &registry,
    );
    assert_eq!(mismatches, Vec::new());
    assert_eq!(&value(&live, "status"), &Json::str("failed"));
    assert_eq!(
        &value(&live, "message"),
        &Json::str("Queries rejected on microsoft_defender · 2 checked on 1 tenant")
    );
    assert_eq!(live.result.exit, ExitCode::Failure);
    let report = live.report(&Env::from_pairs::<&str, &str>([]));
    assert_eq!(report.steps[0].name, "Stand-in queries");
    assert_eq!(report.steps[0].count, Some(2));
}

#[test]
fn sentinel_one_checks_each_correlation_sub_query() {
    let ws = workspace(
        "sentinel_one",
        "url = \"https://s1.invalid\"\napi_token = \"$S1_API_TOKEN\"\naccount_id = 4242\nsite_id \
         = 77\n",
        &[(
            "a-process.yaml",
            rule(
                "SentinelOne process rule",
                "00000000-0000-4000-8046-000000000103",
                "  sentinel_one:\n    status: STAGING\n    condition:\n      type: Correlation\n      \
                 correlation:\n        entity: host\n        match_in_order: true\n        \
                 time_window: 1h\n        sub_queries:\n          - query: EventType = \"Process \
                 Create\"\n            matches_required: 1\n          - query: src.process.name \
                 = 'cmd.exe'\n            matches_required: 1\n",
            ),
        )],
    );
    let (live, mismatches) = live(
        ws.path(),
        "sentinel_one",
        "sentinel_one/validate",
        "S1_API_TOKEN",
        &opentide_connectors::builtin(),
    );
    assert_eq!(mismatches, Vec::new());
    assert_eq!(&value(&live, "status"), &Json::str("passed"));
    // The rule counts once, its two sub-queries checked one by one.
    assert_eq!(
        &value(&live, "message"),
        &Json::str("1 query valid on 1 tenant")
    );
    assert_eq!(
        &value(&live, "queries_per_tenant"),
        &Json::object([("lab", Json::Int(1))])
    );
}

#[test]
fn sentinel_signs_in_once_and_searches_each_rule() {
    let ws = workspace(
        "sentinel",
        "ssl = true\nresource_group = \"soc-rg\"\nworkspace_name = \"soc workspace\"\nworkspace_id \
         = \"11111111-2222-4333-8444-555555555555\"\nazure_tenant_id = \
         \"contoso-tenant-id\"\nazure_subscription_id = \"sub-0001\"\nazure_client_id = \
         \"opentide-app-id\"\nazure_client_secret = \"$AZURE_CLIENT_SECRET\"\n",
        &[
            (
                "a-process.yaml",
                rule(
                    "Sentinel process rule",
                    "00000000-0000-4000-8046-000000000104",
                    "  sentinel:\n    status: STAGING\n    query: |\n      SecurityEvent\n      | \
                     where EventID == 4688\n",
                ),
            ),
            (
                "b-signins.yaml",
                rule(
                    "Sentinel sign-in rule",
                    "00000000-0000-4000-8046-000000000105",
                    "  sentinel:\n    status: STAGING\n    query: |\n      SigninLogs\n      | \
                     project TimeGenerated, Computer\n",
                ),
            ),
        ],
    );
    let sentinel = opentide_connectors::sentinel::Sentinel::new();
    let mut registry = Registry::new();
    registry.register(Box::new(sentinel)).unwrap();
    let (live, mismatches) = live(
        ws.path(),
        "sentinel",
        "sentinel/validate",
        "AZURE_CLIENT_SECRET",
        &registry,
    );
    assert_eq!(mismatches, Vec::new());
    assert_eq!(&value(&live, "status"), &Json::str("passed"));
    assert_eq!(
        &value(&live, "message"),
        &Json::str("2 queries valid on 1 tenant")
    );
    assert_eq!(
        live.result.summary,
        [
            ("queries".to_owned(), Json::Int(2)),
            ("tenants".to_owned(), Json::Int(1))
        ]
    );
}

/// A platform whose checks answer in turn what the test scripted, without
/// a network: each outcome `validate query --live` handles.
struct Scripted {
    id: &'static str,
    outcomes: std::sync::Mutex<std::collections::VecDeque<Result<LiveCheck, ConnectorError>>>,
}

impl Scripted {
    fn registry(id: &'static str, outcomes: Vec<Result<LiveCheck, ConnectorError>>) -> Registry {
        let mut registry = Registry::new();
        registry
            .register(Box::new(Self {
                id,
                outcomes: std::sync::Mutex::new(outcomes.into()),
            }))
            .unwrap();
        registry
    }
}

impl LiveValidator for Scripted {
    fn validate<'a>(
        &'a self,
        _cx: TenantContext<'a>,
        _request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        let next = self.outcomes.lock().unwrap().pop_front().unwrap();
        Box::pin(async move { next })
    }
}

impl Platform for Scripted {
    fn id(&self) -> &'static str {
        self.id
    }

    fn live_validator(&self) -> Option<&dyn LiveValidator> {
        Some(self)
    }
}

/// A Splunk workspace of `count` rules, checked in turn.
fn splunk_rules(count: usize) -> tempfile::TempDir {
    let rules: Vec<(String, String)> = (1..=count)
        .map(|n| {
            (
                format!("rule-{n}.yaml"),
                rule(
                    &format!("Splunk rule {n}"),
                    &format!("00000000-0000-4000-8046-0000000002{n:02}"),
                    &format!("  splunk:\n    status: STAGING\n    query: index=main n={n}\n"),
                ),
            )
        })
        .collect();
    let named: Vec<(&str, String)> = rules
        .iter()
        .map(|(file, text)| (file.as_str(), text.clone()))
        .collect();
    workspace(
        "splunk",
        "url = \"splunk.invalid\"\nport = 8089\napp = \"search\"\ntoken = \"$SPLUNK_TOKEN\"\n",
        &named,
    )
}

/// Installs, once per process, a global subscriber that records nothing.
///
/// `tracing` caches in each callsite whether any subscriber wants it, and
/// every test of this file runs in one process. Without a subscriber a
/// callsite hit first by a test that logs to none (or racing the scoped
/// subscriber of the test that captures its events) can cache "never", and
/// the capturing test then misses that event. With a global subscriber that
/// is interested in everything (it only discards), no callsite is ever
/// cached as "never", so each test's scoped subscriber sees its own events
/// whatever the other threads do.
fn keep_callsites_enabled() {
    use opentide_cli::logging::{Config, LogLayer, Sink, subscriber};
    use opentide_cli::redact::Redactor;
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let sink: Sink = std::sync::Arc::new(std::sync::Mutex::new(std::io::sink()));
        let layer = LogLayer::new(
            Config {
                debug: false,
                quiet: true,
                json_lines: true,
            },
            sink,
            Redactor::new(Vec::new(), Vec::new()),
            String::new,
        );
        // An `Err` means another global subscriber is already installed,
        // which keeps the callsites enabled just the same.
        tracing::subscriber::set_global_default(subscriber(layer)).ok();
    });
}

/// Runs the scripted checks on `ws`'s Splunk rules.
fn scripted(ws: &Path, outcomes: Vec<Result<LiveCheck, ConnectorError>>) -> Live {
    keep_callsites_enabled();
    let registry = Scripted::registry("splunk", outcomes);
    let env = Env::from_pairs([("SPLUNK_TOKEN", SECRET)]);
    let args = Args {
        platform: Some("splunk".to_owned()),
        live: true,
        check_timeout: Some("5".to_owned()),
        ..Args::default()
    };
    let never = || false;
    run(
        &args,
        &Context {
            repo: Some(ws.to_str().unwrap()),
            env: &env,
            cwd: ws,
            proxy: None,
            interrupted: &never,
            now: now(),
            registry: &registry,
            debug: false,
        },
    )
}

fn refused(message: &str, detail: Option<&str>) -> ConnectorError {
    ConnectorError::refused("splunk", "lab", message, detail.map(str::to_owned))
}

fn read_timeout() -> ConnectorError {
    ConnectorError::Timeout {
        platform: "splunk".into(),
        tenant: "lab".into(),
        address: "https://splunk.invalid:8089".into(),
        seconds: 5,
    }
}

#[test]
fn each_outcome_of_a_check_is_the_recorded_one() {
    let ws = splunk_rules(5);
    let accepted = LiveCheck {
        warnings: vec!["the parser timed out".into()],
        ..LiveCheck::default()
    };
    let live = scripted(
        ws.path(),
        vec![
            Err(read_timeout()),
            Err(ConnectorError::Gateway {
                platform: "splunk".into(),
                tenant: "lab".into(),
                message: "the gateway answered 504".into(),
                status: 504,
            }),
            Err(ConnectorError::QueryTimedOut {
                platform: "splunk".into(),
                tenant: "lab".into(),
                message: "the search outlived 5s".into(),
                detail: Some("raise --timeout".into()),
                timeout: std::time::Duration::from_secs(5),
            }),
            Err(refused("Splunk refused the query on lab", Some("bad"))),
            Ok(accepted),
        ],
    );
    assert_eq!(&value(&live, "status"), &Json::str("failed"));
    assert_eq!(
        &value(&live, "message"),
        &Json::str(
            "Queries rejected on splunk · 5 checked on 1 tenant · 3 with no answer within 5s"
        )
    );
    assert_eq!(&value(&live, "check_timeout"), &Json::Float(5.0));
    let Json::Array(timed_out) = &value(&live, "timed_out") else {
        panic!("timed_out is a list")
    };
    assert_eq!(timed_out.len(), 3);
    let first = &timed_out[0];
    assert_eq!(first.get("code"), Some(&Json::str("query_check_timeout")));
    assert_eq!(
        first.get("errors"),
        Some(&Json::Array(vec![Json::str(
            "no answer within the 5s check timeout (no complete answer from \
             https://splunk.invalid:8089 within 5s). Raise it with --check-timeout or \
             OPENTIDE_QUERY_CHECK_TIMEOUT, or make the query cheaper"
        )]))
    );
    assert_eq!(
        &value(&live, "warnings"),
        &Json::Array(vec![Json::str(
            "Query validation reported warnings for splunk"
        )])
    );
    // A refusal fails the run too, so the timeouts are not its only failures:
    // `query_check_timeout` does not name it. It was `command_failed`; the run
    // now says a tenant rejected a query (a departure from opentide 0.23.0).
    assert_eq!(failure_code(&live), Some("query_rejected"));
    // A run that rejected a query has no tick (#1658, E8).
    assert_eq!(
        live.step.as_ref().unwrap().status,
        opentide_cli::render::progress::StepStatus::Failed
    );
    let report = live.report(&Env::from_pairs([("OPENTIDE_PROGRESS", "json")]));
    assert_eq!(
        report.stderr_first,
        "{\"event\":\"progress\",\"step\":\"Stand-in queries\",\"done\":1,\"total\":1}\n"
    );
    assert_eq!(report.outcome.exit_code, 1);
}

/// A buffer the test's log layer writes to.
#[derive(Clone, Default)]
struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Each check's log events name the rule with `rule_name` (it was
/// `mdr_name`, a name from the product opentide grew out of).
#[test]
fn the_check_events_name_the_rule_with_rule_name() {
    use opentide_cli::logging::{Config, LogLayer, Sink, subscriber};
    use opentide_cli::redact::Redactor;

    keep_callsites_enabled();
    let ws = splunk_rules(1);
    let buffer = Captured::default();
    let sink: Sink = std::sync::Arc::new(std::sync::Mutex::new(buffer.clone()));
    let layer = LogLayer::new(
        Config {
            debug: true,
            quiet: false,
            json_lines: true,
        },
        sink,
        Redactor::new(Vec::new(), Vec::new()),
        || "12:00:00".to_owned(),
    );
    tracing::subscriber::with_default(subscriber(layer), || {
        scripted(ws.path(), vec![Ok(LiveCheck::default())]);
    });
    let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    let events: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for event in ["validating_query", "valid_query"] {
        let line = events
            .iter()
            .find(|line| line["event"] == event)
            .unwrap_or_else(|| panic!("no {event} in {text}"));
        assert_eq!(line["rule_name"], "Splunk rule 1", "{line}");
    }
    assert!(!text.contains("mdr_name"), "{text}");
}

#[test]
fn checks_that_only_timed_out_name_their_code() {
    let ws = splunk_rules(2);
    let live = scripted(
        ws.path(),
        vec![Err(read_timeout()), Ok(LiveCheck::default())],
    );
    assert_eq!(failure_code(&live), Some("query_check_timeout"));
}

#[test]
fn three_timeouts_in_a_row_report_the_tenant_unreachable() {
    let ws = splunk_rules(4);
    let live = scripted(
        ws.path(),
        vec![
            Err(read_timeout()),
            Err(read_timeout()),
            Err(read_timeout()),
        ],
    );
    assert_eq!(&value(&live, "host"), &Json::str("splunk.invalid:8089"));
    let Json::Str(message) = &value(&live, "message") else {
        panic!("a message")
    };
    assert!(
        message.starts_with(
            "Cannot reach splunk tenant 'lab' at splunk.invalid:8089: 3 queries in a row got no \
             answer within the 5s check timeout"
        ),
        "{message}"
    );
    let Json::Str(advice) = &value(&live, "advice") else {
        panic!("advice")
    };
    assert!(
        advice.starts_with("if the tenant is up and only slow"),
        "{advice}"
    );
    assert_eq!(
        live.step.unwrap().status,
        opentide_cli::render::progress::StepStatus::Failed
    );
}

#[test]
fn a_tenant_that_only_timed_out_never_answered() {
    let ws = splunk_rules(1);
    let live = scripted(ws.path(), vec![Err(read_timeout())]);
    let Json::Str(message) = &value(&live, "message") else {
        panic!("a message")
    };
    assert!(
        message.contains("it answered no request: 1 timed out after 5s"),
        "{message}"
    );
}

#[test]
fn a_refused_credential_or_an_unreachable_tenant_stops_the_check() {
    let ws = splunk_rules(2);
    let live = scripted(
        ws.path(),
        vec![Err(ConnectorError::authentication(
            "splunk",
            "lab",
            "Cannot authenticate with the tenant configuration",
        ))],
    );
    // The tenant refused the credential: a tenant's failure, with its host
    // and what to check, and no query counted as checked (#1658, E8).
    assert_eq!(
        &value(&live, "message"),
        &Json::str(
            "splunk tenant 'lab' refused the check: Cannot authenticate with the tenant \
             configuration"
        )
    );
    assert_eq!(&value(&live, "tenant"), &Json::str("lab"));
    assert_eq!(&value(&live, "host"), &Json::str("splunk.invalid:8089"));
    let Json::Str(advice) = &value(&live, "advice") else {
        panic!("advice")
    };
    assert!(
        advice.starts_with(
            "check the credentials of the 'lab' tenant in \
             .opentide/configurations/platforms/splunk.toml"
        ),
        "{advice}"
    );
    assert!(!has(&live, "queries_validated"));
    assert_eq!(live.result.exit, ExitCode::Failure);
    assert_eq!(
        live.step.as_ref().unwrap().status,
        opentide_cli::render::progress::StepStatus::Failed
    );
    let live = scripted(
        ws.path(),
        vec![Err(ConnectorError::Unreachable {
            platform: "splunk".into(),
            tenant: "lab".into(),
            address: "https://splunk.invalid:8089".into(),
            reason: "connection refused".into(),
        })],
    );
    assert_eq!(
        &value(&live, "message"),
        &Json::str(
            "Cannot reach splunk tenant 'lab' at https://splunk.invalid:8089: connection refused"
        )
    );
    assert_eq!(
        &value(&live, "host"),
        &Json::str("https://splunk.invalid:8089")
    );
    assert_eq!(&value(&live, "tenant"), &Json::str("lab"));
}

/// A tenant that stops the check after a query it refused as invalid does
/// not hide that query: it is in `rejected`, with its rule's file and line,
/// and a finding for the CI annotations.
#[test]
fn a_tenant_that_stops_the_check_keeps_the_query_it_rejected() {
    let ws = splunk_rules(2);
    let live = scripted(
        ws.path(),
        vec![
            Err(refused("Unknown search command 'bad'.", None)),
            Err(ConnectorError::Unreachable {
                platform: "splunk".into(),
                tenant: "lab".into(),
                address: "https://splunk.invalid:8089".into(),
                reason: "connection refused".into(),
            }),
        ],
    );
    assert_eq!(failure_code(&live), Some("tenant_unreachable"));
    let Json::Array(rejected) = &value(&live, "rejected") else {
        panic!("rejected is a list")
    };
    assert_eq!(rejected.len(), 1);
    assert!(rejected[0].get("file").and_then(Json::as_str).is_some());
    assert!(rejected[0].get("line").and_then(Json::as_u64).is_some());
    assert_eq!(live.findings.len(), 1);
    assert_eq!(live.findings[0].code, "query_rejected");
}

#[test]
fn usage_errors_and_skips_answer_before_any_check() {
    let ws = splunk_rules(1);
    let never = || false;
    let registry = Registry::new();
    let env = Env::from_pairs([("DEPLOYMENT_PLAN", "STAGING")]);
    let cx = |env: &'static Env| Context {
        repo: Some(ws.path().to_str().unwrap()),
        env,
        cwd: ws.path(),
        proxy: None,
        interrupted: &never,
        now: now(),
        registry: &registry,
        debug: false,
    };
    let env: &'static Env = Box::leak(Box::new(env));
    let plain: &'static Env = Box::leak(Box::new(Env::from_pairs::<&str, &str>([])));
    let args = |platform: Option<&str>, strategies: &[&str]| Args {
        platform: platform.map(str::to_owned),
        live: true,
        strategies: strategies.iter().map(|s| (*s).to_owned()).collect(),
        ..Args::default()
    };
    let removed = run(&args(Some("splunk"), &[]), &cx(env));
    assert_eq!(removed.result.exit, ExitCode::Usage);
    let missing = run(&args(None, &[]), &cx(plain));
    assert_eq!(
        missing.result.failure.argument.as_deref(),
        Some("--platform")
    );
    let typo = run(&args(Some("splunk"), &["STAGING"]), &cx(plain));
    assert_eq!(failure_code(&typo), Some("usage_invalid_choice"));
    let disabled = run(&args(Some("elastic"), &[]), &cx(plain));
    assert_eq!(&value(&disabled, "platform_enabled"), &Json::Bool(false));
    let none = run(&args(Some("splunk"), &["RELEASE"]), &cx(plain));
    assert_eq!(&value(&none, "status"), &Json::str("skipped"));
    assert_eq!(
        &value(&none, "message"),
        &Json::str("No rule for this platform has a status that maps to the run's strategies")
    );
    // A RELEASE rule reaches no tenant: the lab tenant takes PREVIEW only.
    std::fs::write(
        ws.path().join("objects/rules/rule-1.yaml"),
        rule(
            "Splunk production rule",
            "00000000-0000-4000-8046-000000000201",
            "  splunk:\n    status: PRODUCTION\n    query: index=main\n",
        ),
    )
    .unwrap();
    let unreached = run(&args(Some("splunk"), &["RELEASE"]), &cx(plain));
    assert_eq!(unreached.result.exit, ExitCode::Usage);
    assert_eq!(failure_code(&unreached), Some("no_tenant_reached"));
    // With --wide the rule goes to the lab tenant under PREVIEW, a strategy
    // the run left out: a skip, not a failure.
    let elsewhere = run(
        &Args {
            wide: true,
            ..args(Some("splunk"), &["RELEASE"])
        },
        &cx(plain),
    );
    assert_eq!(&value(&elsewhere, "status"), &Json::str("skipped"));
    assert_eq!(
        &value(&elsewhere, "message"),
        &Json::str(
            "None of the 1 splunk rule(s) goes to a tenant accepting RELEASE; they are checked \
             by a run with the strategy that deploys them, or without --strategy"
        )
    );
    assert_eq!(
        elsewhere.result.exit,
        ExitCode::Success,
        "{:?}",
        elsewhere.result
    );
    assert_eq!(failure_code(&elsewhere), None);
}

/// A tenant that refuses the credential stops only its own rules: the next
/// tenant is checked, its results kept and counted (#1658, E8).
#[test]
fn a_refused_tenant_does_not_drop_the_next_tenants_checks() {
    let ws = splunk_rules(2);
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/splunk.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        format!(
            "{text}\n[[tenants]]\nname = \"lab2\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\nurl = \
             \"splunk2.invalid\"\nport = 8089\napp = \"search\"\ntoken = \"$SPLUNK_TOKEN\"\n"
        ),
    )
    .unwrap();
    let rejection = LiveCheck {
        errors: vec!["Unknown search command 'stat'".into()],
        ..LiveCheck::default()
    };
    let live = scripted(
        ws.path(),
        vec![
            Err(ConnectorError::authentication(
                "splunk",
                "lab",
                "Splunk refused the credential (HTTP 401)",
            )),
            Ok(rejection),
            Ok(LiveCheck::default()),
        ],
    );
    assert_eq!(&value(&live, "tenant"), &Json::str("lab"));
    assert_eq!(
        &value(&live, "message"),
        &Json::str(
            "splunk tenant 'lab' refused the check: Splunk refused the credential (HTTP 401)"
        )
    );
    // lab2's two queries were checked, one rejected.
    assert_eq!(&value(&live, "queries_validated"), &Json::Int(2));
    assert_eq!(&value(&live, "queries_rejected"), &Json::Int(1));
    assert_eq!(live.result.exit, ExitCode::Failure);
}

/// An Elastic tenant that refuses the API key fails the tenant: no query
/// counts as rejected, and the result names the tenant, its host and what to
/// check (#1658, E8).
#[test]
fn an_elastic_tenant_that_refuses_the_key_fails_the_tenant() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let server = runtime.block_on(wiremock::MockServer::start());
    runtime.block_on(
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(401).set_body_string(
                r#"{"error":{"type":"security_exception","reason":"unable to authenticate"}}"#,
            ))
            .mount(&server),
    );
    let uri = server.uri();
    let rules: Vec<(&str, String)> = (1..=2)
        .map(|n| {
            (
                if n == 1 { "rule-1.yaml" } else { "rule-2.yaml" },
                rule(
                    &format!("Elastic rule {n}"),
                    &format!("00000000-0000-4000-8046-0000000003{n:02}"),
                    "  elastic:\n    status: STAGING\n    type: query\n    language: kuery\n    \
                     query: 'process.name: cmd.exe'\n    index: [logs-*]\n",
                ),
            )
        })
        .collect();
    let ws = workspace(
        "elastic",
        &format!(
            "url = \"{uri}\"\nelasticsearch_url = \"{uri}\"\napi_key = \"$ELASTIC_API_KEY\"\n\
             ssl = false\n"
        ),
        &rules,
    );
    let env = Env::from_pairs([("ELASTIC_API_KEY", SECRET), ("NO_PROXY", "*")]);
    let args = Args {
        platform: Some("elastic".to_owned()),
        live: true,
        ..Args::default()
    };
    let never = || false;
    let live = run(
        &args,
        &Context {
            repo: Some(ws.path().to_str().unwrap()),
            env: &env,
            cwd: ws.path(),
            proxy: None,
            interrupted: &never,
            now: now(),
            registry: &opentide_connectors::builtin(),
            debug: false,
        },
    );
    assert_eq!(
        &value(&live, "status"),
        &Json::str("failed"),
        "{:?}",
        live.result
    );
    assert_eq!(&value(&live, "tenant"), &Json::str("lab"));
    assert_eq!(&value(&live, "host"), &Json::str(uri.as_str()));
    let Json::Str(message) = &value(&live, "message") else {
        panic!("a message")
    };
    assert!(
        message.starts_with("elastic tenant 'lab' refused the check: "),
        "{message}"
    );
    assert!(!message.contains("Queries rejected"), "{message}");
    assert!(!has(&live, "queries_validated"));
    assert_eq!(
        live.step.as_ref().unwrap().status,
        opentide_cli::render::progress::StepStatus::Failed
    );
}

/// Graylog's stream aliases reach the check (smoke E3/D3, #1654): the
/// tenant's `streams` and a rule's own `streams` are resolved through the
/// tenant's `[tenants.setup.stream_ids]` table, as deploy resolves them,
/// rather than refused as `graylog_alias_unknown`.
#[test]
fn graylog_checks_resolve_stream_aliases_through_the_tenants_table() {
    use wiremock::matchers::{method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(
        wiremock::Mock::given(method("POST"))
            .and(path("/api/search/validate"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"status": "OK"})),
            )
            .mount(&server),
    );
    let block = |streams: &str| {
        format!(
            "  graylog:\n    schema: platform::graylog::1.0\n    status: STAGING\n    query: \
             'EventID:1'\n{streams}"
        )
    };
    let ws = workspace(
        "graylog",
        &format!(
            "url = \"{}\"\ntoken = \"$GRAYLOG_TOKEN\"\nstreams = [\"endpoint\"]\n\
             [tenants.setup.stream_ids]\nendpoint = \"65f0c0ffee0123456789abcd\"\nsysmon = \
             \"65f0c0ffee0123456789abce\"\n",
            server.uri()
        ),
        &[
            (
                "a-tenant-streams.yaml",
                rule(
                    "Tenant streams",
                    "00000000-0000-4000-8046-000000000301",
                    &block(""),
                ),
            ),
            (
                "b-own-streams.yaml",
                rule(
                    "Own streams",
                    "00000000-0000-4000-8046-000000000302",
                    &block("    streams: sysmon\n"),
                ),
            ),
        ],
    );
    let env = Env::from_pairs([("GRAYLOG_TOKEN".to_owned(), "token".to_owned())]);
    let args = Args {
        platform: Some("graylog".to_owned()),
        live: true,
        ..Args::default()
    };
    let never = || false;
    let mut registry = Registry::new();
    registry
        .register(Box::new(opentide_connectors::graylog::Graylog::new()))
        .unwrap();
    let live = run(
        &args,
        &Context {
            repo: Some(ws.path().to_str().unwrap()),
            env: &env,
            cwd: ws.path(),
            proxy: None,
            interrupted: &never,
            now: now(),
            registry: &registry,
            debug: false,
        },
    );
    assert_eq!(
        &value(&live, "status"),
        &Json::str("passed"),
        "{:?}",
        live.result
    );
    let streams: Vec<serde_json::Value> = rt
        .block_on(server.received_requests())
        .unwrap()
        .iter()
        .map(|request| {
            serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["streams"].clone()
        })
        .collect();
    assert_eq!(
        streams,
        [
            serde_json::json!(["65f0c0ffee0123456789abcd"]),
            serde_json::json!(["65f0c0ffee0123456789abce"]),
        ]
    );
}

/// A tenant refused before another one stops the check is never hidden by
/// that later failure: the result names it beside the unreachable tenant
/// (#1658, E8).
#[test]
fn a_refused_tenant_is_named_when_the_next_one_is_unreachable() {
    let ws = splunk_rules(1);
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/splunk.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        format!(
            "{text}\n[[tenants]]\nname = \"lab2\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\nurl = \
             \"splunk2.invalid\"\nport = 8089\napp = \"search\"\ntoken = \"$SPLUNK_TOKEN\"\n"
        ),
    )
    .unwrap();
    let live = scripted(
        ws.path(),
        vec![
            Err(ConnectorError::authentication(
                "splunk",
                "lab",
                "Splunk refused the credential (HTTP 401)",
            )),
            Err(ConnectorError::Unreachable {
                platform: "splunk".into(),
                tenant: "lab2".into(),
                address: "https://splunk2.invalid:8089".into(),
                reason: "connection refused".into(),
            }),
        ],
    );
    assert_eq!(&value(&live, "tenant"), &Json::str("lab2"));
    assert_eq!(
        &value(&live, "refused_tenants"),
        &Json::Array(vec![Json::str("lab")])
    );
    assert_eq!(live.result.exit, ExitCode::Failure);
}

/// An Elastic tenant whose first rule timed out and whose second the key
/// is refused on: an answer came, so the tenant refused the check; it is
/// not reported unreachable (#1658, E8).
#[test]
fn an_elastic_refusal_after_a_timeout_is_a_refusal() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let server = runtime.block_on(wiremock::MockServer::start());
    runtime.block_on(async {
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(4)),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(401).set_body_string(
                r#"{"error":{"type":"security_exception","reason":"unable to authenticate"}}"#,
            ))
            .with_priority(2)
            .mount(&server)
            .await;
    });
    let uri = server.uri();
    let rules: Vec<(&str, String)> = (1..=2)
        .map(|n| {
            (
                if n == 1 { "rule-1.yaml" } else { "rule-2.yaml" },
                rule(
                    &format!("Elastic rule {n}"),
                    &format!("00000000-0000-4000-8046-0000000005{n:02}"),
                    "  elastic:\n    status: STAGING\n    type: query\n    language: kuery\n    \
                     query: 'process.name: cmd.exe'\n    index: [logs-*]\n",
                ),
            )
        })
        .collect();
    let ws = workspace(
        "elastic",
        &format!(
            "url = \"{uri}\"\nelasticsearch_url = \"{uri}\"\napi_key = \"$ELASTIC_API_KEY\"\n\
             ssl = false\n"
        ),
        &rules,
    );
    let env = Env::from_pairs([("ELASTIC_API_KEY", SECRET), ("NO_PROXY", "*")]);
    let args = Args {
        platform: Some("elastic".to_owned()),
        live: true,
        check_timeout: Some("1".to_owned()),
        ..Args::default()
    };
    let never = || false;
    let live = run(
        &args,
        &Context {
            repo: Some(ws.path().to_str().unwrap()),
            env: &env,
            cwd: ws.path(),
            proxy: None,
            interrupted: &never,
            now: now(),
            registry: &opentide_connectors::builtin(),
            debug: false,
        },
    );
    let Json::Str(message) = &value(&live, "message") else {
        panic!("a message: {:?}", live.result)
    };
    assert!(
        message.starts_with("elastic tenant 'lab' refused the check: "),
        "{message}"
    );
    // The timed-out check is kept beside the refusal.
    let Json::Array(timed_out) = &value(&live, "timed_out") else {
        panic!("timed_out")
    };
    assert_eq!(timed_out.len(), 1);
}

/// `validate query --live --platform splunk --json` on the golden
/// `live-tenants` workspace, the recorded Splunk tenant answering its first
/// parser check 401: the tenant's failure, end to end through the recorded
/// requests (#1658, E8).
#[test]
fn a_splunk_tenant_refusing_the_token_is_the_tenants_failure_end_to_end() {
    use opentide_cassette::cassette::Body;
    let text =
        std::fs::read_to_string(repo().join("tests/cassettes/golden/validate-live-splunk.json"))
            .unwrap();
    let recorded = Cassette::parse(&text).unwrap();
    let mut interactions = recorded.interactions[..=2].to_vec();
    let answer = &mut interactions[2].response;
    answer.status = 401;
    answer.headers = vec![("content-type".into(), "application/json".into())];
    answer.body = Body::Text(
        r#"{"messages":[{"type":"WARN","text":"call not properly authenticated"}]}"#.into(),
    );
    let cassette = Cassette::new(
        &recorded.scenario,
        recorded.recorded_from.clone(),
        interactions,
    );
    let proxy = Proxy::start(
        Mode::Replay { cassette },
        Redaction::new([SECRET.to_owned()]),
    )
    .unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let ws = scratch.path().join("ws");
    copy_tree(&repo().join("tests/golden/fixtures/live-tenants"), &ws);
    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(proxy.ca_pem().as_bytes()).unwrap();
    let env = Env::from_pairs(
        proxy
            .client_env(ca.path().to_str().unwrap())
            .into_iter()
            .chain([("SPLUNK_TOKEN".to_owned(), SECRET.to_owned())]),
    );
    let args = Args {
        platform: Some("splunk".to_owned()),
        live: true,
        ..Args::default()
    };
    let never = || false;
    let live = run(
        &args,
        &Context {
            repo: Some(ws.to_str().unwrap()),
            env: &env,
            cwd: &ws,
            proxy: None,
            interrupted: &never,
            now: now(),
            registry: &opentide_connectors::builtin(),
            debug: false,
        },
    );
    assert_eq!(proxy.verify(), Vec::new());
    let report = live.result.clone().report("validate query");
    let failure = report.outcome.failure.as_ref().unwrap();
    assert_eq!(failure.code, "authentication_failed");
    let Json::Object(document) = report.outcome.document(0) else {
        panic!("the document is an object")
    };
    let keys: Vec<&str> = document.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "platform",
            "mode",
            "supported",
            "tenant",
            "host",
            "advice",
            "ok",
            "status",
            "message",
            "error",
            "schema_version",
            "command",
            "duration_ms",
            "exit_code",
            "summary",
            "next_actions",
            "failure"
        ]
    );
    assert_eq!(
        &value(&live, "message"),
        &Json::str(
            "splunk tenant 'lab' refused the check: Splunk refused the credential (HTTP \
             401): call not properly authenticated"
        )
    );
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// `git` in `dir`, with a fixed identity and no system or user config.
fn git(dir: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .envs([
            ("GIT_AUTHOR_NAME", "t"),
            ("GIT_AUTHOR_EMAIL", "t@opentide.invalid"),
            ("GIT_COMMITTER_NAME", "t"),
            ("GIT_COMMITTER_EMAIL", "t@opentide.invalid"),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

/// On a push the production deploy will promote, `--changed` checks the
/// changed STAGING rule as the deploy sends it: promoted, on the tenant that
/// takes RELEASE (#1653, smoke E15). It used to check it on PREVIEW tenants
/// only, and with only a RELEASE tenant it reached none (exit 2).
#[test]
fn a_push_checks_the_rules_it_will_promote_on_their_release_tenants() {
    let ws = splunk_rules(1);
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/splunk.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        text.replace("strategies = [\"PREVIEW\"]", "strategies = [\"RELEASE\"]"),
    )
    .unwrap();
    git(ws.path(), &["init", "-q"]);
    git(ws.path(), &["add", "-A"]);
    git(ws.path(), &["commit", "-q", "-m", "base"]);
    let path = ws.path().join("objects/rules/rule-1.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace("n=1", "n=2")).unwrap();
    git(ws.path(), &["commit", "-q", "-a", "-m", "push"]);
    let before = std::fs::read(&path).unwrap();
    let registry = Scripted::registry(
        "splunk",
        vec![Ok(LiveCheck {
            result: None,
            errors: Vec::new(),
            warnings: Vec::new(),
        })],
    );
    let workspace = ws.path().display().to_string();
    let env = Env::from_pairs([
        ("SPLUNK_TOKEN", SECRET),
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_EVENT_NAME", "push"),
        ("GITHUB_REF", "refs/heads/main"),
        ("OPENTIDE_DEFAULT_BRANCH", "main"),
        ("GITHUB_SHA", "HEAD"),
        ("GITHUB_WORKSPACE", workspace.as_str()),
    ]);
    let args = Args {
        platform: Some("splunk".to_owned()),
        live: true,
        changed: true,
        check_timeout: Some("5".to_owned()),
        ..Args::default()
    };
    let never = || false;
    let live = run(
        &args,
        &Context {
            repo: Some(ws.path().to_str().unwrap()),
            env: &env,
            cwd: ws.path(),
            proxy: None,
            interrupted: &never,
            now: now(),
            registry: &registry,
            debug: false,
        },
    );
    assert_eq!(
        &value(&live, "status"),
        &Json::str("passed"),
        "{:?}",
        live.result
    );
    assert_eq!(
        &value(&live, "queries_per_tenant"),
        &Json::object([("lab", Json::Int(1))])
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "a check writes nothing"
    );
}

/// A Splunk live validator that keeps the search of each check it gets.
struct Searches(std::sync::Mutex<Vec<String>>);

impl LiveValidator for Searches {
    fn validate<'a>(
        &'a self,
        _cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        self.0.lock().unwrap().push(request.text.clone());
        Box::pin(async {
            Ok(LiveCheck {
                result: None,
                errors: Vec::new(),
                warnings: Vec::new(),
            })
        })
    }
}

/// Registers a [`Searches`] as `splunk`.
struct SearchesPlatform(&'static Searches);

impl Platform for SearchesPlatform {
    fn id(&self) -> &'static str {
        "splunk"
    }

    fn live_validator(&self) -> Option<&dyn LiveValidator> {
        Some(self.0)
    }
}

/// `validate query --live` checks the Splunk search as deploy writes it:
/// the block's `query`, trimmed, with nothing appended (#1657).
#[test]
fn a_splunk_check_sends_the_query_as_written() {
    let ws = splunk_rules(1);
    let searches: &'static Searches =
        Box::leak(Box::new(Searches(std::sync::Mutex::new(Vec::new()))));
    let mut registry = Registry::new();
    registry
        .register(Box::new(SearchesPlatform(searches)))
        .unwrap();
    let env = Env::from_pairs([("SPLUNK_TOKEN", SECRET)]);
    let args = Args {
        platform: Some("splunk".to_owned()),
        live: true,
        check_timeout: Some("5".to_owned()),
        ..Args::default()
    };
    let never = || false;
    let live = run(
        &args,
        &Context {
            repo: Some(ws.path().to_str().unwrap()),
            env: &env,
            cwd: ws.path(),
            proxy: None,
            interrupted: &never,
            now: now(),
            registry: &registry,
            debug: false,
        },
    );
    assert_eq!(&value(&live, "status"), &Json::str("passed"));
    let searches = searches.0.lock().unwrap();
    assert_eq!(searches[..], ["index=main n=1"], "{searches:?}");
}

/// A Splunk stand-in whose tenants answer after a delay of their own
/// (`lab` the slowest), counting the searches in flight: in all, and on
/// each tenant. `lab2` rejects its first rule's query; `unreachable` names
/// a tenant whose searches cannot connect; `stalled` one whose searches
/// all time out at once, as a TLS handshake that never completes.
struct Paced {
    delayed: bool,
    unreachable: Option<&'static str>,
    stalled: Option<&'static str>,
    flight: std::sync::Mutex<Flight>,
}

/// The searches in flight, now and at most: in all, and by tenant.
#[derive(Default)]
struct Flight {
    now: usize,
    most: usize,
    tenants: std::collections::HashMap<String, (usize, usize)>,
    /// The searches each tenant was asked, by tenant.
    asked: std::collections::HashMap<String, usize>,
}

impl Paced {
    fn leaked(delayed: bool, unreachable: Option<&'static str>) -> &'static Paced {
        Box::leak(Box::new(Paced {
            delayed,
            unreachable,
            stalled: None,
            flight: std::sync::Mutex::new(Flight::default()),
        }))
    }

    /// A [`Paced`], delayed, whose tenant `tenant` stalls.
    fn stalling(tenant: &'static str) -> &'static Paced {
        Box::leak(Box::new(Paced {
            delayed: true,
            unreachable: None,
            stalled: Some(tenant),
            flight: std::sync::Mutex::new(Flight::default()),
        }))
    }

    /// The searches *tenant* was asked.
    fn asked(&self, tenant: &str) -> usize {
        let flight = self.flight.lock().unwrap();
        flight.asked.get(tenant).copied().unwrap_or(0)
    }

    /// The most searches in flight at once: in all, and on one tenant.
    fn most(&self) -> (usize, usize) {
        let flight = self.flight.lock().unwrap();
        let per_tenant = flight.tenants.values().map(|(_, most)| *most).max();
        (flight.most, per_tenant.unwrap_or(0))
    }
}

impl LiveValidator for Paced {
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        let tenant = cx.tenant.label.tenant.clone();
        Box::pin(async move {
            {
                let mut flight = self.flight.lock().unwrap();
                flight.now += 1;
                flight.most = flight.most.max(flight.now);
                let mine = flight.tenants.entry(tenant.clone()).or_default();
                mine.0 += 1;
                mine.1 = mine.1.max(mine.0);
                *flight.asked.entry(tenant.clone()).or_default() += 1;
            }
            if self.stalled == Some(tenant.as_str()) {
                let mut flight = self.flight.lock().unwrap();
                flight.now -= 1;
                if let Some(mine) = flight.tenants.get_mut(&tenant) {
                    mine.0 -= 1;
                }
                return Err(ConnectorError::Timeout {
                    platform: "splunk".into(),
                    tenant: tenant.clone(),
                    address: format!("https://{tenant}.invalid:8089"),
                    seconds: 5,
                });
            }
            if self.delayed {
                let millis = if tenant == "lab" { 150 } else { 40 };
                tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
            }
            {
                let mut flight = self.flight.lock().unwrap();
                flight.now -= 1;
                if let Some(mine) = flight.tenants.get_mut(&tenant) {
                    mine.0 -= 1;
                }
            }
            if self.unreachable == Some(tenant.as_str()) {
                return Err(ConnectorError::Unreachable {
                    platform: "splunk".into(),
                    tenant: tenant.clone(),
                    address: format!("https://{tenant}.invalid:8089"),
                    reason: "connection refused".into(),
                });
            }
            let errors = if tenant == "lab2" && request.text.ends_with("n=1") {
                vec!["Unknown search command 'stat' 😀".to_owned()]
            } else {
                Vec::new()
            };
            Ok(LiveCheck {
                errors,
                ..LiveCheck::default()
            })
        })
    }
}

/// Registers a [`Paced`] as `splunk`.
struct PacedPlatform(&'static Paced);

impl Platform for PacedPlatform {
    fn id(&self) -> &'static str {
        "splunk"
    }

    fn live_validator(&self) -> Option<&dyn LiveValidator> {
        Some(self.0)
    }
}

/// `validate query --live` of `rules` Splunk rules on the tenants `lab`,
/// `lab2` and `lab3`, checked by `validator`; the result, and the time the
/// run took.
fn paced(rules: usize, validator: &'static Paced) -> (Live, std::time::Duration) {
    paced_on(rules, &["lab2", "lab3"], validator)
}

/// [`paced`] on `lab` and the tenants `more`, in that order.
fn paced_on(rules: usize, more: &[&str], validator: &'static Paced) -> (Live, std::time::Duration) {
    keep_callsites_enabled();
    let ws = splunk_rules(rules);
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/splunk.toml");
    let mut text = std::fs::read_to_string(&config).unwrap();
    for tenant in more {
        text.push_str(&format!(
            "\n[[tenants]]\nname = \"{tenant}\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\nurl \
             = \"{tenant}.invalid\"\nport = 8089\napp = \"search\"\ntoken = \"$SPLUNK_TOKEN\"\n"
        ));
    }
    std::fs::write(&config, text).unwrap();
    let mut registry = Registry::new();
    registry
        .register(Box::new(PacedPlatform(validator)))
        .unwrap();
    let env = Env::from_pairs([("SPLUNK_TOKEN", SECRET)]);
    let args = Args {
        platform: Some("splunk".to_owned()),
        live: true,
        check_timeout: Some("5".to_owned()),
        ..Args::default()
    };
    let never = || false;
    let started = std::time::Instant::now();
    let live = run(
        &args,
        &Context {
            repo: Some(ws.path().to_str().unwrap()),
            env: &env,
            cwd: ws.path(),
            proxy: None,
            interrupted: &never,
            now: now(),
            registry: &registry,
            debug: false,
        },
    );
    (live, started.elapsed())
}

/// The tenants of a platform are checked at once, each tenant's queries
/// one after another (its streak of timeouts counts them in order), and the
/// result is the one a serial run gives, whichever tenant answers first
/// (#1941).
#[test]
fn tenants_are_checked_at_once_and_reported_in_order() {
    let instant = Paced::leaked(false, None);
    let (serial, _) = paced(3, instant);
    assert_eq!(
        instant.most(),
        (1, 1),
        "answers that never wait come one by one"
    );
    let delayed = Paced::leaked(true, None);
    let (concurrent, took) = paced(3, delayed);
    // The wall time, which a serial run spends on every query in turn.
    eprintln!("3 tenants x 3 queries, lab 150 ms a query, the others 40 ms: {took:?}");
    let (most, per_tenant) = delayed.most();
    assert!(most >= 2, "the tenants were checked one after another");
    assert_eq!(per_tenant, 1, "a tenant's queries overlapped");
    assert_eq!(concurrent.result, serial.result);
    assert_eq!(&value(&concurrent, "queries_validated"), &Json::Int(9));
    let Json::Array(rejected) = &value(&concurrent, "rejected") else {
        panic!("rejected is a list")
    };
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].get("tenant"), Some(&Json::str("lab2")));
}

/// A tenant that stops the check stops it there, as in a serial run: the
/// tenants after it, checked meanwhile, are not reported (#1941).
#[test]
fn a_tenant_that_stops_the_check_hides_the_tenants_after_it() {
    let instant = Paced::leaked(false, Some("lab"));
    let (serial, _) = paced(2, instant);
    let delayed = Paced::leaked(true, Some("lab"));
    let (concurrent, _) = paced(2, delayed);
    assert_eq!(&value(&serial, "tenant"), &Json::str("lab"));
    assert_eq!(concurrent.result, serial.result);
}

/// A tenant whose every query times out, on fewer queries than the streak
/// of three needs, is unreachable once its batch ends, and stops the check
/// there: the tenants after it that had not started are never asked, as in
/// a serial run (#1941).
#[test]
fn a_stalled_tenant_stops_the_tenants_not_yet_started() {
    let stalled = Paced::stalling("lab");
    let (live, _) = paced_on(2, &["lab2", "lab3", "lab4", "lab5", "lab6"], stalled);
    assert_eq!(&value(&live, "tenant"), &Json::str("lab"));
    assert_eq!(stalled.asked("lab"), 2);
    for later in ["lab5", "lab6"] {
        assert_eq!(
            stalled.asked(later),
            0,
            "{later} was asked after lab stopped the check"
        );
    }
}
