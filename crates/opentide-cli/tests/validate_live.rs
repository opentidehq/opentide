//! `validate query --live`'s flow on the platforms whose checks search the
//! last minute (UC-4.6, #979): Defender for Endpoint, SentinelOne and
//! Sentinel. A golden case cannot replay them (a run's window ends now), so
//! each runs here with the time fixed, against its connector's cassette
//! recorded from the Python client (`tests/cassettes/<platform>/validate.json`):
//! the rules of a workspace, through the deploy plan, the tenant's batch and
//! the connector, send exactly the requests the oracle sent, and the result
//! reads as the oracle's.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use opentide_cassette::{Cassette, Mode, Proxy, Redaction};
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
        },
    );
    (result, proxy.verify())
}

/// The result's value at `key`.
fn value<'a>(live: &'a Live, key: &str) -> &'a Json {
    &live
        .result
        .iter()
        .find(|(name, _)| name == key)
        .unwrap_or_else(|| panic!("no {key} in {:?}", live.result))
        .1
}

/// Defender for Endpoint whose check counts its data's retention from the
/// recording's time, not today's.
struct DefenderAt(opentide_connectors::defender::Defender);

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
        "defender_for_endpoint"
    }

    fn live_validator(&self) -> Option<&dyn LiveValidator> {
        Some(self)
    }
}

#[test]
fn defender_rules_are_checked_with_their_custom_detection_columns() {
    let ws = workspace(
        "defender_for_endpoint",
        "tenant_id = \"contoso-tenant-id\"\nclient_id = \"opentide-app-id\"\nclient_secret = \
         \"$DEFENDER_CLIENT_SECRET\"\n",
        &[
            (
                "a-columns.yaml",
                rule(
                    "Defender columns rule",
                    "00000000-0000-4000-8046-000000000101",
                    "  defender_for_endpoint:\n    status: STAGING\n    query: |\n      \
                     DeviceProcessEvents\n      | project Timestamp, DeviceId, ReportId\n",
                ),
            ),
            (
                "b-no-columns.yaml",
                rule(
                    "Defender rule without columns",
                    "00000000-0000-4000-8046-000000000102",
                    "  defender_for_endpoint:\n    status: STAGING\n    query: |\n      \
                     DeviceProcessEvents\n      | project Timestamp, DeviceName\n",
                ),
            ),
        ],
    );
    let mut registry = Registry::new();
    registry
        .register(Box::new(DefenderAt(
            opentide_connectors::defender::Defender::new(),
        )))
        .unwrap();
    let (live, mismatches) = live(
        ws.path(),
        "defender_for_endpoint",
        "defender/validate",
        "DEFENDER_CLIENT_SECRET",
        &registry,
    );
    assert_eq!(mismatches, Vec::new());
    assert_eq!(value(&live, "status"), &Json::str("failed"));
    assert_eq!(
        value(&live, "message"),
        &Json::str("Queries rejected on defender_for_endpoint · 2 checked on 1 tenant")
    );
    assert_eq!(value(&live, "_exit_code"), &Json::Int(1));
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
    assert_eq!(value(&live, "status"), &Json::str("passed"));
    // The rule counts once, its two sub-queries checked one by one.
    assert_eq!(
        value(&live, "message"),
        &Json::str("1 query valid on 1 tenant")
    );
    assert_eq!(
        value(&live, "queries_per_tenant"),
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
    // `client.py`'s request ids: the n-th id of the run, from 1.
    let next = Arc::new(AtomicU64::new(0));
    let sentinel = opentide_connectors::sentinel::Sentinel::with_identity(
        Arc::new(move || {
            let number = next.fetch_add(1, Ordering::SeqCst) + 1;
            format!("00000000-0000-4000-8000-{number:012x}")
        }),
        "linux",
    );
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
    assert_eq!(value(&live, "status"), &Json::str("passed"));
    assert_eq!(
        value(&live, "message"),
        &Json::str("2 queries valid on 1 tenant")
    );
    assert_eq!(
        value(&live, "_summary"),
        &Json::object([("queries", Json::Int(2)), ("tenants", Json::Int(1))])
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

/// Runs the scripted checks on `ws`'s Splunk rules.
fn scripted(ws: &Path, outcomes: Vec<Result<LiveCheck, ConnectorError>>) -> Live {
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
fn each_outcome_of_a_check_is_the_oracles() {
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
    assert_eq!(value(&live, "status"), &Json::str("failed"));
    assert_eq!(
        value(&live, "message"),
        &Json::str(
            "Queries rejected on splunk · 5 checked on 1 tenant · 3 with no answer within 5s"
        )
    );
    assert_eq!(value(&live, "check_timeout"), &Json::Float(5.0));
    let Json::Array(timed_out) = value(&live, "timed_out") else {
        panic!("timed_out is a list")
    };
    assert_eq!(timed_out.len(), 3);
    let first = &timed_out[0];
    assert_eq!(first.get("code"), Some(&Json::str("query_check_timeout")));
    assert_eq!(
        first.get("errors"),
        Some(&Json::Array(vec![Json::str(
            "no answer within the 5s check timeout (timed out). Raise it with --check-timeout or \
             OPENTIDE_QUERY_CHECK_TIMEOUT, or make the query cheaper"
        )]))
    );
    assert_eq!(
        value(&live, "warnings"),
        &Json::Array(vec![Json::str(
            "Query validation reported warnings for splunk"
        )])
    );
    // A refusal fails the run too, so the timeouts are not its only failures.
    assert!(!live.result.iter().any(|(key, _)| key == "_failure_code"));
    let report = live.report(&Env::from_pairs([("OPENTIDE_PROGRESS", "json")]));
    assert_eq!(
        report.stderr_first,
        "{\"event\":\"progress\",\"step\":\"Stand-in queries\",\"done\":1,\"total\":1}\n"
    );
    assert_eq!(report.outcome.exit_code, 1);
}

#[test]
fn checks_that_only_timed_out_name_their_code() {
    let ws = splunk_rules(2);
    let live = scripted(
        ws.path(),
        vec![Err(read_timeout()), Ok(LiveCheck::default())],
    );
    assert_eq!(
        value(&live, "_failure_code"),
        &Json::str("query_check_timeout")
    );
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
    assert_eq!(value(&live, "host"), &Json::str("splunk.invalid:8089"));
    let Json::Str(message) = value(&live, "message") else {
        panic!("a message")
    };
    assert!(
        message.starts_with(
            "Cannot reach splunk tenant 'lab' at splunk.invalid:8089: 3 queries in a row got no \
             answer within the 5s check timeout"
        ),
        "{message}"
    );
    let Json::Str(advice) = value(&live, "advice") else {
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
    let Json::Str(message) = value(&live, "message") else {
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
    assert_eq!(
        value(&live, "message"),
        &Json::str(
            "Query validation for splunk failed: TenantConnectionError: Cannot authenticate with \
             the tenant configuration"
        )
    );
    assert_eq!(value(&live, "queries_validated"), &Json::Int(2));
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
        value(&live, "message"),
        &Json::str("Cannot reach splunk tenant 'lab' at splunk.invalid:8089: connection refused")
    );
    assert_eq!(value(&live, "tenant"), &Json::str("lab"));
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
    assert_eq!(value(&removed, "_exit_code"), &Json::Int(2));
    let missing = run(&args(None, &[]), &cx(plain));
    assert_eq!(
        value(&missing, "_failure_argument"),
        &Json::str("--platform")
    );
    let typo = run(&args(Some("splunk"), &["STAGING"]), &cx(plain));
    assert_eq!(
        value(&typo, "_failure_code"),
        &Json::str("usage_invalid_choice")
    );
    let disabled = run(&args(Some("elastic"), &[]), &cx(plain));
    assert_eq!(value(&disabled, "platform_enabled"), &Json::Bool(false));
    let none = run(&args(Some("splunk"), &["RELEASE"]), &cx(plain));
    assert_eq!(value(&none, "status"), &Json::str("skipped"));
    assert_eq!(
        value(&none, "message"),
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
    assert_eq!(value(&unreached, "_exit_code"), &Json::Int(2));
    assert_eq!(
        value(&unreached, "_failure_code"),
        &Json::str("no_tenant_reached")
    );
}
