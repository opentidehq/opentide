//! A deploy that sends, on the platforms a golden case cannot replay (UC-4.6,
//! #979): Sentinel (MSAL's and azure-core's random request ids), a Carbon
//! Black Cloud report built or updated (the SDK stamps it with the time) and
//! HarfangLab (the oracle's deploy stopped before any request). Each runs here
//! through the CLI flow, the ids and the time fixed, against the requests of
//! its connector's cassette recorded from the Python client
//! (`tests/cassettes/<platform>/deploy.json`): the rules of a workspace,
//! through the deploy plan, the tenant's batch and the connector, send
//! exactly the requests the oracle sent. The flow's own rules (a refusal
//! stops the run, the rules after it not attempted; deployment state written
//! only when the platform accepted the rule) run against a scripted deployer.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use opentide_cassette::{Cassette, Mode, Proxy, Redaction};
use opentide_cli::commands::deploy_send::{Args, Context, Lines, Sent, run};
use opentide_cli::env::Env;
use opentide_cli::json::Json;
use opentide_cli::render::outcome::Console;
use opentide_cli::render::text::Colour;
use opentide_connectors::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, Operation, Platform, TenantContext,
};
use opentide_connectors::{ConnectorError, Registry};

/// The credential the replayed tenant gets; redacted, as the recording's was.
const SECRET: &str = "replayed-credential-value";

fn repo() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A rule file of one platform block.
fn rule(name: &str, uuid: &str, description: &str, block: &str) -> String {
    format!(
        "name: {name}\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.0\n  version: 1\n  created: \
         2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: {description}\nresponse:\n  \
         alert_severity: High\nconfigurations:\n{block}"
    )
}

/// A workspace whose `platform` has one tenant, `tenant`, of `setup`, that
/// takes PREVIEW and RELEASE runs, and the rules `rules` (file name, text).
fn workspace(
    platform: &str,
    tenant: &str,
    setup: &str,
    rules: &[(&str, String)],
) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let platforms = dir.path().join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::write(
        platforms.join(format!("{platform}.toml")),
        format!(
            "[platform]\nenabled = true\nname = \"Stand-in\"\n\n[[tenants]]\nname = \
             \"{tenant}\"\nstrategies = [\"PREVIEW\", \"RELEASE\"]\n[tenants.setup]\n{setup}"
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

/// What the run wrote on stderr.
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buffer {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// Runs `deploy --platform platform --strategy PREVIEW --strategy RELEASE
/// --all --keep-deprecated` in `ws`, with `env`, at `now`.
fn deploy(ws: &Path, platform: &str, env: &Env, registry: &Registry, now: i64) -> (Sent, String) {
    let args = Args {
        strategies: vec!["PREVIEW".into(), "RELEASE".into()],
        all: true,
        platform: Some(platform.to_owned()),
        keep_deprecated: Some(true),
        ..Args::default()
    };
    deploy_with(ws, &args, env, registry, now)
}

/// Runs `deploy` with `args` in `ws`, with `env`, at `now`.
fn deploy_with(ws: &Path, args: &Args, env: &Env, registry: &Registry, now: i64) -> (Sent, String) {
    let buffer = Buffer::default();
    let lines = Lines {
        sink: Arc::new(Mutex::new(buffer.clone())),
        console: Console {
            colour: Colour::None,
            width: None,
        },
        silent: false,
        quiet: false,
        progress: false,
        terminal: false,
        live: None,
    };
    let never = || false;
    let sent = run(
        args,
        &Context {
            repo: Some(ws.to_str().unwrap()),
            env,
            cwd: ws,
            proxy: None,
            interrupted: &never,
            now: jiff::Timestamp::from_second(now).unwrap(),
            registry,
            lines,
            json: false,
            debug: false,
        },
    );
    (sent, buffer.text())
}

/// A proxy replaying `interactions` of the cassette `scenario`, and the
/// environment that sends the run through it with `variable` set.
fn replay(
    scenario: &str,
    interactions: &[usize],
    variable: &str,
) -> (Proxy, Env, tempfile::NamedTempFile) {
    let text =
        std::fs::read_to_string(repo().join(format!("tests/cassettes/{scenario}.json"))).unwrap();
    let mut cassette = Cassette::parse(&text).unwrap();
    cassette.interactions = interactions
        .iter()
        .map(|index| cassette.interactions[*index].clone())
        .collect();
    let proxy = Proxy::start(
        Mode::Replay { cassette },
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
    (proxy, env, ca)
}

/// The result's value at `key`.
fn value<'a>(sent: &'a Sent, key: &str) -> &'a Json {
    &sent
        .result
        .iter()
        .find(|(name, _)| name == key)
        .unwrap_or_else(|| panic!("no {key} in {:?}", sent.result))
        .1
}

/// Each result row's `status` and `error`.
fn rows(sent: &Sent) -> Vec<(String, Option<String>)> {
    let Json::Array(results) = value(sent, "results") else {
        panic!("no results")
    };
    results
        .iter()
        .map(|row| {
            (
                row.get("status").and_then(Json::as_str).unwrap().to_owned(),
                row.get("error").and_then(Json::as_str).map(str::to_owned),
            )
        })
        .collect()
}

const SENTINEL_SETUP: &str = "ssl = true\nresource_group = \"soc-rg\"\nworkspace_name = \"soc \
     workspace\"\nworkspace_id = \"11111111-2222-4333-8444-555555555555\"\nazure_tenant_id = \
     \"contoso-tenant-id\"\nazure_subscription_id = \"sub-0001\"\nazure_client_id = \
     \"opentide-app-id\"\nazure_client_secret = \"$AZURE_CLIENT_SECRET\"\n";

const SENTINEL_BLOCK: &str = "  sentinel:\n    status: REMOVED\n    query: SecurityEvent\n    \
     scheduling:\n      frequency: PT1H\n      lookback: PT1H\n    grouping:\n      event: \
     SingleAlert\n      alert:\n        enabled: false\n";

/// Sentinel with the request ids `client.py` fixed (`request_id(n)`, from 1).
fn sentinel_registry() -> Registry {
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
    registry
}

#[test]
fn sentinel_retires_a_rule_as_the_python_deployer_did() {
    let ws = workspace(
        "sentinel",
        "soc",
        SENTINEL_SETUP,
        &[(
            "retired.yaml",
            rule(
                "Encoded PowerShell",
                "00000000-0000-4000-8003-000000000001",
                "Retired.",
                SENTINEL_BLOCK,
            ),
        )],
    );
    // Sign in (the OpenID configuration, the token), then the DELETE ARM answered 200.
    let (proxy, env, _ca) = replay("sentinel/deploy", &[0, 1, 6], "AZURE_CLIENT_SECRET");
    let (sent, stderr) = deploy(ws.path(), "sentinel", &env, &sentinel_registry(), 0);
    assert_eq!(proxy.verify(), Vec::new());
    assert_eq!(rows(&sent), [("deployed".to_owned(), None)]);
    assert_eq!(value(&sent, "status"), &Json::str("completed"));
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(0));
    assert!(
        stderr.contains(
            "Deploying to sentinel / soc · 1 rule\n  [1/1] ✓ deleted   Encoded PowerShell"
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains("✓ sentinel · 1 deployed, 0 failed, 0 not attempted · "),
        "{stderr}"
    );
}

#[test]
fn sentinel_stops_the_run_on_a_refusal_with_the_platforms_words() {
    let ws = workspace(
        "sentinel",
        "soc",
        SENTINEL_SETUP,
        &[(
            "retired.yaml",
            rule(
                "Encoded PowerShell",
                "00000000-0000-4000-8003-000000000001",
                "Retired.",
                SENTINEL_BLOCK,
            ),
        )],
    );
    // The DELETE ARM answered 404: `SentinelApiError` stops the run.
    let (proxy, env, _ca) = replay("sentinel/deploy", &[0, 1, 7], "AZURE_CLIENT_SECRET");
    let (sent, _) = deploy(ws.path(), "sentinel", &env, &sentinel_registry(), 0);
    assert_eq!(proxy.verify(), Vec::new());
    let rows = rows(&sent);
    assert_eq!(rows[0].0, "failed");
    let error = rows[0].1.clone().unwrap();
    assert!(
        error.starts_with("HTTP 404: DELETE https://management.azure.com/"),
        "{error}"
    );
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(1));
    assert_eq!(value(&sent, "_failure_code"), &Json::str("issues_found"));
    assert_eq!(
        value(&sent, "error"),
        &Json::str(format!(
            "Deployment to sentinel failed on Encoded PowerShell: {error}"
        ))
    );
    let Json::Str(message) = value(&sent, "message") else {
        panic!("a message")
    };
    assert!(
        message.starts_with("Deployment failed · 1 failed, 0 not attempted · "),
        "{message}"
    );
}

const CBC_SETUP: &str = "ssl = true\nurl = \"https://cbc.invalid\"\norg_key = \"ORGKEY01\"\ntoken \
     = \"$CBC_TOKEN\"\nwatchlist = \"opentide\"\n";

fn cbc_workspace() -> tempfile::TempDir {
    workspace(
        "carbon_black_cloud",
        "lab",
        CBC_SETUP,
        &[(
            "lucene.yaml",
            rule(
                "Carbon Black Lucene Rule",
                "00000000-0000-4000-8003-000000000005",
                "Simulated Carbon Black rule for CLI E2E corpus.",
                "  carbon_black_cloud:\n    status: STAGING\n    query: process_name:cmd.exe\n",
            ),
        )],
    )
}

/// The time `client.py` fixed the SDK's report stamp at.
const CBC_NOW: i64 = 1_793_088_000;

#[test]
fn carbon_black_creates_the_report_as_the_python_deployer_did() {
    let ws = cbc_workspace();
    // The watchlists read twice, the other rule's report, the new report, the watchlist.
    let (proxy, env, _ca) = replay("carbon_black/deploy", &[0, 1, 2, 3, 4], "CBC_TOKEN");
    let (sent, stderr) = deploy(
        ws.path(),
        "carbon_black_cloud",
        &env,
        &opentide_connectors::builtin(),
        CBC_NOW,
    );
    assert_eq!(proxy.verify(), Vec::new());
    assert_eq!(rows(&sent), [("deployed".to_owned(), None)]);
    assert!(
        stderr.contains("[1/1] ✓ deployed  Carbon Black Lucene Rule"),
        "{stderr}"
    );
}

#[test]
fn carbon_black_updates_the_report_as_the_python_deployer_did() {
    let ws = cbc_workspace();
    // The watchlists, both reports, then the rule's own report replaced.
    let (proxy, env, _ca) = replay("carbon_black/deploy", &[5, 6, 7, 8, 9], "CBC_TOKEN");
    let (sent, _) = deploy(
        ws.path(),
        "carbon_black_cloud",
        &env,
        &opentide_connectors::builtin(),
        CBC_NOW,
    );
    assert_eq!(proxy.verify(), Vec::new());
    assert_eq!(rows(&sent), [("deployed".to_owned(), None)]);
    assert_eq!(value(&sent, "status"), &Json::str("completed"));
}

#[test]
fn harfanglab_deletes_a_yara_file_as_the_python_client_did() {
    let ws = workspace(
        "harfanglab",
        "lab",
        "ssl = true\ntype = \"YARA\"\nurl = \"https://hl-tenant.invalid/\"\napi_token = \
         \"$HARFANGLAB_API_TOKEN\"\nsource_id = \"src-0001\"\n",
        &[
            (
                "a-loader.yaml",
                rule(
                    "HarfangLab YARA Loader",
                    "00000000-0000-4000-8003-000000000007",
                    "Retired.",
                    "  harfanglab:\n    status: REMOVED\n    yara:\n      meta:\n        os: \
                     Windows\n      strings: '$a = \"loader\"'\n      condition: $a\n",
                ),
            ),
            (
                "b-sigma.yaml",
                rule(
                    "HarfangLab Sigma on a YARA tenant",
                    "00000000-0000-4000-8003-000000000099",
                    "Skipped.",
                    "  harfanglab:\n    status: STAGING\n    sigma:\n      logsource:\n        \
                     category: process_creation\n        product: windows\n      selections:\n        \
                     - name: selection\n          field: Image\n          value: cmd.exe\n      \
                     condition: selection\n",
                ),
            ),
        ],
    );
    let (proxy, env, _ca) = replay("harfanglab/deploy", &[9], "HARFANGLAB_API_TOKEN");
    let (sent, stderr) = deploy(
        ws.path(),
        "harfanglab",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    assert_eq!(proxy.verify(), Vec::new());
    assert_eq!(
        rows(&sent),
        [("deployed".to_owned(), None), ("skipped".to_owned(), None)]
    );
    assert!(
        stderr.contains("· skipped   HarfangLab Sigma on a YARA tenant  Sigma rule, YARA tenant"),
        "{stderr}"
    );
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(0));
}

/// A deployer that answers each request in turn with `outcomes`.
struct Scripted {
    id: &'static str,
    outcomes: Mutex<std::collections::VecDeque<Result<(), ConnectorError>>>,
    seen: Mutex<Vec<(String, Operation)>>,
}

impl Deployer for Scripted {
    fn deploy<'a>(
        &'a self,
        _cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        self.seen
            .lock()
            .unwrap()
            .push((request.rule_id.clone(), request.operation));
        let next = self.outcomes.lock().unwrap().pop_front().unwrap_or(Ok(()));
        Box::pin(async move {
            next.map(|()| DeployOutcome {
                remote_id: None,
                operation: request.operation,
            })
        })
    }
}

impl Platform for Scripted {
    fn id(&self) -> &'static str {
        self.id
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self)
    }
}

#[test]
fn a_refusal_stops_the_run_and_the_rest_is_not_attempted() {
    let block = "  sentinel:\n    status: STAGING\n    query: SecurityEvent\n    scheduling:\n      \
         frequency: PT1H\n      lookback: PT1H\n    alert:\n      suppression: false\n    \
         grouping:\n      event: SingleAlert\n      alert:\n        enabled: false\n";
    let ws = workspace(
        "sentinel",
        "soc",
        SENTINEL_SETUP,
        &[
            (
                "a.yaml",
                rule(
                    "First",
                    "00000000-0000-4000-8099-000000000001",
                    "First.",
                    block,
                ),
            ),
            (
                "b.yaml",
                rule(
                    "Second",
                    "00000000-0000-4000-8099-000000000002",
                    "Second.",
                    block,
                ),
            ),
            (
                "c.yaml",
                rule(
                    "Third",
                    "00000000-0000-4000-8099-000000000003",
                    "Third.",
                    block,
                ),
            ),
        ],
    );
    let scripted = Scripted {
        id: "sentinel",
        outcomes: Mutex::new(
            [
                Ok(()),
                Err(ConnectorError::refused(
                    "sentinel",
                    "soc",
                    "PUT https://x failed with HTTP 400 BadRequest: no",
                    None,
                )),
            ]
            .into(),
        ),
        seen: Mutex::new(Vec::new()),
    };
    let mut registry = Registry::new();
    registry.register(Box::new(scripted)).unwrap();
    let env = Env::from_pairs([("AZURE_CLIENT_SECRET", SECRET)]);
    let (sent, stderr) = deploy(ws.path(), "sentinel", &env, &registry, 0);
    let statuses: Vec<String> = rows(&sent).into_iter().map(|(status, _)| status).collect();
    assert_eq!(statuses, ["deployed", "failed", "not_attempted"]);
    assert!(
        stderr.contains("[3/3] · skipped   Third   not attempted after a failure"),
        "{stderr}"
    );
    assert!(
        stderr.contains("✗ sentinel · 1 deployed, 1 failed, 1 not attempted · "),
        "{stderr}"
    );
    assert_eq!(
        value(&sent, "error"),
        &Json::str(
            "Deployment to sentinel failed on Second: HTTP 400: PUT https://x failed with HTTP 400 \
             BadRequest: no"
        )
    );
    assert_eq!(value(&sent, "deployed"), &Json::Array(Vec::new()));
}

#[test]
fn a_platform_without_tenants_is_refused_before_anything_is_sent() {
    let dir = tempfile::tempdir().unwrap();
    let platforms = dir.path().join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::write(
        platforms.join("sentinel.toml"),
        "[platform]\nenabled = true\nname = \"Stand-in\"\n",
    )
    .unwrap();
    let rules = dir.path().join("objects/rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("a.yaml"),
        rule(
            "Only",
            "00000000-0000-4000-8099-000000000009",
            "Only.",
            SENTINEL_BLOCK,
        ),
    )
    .unwrap();
    let env = Env::from_pairs(Vec::<(String, String)>::new());
    let (sent, stderr) = deploy(dir.path(), "sentinel", &env, &Registry::new(), 0);
    assert_eq!(stderr, "");
    assert_eq!(value(&sent, "status"), &Json::str("failed"));
    assert_eq!(
        value(&sent, "message"),
        &Json::str(
            "Cannot deploy: sentinel has no tenants configured in \
             .opentide/configurations/platforms/sentinel.toml"
        )
    );
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(1));
    let report = sent.report();
    assert_eq!(report.outcome.exit_code, 1);
    assert_eq!(
        report.outcome.failure.map(|failure| failure.code),
        Some("command_failed".to_owned())
    );
}

#[test]
fn a_platform_with_no_rule_to_deploy_is_skipped_and_counts_the_blocks_left_out() {
    let ws = workspace(
        "sentinel",
        "soc",
        SENTINEL_SETUP,
        &[(
            "design.yaml",
            rule(
                "Designed",
                "00000000-0000-4000-8099-000000000010",
                "Designed.",
                &SENTINEL_BLOCK.replace("REMOVED", "DESIGN"),
            ),
        )],
    );
    let env = Env::from_pairs([("GITHUB_ACTIONS", "true")]);
    let (sent, stderr) = deploy(ws.path(), "sentinel", &env, &Registry::new(), 0);
    assert_eq!(stderr, "");
    assert_eq!(value(&sent, "status"), &Json::str("skipped"));
    assert_eq!(
        value(&sent, "message"),
        &Json::str("No rules to deploy for this platform")
    );
    let report = sent.report();
    assert_eq!(report.outcome.exit_code, 0);
    assert_eq!(
        report.outcome_line.as_deref(),
        Some("No rule has a status this run deploys · 1 rule in DESIGN")
    );
}

const S1_SETUP: &str = "ssl = true\nurl = \"https://s1.invalid\"\naccount_id = 1001\napi_token = \
     \"$S1_API_TOKEN\"\n";

fn s1_block(status: &str) -> String {
    format!(
        "  sentinel_one:\n    status: {status}\n    condition:\n      type: Single Event\n      \
         single_event:\n        query: src.process.name = 'cmd.exe'\n    response:\n      \
         treat_as_threat: Malicious\n      network_quarantine: false\n"
    )
}

/// SentinelOne rules every one of which deployment state refuses or skips
/// before any request: no tenant is contacted.
fn s1_workspace(rules: &[(&str, &str, &str)]) -> tempfile::TempDir {
    let files: Vec<(&str, String)> = rules
        .iter()
        .map(|(file, uuid, status)| (*file, rule("S1 rule", uuid, "S1.", &s1_block(status))))
        .collect();
    workspace("sentinel_one", "lab", S1_SETUP, &files)
}

#[test]
fn deployment_state_refuses_or_skips_rules_before_any_request() {
    let ws = s1_workspace(&[
        ("a.yaml", "00000000-0000-4000-8099-000000000021", "STAGING"),
        ("b.yaml", "00000000-0000-4000-8099-000000000022", "DISABLED"),
        ("c.yaml", "00000000-0000-4000-8099-000000000023", "STAGING"),
    ]);
    let states = ws.path().join(".opentide/states/deployment");
    std::fs::create_dir_all(&states).unwrap();
    // A shard that names another rule.
    std::fs::write(
        states.join("00000000-0000-4000-8099-000000000023.json"),
        "{\"schema\": \"deployment.state::1.0\", \"object_uuid\": \"x\", \"platforms\": {}}",
    )
    .unwrap();
    // A PREVIEW run in a pull request's CI cannot keep a created id.
    let env = Env::from_pairs([
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_EVENT_NAME", "pull_request"),
    ]);
    let args = Args {
        strategies: vec!["PREVIEW".into(), "RELEASE".into()],
        all: true,
        keep_deprecated: Some(true),
        platform: Some("sentinel_one".into()),
        ..Args::default()
    };
    let (sent, stderr) = deploy_with(ws.path(), &args, &env, &Registry::new(), 0);
    let rows = rows(&sent);
    assert_eq!(rows[0].0, "failed");
    assert!(
        rows[0]
            .1
            .as_deref()
            .unwrap()
            .contains("in CI cannot keep the id a create would return")
    );
    assert_eq!(rows[1].0, "skipped");
    assert_eq!(rows[2].0, "failed");
    assert!(
        rows[2]
            .1
            .as_deref()
            .unwrap()
            .contains("records object_uuid \"x\""),
        "{rows:?}"
    );
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(1));
    assert!(stderr.contains("[2/3] · skipped "), "{stderr}");
    // `--persist-state-externally` lifts the CI refusal: the create would be sent.
    let persist = Args {
        persist_state_externally: true,
        uuids: vec!["00000000-0000-4000-8099-000000000022".into()],
        all: false,
        ..args
    };
    let (sent, _) = deploy_with(ws.path(), &persist, &env, &Registry::new(), 0);
    assert_eq!(rows_of(&sent), ["skipped"]);
    assert_eq!(value(&sent, "scope"), &Json::str("selected"));
}

fn rows_of(sent: &Sent) -> Vec<String> {
    rows(sent).into_iter().map(|(status, _)| status).collect()
}

#[test]
fn a_create_is_refused_while_git_ignores_deployment_state() {
    let ws = s1_workspace(&[("a.yaml", "00000000-0000-4000-8099-000000000031", "STAGING")]);
    std::fs::write(ws.path().join(".gitignore"), ".opentide/states/\n").unwrap();
    let env = Env::from_pairs(Vec::<(String, String)>::new());
    let (sent, _) = deploy(ws.path(), "sentinel_one", &env, &Registry::new(), 0);
    let rows = rows(&sent);
    assert_eq!(rows[0].0, "failed");
    assert!(
        rows[0].1.as_deref().unwrap().starts_with(
            "git ignores .opentide/states/deployment/ (.gitignore:1: .opentide/states/)"
        ),
        "{rows:?}"
    );
}

#[test]
fn usage_errors_and_selections_that_match_nothing_are_refused_before_planning() {
    let ws = s1_workspace(&[("a.yaml", "00000000-0000-4000-8099-000000000041", "STAGING")]);
    let none = Env::from_pairs(Vec::<(String, String)>::new());
    let base = Args {
        platform: Some("sentinel_one".into()),
        all: true,
        ..Args::default()
    };
    let (sent, _) = deploy_with(ws.path(), &base, &none, &Registry::new(), 0);
    assert_eq!(
        value(&sent, "_failure_code"),
        &Json::str("usage_missing_option")
    );
    let typo = Args {
        strategies: vec!["PREVEW".into()],
        ..base.clone()
    };
    let (sent, _) = deploy_with(ws.path(), &typo, &none, &Registry::new(), 0);
    assert_eq!(
        value(&sent, "_failure_code"),
        &Json::str("usage_invalid_choice")
    );
    assert_eq!(value(&sent, "_failure_suggestion"), &Json::str("PREVIEW"));
    let plan = Env::from_pairs([("DEPLOYMENT_PLAN", "STAGING")]);
    let preview = Args {
        strategies: vec!["PREVIEW".into()],
        ..base.clone()
    };
    let (sent, _) = deploy_with(ws.path(), &preview, &plan, &Registry::new(), 0);
    assert_eq!(
        value(&sent, "_failure_code"),
        &Json::str("usage_invalid_value")
    );
    let unmatched = Args {
        all: false,
        uuids: vec!["00000000-0000-4000-8099-00000000ffff".into()],
        ..preview.clone()
    };
    let (sent, _) = deploy_with(ws.path(), &unmatched, &none, &Registry::new(), 0);
    assert_eq!(value(&sent, "scope"), &Json::str("selected"));
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(1));
    // No git checkout: the changed rules cannot be read.
    let changed = Args {
        all: false,
        ..preview.clone()
    };
    let (sent, _) = deploy_with(ws.path(), &changed, &none, &Registry::new(), 0);
    let Json::Str(message) = value(&sent, "message") else {
        panic!("a message")
    };
    assert!(message.contains("needs a git checkout"), "{message}");
    // A platform the plan does not reach.
    let other = Args {
        platform: Some("crowdstrike".into()),
        ..preview.clone()
    };
    let (sent, _) = deploy_with(ws.path(), &other, &none, &Registry::new(), 0);
    assert_eq!(value(&sent, "status"), &Json::str("skipped"));
    assert_eq!(value(&sent, "platform"), &Json::str("crowdstrike"));
}

#[test]
fn every_platform_without_tenants_can_be_skipped_with_skip_unconfigured() {
    let dir = tempfile::tempdir().unwrap();
    let platforms = dir.path().join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::write(
        platforms.join("sentinel_one.toml"),
        "[platform]\nenabled = true\nname = \"Stand-in\"\n",
    )
    .unwrap();
    let rules = dir.path().join("objects/rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("a.yaml"),
        rule(
            "S1",
            "00000000-0000-4000-8099-000000000051",
            "S1.",
            &s1_block("STAGING"),
        ),
    )
    .unwrap();
    let args = Args {
        strategies: vec!["PREVIEW".into()],
        all: true,
        platform: Some("sentinel_one".into()),
        skip_unconfigured: true,
        ..Args::default()
    };
    let env = Env::from_pairs(Vec::<(String, String)>::new());
    let (sent, _) = deploy_with(dir.path(), &args, &env, &Registry::new(), 0);
    assert_eq!(value(&sent, "status"), &Json::str("skipped"));
    assert!(
        matches!(value(&sent, "message"), Json::Str(text) if text.starts_with("Skipped deploy: "))
    );
    assert_eq!(sent.report().outcome.exit_code, 0);
}

/// A workspace of `platform` whose rules each have their id `state` on the
/// tenant `lab`: (file, uuid, block, recorded id).
fn stated(platform: &str, setup: &str, rules: &[(&str, &str, String, &str)]) -> tempfile::TempDir {
    let files: Vec<(&str, String)> = rules
        .iter()
        .map(|(file, uuid, block, _)| (*file, rule("Recorded rule", uuid, "Recorded.", block)))
        .collect();
    let ws = workspace(platform, "lab", setup, &files);
    let states = ws.path().join(".opentide/states/deployment");
    std::fs::create_dir_all(&states).unwrap();
    for (_, uuid, _, id) in rules {
        std::fs::write(
            states.join(format!("{uuid}.json")),
            format!(
                "{{\"object_uuid\": \"{uuid}\", \"platforms\": {{\"{platform}\": {{\"lab\": \"{id}\"}}}}, \"schema\": \"deployment.state::1.0\"}}\n"
            ),
        )
        .unwrap();
    }
    ws
}

#[test]
fn crowdstrike_stops_on_a_delete_the_tenant_refuses() {
    let block = "  crowdstrike:\n    status: REMOVED\n    query: \"#event_simpleName=ProcessRollup2\"\n    \
         details:\n      trigger: verbose\n      outcome: detection\n    schedule:\n      frequency: \
         1h\n      lookback: 2h\n"
        .to_owned();
    let uuid = "00000000-0000-4000-8099-000000000061";
    let ws = stated(
        "crowdstrike",
        "ssl = true\napi = \"EU-1\"\nclient_id = \"opentide-client\"\nclient_secret = \
         \"$CROWDSTRIKE_CLIENT_SECRET\"\ncustomer_id = \"0123456789ABCDEF-12\"\n",
        &[("a.yaml", uuid, block, "cs-rule-missing")],
    );
    // The token, then the DELETE the tenant answers 404.
    let (proxy, env, _ca) = replay("crowdstrike/deploy", &[0, 7], "CROWDSTRIKE_CLIENT_SECRET");
    let (sent, _) = deploy(
        ws.path(),
        "crowdstrike",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    assert_eq!(proxy.verify(), Vec::new());
    assert_eq!(
        rows(&sent),
        [(
            "failed".to_owned(),
            Some("DetectionRuleDeletionFailed: Could not delete rule".to_owned())
        )]
    );
    // The shard is kept: the platform did not confirm the delete.
    assert!(
        ws.path()
            .join(format!(".opentide/states/deployment/{uuid}.json"))
            .is_file()
    );
}

#[test]
fn defender_deletes_a_recorded_rule_and_forgets_its_id() {
    let uuid = "00000000-0000-4000-8099-000000000071";
    let block = "  defender_for_endpoint:\n    status: REMOVED\n    query: |\n      DeviceProcessEvents\n      \
         | take 1\n    scheduling: 1H\n    alert:\n      category: Execution\n    impacted_entities:\n      \
         device: device_id\n"
        .to_owned();
    let ws = stated(
        "defender_for_endpoint",
        "tenant_id = \"contoso-tenant-id\"\nclient_id = \"opentide-app-id\"\nclient_secret = \
         \"$DEFENDER_CLIENT_SECRET\"\n",
        &[("a.yaml", uuid, block, "42")],
    );
    // The sign-in, then the DELETE Graph answers 204.
    let (proxy, env, _ca) = replay("defender/deploy", &[0, 5], "DEFENDER_CLIENT_SECRET");
    let (sent, stderr) = deploy(
        ws.path(),
        "defender_for_endpoint",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    assert_eq!(proxy.verify(), Vec::new());
    assert_eq!(rows(&sent), [("deployed".to_owned(), None)]);
    assert!(stderr.contains("✓ deleted   Recorded rule"), "{stderr}");
    assert!(
        !ws.path()
            .join(format!(".opentide/states/deployment/{uuid}.json"))
            .exists()
    );
}

#[test]
fn sysdig_forgets_a_rule_to_disable_the_tenant_lost_and_stops_on_a_refused_read() {
    let block = |status: &str| {
        format!(
            "  sysdig:\n    schema: platform::sysdig::1.0\n    status: {status}\n    condition: \
             spawned_process and container\n    tags: [container]\n"
        )
    };
    let lost = "00000000-0000-4000-8099-000000000081";
    let denied = "00000000-0000-4000-8099-000000000082";
    let ws = stated(
        "sysdig",
        "ssl = true\nurl = \"https://sysdig-tenant.invalid/\"\napi_token = \
         \"$SYSDIG_SECURE_API_TOKEN\"\n",
        &[
            ("a.yaml", lost, block("DISABLED"), "42"),
            ("b.yaml", denied, block("STAGING"), "401"),
        ],
    );
    // Rule 42 is gone (404); the token may not read rule 401 (403).
    let (proxy, env, _ca) = replay("sysdig/deploy", &[17, 25], "SYSDIG_SECURE_API_TOKEN");
    let (sent, _) = deploy(
        ws.path(),
        "sysdig",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    assert_eq!(proxy.verify(), Vec::new());
    let rows = rows(&sent);
    assert_eq!(rows[0], ("deployed".to_owned(), None));
    assert_eq!(rows[1].0, "failed");
    assert!(
        !ws.path()
            .join(format!(".opentide/states/deployment/{lost}.json"))
            .exists()
    );
    assert!(
        ws.path()
            .join(format!(".opentide/states/deployment/{denied}.json"))
            .is_file()
    );
    assert_eq!(value(&sent, "status"), &Json::str("failed"));
    assert_eq!(
        value(&sent, "warnings"),
        &Json::Array(vec![Json::str("Some rules reported deployment warnings")])
    );
}

/// Runs `opentide <argv>` on the command line, in `ws`, with `env`: the
/// exit code, stdout and stderr.
fn cli(ws: &Path, argv: &[&str], env: &[(&str, String)]) -> (i32, String, String) {
    use opentide_cli::logging::Sink;
    use opentide_cli::{Host, run as run_cli};
    let stderr = Buffer::default();
    let sink: Sink = Arc::new(Mutex::new(stderr.clone()));
    let host = Host {
        version: "0.28.1".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = argv.iter().map(|arg| (*arg).to_owned()).collect();
    let mut out = Vec::new();
    let mut err = stderr.clone();
    let env = Env::from_pairs(env.iter().map(|(k, v)| ((*k).to_owned(), v.clone())));
    let code = run_cli(&argv, &env, &host, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap(), stderr.text())
}

/// `ws` as a git checkout of two commits, the second changing `file`.
fn pushed(ws: &Path, file: &str) {
    let git = |args: &[&str]| {
        let output = std::process::Command::new("git")
            .args([
                "-c",
                "init.defaultBranch=main",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(ws)
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
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "base"]);
    let path = ws.join(file);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.replace("description: ", "description: Changed. "),
    )
    .unwrap();
    git(&["commit", "-q", "-a", "-m", "push"]);
}

/// A RELEASE deploy on a push promotes the rule the push changed (UC-4.6c,
/// #979); an invalid promotion target ends the run as the oracle's
/// `sys.exit(1)` does: exit 1, no document, the failed step on stderr.
#[test]
fn a_push_promotes_its_rules_and_an_invalid_target_exits_without_a_document() {
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"$SPLUNK_TOKEN\"\n",
        &[(
            "r.yaml",
            rule(
                "Promoted",
                "00000000-0000-4000-8047-000000000901",
                "A rule.",
                "  splunk:\n    status: STAGING\n    query: index=main\n",
            ),
        )],
    );
    pushed(ws.path(), "objects/rules/r.yaml");
    let push = || -> Vec<(&str, String)> {
        vec![
            ("GITHUB_ACTIONS", "true".to_owned()),
            ("GITHUB_EVENT_NAME", "push".to_owned()),
            ("GITHUB_SHA", "HEAD".to_owned()),
            ("GITHUB_WORKSPACE", ws.path().display().to_string()),
        ]
    };
    let argv = [
        "--json",
        "deploy",
        "--platform",
        "splunk",
        "--strategy",
        "RELEASE",
    ];
    let config = ws.path().join(".opentide/configurations/deployment.toml");
    std::fs::write(&config, "[promotion]\npromotion_target = \"LIVE\"\n").unwrap();
    let (code, out, err) = cli(ws.path(), &argv, &push());
    assert_eq!((code, out.as_str()), (1, ""), "{err}");
    assert!(err.contains("invalid_promotion_target"), "{err}");
    let rule = ws.path().join("objects/rules/r.yaml");
    assert!(
        std::fs::read_to_string(&rule)
            .unwrap()
            .contains("status: STAGING")
    );
    let plain = ["deploy", "--platform", "splunk", "--strategy", "RELEASE"];
    let (code, out, err) = cli(ws.path(), &plain, &push());
    assert_eq!((code, out.as_str()), (1, ""), "{err}");
    assert!(err.contains("✗ status promotion · 1 rule"), "{err}");

    std::fs::remove_file(&config).unwrap();
    let (code, out, err) = cli(ws.path(), &argv, &push());
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("\"status\":\"completed\""), "{out}");
    let text = std::fs::read_to_string(&rule).unwrap();
    assert!(text.contains("    status: PRODUCTION\n"), "{text}");
}
