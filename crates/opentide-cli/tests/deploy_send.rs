//! A deploy that sends, on the platforms a golden case cannot replay (UC-4.6,
//! #979): Sentinel (MSAL's and azure-core's random request ids), a Carbon
//! Black Cloud report built or updated (the SDK stamps it with the time) and
//! HarfangLab (the oracle's deploy stopped before any request). Each runs here
//! through the CLI flow, the ids and the time fixed, against the requests of
//! its connector's cassette recorded from the Python client
//! (`tests/cassettes/<platform>/deploy.json`): the rules of a workspace,
//! through the deploy plan, the tenant's batch and the connector, send
//! exactly the requests the oracle sent. The flow's own rules (a refused
//! rule fails alone and the run goes on; deployment state written
//! only when the platform accepted the rule) run against a scripted deployer.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use opentide_cassette::{Cassette, Mode, Proxy, Redaction};
use opentide_cli::commands::deploy_send::{Args, Context, Lines, Sent, run};
use opentide_cli::env::Env;
use opentide_cli::json::Json;
use opentide_cli::render::outcome::Console;
use opentide_cli::render::text::Colour;
use opentide_connectors::connector::{
    BoxFuture, DeployError, DeployOutcome, DeployRequest, Deployer, Operation, Platform,
    TenantContext, deploying,
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
    deploy_into(ws, args, env, registry, now, &Buffer::default())
}

/// [`deploy_with`], its lines written to `buffer`.
fn deploy_into(
    ws: &Path,
    args: &Args,
    env: &Env,
    registry: &Registry,
    now: i64,
    buffer: &Buffer,
) -> (Sent, String) {
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
    replay_with(scenario, interactions, &[(variable, SECRET)])
}

/// [`replay`] with every `(name, value)` of `variables` set.
fn replay_with(
    scenario: &str,
    interactions: &[usize],
    variables: &[(&str, &str)],
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
            .chain(
                variables
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
            ),
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

/// The Sentinel connector, registered.
fn sentinel_registry() -> Registry {
    let sentinel = opentide_connectors::sentinel::Sentinel::new();
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
    // The DELETE ARM answered 404: the run stops with ARM's words.
    let (proxy, env, _ca) = replay("sentinel/deploy", &[0, 1, 7], "AZURE_CLIENT_SECRET");
    let (sent, _) = deploy(ws.path(), "sentinel", &env, &sentinel_registry(), 0);
    assert_eq!(proxy.verify(), Vec::new());
    let rows = rows(&sent);
    assert_eq!(rows[0].0, "failed");
    let error = rows[0].1.clone().unwrap();
    assert!(
        error.starts_with("DELETE https://management.azure.com/"),
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
    // The watchlists read once (#1932), the other rule's report, the new report, the watchlist.
    let (proxy, env, _ca) = replay("carbon_black/deploy", &[0, 1, 2, 3], "CBC_TOKEN");
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
    let (proxy, env, _ca) = replay("carbon_black/deploy", &[4, 5, 6, 7], "CBC_TOKEN");
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
        "ssl = true\nurl = \"https://hl-tenant.invalid/\"\napi_token = \
         \"$HARFANGLAB_API_TOKEN\"\nsource_id = \"src-0001\"\n",
        &[(
            "a-loader.yaml",
            rule(
                "HarfangLab YARA Loader",
                "00000000-0000-4000-8003-000000000007",
                "Retired.",
                "  harfanglab:\n    status: REMOVED\n    yara:\n      meta:\n        os: \
                 Windows\n      strings: '$a = \"loader\"'\n      condition: $a\n",
            ),
        )],
    );
    let (proxy, env, _ca) = replay("harfanglab/deploy", &[9], "HARFANGLAB_API_TOKEN");
    let (sent, _) = deploy(
        ws.path(),
        "harfanglab",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    assert_eq!(proxy.verify(), Vec::new());
    assert_eq!(rows(&sent), [("deployed".to_owned(), None)]);
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(0));
}

/// A HarfangLab tenant that still sets the removed `type` fails before
/// anything is sent or resolved, with the message `validate` reports: an
/// unset `$NAME` there is not looked up.
#[test]
fn harfanglab_refuses_a_tenant_that_still_sets_type() {
    let removed = "harfanglab tenant 'lab' setup: type: `type` is removed: a HarfangLab tenant \
                   takes both Sigma and YARA rules, and each rule's own `sigma` or `yara` block \
                   picks its kind; delete this key";
    for kind in ["Sigma", "$HARFANGLAB_TYPE"] {
        let ws = workspace(
            "harfanglab",
            "lab",
            &format!(
                "ssl = true\ntype = \"{kind}\"\nurl = \"https://hl-tenant.invalid/\"\napi_token = \
                 \"$HARFANGLAB_API_TOKEN\"\nsource_id = \"src-0001\"\n"
            ),
            &[(
                "a.yaml",
                rule(
                    "HarfangLab YARA Loader",
                    "00000000-0000-4000-8003-000000000007",
                    "Retired.",
                    "  harfanglab:\n    status: REMOVED\n    yara:\n      meta:\n        os: \
                     Windows\n      strings: '$a = \"loader\"'\n      condition: $a\n",
                ),
            )],
        );
        let env = Env::from_pairs([("HARFANGLAB_API_TOKEN".to_owned(), "token".to_owned())]);
        let (sent, stderr) = deploy(
            ws.path(),
            "harfanglab",
            &env,
            &opentide_connectors::builtin(),
            0,
        );
        assert_eq!(value(&sent, "status"), &Json::str("failed"), "{kind}");
        assert_eq!(rows(&sent), [("not_attempted".to_owned(), None)], "{kind}");
        let Json::Array(failures) = value(&sent, "failures") else {
            panic!("no failures")
        };
        let error = failures[0].get("error").and_then(Json::as_str).unwrap();
        assert_eq!(error, removed, "{kind}");
        assert!(!stderr.contains("HARFANGLAB_TYPE"), "{kind}: {stderr}");
    }
}

/// One HarfangLab tenant deploys Sigma rules and YARA files in one run
/// (platform-harfanglab 1.6): each rule goes to the endpoint of its own
/// block's kind, created, updated or deleted there; nothing is skipped for
/// its kind.
#[test]
fn harfanglab_deploys_sigma_and_yara_to_one_tenant() {
    use wiremock::matchers::{method, path};
    const SIGMA: &str = "00000000-0000-4000-8003-0000000000a1";
    const YARA: &str = "00000000-0000-4000-8003-0000000000a2";
    const GONE_SIGMA: &str = "00000000-0000-4000-8003-0000000000a3";
    const GONE_YARA: &str = "00000000-0000-4000-8003-0000000000a4";
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    let endpoint = "/api/data/threat_intelligence";
    rt.block_on(async {
        for (verb, at, status) in [
            ("PUT", format!("{endpoint}/SigmaRule/{SIGMA}/"), 200),
            ("POST", format!("{endpoint}/YaraFile/"), 201),
            ("DELETE", format!("{endpoint}/SigmaRule/{GONE_SIGMA}/"), 204),
            ("DELETE", format!("{endpoint}/YaraFile/{GONE_YARA}/"), 204),
        ] {
            wiremock::Mock::given(method(verb))
                .and(path(at))
                .respond_with(wiremock::ResponseTemplate::new(status).set_body_string("{}"))
                .expect(1)
                .mount(&server)
                .await;
        }
    });
    let sigma = |status: &str| {
        format!(
            "  harfanglab:\n    status: {status}\n    sigma:\n      logsource:\n        \
             category: process_creation\n        product: windows\n      selections:\n        \
             - name: selection\n          field: Image\n          value: cmd.exe\n      \
             condition: selection\n"
        )
    };
    let yara = |status: &str| {
        format!(
            "  harfanglab:\n    status: {status}\n    yara:\n      meta:\n        os: \
             Windows\n      strings: '$a = \"loader\"'\n      condition: $a\n"
        )
    };
    let ws = workspace(
        "harfanglab",
        "lab",
        &format!(
            "url = \"{}\"\napi_token = \"$HARFANGLAB_API_TOKEN\"\nsource_id = \"src-0001\"\n",
            server.uri()
        ),
        &[
            ("a.yaml", rule("Sigma rule", SIGMA, "A.", &sigma("STAGING"))),
            ("b.yaml", rule("YARA file", YARA, "B.", &yara("STAGING"))),
            (
                "c.yaml",
                rule("Gone Sigma", GONE_SIGMA, "C.", &sigma("REMOVED")),
            ),
            (
                "d.yaml",
                rule("Gone YARA", GONE_YARA, "D.", &yara("REMOVED")),
            ),
        ],
    );
    let env = Env::from_pairs([("HARFANGLAB_API_TOKEN".to_owned(), "token".to_owned())]);
    let (sent, _) = deploy(
        ws.path(),
        "harfanglab",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    rt.block_on(server.verify());
    assert_eq!(rows(&sent), vec![("deployed".to_owned(), None); 4]);
    assert_eq!(value(&sent, "status"), &Json::str("completed"));
}

/// A registered platform that forwards to a [`Scripted`] the test keeps.
struct Forward(&'static Scripted);

impl Platform for Forward {
    fn id(&self) -> &'static str {
        self.0.id
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self.0)
    }
}

/// A deployer that answers each request in turn with `outcomes`: every
/// tenant's, or with `only` the requests of that tenant alone (the others
/// answered `Ok`), as tenants deploy at once.
struct Scripted {
    id: &'static str,
    outcomes: Mutex<std::collections::VecDeque<Result<(), ConnectorError>>>,
    seen: Mutex<Vec<(String, Operation)>>,
    only: Option<&'static str>,
}

impl Deployer for Scripted {
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        self.seen
            .lock()
            .unwrap()
            .push((request.rule_id.clone(), request.operation));
        let next = if self
            .only
            .is_none_or(|tenant| cx.tenant.label.tenant == tenant)
        {
            self.outcomes.lock().unwrap().pop_front().unwrap_or(Ok(()))
        } else {
            Ok(())
        };
        deploying(async move { next.map(|()| DeployOutcome::new(None, request.operation)) })
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

const SENTINEL_STAGING: &str = "  sentinel:\n    status: STAGING\n    query: SecurityEvent\n    \
     scheduling:\n      frequency: PT1H\n      lookback: PT1H\n    alert:\n      suppression: \
     false\n    grouping:\n      event: SingleAlert\n      alert:\n        enabled: false\n";

const SPLUNK_BLOCK: &str = "  splunk:\n    status: STAGING\n    query: index=main\n";

/// Three rules of `block`: First, Second and Third.
fn three_rules(block: &str) -> Vec<(&'static str, String)> {
    [
        ("a.yaml", "First", 1),
        ("b.yaml", "Second", 2),
        ("c.yaml", "Third", 3),
    ]
    .into_iter()
    .map(|(file, name, n)| {
        let uuid = format!("00000000-0000-4000-8099-00000000000{n}");
        (file, rule(name, &uuid, &format!("{name}."), block))
    })
    .collect()
}

/// A scripted `platform` deployer answering with `outcomes`, then `Ok`.
fn scripted(
    platform: &'static str,
    outcomes: Vec<Result<(), ConnectorError>>,
) -> (Registry, &'static Scripted) {
    scripted_on(platform, None, outcomes)
}

/// [`scripted`], `outcomes` answering only the requests of the tenant
/// `only` when it is set.
fn scripted_on(
    platform: &'static str,
    only: Option<&'static str>,
    outcomes: Vec<Result<(), ConnectorError>>,
) -> (Registry, &'static Scripted) {
    let scripted: &'static Scripted = Box::leak(Box::new(Scripted {
        id: platform,
        outcomes: Mutex::new(outcomes.into()),
        seen: Mutex::new(Vec::new()),
        only,
    }));
    let mut registry = Registry::new();
    registry.register(Box::new(Forward(scripted))).unwrap();
    (registry, scripted)
}

/// A Sentinel rule whose objective maps an id newer than ATT&CK v18 deploys
/// with the technique warning: the run's `warnings` say so, and the log has
/// it once for the rule, not once for each tenant.
#[test]
fn a_sentinel_technique_warning_reaches_the_run_once_per_rule() {
    use opentide_cli::logging::{Config, LogLayer, Sink, subscriber};
    use opentide_cli::redact::Redactor;

    const OBJECTIVE: &str = "00000000-0000-4000-8002-000000000001";
    let text = rule(
        "Newer technique",
        "00000000-0000-4000-8099-000000000001",
        "d.",
        SENTINEL_STAGING,
    )
    .replacen(
        "response:",
        &format!("detection_model: {OBJECTIVE}\nresponse:"),
        1,
    );
    let ws = workspace("sentinel", "soc", SENTINEL_SETUP, &[("a.yaml", text)]);
    std::fs::create_dir_all(ws.path().join("objects/objectives")).unwrap();
    std::fs::write(
        ws.path().join("objects/objectives/o.yaml"),
        format!(
            "name: Objective\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n  \
             version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\n\
             objective:\n  priority: High\n  type: Threat\n  mitre_attack: [T1685.002, T1562.001]\n"
        ),
    )
    .unwrap();
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/sentinel.toml");
    let first = std::fs::read_to_string(&config).unwrap();
    let second = first.replacen(
        "[[tenants]]\nname = \"soc\"",
        "[[tenants]]\nname = \"lab\"",
        1,
    );
    let tenants = &second[second.find("[[tenants]]").unwrap()..];
    std::fs::write(&config, format!("{first}\n{tenants}")).unwrap();

    let (registry, deployer) = scripted("sentinel", Vec::new());
    let env = Env::from_pairs([("AZURE_CLIENT_SECRET", SECRET)]);
    let captured = Buffer::default();
    let sink: Sink = Arc::new(Mutex::new(captured.clone()));
    let layer = LogLayer::new(
        Config {
            debug: false,
            quiet: false,
            json_lines: true,
        },
        sink,
        Redactor::new(Vec::new(), Vec::new()),
        || "12:00:00".to_owned(),
    );
    let (sent, _) = tracing::subscriber::with_default(subscriber(layer), || {
        deploy(ws.path(), "sentinel", &env, &registry, 0)
    });
    assert_eq!(
        deployer.seen.lock().unwrap().len(),
        2,
        "one request each tenant"
    );
    assert_eq!(
        value(&sent, "warnings"),
        &Json::Array(vec![Json::str("Some rules reported deployment warnings")])
    );
    let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        log.matches("technique_newer_than_sentinel_attack").count(),
        1,
        "{log}"
    );
    assert!(
        log.contains("sending T1562.008 in place of T1685.002"),
        "{log}"
    );
}

/// A refused rule fails alone: the rules after it are still sent, the run
/// reports the failure and exits 1. The Python deployer stopped the run at
/// the first refusal (`DEPLOYMENT_ERROR_RAISED` raised): opentide deploys
/// everything that can deploy.
#[test]
fn a_refused_rule_fails_alone_and_the_rules_after_it_are_deployed() {
    let splunk_setup = "url = \"splunk.invalid\"\ntoken = \"$SPLUNK_TOKEN\"\n";
    for (platform, setup, block) in [
        ("sentinel", SENTINEL_SETUP, SENTINEL_STAGING),
        ("splunk", splunk_setup, SPLUNK_BLOCK),
    ] {
        let ws = workspace(platform, "soc", setup, &three_rules(block));
        let (registry, deployer) = scripted(
            platform,
            vec![
                Ok(()),
                Err(ConnectorError::refused(
                    platform,
                    "soc",
                    "PUT https://x failed with HTTP 400 BadRequest: no",
                    None,
                )),
            ],
        );
        let env = Env::from_pairs([("AZURE_CLIENT_SECRET", SECRET), ("SPLUNK_TOKEN", SECRET)]);
        let (sent, stderr) = deploy(ws.path(), platform, &env, &registry, 0);
        let statuses: Vec<String> = rows(&sent).into_iter().map(|(status, _)| status).collect();
        assert_eq!(statuses, ["deployed", "failed", "deployed"], "{platform}");
        assert_eq!(deployer.seen.lock().unwrap().len(), 3, "{platform}");
        assert!(
            stderr.contains(&format!(
                "✗ {platform} · 2 deployed, 1 failed, 0 not attempted · "
            )),
            "{stderr}"
        );
        assert_eq!(value(&sent, "_exit_code"), &Json::Int(1), "{platform}");
        assert_eq!(value(&sent, "status"), &Json::str("failed"), "{platform}");
        assert_eq!(
            value(&sent, "error"),
            &Json::str(
                "Deployment to {platform} failed on Second: PUT https://x failed with HTTP 400 \
                 BadRequest: no"
                    .replace("{platform}", platform)
            ),
            "{platform}"
        );
        assert_eq!(
            value(&sent, "failures"),
            &Json::Array(vec![Json::object([
                ("platform", Json::str(platform)),
                ("tenant", Json::str("soc")),
                ("id", Json::str("00000000-0000-4000-8099-000000000002")),
                ("name", Json::str("Second")),
                (
                    "error",
                    Json::str("PUT https://x failed with HTTP 400 BadRequest: no")
                ),
            ])]),
            "{platform}"
        );
        assert_eq!(
            value(&sent, "deployed"),
            &Json::Array(vec![Json::str(platform)]),
            "{platform}"
        );
    }
}

/// A tenant that refuses the credentials stops only its own rules: the
/// next tenant gets every rule. The refusal came on the tenant's first
/// rule, before it took anything, so no rule was sent to it: each of its
/// rules is `not attempted`, and the failure is the tenant's (#1701).
#[test]
fn a_tenant_refusing_the_credentials_stops_only_its_own_rules() {
    let ws = workspace(
        "sentinel",
        "soc",
        SENTINEL_SETUP,
        &three_rules(SENTINEL_STAGING),
    );
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/sentinel.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    let second = text.replacen(
        "[[tenants]]\nname = \"soc\"",
        "[[tenants]]\nname = \"lab\"",
        1,
    );
    let tenants = &second[second.find("[[tenants]]").unwrap()..];
    std::fs::write(&config, format!("{text}\n{tenants}")).unwrap();
    let (registry, deployer) = scripted_on(
        "sentinel",
        Some("soc"),
        vec![Err(ConnectorError::Authentication {
            platform: "sentinel".into(),
            tenant: "soc".into(),
            message: "the credentials were refused".into(),
            detail: None,
        })],
    );
    let env = Env::from_pairs([("AZURE_CLIENT_SECRET", SECRET)]);
    let (sent, stderr) = deploy(ws.path(), "sentinel", &env, &registry, 0);
    let mut by_tenant: Vec<(String, String)> = match value(&sent, "results") {
        Json::Array(rows) => rows
            .iter()
            .map(|row| {
                let text = |key| {
                    row.get(key)
                        .and_then(Json::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                (text("tenant"), text("status"))
            })
            .collect(),
        other => panic!("{other:?}"),
    };
    by_tenant.sort();
    assert_eq!(
        by_tenant,
        [
            ("lab", "deployed"),
            ("lab", "deployed"),
            ("lab", "deployed"),
            ("soc", "not_attempted"),
            ("soc", "not_attempted"),
            ("soc", "not_attempted"),
        ]
        .map(|(tenant, status)| (tenant.to_owned(), status.to_owned()))
    );
    assert_eq!(deployer.seen.lock().unwrap().len(), 4);
    assert!(
        stderr.contains("not attempted: tenant soc failed"),
        "{stderr}"
    );
    // One cause, one failure: the tenant's.
    assert_failed_before_any_rule(
        &sent,
        "sentinel",
        "soc",
        "sentinel tenant 'soc': the credentials were refused",
    );
    let Json::Array(failures) = value(&sent, "failures") else {
        panic!("no failures")
    };
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(
        value(&sent, "error"),
        &Json::str(
            "Deployment to sentinel failed on tenant soc: sentinel tenant 'soc': the credentials were refused"
        )
    );
    // No rule failed: the run's code is not `issues_found`.
    assert!(
        !sent.result.iter().any(|(key, _)| key == "_failure_code"),
        "{:?}",
        sent.result
    );
    assert_eq!(
        value(&sent, "deployed"),
        &Json::Array(vec![Json::str("sentinel")])
    );
}

/// A rule refused before planning (vendor ids on the rule) is a failure
/// the result lists, while the other rules deploy.
#[test]
fn a_rule_refused_before_planning_is_listed_with_the_failures() {
    let mut rules = three_rules(SENTINEL_STAGING);
    rules[1].1.push_str("    rule_id: legacy-1\n");
    let ws = workspace("sentinel", "soc", SENTINEL_SETUP, &rules);
    let (registry, deployer) = scripted("sentinel", Vec::new());
    let env = Env::from_pairs([("AZURE_CLIENT_SECRET", SECRET)]);
    let (sent, _) = deploy(ws.path(), "sentinel", &env, &registry, 0);
    assert_eq!(deployer.seen.lock().unwrap().len(), 2);
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(1));
    let Json::Array(failures) = value(&sent, "failures") else {
        panic!("no failures")
    };
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(
        failures[0].get("id"),
        Some(&Json::str("00000000-0000-4000-8099-000000000002"))
    );
}

/// An interrupt still stops the run: the rule it came on fails, nothing
/// after it is sent, and the failures before it are still listed.
#[test]
fn an_interrupt_stops_the_run_and_keeps_the_failures_before_it() {
    let ws = workspace(
        "sentinel",
        "soc",
        SENTINEL_SETUP,
        &three_rules(SENTINEL_STAGING),
    );
    let (registry, deployer) = scripted(
        "sentinel",
        vec![
            Err(ConnectorError::refused(
                "sentinel",
                "soc",
                "PUT https://x failed with HTTP 400",
                None,
            )),
            Err(ConnectorError::Cancelled),
        ],
    );
    let env = Env::from_pairs([("AZURE_CLIENT_SECRET", SECRET)]);
    let (sent, _) = deploy(ws.path(), "sentinel", &env, &registry, 0);
    let statuses: Vec<String> = rows(&sent).into_iter().map(|(status, _)| status).collect();
    assert_eq!(statuses, ["failed", "failed", "not_attempted"]);
    assert_eq!(deployer.seen.lock().unwrap().len(), 2);
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(1));
    assert_eq!(
        value(&sent, "error"),
        &Json::str("Deployment to sentinel failed on Second: interrupted")
    );
    let Json::Array(failures) = value(&sent, "failures") else {
        panic!("no failures")
    };
    let names: Vec<_> = failures
        .iter()
        .filter_map(|failure| failure.get("name"))
        .collect();
    assert_eq!(names, [&Json::str("First"), &Json::str("Second")]);
}

/// A rule refused on one platform leaves the next platform's rules to
/// deploy.
#[test]
fn a_refused_rule_on_one_platform_leaves_the_next_platform_to_deploy() {
    let ws = workspace("sentinel", "soc", SENTINEL_SETUP, &[]);
    let platforms = ws.path().join(".opentide/configurations/platforms");
    std::fs::write(
        platforms.join("splunk.toml"),
        "[platform]\nenabled = true\nname = \"Stand-in\"\n\n[[tenants]]\nname = \"lab\"\n\
         strategies = [\"PREVIEW\", \"RELEASE\"]\n[tenants.setup]\nurl = \"splunk.invalid\"\n\
         token = \"$SPLUNK_TOKEN\"\n",
    )
    .unwrap();
    std::fs::write(
        ws.path().join("objects/rules/a.yaml"),
        rule(
            "Both",
            "00000000-0000-4000-8099-000000000001",
            "Both.",
            &format!("{SENTINEL_STAGING}{SPLUNK_BLOCK}"),
        ),
    )
    .unwrap();
    let refused = ConnectorError::refused(
        "sentinel",
        "soc",
        "PUT https://x failed with HTTP 400",
        None,
    );
    let sentinel: &'static Scripted = Box::leak(Box::new(Scripted {
        id: "sentinel",
        outcomes: Mutex::new([Err(refused)].into()),
        seen: Mutex::new(Vec::new()),
        only: None,
    }));
    let splunk: &'static Scripted = Box::leak(Box::new(Scripted {
        id: "splunk",
        outcomes: Mutex::new(std::collections::VecDeque::new()),
        seen: Mutex::new(Vec::new()),
        only: None,
    }));
    let mut registry = Registry::new();
    registry.register(Box::new(Forward(sentinel))).unwrap();
    registry.register(Box::new(Forward(splunk))).unwrap();
    let args = Args {
        strategies: vec!["PREVIEW".into(), "RELEASE".into()],
        all: true,
        keep_deprecated: Some(true),
        ..Args::default()
    };
    let env = Env::from_pairs([("AZURE_CLIENT_SECRET", SECRET), ("SPLUNK_TOKEN", SECRET)]);
    let (sent, _) = deploy_with(ws.path(), &args, &env, &registry, 0);
    let mut statuses: Vec<(String, String)> = match value(&sent, "results") {
        Json::Array(rows) => rows
            .iter()
            .map(|row| {
                let text = |key| {
                    row.get(key)
                        .and_then(Json::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                (text("platform"), text("status"))
            })
            .collect(),
        other => panic!("{other:?}"),
    };
    statuses.sort();
    assert_eq!(
        statuses,
        [("sentinel", "failed"), ("splunk", "deployed")]
            .map(|(platform, status)| (platform.to_owned(), status.to_owned()))
    );
    assert_eq!(splunk.seen.lock().unwrap().len(), 1);
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(1));
    // Both platforms' sends ran on the process's one runtime (#1558).
    assert_eq!(opentide_connectors::runtime::started(), 1);
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
        Some("No rule has a status PREVIEW or RELEASE deploys · 1 rule in DESIGN")
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
            Some(
                "could not delete the rule: Was not able to delete rule with ID cs-rule-missing \
                 against tenant lab - Error Code 404"
                    .to_owned()
            )
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
fn sysdig_forgets_a_rule_to_disable_the_tenant_lost_and_stops_on_a_refused_read() {
    let block = |status: &str| {
        format!(
            "  sysdig:\n    schema: platform::sysdig::1.0\n    status: {status}\n    condition: \
             spawned_process and container\n    tags: [container]\n"
        )
    };
    let lost = "00000000-0000-4000-8099-000000000081";
    let denied = "00000000-0000-4000-8099-000000000082";
    let after = "00000000-0000-4000-8099-000000000084";
    let ws = stated(
        "sysdig",
        "ssl = true\nurl = \"https://sysdig-tenant.invalid/\"\napi_token = \
         \"$SYSDIG_SECURE_API_TOKEN\"\n",
        &[
            ("a.yaml", lost, block("DISABLED"), "42"),
            ("b.yaml", denied, block("STAGING"), "401"),
            ("c.yaml", after, block("STAGING"), "402"),
        ],
    );
    // Rule 42 is gone (404); the token may not read rule 401 (403), which
    // stops the tenant: rule 402 is never sent.
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
    assert_eq!(rows[2].0, "not_attempted", "{rows:?}");
    assert_eq!(rows.len(), 3, "{rows:?}");
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

/// A Sysdig rule created, then refused its runtime policies (the listing
/// fails): its new id is still recorded, and the rule fails with Sysdig's
/// answer.
#[test]
fn sysdig_records_a_rule_created_before_its_policies_failed() {
    use wiremock::matchers::{method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(async {
        wiremock::Mock::given(method("POST"))
            .and(path("/api/secure/rules"))
            .respond_with(wiremock::ResponseTemplate::new(201).set_body_string(r#"{"id": 43}"#))
            .expect(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(method("GET"))
            .and(path("/api/v2/policies"))
            .respond_with(wiremock::ResponseTemplate::new(500).set_body_string("down"))
            .mount(&server)
            .await;
    });
    let uuid = "00000000-0000-4000-8099-000000000083";
    let block = "  sysdig:\n    schema: platform::sysdig::1.0\n    status: STAGING\n    condition: \
                 spawned_process and container\n    tags: [container]\n";
    let ws = workspace(
        "sysdig",
        "lab",
        &format!(
            "url = \"{}\"\napi_token = \"$SYSDIG_SECURE_API_TOKEN\"\npolicies = [\"managed\"]\n",
            server.uri()
        ),
        &[("a.yaml", rule("Created rule", uuid, "Created.", block))],
    );
    let env = Env::from_pairs([("SYSDIG_SECURE_API_TOKEN".to_owned(), "token".to_owned())]);
    let (sent, _) = deploy(
        ws.path(),
        "sysdig",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    rt.block_on(server.verify());
    let rows = rows(&sent);
    assert_eq!(rows[0].0, "failed");
    assert!(
        rows[0]
            .1
            .as_deref()
            .unwrap_or_default()
            .contains("HTTP 500"),
        "{rows:?}"
    );
    let state = std::fs::read_to_string(
        ws.path()
            .join(format!(".opentide/states/deployment/{uuid}.json")),
    )
    .unwrap();
    assert!(state.contains("\"lab\": \"43\""), "{state}");
}

/// An Exabeam tenant on `server`, its token answered, and the environment
/// with its credentials.
fn exabeam_stand(server: &wiremock::MockServer, rt: &tokio::runtime::Runtime) -> (String, Env) {
    use wiremock::matchers::{method, path};
    rt.block_on(
        wiremock::Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(
                r#"{"access_token": "t1", "token_type": "Bearer", "expires_in": 14400}"#,
            ))
            // One token for the tenant, across its rules.
            .expect(1)
            .mount(server),
    );
    let setup = format!(
        "region = \"eu\"\nclient_id = \"$EXABEAM_CLIENT_ID\"\nclient_secret = \
         \"$EXABEAM_CLIENT_SECRET\"\napi_url = \"{}/\"\n",
        server.uri()
    );
    let env = Env::from_pairs([
        ("EXABEAM_CLIENT_ID".to_owned(), "id".to_owned()),
        ("EXABEAM_CLIENT_SECRET".to_owned(), "secret".to_owned()),
    ]);
    (setup, env)
}

const EXABEAM_BLOCK: &str = "  exabeam:\n    schema: platform::exabeam::1.0\n    status: \
                             STAGING\n    sequences:\n      - query: \
                             activity_type:\"process-create\"\n";

/// Exabeam through the command line: a created rule's id is recorded; a
/// rule whose name another rule has fails with Exabeam's code and the
/// other rule's id, and the next rule still deploys.
#[test]
fn exabeam_records_a_created_rule_and_fails_one_whose_name_is_taken() {
    use wiremock::matchers::{method, path, query_param};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    let (setup, env) = exabeam_stand(&server, &rt);
    let created = "016dbc1d-a727-43df-a143-9546dcc81a5a";
    rt.block_on(async {
        wiremock::Mock::given(method("GET"))
            .and(path("/correlation-rules/v2/rules"))
            .and(query_param("nameContains", "Taken rule"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(r#"[{"id": "z", "name": "Taken rule"}]"#),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(method("GET"))
            .and(path("/correlation-rules/v2/rules"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/correlation-rules/v2/rules"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(format!(r#"{{"id": "{created}", "name": "Fresh rule"}}"#)),
            )
            .expect(1)
            .mount(&server)
            .await;
    });
    let taken = "00000000-0000-4000-8099-000000000091";
    let fresh = "00000000-0000-4000-8099-000000000092";
    let ws = workspace(
        "exabeam",
        "lab",
        &setup,
        &[
            ("a.yaml", rule("Taken rule", taken, "Taken.", EXABEAM_BLOCK)),
            ("b.yaml", rule("Fresh rule", fresh, "Fresh.", EXABEAM_BLOCK)),
        ],
    );
    let (sent, _) = deploy(
        ws.path(),
        "exabeam",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    rt.block_on(server.verify());
    let mut rows = rows(&sent);
    rows.sort();
    assert_eq!(rows[0].0, "deployed", "{rows:?}");
    assert_eq!(rows[1].0, "failed", "{rows:?}");
    let error = rows[1].1.as_deref().unwrap_or_default();
    assert!(error.starts_with("exabeam_name_conflict: "), "{error}");
    assert!(error.contains("(id z)"), "{error}");
    let state = std::fs::read_to_string(
        ws.path()
            .join(format!(".opentide/states/deployment/{fresh}.json")),
    )
    .unwrap();
    assert!(state.contains(created), "{state}");
    assert!(
        !ws.path()
            .join(format!(".opentide/states/deployment/{taken}.json"))
            .exists()
    );
}

/// A Datadog tenant on `server`, and the environment with its keys.
fn datadog_stand(server: &wiremock::MockServer) -> (String, Env) {
    let setup = format!(
        "site = \"datadoghq.eu\"\napi_key = \"$DD_API_KEY\"\napp_key = \"$DD_APP_KEY\"\napi_url = \
         \"{}/\"\n[tenants.setup.notifications]\nsoc = \"@slack-soc\"\n",
        server.uri()
    );
    let env = Env::from_pairs([
        ("DD_API_KEY".to_owned(), "api".to_owned()),
        ("DD_APP_KEY".to_owned(), "app".to_owned()),
    ]);
    (setup, env)
}

const DATADOG_BLOCK: &str = "  datadog:\n    schema: platform::datadog::1.0\n    status: \
                             PRODUCTION\n    queries:\n      - query: source:okta \
                             @evt.outcome:FAILURE\n    cases:\n      - condition: a > 5\n        \
                             notify: [soc]\n";

/// Datadog through the command line (RFC rfc-datadog-cloud-siem §8.2): a
/// created rule is validated first and its id recorded; the next run reads
/// the rule by that id, finds it unchanged and sends no `PUT`, and its row
/// says `unchanged`.
#[test]
fn datadog_records_a_created_rule_and_leaves_an_unchanged_one_alone() {
    use wiremock::matchers::{body_partial_json, header, method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    let (setup, env) = datadog_stand(&server);
    let uuid = "00000000-0000-4000-8099-0000000000d1";
    let ws = workspace(
        "datadog",
        "eu",
        &setup,
        &[(
            "a.yaml",
            rule("Failed logins", uuid, "Failed logins.", DATADOG_BLOCK),
        )],
    );
    let body: std::sync::Arc<std::sync::Mutex<Option<serde_json::Value>>> =
        std::sync::Arc::default();
    let kept = std::sync::Arc::clone(&body);
    rt.block_on(async {
        wiremock::Mock::given(method("POST"))
            .and(path("/api/v2/security_monitoring/rules/validation"))
            .and(header("DD-API-KEY", "api"))
            .respond_with(wiremock::ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/api/v2/security_monitoring/rules"))
            .and(body_partial_json(serde_json::json!({
                "name": "Failed logins",
                "type": "log_detection",
                "cases": [{"status": "high", "condition": "a > 5",
                           "notifications": ["@slack-soc"]}],
            })))
            .respond_with(move |request: &wiremock::Request| {
                let sent: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                *kept.lock().unwrap() = Some(sent.clone());
                let mut stored = sent;
                stored["id"] = "abc-def-ghi".into();
                stored["version"] = 1.into();
                wiremock::ResponseTemplate::new(200).set_body_json(stored)
            })
            .expect(1)
            .mount(&server)
            .await;
    });
    let (sent, _) = deploy(
        ws.path(),
        "datadog",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    rt.block_on(server.verify());
    assert_eq!(rows(&sent)[0].0, "deployed", "{:?}", rows(&sent));
    let state = std::fs::read_to_string(
        ws.path()
            .join(format!(".opentide/states/deployment/{uuid}.json")),
    )
    .unwrap();
    assert!(state.contains("\"eu\": \"abc-def-ghi\""), "{state}");
    // The second run: the rule Datadog holds is the one the run would write.
    let mut stored = body.lock().unwrap().clone().unwrap();
    stored["id"] = "abc-def-ghi".into();
    stored["version"] = 1.into();
    stored["isDefault"] = false.into();
    rt.block_on(async {
        server.reset().await;
        wiremock::Mock::given(method("GET"))
            .and(path("/api/v2/security_monitoring/rules/abc-def-ghi"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(stored))
            .expect(1)
            .mount(&server)
            .await;
        for verb in ["PUT", "POST", "DELETE"] {
            wiremock::Mock::given(method(verb))
                .respond_with(wiremock::ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
        }
    });
    let (sent, _) = deploy(
        ws.path(),
        "datadog",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    rt.block_on(server.verify());
    let Json::Array(results) = value(&sent, "results") else {
        panic!("no results")
    };
    assert_eq!(
        results[0].get("action").and_then(Json::as_str),
        Some("unchanged"),
        "{results:?}"
    );
}

/// An Exabeam rule the tenant lost, while git ignores deployment state: it
/// is not created again, the run warns that it was missing and fails the
/// rule with the state's refusal.
#[test]
fn exabeam_does_not_create_again_a_lost_rule_git_would_not_keep() {
    use wiremock::matchers::{method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    let (setup, _) = exabeam_stand(&server, &rt);
    let stored = "016dbc1d-a727-43df-a143-9546dcc81a5a";
    rt.block_on(async {
        wiremock::Mock::given(method("PUT"))
            .and(path(format!("/correlation-rules/v2/rules/{stored}")))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/correlation-rules/v2/rules"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
    });
    let uuid = "00000000-0000-4000-8099-000000000093";
    let ws = stated(
        "exabeam",
        &setup,
        &[("a.yaml", uuid, EXABEAM_BLOCK.to_owned(), stored)],
    );
    std::fs::write(ws.path().join(".gitignore"), ".opentide/states/\n").unwrap();
    let (code, _, err) = cli(
        ws.path(),
        &[
            "deploy",
            "--platform",
            "exabeam",
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
        ],
        &[
            ("EXABEAM_CLIENT_ID", "id".to_owned()),
            ("EXABEAM_CLIENT_SECRET", "secret".to_owned()),
        ],
    );
    rt.block_on(server.verify());
    assert_eq!(code, 1, "{err}");
    // The warning raised before the refusal, then the state's refusal
    // itself (`report_failure`'s `detail`), never a rule error.
    let warned = err.find("code: exabeam_rule_recreated").expect(&err);
    let refused = err
        .find("error: Deployment state ignored · detail: git ignores")
        .expect(&err);
    assert!(warned < refused, "{err}");
    assert!(!err.contains("· error: git ignores"), "{err}");
}

/// Bitdefender through the command line, against a stand-in GravityZone: a
/// created rule's id is recorded, a rule whose name another has fails with
/// GravityZone's code, and a recorded rule the tenant lost is created again
/// (a warning) and its new id recorded.
#[test]
fn bitdefender_records_created_rules_and_fails_one_whose_name_is_taken() {
    use wiremock::matchers::{method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    let ids = Arc::new(Mutex::new(vec![
        "bbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        "aaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
    ]));
    let respond = move |request: &wiremock::Request| {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let (call, params, id) = (&body["method"], &body["params"], &body["id"]);
        let answer = match call.as_str().unwrap() {
            "createCustomRule" if params["name"] == "Taken rule" => serde_json::json!({
                "jsonrpc": "2.0", "id": id, "error": {"code": -32602, "message": "Invalid params",
                "data": {"details": "A rule with this name already exists"}}
            }),
            "createCustomRule" => {
                serde_json::json!({"jsonrpc": "2.0", "id": id, "result": ids.lock().unwrap().pop()})
            }
            _ => serde_json::json!({
                "jsonrpc": "2.0", "id": id, "error": {"code": -32002, "message": "Resource not found"}
            }),
        };
        wiremock::ResponseTemplate::new(200).set_body_json(answer)
    };
    rt.block_on(
        wiremock::Mock::given(method("POST"))
            .and(path("/api/v1.0/jsonrpc/incidents"))
            .respond_with(respond)
            .mount(&server),
    );
    let block = bitdefender_block(false);
    let (fresh, taken, lost) = (
        "00000000-0000-4000-8099-000000000101",
        "00000000-0000-4000-8099-000000000102",
        "00000000-0000-4000-8099-000000000103",
    );
    let setup = format!(
        "ssl = false\nurl = \"{}/api\"\napi_key = \"$GRAVITYZONE_API_KEY\"\n",
        server.uri()
    );
    let ws = stated(
        "bitdefender",
        &setup,
        &[("c.yaml", lost, block.clone(), "cccccccccccccccccccccccc")],
    );
    for (file, uuid, name) in [
        ("a.yaml", fresh, "Fresh rule"),
        ("b.yaml", taken, "Taken rule"),
    ] {
        std::fs::write(
            ws.path().join("objects/rules").join(file),
            rule(name, uuid, "A rule.", &block),
        )
        .unwrap();
    }
    let env = Env::from_pairs([("GRAVITYZONE_API_KEY".to_owned(), "key".to_owned())]);
    let (sent, _) = deploy(
        ws.path(),
        "bitdefender",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    let shard = |uuid: &str| {
        std::fs::read_to_string(
            ws.path()
                .join(format!(".opentide/states/deployment/{uuid}.json")),
        )
        .unwrap_or_default()
    };
    let rows = rows(&sent);
    let failed: Vec<&str> = rows
        .iter()
        .filter(|(status, _)| status == "failed")
        .filter_map(|(_, error)| error.as_deref())
        .collect();
    assert_eq!(failed.len(), 1, "{rows:?}");
    assert!(
        failed[0].starts_with("bitdefender_name_conflict: "),
        "{rows:?}"
    );
    assert!(shard(taken).is_empty());
    let recorded = [shard(fresh), shard(lost)].join("\n");
    assert!(recorded.contains("aaaaaaaaaaaaaaaaaaaaaaaa"), "{recorded}");
    assert!(recorded.contains("bbbbbbbbbbbbbbbbbbbbbbbb"), "{recorded}");
    assert!(!recorded.contains("cccccccccccccccccccccccc"), "{recorded}");
    // The lost rule's `bitdefender_rule_recreated` warning.
    assert_eq!(
        value(&sent, "warnings"),
        &Json::Array(vec![Json::str("Some rules reported deployment warnings")])
    );
}

/// Bitdefender through the command line: a disabled rule the tenant lost is
/// forgotten (a warning); a tenant that refuses the key fails at its first
/// rule and no other request is sent to it.
#[test]
fn bitdefender_forgets_a_lost_rule_to_disable_and_stops_a_tenant_refusing_the_key() {
    use wiremock::matchers::{body_partial_json, method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(
        wiremock::Mock::given(method("POST"))
            .and(path("/api/v1.0/jsonrpc/incidents"))
            .and(body_partial_json(serde_json::json!({"method": "updateCustomRule"})))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(
                r#"{"jsonrpc": "2.0", "id": "1", "error": {"code": -32002, "message": "Resource not found"}}"#,
            ))
            .mount(&server),
    );
    let disabled = bitdefender_block(false).replace("status: STAGING", "status: DISABLED");
    let lost = "00000000-0000-4000-8099-000000000111";
    let setup = |url: &str| {
        format!("ssl = false\nurl = \"{url}/api\"\napi_key = \"$GRAVITYZONE_API_KEY\"\n")
    };
    let env = Env::from_pairs([("GRAVITYZONE_API_KEY".to_owned(), "key".to_owned())]);
    let ws = stated(
        "bitdefender",
        &setup(&server.uri()),
        &[("a.yaml", lost, disabled, "cccccccccccccccccccccccc")],
    );
    let (sent, _) = deploy(
        ws.path(),
        "bitdefender",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    assert_eq!(rows(&sent)[0].0, "deployed", "{:?}", rows(&sent));
    assert!(
        !ws.path()
            .join(format!(".opentide/states/deployment/{lost}.json"))
            .exists()
    );
    assert_eq!(
        value(&sent, "warnings"),
        &Json::Array(vec![Json::str("Some rules reported deployment warnings")])
    );

    let refusing = rt.block_on(wiremock::MockServer::start());
    rt.block_on(
        wiremock::Mock::given(method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .expect(1)
            .mount(&refusing),
    );
    let block = bitdefender_block(false);
    let ws = workspace(
        "bitdefender",
        "lab",
        &setup(&refusing.uri()),
        &[
            (
                "a.yaml",
                rule(
                    "First rule",
                    "00000000-0000-4000-8099-000000000112",
                    "A.",
                    &block,
                ),
            ),
            (
                "b.yaml",
                rule(
                    "Second rule",
                    "00000000-0000-4000-8099-000000000113",
                    "B.",
                    &block,
                ),
            ),
        ],
    );
    let (sent, _) = deploy(
        ws.path(),
        "bitdefender",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    rt.block_on(refusing.verify());
    // The key was refused on the tenant's first request: no rule was sent
    // (#1701).
    assert_failed_before_any_rule(
        &sent,
        "bitdefender",
        "lab",
        "bitdefender_tenant_unauthorized: ",
    );
    assert_tenant_stopped(&sent, "lab");
}

/// The run of a platform whose tenant `tenant` failed before any rule was
/// sent to it (#1701): each of its rules is `not attempted`, naming the
/// tenant, the one failure that names it is the tenant's own (no rule), its
/// error starting with `error`, and the run fails with exit 1.
fn assert_failed_before_any_rule(sent: &Sent, platform: &str, tenant: &str, error: &str) {
    let Json::Array(results) = value(sent, "results") else {
        panic!("no results")
    };
    let reason = format!("not attempted: tenant {tenant} failed");
    let mine: Vec<&Json> = results
        .iter()
        .filter(|row| row.get("tenant").and_then(Json::as_str) == Some(tenant))
        .collect();
    assert!(!mine.is_empty(), "{results:?}");
    for row in mine {
        assert_eq!(
            row.get("status").and_then(Json::as_str),
            Some("not_attempted"),
            "{results:?}"
        );
        assert_eq!(
            row.get("reason").and_then(Json::as_str),
            Some(reason.as_str()),
            "{results:?}"
        );
    }
    let Json::Array(failures) = value(sent, "failures") else {
        panic!("no failures")
    };
    let theirs: Vec<&Json> = failures
        .iter()
        .filter(|failure| failure.get("tenant").and_then(Json::as_str) == Some(tenant))
        .collect();
    assert_eq!(theirs.len(), 1, "{failures:?}");
    assert_eq!(theirs[0].get("platform"), Some(&Json::str(platform)));
    assert_eq!(theirs[0].get("id"), None, "{failures:?}");
    let text = theirs[0].get("error").and_then(Json::as_str).unwrap();
    assert!(text.starts_with(error), "{text}");
    assert_eq!(value(sent, "_exit_code"), &Json::Int(1));
    assert_eq!(value(sent, "status"), &Json::str("failed"));
}

/// The run of a platform whose only tenant, `tenant`, failed on a rule: the
/// platform is not in `deployed`, and every rule after it says which tenant
/// failed.
fn assert_tenant_stopped(sent: &Sent, tenant: &str) {
    assert_eq!(value(sent, "deployed"), &Json::Array(Vec::new()));
    let Json::Array(results) = value(sent, "results") else {
        panic!("no results")
    };
    let unsent: Vec<&Json> = results
        .iter()
        .filter(|row| row.get("status").and_then(Json::as_str) == Some("not_attempted"))
        .collect();
    assert!(!unsent.is_empty(), "{results:?}");
    let reason = format!("not attempted: tenant {tenant} failed");
    for row in unsent {
        assert_eq!(
            row.get("reason").and_then(Json::as_str),
            Some(reason.as_str())
        );
    }
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

/// In a GitHub Actions job, a deploy that failed writes each failure to the
/// job's summary: what failed, where, and why, without the log.
#[test]
fn a_failed_deploy_lists_its_failures_in_the_job_summary() {
    let ws = workspace(
        "sentinel",
        "soc",
        SENTINEL_SETUP,
        &three_rules(SENTINEL_STAGING),
    );
    let summary = ws.path().join("step-summary.md");
    let refusing = "http://127.0.0.1:9".to_owned();
    let (code, _, _) = cli(
        ws.path(),
        &[
            "deploy",
            "--platform",
            "sentinel",
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
            "--keep-deprecated",
        ],
        &[
            ("GITHUB_ACTIONS", "true".to_owned()),
            ("GITHUB_STEP_SUMMARY", summary.display().to_string()),
            ("AZURE_CLIENT_SECRET", SECRET.to_owned()),
            ("HTTPS_PROXY", refusing.clone()),
            ("HTTP_PROXY", refusing.clone()),
            ("ALL_PROXY", refusing),
        ],
    );
    assert_eq!(code, 1);
    let text = std::fs::read_to_string(&summary).unwrap();
    assert!(text.contains("| `sentinel` | not deployed | 3 |"), "{text}");
    // The sign-in, before any rule, could not reach Entra ID: the failure is
    // the tenant's, on every rule (#1701).
    assert!(
        text.contains(
            "**1 failure**\n\n| Platform | Tenant | Rule | Error |\n|---|---|---|---|\n\
             | `sentinel` | soc | every rule | Cannot reach sentinel tenant 'soc' at \
             https://login.microsoftonline.com"
        ),
        "{text}"
    );
}

/// `ws` as a git checkout of two commits, the second changing `file`.
fn pushed(ws: &Path, file: &str) {
    pushed_files(ws, &[file]);
}

/// `ws` as a repository whose last commit changed each of `files`.
fn pushed_files(ws: &Path, files: &[&str]) {
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
    for file in files {
        let path = ws.join(file);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            text.replace("description: ", "description: Changed. "),
        )
        .unwrap();
    }
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
            ("GITHUB_REF", "refs/heads/main".to_owned()),
            ("OPENTIDE_DEFAULT_BRANCH", "main".to_owned()),
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
    // The promoted rule goes to the tenant, which does not resolve here:
    // the failure is that tenant's own, and since no tenant received the
    // rule its promotion is put back (#1653).
    assert_eq!(code, 1, "{out}{err}");
    assert!(out.contains("\"tenant\":\"lab\""), "{out}");
    assert!(out.contains("\"failures\":[{"), "{out}");
    let text = std::fs::read_to_string(&rule).unwrap();
    assert!(text.contains("    status: STAGING\n"), "{text}");
}

/// The rule a RELEASE push promotes is deployed to the tenants that take
/// RELEASE, with its new status: the run reads the workspace again after the
/// promotion rewrote the file. It used to plan the rule from the status it
/// had before, route it to no tenant, send nothing and report it deployed.
#[test]
fn a_push_deploys_the_rule_it_promotes_to_its_release_tenants() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = graylog_stand(&rt, "7.1.0");
    let setup = format!("url = \"{}\"\ntoken = \"$GRAYLOG_TOKEN\"\n", server.uri());
    let uuid = "00000000-0000-4000-8047-000000000904";
    let ws = workspace(
        "graylog",
        "lab",
        &setup,
        &[(
            "r.yaml",
            rule(
                "Promoted",
                uuid,
                "A rule.",
                &graylog_block("STAGING", "EventID:1"),
            ),
        )],
    );
    pushed(ws.path(), "objects/rules/r.yaml");
    let env = vec![
        ("GITHUB_ACTIONS", "true".to_owned()),
        ("GITHUB_EVENT_NAME", "push".to_owned()),
        ("GITHUB_REF", "refs/heads/main".to_owned()),
        ("OPENTIDE_DEFAULT_BRANCH", "main".to_owned()),
        ("GITHUB_SHA", "HEAD".to_owned()),
        ("GITHUB_WORKSPACE", ws.path().display().to_string()),
        ("GRAYLOG_TOKEN", "token".to_owned()),
    ];
    let argv = [
        "--json",
        "deploy",
        "--platform",
        "graylog",
        "--strategy",
        "RELEASE",
    ];
    let (code, out, err) = cli(ws.path(), &argv, &env);
    // The tenant's version was read: the run reached the tenant.
    rt.block_on(server.verify());
    assert_eq!(code, 0, "{out}{err}");
    let text = std::fs::read_to_string(ws.path().join("objects/rules/r.yaml")).unwrap();
    assert!(text.contains("    status: PRODUCTION\n"), "{text}");
    let received = rt.block_on(server.received_requests()).unwrap();
    let created = received
        .iter()
        .filter(|request| {
            request.method == wiremock::http::Method::POST
                && request.url.path() == "/api/events/definitions"
        })
        .count();
    assert_eq!(created, 1, "{out}{err}");
    assert!(out.contains("\"tenant\":\"lab\""), "{out}");
    assert!(shard_of(ws.path(), uuid).contains(GRAYLOG_CREATED), "{err}");
}

/// A `RELEASE` push of `r.yaml` with *extra* in the environment: the changed
/// rule is promoted; returns whether the other rule file in the rules folder
/// (`s.yaml`) was promoted too (whole-folder promotion).
fn push_promotes_the_whole_folder(extra: &[(&str, &str)]) -> bool {
    let block = "  splunk:\n    status: STAGING\n    query: index=main\n";
    let disabled = "  splunk:\n    status: DISABLED\n    query: index=main\n";
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"token\"\n",
        &[
            (
                "r.yaml",
                rule(
                    "Promoted",
                    "00000000-0000-4000-8047-000000000902",
                    "A rule.",
                    block,
                ),
            ),
            (
                "s.yaml",
                rule(
                    "Untouched",
                    "00000000-0000-4000-8047-000000000903",
                    "Another rule.",
                    block,
                ),
            ),
            (
                "t.yaml",
                rule(
                    "Disabled",
                    "00000000-0000-4000-8047-000000000905",
                    "A disabled rule.",
                    disabled,
                ),
            ),
        ],
    );
    pushed(ws.path(), "objects/rules/r.yaml");
    let mut pairs: Vec<(String, String)> = github_push(ws.path())
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
    pairs.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    let env = Env::from_pairs(pairs);
    let (registry, deployer) = scripted("splunk", Vec::new());
    let args = Args {
        strategies: vec!["RELEASE".into()],
        platform: Some("splunk".into()),
        ..Args::default()
    };
    let (sent, text) = deploy_with(ws.path(), &args, &env, &registry, 0);
    assert!(
        rows(&sent).iter().all(|(status, _)| status == "deployed"),
        "{text}"
    );
    let read = |name: &str| std::fs::read_to_string(ws.path().join("objects/rules").join(name));
    let changed = read("r.yaml").unwrap();
    assert!(changed.contains("    status: PRODUCTION\n"), "{changed}");
    let other = read("s.yaml").unwrap();
    let promoted = other.contains("    status: PRODUCTION\n");
    // Whole-folder promotion deploys what it promoted, s.yaml too, and
    // nothing else of the folder: never the disabled rule (#1653).
    let seen: Vec<String> = deployer
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    assert_eq!(seen.contains(&"Untouched".to_owned()), promoted, "{seen:?}");
    assert!(!seen.contains(&"Disabled".to_owned()), "{seen:?}");
    assert!(seen.contains(&"Promoted".to_owned()), "{seen:?}");
    promoted
}

/// VS Code's integrated terminal (`TERM_PROGRAM=vscode`) does not turn on
/// debug promotion: a push promotes the rule it changed and leaves the other
/// rule files in the rules folder as they are, as it does from any terminal.
/// The oracle promoted every rule file from that terminal.
#[test]
fn a_push_from_vs_codes_terminal_promotes_only_the_changed_rules() {
    assert!(!push_promotes_the_whole_folder(&[(
        "TERM_PROGRAM",
        "vscode"
    )]));
}

/// Whole-folder promotion rewrites every rule file: it follows `--debug` or
/// `OPENTIDE_DEBUG`, never a bare `DEBUG`, which CI systems and tools set
/// for their own logging (the Python CLI promoted every rule under
/// `DEBUG=True`).
#[test]
fn only_opentide_debug_promotes_the_whole_folder_not_debug() {
    assert!(!push_promotes_the_whole_folder(&[]));
    assert!(!push_promotes_the_whole_folder(&[("DEBUG", "1")]));
    assert!(!push_promotes_the_whole_folder(&[("DEBUG", "true")]));
    assert!(push_promotes_the_whole_folder(&[("OPENTIDE_DEBUG", "1")]));
}

/// A Bitdefender block: a YARA rule, or a custom detection rule.
fn bitdefender_block(yara: bool) -> String {
    let rule = if yara {
        "    yara:\n      signature: |\n        rule A {\n          strings:\n            $a = \"evil\"\n          condition:\n            $a\n        }\n"
    } else {
        "    detection:\n      target: process\n      criteria:\n        - field: Process.Name\n          is: evil.exe\n"
    };
    format!(
        "  bitdefender:\n    enabled: true\n    schema: platform::bitdefender::1.0\n    status: STAGING\n{rule}"
    )
}

const BITDEFENDER_SETUP: &str = "api_key = \"key\"\nurl = \"https://127.0.0.1:9\"\n";

/// The rows of the run, each `(status, message)`: `count` of them.
fn rows_for(sent: &Sent, count: usize) -> Vec<(String, Option<String>)> {
    let rows = rows(sent);
    assert_eq!(rows.len(), count, "{rows:?}");
    rows
}

/// GravityZone holds at most 50 YARA rules per company (bitdefender-1.0): a
/// deploy that would leave more refuses its YARA creates before anything is
/// sent (the tenant here is unreachable), naming the count, instead of
/// letting the API fail part-way.
#[test]
fn bitdefender_refuses_yara_creates_past_fifty_rules() {
    let block = bitdefender_block(true);
    let files: Vec<(String, String)> = (0..51)
        .map(|i| {
            let uuid = format!("00000000-0000-4000-8099-{i:012}");
            (
                format!("r{i}.yaml"),
                rule("YARA rule", &uuid, "A YARA rule.", &block),
            )
        })
        .collect();
    let refs: Vec<(&str, String)> = files.iter().map(|(f, t)| (f.as_str(), t.clone())).collect();
    let ws = workspace("bitdefender", "lab", BITDEFENDER_SETUP, &refs);
    let env = Env::from_pairs(Vec::<(String, String)>::new());
    let (sent, _) = deploy(ws.path(), "bitdefender", &env, &Registry::new(), 0);
    for (status, message) in rows_for(&sent, 51) {
        assert_eq!(status, "failed");
        let message = message.unwrap();
        assert!(
            message
                .starts_with("the deploy would leave 51 YARA rules on tenant \"lab\" (0 recorded"),
            "{message}"
        );
        assert!(message.contains("at most 50 per company"), "{message}");
    }
}

/// The YARA rules deployment state records on the tenant count with those
/// the run creates; a recorded custom detection rule (a valid block, so the
/// count reads its kind) does not.
#[test]
fn bitdefender_counts_the_yara_rules_deployment_state_records() {
    let yara = bitdefender_block(true);
    let mut rules: Vec<(String, String, String, String)> = (0..50)
        .map(|i| {
            (
                format!("s{i}.yaml"),
                format!("00000000-0000-4000-8098-{i:012}"),
                yara.clone(),
                format!("{i:024x}"),
            )
        })
        .collect();
    // A custom detection rule recorded on the tenant does not count.
    rules.push((
        "d.yaml".into(),
        "00000000-0000-4000-8097-000000000001".into(),
        bitdefender_block(false),
        format!("{:024x}", 99),
    ));
    let refs: Vec<(&str, &str, String, &str)> = rules
        .iter()
        .map(|(f, u, b, id)| (f.as_str(), u.as_str(), b.clone(), id.as_str()))
        .collect();
    let ws = stated("bitdefender", BITDEFENDER_SETUP, &refs);
    let new = "00000000-0000-4000-8096-000000000001";
    let dir = ws.path().join("objects/rules");
    std::fs::write(
        dir.join("new.yaml"),
        rule("New YARA rule", new, "New.", &yara),
    )
    .unwrap();
    let args = Args {
        strategies: vec!["PREVIEW".into(), "RELEASE".into()],
        uuids: vec![new.into()],
        platform: Some("bitdefender".into()),
        keep_deprecated: Some(true),
        ..Args::default()
    };
    let env = Env::from_pairs(Vec::<(String, String)>::new());
    let (sent, text) = deploy_with(ws.path(), &args, &env, &Registry::new(), 0);
    let rows = rows_for(&sent, 1);
    assert_eq!(rows[0].0, "failed", "{text}");
    assert!(
        rows[0].1.as_deref().unwrap().starts_with(
            "the deploy would leave 51 YARA rules on tenant \"lab\" (50 recorded in deployment \
             state, 1 to create)"
        ),
        "{rows:?}"
    );
}

/// A Graylog rule block of `status` whose query is `query`.
fn graylog_block(status: &str, query: &str) -> String {
    format!(
        "  graylog:\n    schema: platform::graylog::1.0\n    status: {status}\n    query: \
         '{query}'\n"
    )
}

/// A stand-in Graylog of `version`: the query check refuses a query that
/// says `refused` and warns on one that says `odd`; a create answers
/// `CREATED_ID`; an update of `LOST_ID` is a 404, of any other id a 200; a
/// delete a 204.
fn graylog_stand(rt: &tokio::runtime::Runtime, version: &str) -> wiremock::MockServer {
    use wiremock::matchers::{method, path, path_regex};
    let server = rt.block_on(wiremock::MockServer::start());
    let verdict = |request: &wiremock::Request| {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let query = body["query"].as_str().unwrap_or_default();
        let verdict = if query.contains("refused") {
            serde_json::json!({"status": "ERROR", "explanations": [
                {"error_type": "QUERY_PARSING_ERROR", "error_message": "cannot parse"}]})
        } else if query.contains("odd") {
            serde_json::json!({"status": "WARNING", "explanations": [
                {"error_type": "UNKNOWN_FIELD", "error_message": "no field odd"}]})
        } else {
            serde_json::json!({"status": "OK"})
        };
        wiremock::ResponseTemplate::new(200).set_body_json(verdict)
    };
    rt.block_on(async {
        wiremock::Mock::given(method("GET"))
            .and(path("/api/system"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"version": version})),
            )
            // Read once for the tenant, whatever its rules.
            .expect(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/api/search/validate"))
            .respond_with(verdict)
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/api/events/definitions"))
            .respond_with(
                wiremock::ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"id": GRAYLOG_CREATED})),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(method("PUT"))
            .and(path(format!("/api/events/definitions/{GRAYLOG_BROKEN}")))
            .respond_with(
                wiremock::ResponseTemplate::new(500).set_body_json(
                    serde_json::json!({"type": "ApiError", "message": "storage down"}),
                ),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(method("PUT"))
            .and(path(format!("/api/events/definitions/{GRAYLOG_LOST}")))
            .respond_with(
                wiremock::ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"type": "ApiError", "message": "Not found"})),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(method("PUT"))
            .and(path_regex("^/api/events/definitions/[0-9a-f]{24}$"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id": GRAYLOG_KEPT})),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(method("DELETE"))
            .respond_with(wiremock::ResponseTemplate::new(204))
            .mount(&server)
            .await;
    });
    server
}

const GRAYLOG_CREATED: &str = "65f1c0de2a3b4c5d6e7f8091";
const GRAYLOG_LOST: &str = "65f1c0de2a3b4c5d6e7f0000";
const GRAYLOG_KEPT: &str = "65f1c0de2a3b4c5d6e7f1111";
const GRAYLOG_BROKEN: &str = "65f1c0de2a3b4c5d6e7f5000";

/// `opentide deploy --platform graylog` in `ws`, both strategies, every rule.
fn graylog_deploy(ws: &Path) -> (i32, String) {
    let (code, _, err) = cli(
        ws,
        &[
            "--verbose",
            "deploy",
            "--platform",
            "graylog",
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
            "--keep-deprecated",
        ],
        &[("GRAYLOG_TOKEN", "token".to_owned())],
    );
    (code, err)
}

/// The deployment state's shard of `uuid` in `ws`, empty when there is none.
fn shard_of(ws: &Path, uuid: &str) -> String {
    std::fs::read_to_string(ws.join(format!(".opentide/states/deployment/{uuid}.json")))
        .unwrap_or_default()
}

/// Graylog through the command line, on a version that does not revoke
/// tokens: the version is read and warned about once; a created definition's
/// id is recorded; a query Graylog warns about is updated with the warning;
/// a disabled definition the tenant lost is forgotten; a refused query fails
/// its rule alone; a removed one is deleted and forgotten.
#[test]
fn graylog_logs_records_and_forgets_as_it_deploys() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = graylog_stand(&rt, "7.1.0");
    let setup = format!("url = \"{}\"\ntoken = \"$GRAYLOG_TOKEN\"\n", server.uri());
    let (created, warned, lost, refused, removed, broken) = (
        "00000000-0000-4000-8099-000000000121",
        "00000000-0000-4000-8099-000000000122",
        "00000000-0000-4000-8099-000000000123",
        "00000000-0000-4000-8099-000000000124",
        "00000000-0000-4000-8099-000000000125",
        "00000000-0000-4000-8099-000000000126",
    );
    let ws = stated(
        "graylog",
        &setup,
        &[
            (
                "b.yaml",
                warned,
                graylog_block("STAGING", "odd:1"),
                GRAYLOG_KEPT,
            ),
            (
                "c.yaml",
                lost,
                graylog_block("DISABLED", "EventID:1"),
                GRAYLOG_LOST,
            ),
            (
                "d.yaml",
                refused,
                graylog_block("STAGING", "refused"),
                GRAYLOG_KEPT,
            ),
            (
                "e.yaml",
                removed,
                graylog_block("REMOVED", "EventID:1"),
                GRAYLOG_KEPT,
            ),
            (
                "f.yaml",
                broken,
                graylog_block("STAGING", "EventID:1"),
                GRAYLOG_BROKEN,
            ),
        ],
    );
    std::fs::write(
        ws.path().join("objects/rules/a.yaml"),
        rule(
            "Created rule",
            created,
            "Created.",
            &graylog_block("STAGING", "EventID:1"),
        ),
    )
    .unwrap();
    let (code, err) = graylog_deploy(ws.path());
    rt.block_on(server.verify());
    assert_eq!(code, 1, "{err}");
    // Once for the tenant, before any rule.
    assert_eq!(
        err.matches("Graylog version vulnerable").count(),
        1,
        "{err}"
    );
    let ordered = [
        "warning: Graylog version vulnerable",
        "warning: External id recorded",
        "✓ created   Created rule",
        "warning: Graylog unknown field",
        "✓ updated   Recorded rule",
        "warning: Graylog definition missing",
        "✓ disabled  Recorded rule",
        "code: graylog_query_invalid · error: Graylog refuses the query, so nothing is saved: \
         QUERY_PARSING_ERROR: cannot parse",
        "✓ deleted   Recorded rule",
        "status_code: 500 · code: graylog_request_failed",
    ];
    let at: Vec<usize> = ordered
        .iter()
        .map(|line| {
            err.find(line)
                .unwrap_or_else(|| panic!("no {line} in {err}"))
        })
        .collect();
    assert!(at.windows(2).all(|pair| pair[0] < pair[1]), "{err}");
    assert!(
        shard_of(ws.path(), created).contains(GRAYLOG_CREATED),
        "{err}"
    );
    assert!(shard_of(ws.path(), warned).contains(GRAYLOG_KEPT));
    assert!(shard_of(ws.path(), lost).is_empty());
    assert!(shard_of(ws.path(), refused).contains(GRAYLOG_KEPT));
    assert!(shard_of(ws.path(), removed).is_empty());
}

/// A deploy resolves the tenant's stream and notification aliases through
/// its `stream_ids` and `notification_ids`, as the dry run does, in every
/// request it builds from the rule: the query check, a create and an update
/// name the ids, never an empty list (which Graylog reads as every stream and
/// no notification). An alias the tenant does not define fails its rule
/// alone, before any request for it.
#[test]
fn graylog_deploy_resolves_the_tenants_stream_and_notification_aliases() {
    const STREAM: &str = "65f1c0de2a3b4c5d6e7f2222";
    const NOTIFICATION: &str = "65f1c0de2a3b4c5d6e7f3333";
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = graylog_stand(&rt, "7.1.0");
    let setup = format!(
        "url = \"{}\"\ntoken = \"$GRAYLOG_TOKEN\"\nstreams = [\"endpoint\"]\n\
         [tenants.setup.stream_ids]\nendpoint = \"{STREAM}\"\n\
         [tenants.setup.notification_ids]\npager = \"{NOTIFICATION}\"\n",
        server.uri()
    );
    let (created, recorded, unknown) = (
        "00000000-0000-4000-8099-000000000127",
        "00000000-0000-4000-8099-000000000128",
        "00000000-0000-4000-8099-000000000129",
    );
    let notify = |alias: &str| {
        format!(
            "{}    notifications:\n      - {alias}\n",
            graylog_block("STAGING", "EventID:1")
        )
    };
    let ws = stated(
        "graylog",
        &setup,
        &[("b.yaml", recorded, notify("pager"), GRAYLOG_KEPT)],
    );
    let rules = ws.path().join("objects/rules");
    std::fs::write(
        rules.join("a.yaml"),
        rule("Aliased rule", created, "Aliased.", &notify("pager")),
    )
    .unwrap();
    std::fs::write(
        rules.join("c.yaml"),
        rule("Unknown alias rule", unknown, "Unknown.", &notify("nobody")),
    )
    .unwrap();
    let (code, err) = graylog_deploy(ws.path());
    rt.block_on(server.verify());
    // The unknown alias fails its rule, and the run; the others deploy.
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("graylog_alias_unknown"), "{err}");
    assert!(err.contains("nobody"), "{err}");
    // The failure keeps the compiler's hint, as the dry run shows it.
    assert!(
        err.contains("add the alias to the tenant's stream_ids or notification_ids table"),
        "{err}"
    );
    let received = rt.block_on(server.received_requests()).unwrap();
    let bodies = |verb: wiremock::http::Method, prefix: &str| -> Vec<serde_json::Value> {
        received
            .iter()
            .filter(|request| request.method == verb && request.url.path().starts_with(prefix))
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect()
    };
    // Graylog 7 takes a created definition under `entity`; an update is bare.
    let created_bodies = bodies(wiremock::http::Method::POST, "/api/events/definitions");
    let updated = bodies(
        wiremock::http::Method::PUT,
        &format!("/api/events/definitions/{GRAYLOG_KEPT}"),
    );
    let checked = bodies(wiremock::http::Method::POST, "/api/search/validate");
    assert_eq!((created_bodies.len(), updated.len()), (1, 1), "{err}");
    // The query is checked for the two rules that resolve, never the third.
    assert_eq!(checked.len(), 2, "{err}");
    for definition in [&created_bodies[0]["entity"], &updated[0]] {
        assert_eq!(
            definition["config"]["streams"],
            serde_json::json!([STREAM]),
            "{definition}"
        );
        assert_eq!(
            definition["notifications"],
            serde_json::json!([{"notification_id": NOTIFICATION}]),
            "{definition}"
        );
    }
    for body in &checked {
        assert_eq!(body["streams"], serde_json::json!([STREAM]), "{body}");
    }
    assert!(shard_of(ws.path(), unknown).is_empty(), "{err}");
}

/// A definition the tenant lost while git ignores deployment state is not
/// created again: the warning, then the state's refusal; and a tenant that
/// refuses the token on a rule stops there.
#[test]
fn graylog_does_not_create_again_a_lost_definition_and_stops_on_a_refused_token() {
    use wiremock::matchers::{method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = graylog_stand(&rt, "7.2.1");
    let setup = format!("url = \"{}\"\ntoken = \"$GRAYLOG_TOKEN\"\n", server.uri());
    let lost = "00000000-0000-4000-8099-000000000131";
    let ws = stated(
        "graylog",
        &setup,
        &[(
            "a.yaml",
            lost,
            graylog_block("STAGING", "EventID:1"),
            GRAYLOG_LOST,
        )],
    );
    std::fs::write(ws.path().join(".gitignore"), ".opentide/states/\n").unwrap();
    let (code, err) = graylog_deploy(ws.path());
    rt.block_on(server.verify());
    assert_eq!(code, 1, "{err}");
    // The warning, then the state's refusal, and nothing created.
    let warned = err
        .find("warning: Graylog definition recreated")
        .expect(&err);
    let refused = err
        .find("✗ failed    Recorded rule  git ignores")
        .expect(&err);
    assert!(warned < refused, "{err}");
    // Logged as the request it stopped.
    assert!(
        err.contains("code: graylog_request_failed · error: git ignores"),
        "{err}"
    );
    assert!(!err.contains("External id recorded"), "{err}");
    assert!(!err.contains("Graylog version vulnerable"), "{err}");
    assert!(shard_of(ws.path(), lost).contains(GRAYLOG_LOST));

    let refusing = rt.block_on(wiremock::MockServer::start());
    rt.block_on(async {
        wiremock::Mock::given(method("GET"))
            .and(path("/api/system"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"version": "7.2.1"})),
            )
            .expect(1)
            .mount(&refusing)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/api/search/validate"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .expect(1)
            .mount(&refusing)
            .await;
    });
    let setup = format!("url = \"{}\"\ntoken = \"$GRAYLOG_TOKEN\"\n", refusing.uri());
    let block = graylog_block("STAGING", "EventID:1");
    let ws = workspace(
        "graylog",
        "lab",
        &setup,
        &[
            (
                "a.yaml",
                rule(
                    "First rule",
                    "00000000-0000-4000-8099-000000000132",
                    "A.",
                    &block,
                ),
            ),
            (
                "b.yaml",
                rule(
                    "Second rule",
                    "00000000-0000-4000-8099-000000000133",
                    "B.",
                    &block,
                ),
            ),
        ],
    );
    let (code, err) = graylog_deploy(ws.path());
    rt.block_on(refusing.verify());
    assert_eq!(code, 1, "{err}");
    // The token is refused on the tenant's first request: no rule was sent,
    // each is not attempted (#1701).
    assert!(
        err.contains("code: graylog_tenant_unauthenticated"),
        "{err}"
    );
    assert!(!err.contains("✗ failed"), "{err}");
    assert!(
        err.contains("· skipped   First rule") && err.contains("not attempted: tenant lab failed"),
        "{err}"
    );
}

/// An Elastic rule block of `status`, on `logs-*`, with `extra` lines.
fn elastic_block(status: &str, extra: &str) -> String {
    format!(
        "  elastic:\n    status: {status}\n    type: query\n    language: kuery\n    query: \
         'process.name: \"cmd.exe\"'\n    index: [\"logs-*\"]\n    scheduling:\n      interval: \
         5m\n{extra}"
    )
}

/// `opentide deploy --platform elastic` in `ws`, both strategies, every rule.
fn elastic_deploy(ws: &Path) -> (i32, String) {
    let (code, _, err) = cli(
        ws,
        &[
            "--verbose",
            "deploy",
            "--platform",
            "elastic",
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
            "--keep-deprecated",
        ],
        &[("ELASTIC_API_KEY", "key".to_owned())],
    );
    (code, err)
}

/// A workspace of one Elastic tenant, `lab`, on `server` (Kibana and
/// Elasticsearch both), with `rules` (file, name, uuid, block).
fn elastic_workspace(server: &str, rules: &[(&str, &str, &str, String)]) -> tempfile::TempDir {
    let setup = format!(
        "url = \"{server}\"\nelasticsearch_url = \"{server}\"\napi_key = \"$ELASTIC_API_KEY\"\n"
    );
    let files: Vec<(&str, String)> = rules
        .iter()
        .map(|(file, name, uuid, block)| (*file, rule(name, uuid, "A rule.", block)))
        .collect();
    workspace("elastic", "lab", &setup, &files)
}

/// The stand-in Kibana and Elasticsearch of the Elastic deploy test: the
/// mappings lack every field; Kibana has `present` and the prebuilt
/// `prebuilt`, deletes `removed`, refuses to create `broken` (500) and
/// creates any other rule.
fn mount_elastic(
    rt: &tokio::runtime::Runtime,
    server: &wiremock::MockServer,
    [present, prebuilt, removed, broken]: [&str; 4],
) {
    use wiremock::matchers::{method, path, path_regex, query_param};
    rt.block_on(async {
        // The timestamp override is not in the mappings yet: a warning.
        wiremock::Mock::given(method("GET"))
            .and(path_regex("/_field_caps$"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"indices": ["logs-1"], "fields": {}})),
            )
            .mount(server)
            .await;
        let rules = "/api/detection_engine/rules";
        for (uuid, answer) in [
            (
                present,
                serde_json::json!({"rule_id": present, "type": "query"}),
            ),
            (
                prebuilt,
                serde_json::json!({"rule_id": prebuilt, "type": "query", "immutable": true}),
            ),
        ] {
            wiremock::Mock::given(method("GET"))
                .and(path(rules))
                .and(query_param("rule_id", uuid))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(answer))
                .mount(server)
                .await;
        }
        wiremock::Mock::given(method("GET"))
            .and(path(rules))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path(rules))
            .and(wiremock::matchers::body_partial_json(
                serde_json::json!({"rule_id": broken}),
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(500)
                    .set_body_json(serde_json::json!({"message": "storage down"})),
            )
            .mount(server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path(rules))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(server)
            .await;
        wiremock::Mock::given(method("PUT"))
            .and(path(rules))
            .and(query_param("rule_id", present))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(server)
            .await;
        wiremock::Mock::given(method("DELETE"))
            .and(path(rules))
            .and(query_param("rule_id", removed))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(server)
            .await;
    });
}

/// Elastic through the command line: a rule the checks warn about is
/// created, one Kibana has is updated, a prebuilt one is refused, a removed
/// one deleted, and a create Kibana refuses fails alone with its status.
#[test]
fn elastic_creates_updates_refuses_and_deletes_as_it_deploys() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    let (fresh, present, prebuilt, removed, broken) = (
        "00000000-0000-4000-8099-000000000141",
        "00000000-0000-4000-8099-000000000142",
        "00000000-0000-4000-8099-000000000143",
        "00000000-0000-4000-8099-000000000144",
        "00000000-0000-4000-8099-000000000145",
    );
    mount_elastic(&rt, &server, [present, prebuilt, removed, broken]);
    let overridden = "    overrides:\n      timestamp: event.ingested\n";
    let ws = elastic_workspace(
        &server.uri(),
        &[
            (
                "a.yaml",
                "Fresh rule",
                fresh,
                elastic_block("STAGING", overridden),
            ),
            (
                "b.yaml",
                "Present rule",
                present,
                elastic_block("STAGING", ""),
            ),
            (
                "c.yaml",
                "Prebuilt rule",
                prebuilt,
                elastic_block("STAGING", ""),
            ),
            (
                "d.yaml",
                "Removed rule",
                removed,
                elastic_block("REMOVED", ""),
            ),
            (
                "e.yaml",
                "Broken rule",
                broken,
                elastic_block("STAGING", overridden),
            ),
        ],
    );
    let (code, err) = elastic_deploy(ws.path());
    rt.block_on(server.verify());
    assert_eq!(code, 1, "{err}");
    let ordered = [
        "Timestamp field 'event.ingested' not found in mappings yet",
        // Kibana said which: a create, an update (#1662, E10).
        "✓ created   Fresh rule",
        "✓ updated   Present rule",
        "refusing to modify prebuilt rule",
        "✓ deleted   Removed rule",
        // The checks' warning, then Kibana's refusal.
        "rule_id: 00000000-0000-4000-8099-000000000145 · rule: Broken rule · warning: Timestamp \
         field",
        "status_code: 500",
        "HTTP 500: storage down",
    ];
    let at: Vec<usize> = ordered
        .iter()
        .map(|line| {
            err.find(line)
                .unwrap_or_else(|| panic!("no {line} in {err}"))
        })
        .collect();
    assert!(at.windows(2).all(|pair| pair[0] < pair[1]), "{err}");
}

/// A tenant whose key Kibana refuses on its first request fails before any
/// rule was sent: each rule is not attempted, and no other request is sent
/// (#1701).
#[test]
fn elastic_stops_a_tenant_refusing_the_key() {
    use wiremock::matchers::method;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(
        wiremock::Mock::given(method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .expect(1)
            .mount(&server),
    );
    let ws = elastic_workspace(
        &server.uri(),
        &[
            (
                "a.yaml",
                "First rule",
                "00000000-0000-4000-8099-000000000151",
                elastic_block("STAGING", ""),
            ),
            (
                "b.yaml",
                "Second rule",
                "00000000-0000-4000-8099-000000000152",
                elastic_block("STAGING", ""),
            ),
        ],
    );
    let (code, err) = elastic_deploy(ws.path());
    rt.block_on(server.verify());
    assert_eq!(code, 1, "{err}");
    assert!(!err.contains("✗ failed    First rule"), "{err}");
    assert!(
        err.contains("· skipped   First rule") && err.contains("not attempted: tenant lab failed"),
        "{err}"
    );
    assert!(
        err.contains("error: Elastic tenant deployment failed · tenant: *** · error: Tenant *** auth error: HTTP 401"),
        "{err}"
    );
}

/// A SentinelOne tenant that refuses the key (401) on its first rule fails,
/// as the SDK's `sentinel_one_unauthorized` (tenant scope) says, before any
/// rule was sent: each rule is not attempted, and nothing more is sent to
/// it (#1701).
#[test]
fn sentinel_one_stops_a_tenant_refusing_the_key() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(
                wiremock::ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"errors": [{"title": "Unauthorized"}]})),
            )
            .expect(1)
            .mount(&server),
    );
    let setup = format!(
        "url = \"{}\"\naccount_id = 1001\napi_token = \"$S1_API_TOKEN\"\n",
        server.uri()
    );
    let ws = workspace(
        "sentinel_one",
        "lab",
        &setup,
        &[
            (
                "a.yaml",
                rule(
                    "First rule",
                    "00000000-0000-4000-8099-000000000171",
                    "A.",
                    &s1_block("STAGING"),
                ),
            ),
            (
                "b.yaml",
                rule(
                    "Second rule",
                    "00000000-0000-4000-8099-000000000172",
                    "B.",
                    &s1_block("STAGING"),
                ),
            ),
        ],
    );
    let env = Env::from_pairs([("S1_API_TOKEN".to_owned(), "token".to_owned())]);
    let (sent, _) = deploy(
        ws.path(),
        "sentinel_one",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    rt.block_on(server.verify());
    let rows = rows(&sent);
    assert_eq!(rows.len(), 2, "{rows:?}");
    // The key was refused on the tenant's first request: no rule was sent
    // (#1701).
    assert_failed_before_any_rule(
        &sent,
        "sentinel_one",
        "lab",
        "sentinel_one_unauthorized: could not create the rule on tenant 'lab': ",
    );
}

/// A platform none of whose tenants deployed is not in `deployed`, even when
/// its tenant failed mid-batch, on a rule (here Graylog's refused token on
/// the second rule, after the first was created): a failed deploy never
/// looks deployed. The rule it came on is `failed`, and the tenant's other
/// rules are not attempted, naming the tenant.
#[test]
fn a_platform_whose_every_tenant_failed_on_a_rule_is_not_deployed() {
    use wiremock::matchers::{method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(async {
        wiremock::Mock::given(method("GET"))
            .and(path("/api/system"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"version": "7.2.1"})),
            )
            .mount(&server)
            .await;
        // The first rule's query check passes and the rule is created; the
        // token is refused on the second.
        wiremock::Mock::given(method("POST"))
            .and(path("/api/search/validate"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"status": "OK"})),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/api/events/definitions"))
            .respond_with(
                wiremock::ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"id": GRAYLOG_CREATED})),
            )
            .expect(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/api/search/validate"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;
    });
    let setup = format!("url = \"{}\"\ntoken = \"$GRAYLOG_TOKEN\"\n", server.uri());
    let block = graylog_block("STAGING", "EventID:1");
    let ws = workspace(
        "graylog",
        "lab",
        &setup,
        &[
            (
                "a.yaml",
                rule(
                    "First rule",
                    "00000000-0000-4000-8099-000000000191",
                    "A.",
                    &block,
                ),
            ),
            (
                "b.yaml",
                rule(
                    "Second rule",
                    "00000000-0000-4000-8099-000000000192",
                    "B.",
                    &block,
                ),
            ),
            (
                "c.yaml",
                rule(
                    "Third rule",
                    "00000000-0000-4000-8099-000000000193",
                    "C.",
                    &block,
                ),
            ),
        ],
    );
    let env = Env::from_pairs([("GRAYLOG_TOKEN".to_owned(), "token".to_owned())]);
    let (sent, _) = deploy(
        ws.path(),
        "graylog",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    rt.block_on(server.verify());
    assert_eq!(value(&sent, "deployed"), &Json::Array(Vec::new()));
    assert_eq!(value(&sent, "status"), &Json::str("failed"));
    let rows = rows(&sent);
    let statuses: Vec<&str> = rows.iter().map(|(status, _)| status.as_str()).collect();
    assert_eq!(
        statuses,
        ["deployed", "failed", "not_attempted"],
        "{rows:?}"
    );
    let Json::Array(results) = value(&sent, "results") else {
        panic!("no results")
    };
    assert_eq!(
        results[2].get("reason").and_then(Json::as_str),
        Some("not attempted: tenant lab failed")
    );
}

/// An Exabeam tenant that signs in, then refuses the token on the first
/// rule's first request (a read), has taken nothing: each rule is not
/// attempted, naming the tenant, and Exabeam is not deployed (#1701).
#[test]
fn exabeam_stops_a_tenant_refusing_the_token_on_a_rule() {
    use wiremock::matchers::{method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    let (setup, env) = exabeam_stand(&server, &rt);
    rt.block_on(
        wiremock::Mock::given(method("GET"))
            .and(path("/correlation-rules/v2/rules"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .expect(1)
            .mount(&server),
    );
    let ws = workspace(
        "exabeam",
        "lab",
        &setup,
        &[
            (
                "a.yaml",
                rule(
                    "First rule",
                    "00000000-0000-4000-8099-000000000211",
                    "A.",
                    EXABEAM_BLOCK,
                ),
            ),
            (
                "b.yaml",
                rule(
                    "Second rule",
                    "00000000-0000-4000-8099-000000000212",
                    "B.",
                    EXABEAM_BLOCK,
                ),
            ),
        ],
    );
    let (sent, _) = deploy(
        ws.path(),
        "exabeam",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    rt.block_on(server.verify());
    assert_failed_before_any_rule(&sent, "exabeam", "lab", "");
    assert_tenant_stopped(&sent, "lab");
}

/// A push's environment in GitHub Actions for `ws`.
fn github_push(ws: &Path) -> Vec<(&'static str, String)> {
    vec![
        ("GITHUB_ACTIONS", "true".to_owned()),
        ("GITHUB_EVENT_NAME", "push".to_owned()),
        ("GITHUB_REF", "refs/heads/main".to_owned()),
        ("OPENTIDE_DEFAULT_BRANCH", "main".to_owned()),
        ("GITHUB_SHA", "HEAD".to_owned()),
        ("GITHUB_WORKSPACE", ws.display().to_string()),
    ]
}

/// A rule a RELEASE push promotes but no tenant takes (the tenant accepts
/// PREVIEW only) is not sent: it is reported skipped, with why, never
/// `deployed`, and its file keeps the status it had, so the write-back
/// commits no status that was never deployed (#1653).
#[test]
fn a_promoted_rule_no_tenant_takes_is_skipped_and_keeps_its_status() {
    let uuid = "00000000-0000-4000-8047-000000000911";
    let block = "  splunk:\n    status: STAGING\n    query: index=main\n";
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"token\"\n",
        &[("r.yaml", rule("Unrouted", uuid, "A rule.", block))],
    );
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/splunk.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        text.replace(
            "strategies = [\"PREVIEW\", \"RELEASE\"]",
            "strategies = [\"PREVIEW\"]",
        ),
    )
    .unwrap();
    pushed(ws.path(), "objects/rules/r.yaml");
    let before = std::fs::read(ws.path().join("objects/rules/r.yaml")).unwrap();
    let argv = [
        "--json",
        "deploy",
        "--platform",
        "splunk",
        "--strategy",
        "RELEASE",
    ];
    let (code, out, err) = cli(ws.path(), &argv, &github_push(ws.path()));
    assert_eq!(code, 0, "{out}{err}");
    let document: serde_json::Value = serde_json::from_str(&out).unwrap();
    let results = document["results"].as_array().unwrap();
    assert_eq!(results.len(), 1, "{out}");
    assert_eq!(results[0]["status"], "skipped", "{out}");
    assert_eq!(results[0]["tenant"], serde_json::Value::Null, "{out}");
    assert!(
        results[0]["reason"]
            .as_str()
            .unwrap()
            .contains("no splunk tenant takes its status PRODUCTION"),
        "{out}"
    );
    assert_eq!(
        std::fs::read(ws.path().join("objects/rules/r.yaml")).unwrap(),
        before,
        "the promotion was put back"
    );
}

/// A RELEASE push skipped for want of tenants (`--skip-unconfigured`) sends
/// nothing, so the rules it promoted keep the status they had: the
/// write-back commits no PRODUCTION status for a rule never deployed
/// (#1653, smoke A4).
#[test]
fn a_skipped_push_keeps_the_status_it_would_have_promoted() {
    let ws = tempfile::tempdir().unwrap();
    let platforms = ws.path().join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::write(
        platforms.join("splunk.toml"),
        "[platform]\nenabled = true\nname = \"Stand-in\"\n",
    )
    .unwrap();
    let rules = ws.path().join("objects/rules");
    std::fs::create_dir_all(&rules).unwrap();
    let block = "  splunk:\n    status: STAGING\n    query: index=main\n";
    std::fs::write(
        rules.join("r.yaml"),
        rule(
            "Unconfigured",
            "00000000-0000-4000-8047-000000000912",
            "A rule.",
            block,
        ),
    )
    .unwrap();
    pushed(ws.path(), "objects/rules/r.yaml");
    let before = std::fs::read(rules.join("r.yaml")).unwrap();
    let argv = [
        "--json",
        "deploy",
        "--strategy",
        "RELEASE",
        "--skip-unconfigured",
    ];
    let (code, out, err) = cli(ws.path(), &argv, &github_push(ws.path()));
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("\"status\":\"skipped\""), "{out}");
    assert_eq!(
        std::fs::read(rules.join("r.yaml")).unwrap(),
        before,
        "{err}"
    );
}

/// The dry run of a RELEASE push previews the status promotion the push's
/// deploy makes first (#1653, smoke E13): the changed STAGING rule is
/// planned as promoted, for the tenant that takes RELEASE, with a warning
/// saying so, and nothing is written. It used to say no rule would deploy.
#[test]
fn a_release_pushs_dry_run_plans_the_rules_it_will_promote() {
    let uuid = "00000000-0000-4000-8047-000000000913";
    let block = "  splunk:\n    status: STAGING\n    query: index=main\n";
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"token\"\n",
        &[("r.yaml", rule("Previewed", uuid, "A rule.", block))],
    );
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/splunk.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        text.replace(
            "strategies = [\"PREVIEW\", \"RELEASE\"]",
            "strategies = [\"RELEASE\"]",
        ),
    )
    .unwrap();
    pushed(ws.path(), "objects/rules/r.yaml");
    let before = std::fs::read(ws.path().join("objects/rules/r.yaml")).unwrap();
    let argv = [
        "--json",
        "deploy",
        "--dry-run",
        "--platform",
        "splunk",
        "--strategy",
        "RELEASE",
    ];
    let (code, out, err) = cli(ws.path(), &argv, &github_push(ws.path()));
    assert_eq!(code, 0, "{out}{err}");
    let document: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        document["plan"],
        serde_json::json!({"splunk": [uuid]}),
        "{out}"
    );
    assert!(
        document["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning
                .as_str()
                .unwrap()
                .contains("promotes 1 rule to PRODUCTION first")),
        "{out}"
    );
    // The plan reads the promoted file: its change carries the new status.
    assert_eq!(document["changes"][0]["status"], "PRODUCTION", "{out}");
    assert_eq!(document["changes"][0]["tenant"], "lab", "{out}");
    assert_eq!(
        std::fs::read(ws.path().join("objects/rules/r.yaml")).unwrap(),
        before,
        "a dry run writes nothing"
    );
    // --skip-promotion previews none: nothing in STAGING goes to RELEASE.
    let mut skipped = argv.to_vec();
    skipped.push("--skip-promotion");
    let (code, out, _) = cli(ws.path(), &skipped, &github_push(ws.path()));
    assert_eq!(code, 0, "{out}");
    let document: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(document["plan"].get("splunk").is_none(), "{out}");
}

/// A promoted rule whose tenant the run cannot use (its credential is
/// unset) was sent nowhere: its file is put back, so the write-back commits
/// no status that was never deployed (#1653).
#[test]
fn a_promoted_rule_whose_tenant_fails_keeps_its_status() {
    let block = "  splunk:\n    status: STAGING\n    query: index=main\n";
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"$SPLUNK_TOKEN\"\n",
        &[(
            "r.yaml",
            rule(
                "Unsent",
                "00000000-0000-4000-8047-000000000914",
                "A rule.",
                block,
            ),
        )],
    );
    pushed(ws.path(), "objects/rules/r.yaml");
    let before = std::fs::read(ws.path().join("objects/rules/r.yaml")).unwrap();
    let argv = [
        "--json",
        "deploy",
        "--platform",
        "splunk",
        "--strategy",
        "RELEASE",
    ];
    let (code, out, err) = cli(ws.path(), &argv, &github_push(ws.path()));
    assert_eq!(code, 1, "{out}{err}");
    assert!(out.contains("SPLUNK_TOKEN"), "{out}");
    assert_eq!(
        std::fs::read(ws.path().join("objects/rules/r.yaml")).unwrap(),
        before,
        "the promotion was put back"
    );
}

/// A run that ends before it plans anything puts back what it promoted:
/// `--platform` naming a platform the promoted rule has no block for, and
/// a promoted rule whose only platform is not enabled (#1653).
#[test]
fn a_push_that_plans_nothing_keeps_the_status_it_promoted() {
    for (argv, rule_block) in [
        (
            vec![
                "--json",
                "deploy",
                "--platform",
                "sentinel",
                "--strategy",
                "RELEASE",
            ],
            "  splunk:\n    status: STAGING\n    query: index=main\n",
        ),
        (
            vec!["--json", "deploy", "--strategy", "RELEASE"],
            "  graylog:\n    status: STAGING\n    query: 'EventID:1'\n",
        ),
    ] {
        let ws = workspace(
            "splunk",
            "lab",
            "url = \"splunk.invalid\"\ntoken = \"token\"\n",
            &[(
                "r.yaml",
                rule(
                    "Unplanned",
                    "00000000-0000-4000-8047-000000000915",
                    "A rule.",
                    rule_block,
                ),
            )],
        );
        pushed(ws.path(), "objects/rules/r.yaml");
        let before = std::fs::read(ws.path().join("objects/rules/r.yaml")).unwrap();
        let (code, out, err) = cli(ws.path(), &argv, &github_push(ws.path()));
        assert_eq!(code, 0, "{argv:?}: {out}{err}");
        assert_eq!(
            std::fs::read(ws.path().join("objects/rules/r.yaml")).unwrap(),
            before,
            "{argv:?}: the promotion was put back"
        );
    }
}

/// A dry run whose push's promotion would stop the run (a promotion target
/// that names no status) says so, rather than preview nothing (#1653).
#[test]
fn a_release_pushs_dry_run_warns_of_a_promotion_that_would_stop() {
    let block = "  splunk:\n    status: STAGING\n    query: index=main\n";
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"token\"\n",
        &[(
            "r.yaml",
            rule(
                "Stopping",
                "00000000-0000-4000-8047-000000000916",
                "A rule.",
                block,
            ),
        )],
    );
    std::fs::write(
        ws.path().join(".opentide/configurations/deployment.toml"),
        "[promotion]\nenabled = true\npromotion_target = \"NOWHERE\"\n",
    )
    .unwrap();
    pushed(ws.path(), "objects/rules/r.yaml");
    let argv = [
        "--json",
        "deploy",
        "--dry-run",
        "--platform",
        "splunk",
        "--strategy",
        "RELEASE",
    ];
    let (_, out, err) = cli(ws.path(), &argv, &github_push(ws.path()));
    assert!(
        out.contains("would stop at its status promotion: Invalid promotion target"),
        "{out}{err}"
    );
}

/// The dry run reports a rule no tenant takes as the deploy skips it, with
/// the reason, and previews no promotion for it (#1653).
#[test]
fn a_dry_run_reports_a_rule_no_tenant_takes() {
    let uuid = "00000000-0000-4000-8047-000000000917";
    let block = "  splunk:\n    status: STAGING\n    query: index=main\n    tenants: [other]\n";
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"token\"\n",
        &[("r.yaml", rule("Listed elsewhere", uuid, "A rule.", block))],
    );
    let argv = [
        "--json",
        "deploy",
        "--dry-run",
        "--all",
        "--platform",
        "splunk",
        "--strategy",
        "PREVIEW",
    ];
    let (code, out, err) = cli(ws.path(), &argv, &[]);
    assert_eq!(code, 0, "{out}{err}");
    let document: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(document["changes"], serde_json::json!([]), "{out}");
    assert_eq!(document["unrouted"][0]["uuid"], uuid, "{out}");
    assert!(
        document["unrouted"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("its tenants list names no splunk tenant"),
        "{out}"
    );
}

/// A Splunk stand-in that runs `during` on its first request, then answers
/// each request in turn with `answers`, then `Ok`.
struct HookedSplunk {
    during: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    answers: Mutex<std::collections::VecDeque<Result<(), ConnectorError>>>,
}

impl Deployer for HookedSplunk {
    fn deploy<'a>(
        &'a self,
        _cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        let during = self.during.lock().unwrap().take();
        if let Some(during) = during {
            during();
        }
        let next = self.answers.lock().unwrap().pop_front().unwrap_or(Ok(()));
        deploying(async move { next.map(|()| DeployOutcome::new(None, request.operation)) })
    }
}

/// Registers a [`HookedSplunk`] as `splunk`.
struct Hooked(&'static HookedSplunk);

impl Platform for Hooked {
    fn id(&self) -> &'static str {
        "splunk"
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self.0)
    }
}

/// A RELEASE push in `ws` deployed to Splunk by a [`HookedSplunk`].
fn hooked_push(
    ws: &Path,
    during: Box<dyn FnOnce() + Send>,
    answers: Vec<Result<(), ConnectorError>>,
) -> (Sent, String) {
    let splunk: &'static HookedSplunk = Box::leak(Box::new(HookedSplunk {
        during: Mutex::new(Some(during)),
        answers: Mutex::new(answers.into()),
    }));
    let mut registry = Registry::new();
    registry.register(Box::new(Hooked(splunk))).unwrap();
    let args = Args {
        strategies: vec!["RELEASE".into()],
        platform: Some("splunk".into()),
        ..Args::default()
    };
    let env = Env::from_pairs(
        github_push(ws)
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value)),
    );
    deploy_with(ws, &args, &env, &registry, 0)
}

/// Two promoted rules: `a.yaml`, which the tenant receives, and `b.yaml`,
/// which no tenant takes (it lists another tenant), so its file is put back.
fn sent_and_unsent() -> tempfile::TempDir {
    let block = "  splunk:\n    status: STAGING\n    query: index=main\n";
    let elsewhere = format!("{block}    tenants: [other]\n");
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"token\"\n",
        &[
            (
                "a.yaml",
                rule(
                    "Sent",
                    "00000000-0000-4000-8047-000000000920",
                    "A rule.",
                    block,
                ),
            ),
            (
                "b.yaml",
                rule(
                    "Unsent",
                    "00000000-0000-4000-8047-000000000921",
                    "A rule.",
                    &elsewhere,
                ),
            ),
        ],
    );
    pushed_files(ws.path(), &["objects/rules/a.yaml", "objects/rules/b.yaml"]);
    ws
}

fn text_of(json: &Json) -> String {
    match json {
        Json::Str(text) => text.clone(),
        other => format!("{other:?}"),
    }
}

/// A promoted file the run cannot put back fails the run (exit 1), naming
/// the file: its commit would carry a status no tenant received (#1653).
/// The rules folder is made read-only while the rule is sent; a privileged
/// user writes there all the same, and the test then has nothing to show.
#[test]
fn a_promotion_the_run_cannot_undo_fails_the_run() {
    use std::os::unix::fs::PermissionsExt as _;
    let ws = sent_and_unsent();
    let rules = ws.path().join("objects/rules");
    let mode = |bits| std::fs::set_permissions(&rules, std::fs::Permissions::from_mode(bits));
    mode(0o555).unwrap();
    let privileged = std::fs::write(rules.join("probe"), "").is_ok();
    mode(0o755).unwrap();
    if privileged {
        eprintln!("skipped: this user writes a read-only folder");
        return;
    }
    let shut = rules.clone();
    let (sent, text) = hooked_push(
        ws.path(),
        Box::new(move || {
            std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o555)).unwrap();
        }),
        Vec::new(),
    );
    mode(0o755).unwrap();
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(1), "{text}");
    assert_eq!(value(&sent, "status"), &Json::str("failed"), "{text}");
    let message = text_of(value(&sent, "message"));
    assert!(
        message.contains("Could not undo the status promotion of") && message.contains("b.yaml"),
        "{message}"
    );
    let Json::Array(failures) = value(&sent, "failures") else {
        panic!("{:?}", sent.result)
    };
    assert!(
        failures.iter().any(|failure| failure
            .get("path")
            .and_then(Json::as_str)
            .is_some_and(|path| path.ends_with("b.yaml"))),
        "{failures:?}"
    );
    for file in ["a.yaml", "b.yaml"] {
        let now = std::fs::read_to_string(rules.join(file)).unwrap();
        assert!(now.contains("status: PRODUCTION"), "{file}: {now}");
    }
}

/// A promoted file edited or deleted while the run sends is left as it is:
/// the run never overwrites an edit, nor makes a deleted file again
/// (#1653). An edited file fails the run (exit 1), since the write-back
/// would commit a status no tenant received; a deleted one is a warning.
#[test]
fn a_promoted_file_changed_during_the_run_is_left_as_it_is() {
    for deleted in [false, true] {
        let ws = sent_and_unsent();
        let unsent = ws.path().join("objects/rules/b.yaml");
        let touched = unsent.clone();
        let (sent, text) = hooked_push(
            ws.path(),
            Box::new(move || {
                if deleted {
                    std::fs::remove_file(&touched).unwrap();
                } else {
                    let mut file = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&touched)
                        .unwrap();
                    file.write_all(b"# edited\n").unwrap();
                }
            }),
            Vec::new(),
        );
        if deleted {
            assert_eq!(value(&sent, "_exit_code"), &Json::Int(0), "{text}");
            let Json::Array(warnings) = value(&sent, "warnings") else {
                panic!("{:?}", sent.result)
            };
            assert!(
                warnings.iter().any(|warning| {
                    let warning = text_of(warning);
                    warning.contains("was deleted during the deploy") && warning.contains("b.yaml")
                }),
                "{warnings:?}"
            );
            assert!(!unsent.exists(), "the deleted file was made again");
        } else {
            assert_eq!(value(&sent, "_exit_code"), &Json::Int(1), "{text}");
            let message = text_of(value(&sent, "message"));
            assert!(
                message.contains("b.yaml") && message.contains("changed during the deploy"),
                "{message}"
            );
            let now = std::fs::read_to_string(&unsent).unwrap();
            assert!(now.ends_with("# edited\n"), "{now}");
        }
    }
}

/// A rule that reached one tenant and failed on another was deployed: its
/// file stays promoted, and `deploy --uuid` sends it again (#1653).
#[test]
fn a_promoted_rule_that_reached_one_tenant_of_two_stays_promoted() {
    let block = "  splunk:\n    status: STAGING\n    query: index=main\n";
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"token\"\n",
        &[(
            "r.yaml",
            rule(
                "Partial",
                "00000000-0000-4000-8047-000000000922",
                "A rule.",
                block,
            ),
        )],
    );
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/splunk.toml");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(
        "\n[[tenants]]\nname = \"backup\"\nstrategies = [\"PREVIEW\", \"RELEASE\"]\n\
         [tenants.setup]\nurl = \"backup.invalid\"\ntoken = \"token\"\n",
    );
    std::fs::write(&config, text).unwrap();
    pushed(ws.path(), "objects/rules/r.yaml");
    let (sent, text) = hooked_push(
        ws.path(),
        Box::new(|| {}),
        vec![
            Ok(()),
            Err(ConnectorError::refused(
                "splunk",
                "backup",
                "POST https://x failed with HTTP 400 Bad Request: no",
                None,
            )),
        ],
    );
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(1), "{text}");
    let mut statuses: Vec<String> = rows(&sent).into_iter().map(|(status, _)| status).collect();
    statuses.sort();
    assert_eq!(statuses, ["deployed", "failed"], "{text}");
    let now = std::fs::read_to_string(ws.path().join("objects/rules/r.yaml")).unwrap();
    assert!(now.contains("status: PRODUCTION"), "{now}");
}

/// A `--platform` run (not a dry run) with no rule of its strategies counts
/// only its own platform's left-out rules, and names its strategies in its
/// advice, never "this run" (#1662, D11): the result names the platform,
/// not the strategies.
#[test]
fn a_platform_run_with_nothing_to_deploy_names_its_strategies() {
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\nport = 8089\napp = \"search\"\ntoken = \"$SPLUNK_TOKEN\"\n",
        &[(
            "production.yaml",
            rule(
                "Production rule",
                "00000000-0000-4000-8046-000000000401",
                "A rule in production.",
                "  splunk:\n    status: PRODUCTION\n    query: index=main\n",
            ),
        )],
    );
    // Another platform's left-out rule, which a `--platform splunk` run does
    // not count (#1662, D11).
    std::fs::write(
        ws.path()
            .join(".opentide/configurations/platforms/sentinel.toml"),
        "[platform]\nenabled = true\n",
    )
    .unwrap();
    std::fs::write(
        ws.path().join("objects/rules/sentinel.yaml"),
        rule(
            "Sentinel production rule",
            "00000000-0000-4000-8046-000000000402",
            "Another platform's rule.",
            "  sentinel:\n    status: PRODUCTION\n    query: SecurityEvent\n",
        ),
    )
    .unwrap();
    let args = Args {
        strategies: vec!["PREVIEW".into()],
        all: true,
        platform: Some("splunk".to_owned()),
        ..Args::default()
    };
    let (sent, _) = deploy_with(
        ws.path(),
        &args,
        &Env::from_pairs::<&str, &str>([]),
        &Registry::new(),
        0,
    );
    assert_eq!(value(&sent, "status"), &Json::str("skipped"));
    let Json::Str(advice) = value(&sent, "advice") else {
        panic!("advice")
    };
    assert!(
        advice.starts_with("set a platform block's status to ")
            && advice.ends_with(" for PREVIEW to deploy it"),
        "{advice}"
    );
    assert_eq!(
        value(&sent, "_outcome"),
        &Json::str("No rule has a status PREVIEW deploys · 1 rule in PRODUCTION")
    );
    let Json::Array(skipped) = value(&sent, "skipped") else {
        panic!("skipped")
    };
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    assert_eq!(skipped[0].get("platform"), Some(&Json::str("splunk")));
}

/// A setup of one platform's tenant whose credential is `credential` (a
/// `$NAME`) and whose every address is `address`.
type Setup = fn(credential: &str, address: &str) -> String;

/// A platform, its tenant setup and the rule files (name, text) it deploys.
type Case = (&'static str, Setup, Vec<(String, String)>);

/// Each platform's tenant setup and one rule it deploys, for
/// `a_tenant_failing_before_any_rule_leaves_each_of_its_rules_not_attempted`.
#[expect(clippy::too_many_lines, reason = "one row per platform, as a table")]
fn first_request_cases() -> Vec<Case> {
    let fixture = |file: &str| {
        let text = std::fs::read_to_string(repo().join(format!(
            "tests/golden/fixtures/deploy-tenants/objects/rules/{file}"
        )))
        .unwrap();
        vec![(file.to_owned(), text)]
    };
    let own = |platform: &str, block: &str| {
        vec![(
            format!("{platform}.yaml"),
            rule(
                &format!("{platform} rule"),
                "00000000-0000-4000-8099-000000000901",
                "A rule.",
                block,
            ),
        )]
    };
    let secops = std::fs::read_to_string(
        repo().join("tests/fixtures/google_secops/rule-google-secops-process-1.0.yaml"),
    )
    .unwrap();
    vec![
        (
            "sentinel",
            |credential, _| SENTINEL_SETUP.replace("$AZURE_CLIENT_SECRET", credential),
            fixture("sentinel-a-create.yaml"),
        ),
        (
            "microsoft_defender",
            |credential, _| {
                format!("tenant_id = \"t\"\nclient_id = \"c\"\nclient_secret = \"{credential}\"\n")
            },
            fixture("microsoft-defender-a-create.yaml"),
        ),
        (
            "splunk",
            |credential, _| format!("url = \"127.0.0.1\"\nport = 9\ntoken = \"{credential}\"\n"),
            fixture("splunk-a-create.yaml"),
        ),
        (
            "sentinel_one",
            |credential, address| {
                format!("url = \"{address}\"\naccount_id = 1001\napi_token = \"{credential}\"\n")
            },
            fixture("sentinel-one-a-create.yaml"),
        ),
        (
            "crowdstrike",
            |credential, _| {
                format!("api = \"EU-1\"\nclient_id = \"c\"\nclient_secret = \"{credential}\"\n")
            },
            fixture("crowdstrike-a-create.yaml"),
        ),
        (
            "harfanglab",
            |credential, address| {
                format!("url = \"{address}\"\napi_token = \"{credential}\"\nsource_id = \"s\"\n")
            },
            fixture("harfanglab-a-sigma.yaml"),
        ),
        (
            "carbon_black_cloud",
            |credential, address| {
                format!(
                    "url = \"{address}\"\norg_key = \"ORG\"\ntoken = \"{credential}\"\nwatchlist \
                     = \"opentide\"\n"
                )
            },
            own(
                "carbon_black_cloud",
                "  carbon_black_cloud:\n    status: STAGING\n    query: process_name:cmd.exe\n",
            ),
        ),
        (
            "elastic",
            |credential, address| {
                format!(
                    "url = \"{address}\"\nelasticsearch_url = \"{address}\"\napi_key = \
                     \"{credential}\"\nindex = [\"logs-*\"]\n"
                )
            },
            fixture("elastic-a-create.yaml"),
        ),
        (
            "sysdig",
            |credential, address| {
                format!("url = \"{address}\"\napi_token = \"{credential}\"\npolicies = [\"p\"]\n")
            },
            fixture("sysdig-a-create.yaml"),
        ),
        (
            "bitdefender",
            |credential, address| format!("url = \"{address}\"\napi_key = \"{credential}\"\n"),
            own("bitdefender", &bitdefender_block(false)),
        ),
        (
            "graylog",
            |credential, address| format!("url = \"{address}\"\ntoken = \"{credential}\"\n"),
            own("graylog", &graylog_block("STAGING", "EventID:1")),
        ),
        (
            "exabeam",
            |credential, address| {
                format!(
                    "region = \"eu\"\nclient_id = \"c\"\nclient_secret = \"{credential}\"\napi_url \
                     = \"{address}/\"\n"
                )
            },
            own("exabeam", EXABEAM_BLOCK),
        ),
        (
            "google_secops",
            // The unset tenant names its credentials; the unreachable one
            // takes Application Default Credentials, whose token endpoint
            // is unreachable too.
            |credential, address| {
                let credentials = if credential.contains("UNSET") {
                    format!("credentials = \"{credential}\"\n")
                } else {
                    String::new()
                };
                format!(
                    "project = \"p\"\nlocation = \"eu\"\ninstance = \"i\"\nendpoint = \
                     \"{address}\"\n{credentials}"
                )
            },
            vec![("process.yaml".to_owned(), secops)],
        ),
    ]
}

/// A workspace whose `platform` has two tenants of `setup` at `address`:
/// `unset`, whose credential variable is unset, and `unreachable`, whose
/// credential is set; and the rule files `rules`.
fn two_failing_tenants(
    platform: &str,
    setup: Setup,
    rules: &[(String, String)],
    address: &str,
) -> tempfile::TempDir {
    let ws = tempfile::tempdir().unwrap();
    let platforms = ws.path().join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    let tenant = |name: &str, credential: &str| {
        format!(
            "[[tenants]]\nname = \"{name}\"\nstrategies = [\"PREVIEW\", \"RELEASE\"]\n\
             [tenants.setup]\n{}\n",
            setup(credential, address)
        )
    };
    std::fs::write(
        platforms.join(format!("{platform}.toml")),
        format!(
            "[platform]\nenabled = true\nname = \"Stand-in\"\n\n{}{}",
            tenant("unset", "$OPENTIDE_TEST_UNSET"),
            tenant("unreachable", "$OPENTIDE_TEST_SECRET"),
        ),
    )
    .unwrap();
    let dir = ws.path().join("objects/rules");
    std::fs::create_dir_all(&dir).unwrap();
    for (file, text) in rules {
        std::fs::write(dir.join(file), text).unwrap();
    }
    ws
}

/// A tenant that fails before any rule is sent to it, whatever the
/// platform: its credential variable unset, or the tenant unreachable
/// (every connection refused, through a proxy that is not there). Each of
/// its rules is `not attempted`, the failure is the tenant's (no rule
/// failed, so the code is not `issues_found`), the platform's next tenant is
/// tried all the same, and the run exits 1 (#1701, smoke D7). On ten
/// platforms the first rule used to be `failed` instead, and Bitdefender
/// went on to its next rule after an unset credential.
#[test]
fn a_tenant_failing_before_any_rule_leaves_each_of_its_rules_not_attempted() {
    let dead = "http://127.0.0.1:9".to_owned();
    let address = "https://127.0.0.1:9";
    let mut failed = Vec::new();
    for (platform, setup, rules) in first_request_cases() {
        let ws = two_failing_tenants(platform, setup, &rules, address);
        let adc = ws.path().join("adc.json");
        std::fs::write(
            &adc,
            format!(
                r#"{{"type": "authorized_user", "client_id": "c", "client_secret": "s",
                    "refresh_token": "r", "token_uri": "{address}/token"}}"#
            ),
        )
        .unwrap();
        let env = [
            ("OPENTIDE_TEST_SECRET", SECRET.to_owned()),
            ("GOOGLE_APPLICATION_CREDENTIALS", adc.display().to_string()),
            ("HTTPS_PROXY", dead.clone()),
            ("HTTP_PROXY", dead.clone()),
            ("ALL_PROXY", dead.clone()),
        ];
        let argv = [
            "--json",
            "deploy",
            "--platform",
            platform,
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
            "--keep-deprecated",
        ];
        let (code, out, err) = cli(ws.path(), &argv, &env);
        // Each platform is checked, then every one that failed is named.
        let checked = std::panic::catch_unwind(|| {
            assert_eq!(code, 1, "{platform}: {out}{err}");
            let document: serde_json::Value = serde_json::from_str(&out)
                .unwrap_or_else(|error| panic!("{platform}: {error}: {out}{err}"));
            let results = document["results"].as_array().unwrap();
            assert_eq!(results.len(), 2 * rules.len(), "{platform}: {out}");
            for row in results {
                let tenant = row["tenant"].as_str().unwrap();
                assert_eq!(row["status"], "not_attempted", "{platform}: {out}");
                assert_eq!(
                    row["reason"],
                    format!("not attempted: tenant {tenant} failed").as_str(),
                    "{platform}: {out}"
                );
            }
            let failures = document["failures"].as_array().unwrap();
            let tenants: Vec<&str> = failures
                .iter()
                .map(|failure| failure["tenant"].as_str().unwrap())
                .collect();
            assert_eq!(tenants, ["unset", "unreachable"], "{platform}: {out}");
            for failure in failures {
                assert_eq!(failure["platform"], platform, "{platform}: {out}");
                assert!(failure.get("id").is_none(), "{platform}: {out}");
            }
            assert!(
                failures[0]["error"]
                    .as_str()
                    .unwrap()
                    .contains("OPENTIDE_TEST_UNSET"),
                "{platform}: {out}"
            );
            assert_eq!(document["status"], "failed", "{platform}: {out}");
            assert_eq!(document["exit_code"], 1, "{platform}: {out}");
            assert_eq!(
                document["failure"]["code"], "command_failed",
                "{platform}: {out}"
            );
            assert_eq!(document["summary"]["failed"], 0, "{platform}: {out}");
            assert_eq!(
                document["summary"]["not_attempted"],
                2 * rules.len(),
                "{platform}: {out}"
            );
            assert_eq!(
                document["deployed"],
                serde_json::json!([]),
                "{platform}: {out}"
            );
        });
        if checked.is_err() {
            failed.push(platform);
        }
    }
    assert!(failed.is_empty(), "failed on {failed:?}");
}

/// A HarfangLab tenant that refuses the API token (401) on its first
/// request fails before any rule was sent: each rule is not attempted and
/// nothing more is sent to it. A 401 was the rule's refusal, so every rule
/// was sent and failed in turn (#1701).
#[test]
fn harfanglab_stops_a_tenant_refusing_the_token_before_any_rule() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(
                wiremock::ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"detail": "Invalid token."})),
            )
            .expect(1)
            .mount(&server),
    );
    let setup = format!(
        "url = \"{}\"\napi_token = \"$HARFANGLAB_API_TOKEN\"\nsource_id = \"s\"\n",
        server.uri()
    );
    let fixture = |file: &str| {
        std::fs::read_to_string(repo().join(format!(
            "tests/golden/fixtures/deploy-tenants/objects/rules/{file}"
        )))
        .unwrap()
    };
    let ws = workspace(
        "harfanglab",
        "lab",
        &setup,
        &[
            ("a.yaml", fixture("harfanglab-a-sigma.yaml")),
            ("b.yaml", fixture("harfanglab-b-yara.yaml")),
        ],
    );
    let env = Env::from_pairs([("HARFANGLAB_API_TOKEN".to_owned(), "token".to_owned())]);
    let (sent, _) = deploy(
        ws.path(),
        "harfanglab",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    rt.block_on(server.verify());
    assert_eq!(rows(&sent).len(), 2, "{:?}", rows(&sent));
    assert_failed_before_any_rule(
        &sent,
        "harfanglab",
        "lab",
        "harfanglab tenant 'lab': HarfangLab tenant lab refused the API token (HTTP 401)",
    );
}

/// A stand-in Kibana that keeps the rules written to it: a lookup answers
/// the rule as last written, with the fields Kibana adds itself (its id,
/// times, revision, empty defaults); each create or replace is counted.
#[derive(Clone, Default)]
struct KeepingKibana {
    rules: Arc<Mutex<std::collections::HashMap<String, serde_json::Value>>>,
    writes: Arc<Mutex<Vec<String>>>,
}

impl wiremock::Respond for KeepingKibana {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        let rule_id = request
            .url
            .query_pairs()
            .find(|(key, _)| key == "rule_id")
            .map(|(_, value)| value.into_owned());
        let mut rules = self.rules.lock().unwrap();
        match request.method.as_str() {
            "GET" => match rule_id.and_then(|id| rules.get(&id).cloned()) {
                Some(rule) => wiremock::ResponseTemplate::new(200).set_body_json(rule),
                None => wiremock::ResponseTemplate::new(404),
            },
            method @ ("POST" | "PUT") => {
                let mut rule: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let id = rule["rule_id"].as_str().unwrap().to_owned();
                let revision = rules
                    .get(&id)
                    .map_or(0, |held| held["revision"].as_i64().unwrap() + 1);
                let added = serde_json::json!({
                    "id": "kb-1", "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": format!("2026-01-01T00:00:{revision:02}Z"),
                    "revision": revision, "version": revision + 1, "immutable": false,
                    "rule_source": {"type": "internal"}, "max_signals": 100,
                    "references": [], "false_positives": [], "risk_score_mapping": [],
                    "severity_mapping": [], "exceptions_list": [], "actions": [],
                });
                for (key, value) in added.as_object().unwrap() {
                    rule.as_object_mut()
                        .unwrap()
                        .entry(key.clone())
                        .or_insert(value.clone());
                }
                self.writes.lock().unwrap().push(format!("{method} {id}"));
                rules.insert(id, rule.clone());
                wiremock::ResponseTemplate::new(200).set_body_json(rule)
            }
            _ => wiremock::ResponseTemplate::new(405),
        }
    }
}

/// `opentide --json deploy --platform elastic` in `ws`: the document.
fn elastic_json(ws: &Path) -> serde_json::Value {
    let (code, out, err) = cli(
        ws,
        &[
            "--json",
            "deploy",
            "--platform",
            "elastic",
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
            "--keep-deprecated",
        ],
        &[("ELASTIC_API_KEY", "key".to_owned())],
    );
    assert_eq!(code, 0, "{out}{err}");
    serde_json::from_str(&out).unwrap()
}

/// Deploying again with nothing changed writes nothing (#1711, smoke E10):
/// Kibana already holds each rule as a replace would write it, so each is
/// reported `unchanged`, in its row, the summary and the outcome line. A
/// rule whose block changed is still replaced.
#[test]
fn a_redeploy_with_nothing_changed_writes_nothing_and_reports_unchanged() {
    use wiremock::matchers::{path, path_regex};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    let kibana = KeepingKibana::default();
    rt.block_on(async {
        wiremock::Mock::given(path_regex("/_field_caps$"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"indices": ["logs-1"], "fields": {}})),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(path("/api/detection_engine/rules"))
            .respond_with(kibana.clone())
            .mount(&server)
            .await;
    });
    let (first, second) = (
        "00000000-0000-4000-8099-000000000161",
        "00000000-0000-4000-8099-000000000162",
    );
    let ws = elastic_workspace(
        &server.uri(),
        &[
            ("a.yaml", "First rule", first, elastic_block("STAGING", "")),
            (
                "b.yaml",
                "Second rule",
                second,
                elastic_block("STAGING", ""),
            ),
        ],
    );
    let created = elastic_json(ws.path());
    assert_eq!(created["summary"]["create"], 2, "{created}");
    assert_eq!(kibana.writes.lock().unwrap().len(), 2);

    // Nothing changed: nothing is written.
    let again = elastic_json(ws.path());
    assert_eq!(kibana.writes.lock().unwrap().len(), 2, "{again}");
    for row in again["results"].as_array().unwrap() {
        assert_eq!(row["status"], "deployed", "{again}");
        assert_eq!(row["action"], "unchanged", "{again}");
    }
    assert_eq!(again["summary"]["unchanged"], 2, "{again}");
    assert_eq!(again["summary"]["update"], 0, "{again}");
    assert!(
        again["message"]
            .as_str()
            .unwrap()
            .contains("2 unchanged · 0 failed, 0 not attempted"),
        "{again}"
    );
    let (code, _, err) = cli(
        ws.path(),
        &[
            "deploy",
            "--platform",
            "elastic",
            "--strategy",
            "PREVIEW",
            "--all",
        ],
        &[("ELASTIC_API_KEY", "key".to_owned())],
    );
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("✓ unchanged First rule"), "{err}");
    assert_eq!(kibana.writes.lock().unwrap().len(), 2, "{err}");

    // A changed query is replaced; the other rule is still unchanged.
    let file = ws.path().join("objects/rules/a.yaml");
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, text.replace("cmd.exe", "powershell.exe")).unwrap();
    let changed = elastic_json(ws.path());
    assert_eq!(
        *kibana.writes.lock().unwrap(),
        [
            format!("POST {first}"),
            format!("POST {second}"),
            format!("PUT {first}")
        ],
        "{changed}"
    );
    assert_eq!(changed["summary"]["update"], 1, "{changed}");
    assert_eq!(changed["summary"]["unchanged"], 1, "{changed}");
}

/// A tenant that fails on the lookup that decides whether a rule is already
/// there follows #1701's rule: a lookup is a read, so it is not a rule sent.
/// When it is the first rule's, nothing was sent: every rule is `not
/// attempted`, the tenant is failed and the run exits 1. When an earlier
/// rule was looked up and found unchanged, the tenant was in use: that rule
/// is `unchanged`, the one whose lookup failed is `failed`, the rest are not
/// attempted.
#[test]
fn a_tenant_failing_the_unchanged_lookup_follows_the_failure_before_any_rule() {
    use wiremock::matchers::{method, path, path_regex, query_param};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    let kibana = KeepingKibana::default();
    rt.block_on(async {
        wiremock::Mock::given(path_regex("/_field_caps$"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"indices": ["logs-1"], "fields": {}})),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(path("/api/detection_engine/rules"))
            .respond_with(kibana.clone())
            .mount(&server)
            .await;
    });
    let uuids = [
        "00000000-0000-4000-8099-000000000171",
        "00000000-0000-4000-8099-000000000172",
        "00000000-0000-4000-8099-000000000173",
    ];
    let ws = elastic_workspace(
        &server.uri(),
        &[
            (
                "a.yaml",
                "First rule",
                uuids[0],
                elastic_block("STAGING", ""),
            ),
            (
                "b.yaml",
                "Second rule",
                uuids[1],
                elastic_block("STAGING", ""),
            ),
            (
                "c.yaml",
                "Third rule",
                uuids[2],
                elastic_block("STAGING", ""),
            ),
        ],
    );
    // Kibana holds the three rules.
    let created = elastic_json(ws.path());
    assert_eq!(created["summary"]["create"], 3, "{created}");
    let writes = kibana.writes.lock().unwrap().len();
    let env = Env::from_pairs([("ELASTIC_API_KEY".to_owned(), "key".to_owned())]);

    // The first rule's lookup fails: nothing was sent.
    rt.block_on(
        wiremock::Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules"))
            .and(query_param("rule_id", uuids[0]))
            .respond_with(wiremock::ResponseTemplate::new(503).set_body_string("<html>down</html>"))
            .with_priority(1)
            .mount(&server),
    );
    let (sent, text) = deploy(
        ws.path(),
        "elastic",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    let statuses: Vec<String> = rows(&sent).into_iter().map(|(status, _)| status).collect();
    assert_eq!(statuses, ["not_attempted"; 3], "{text}");
    assert_failed_before_any_rule(&sent, "elastic", "lab", "");
    assert_eq!(kibana.writes.lock().unwrap().len(), writes, "{text}");

    // The second rule's lookup fails after the first was found unchanged.
    rt.block_on(server.reset());
    rt.block_on(async {
        wiremock::Mock::given(path_regex("/_field_caps$"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"indices": ["logs-1"], "fields": {}})),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(path("/api/detection_engine/rules"))
            .respond_with(kibana.clone())
            .mount(&server)
            .await;
        wiremock::Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules"))
            .and(query_param("rule_id", uuids[1]))
            .respond_with(wiremock::ResponseTemplate::new(503).set_body_string("<html>down</html>"))
            .with_priority(1)
            .mount(&server)
            .await;
    });
    let (sent, text) = deploy(
        ws.path(),
        "elastic",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    let statuses: Vec<String> = rows(&sent).into_iter().map(|(status, _)| status).collect();
    assert_eq!(statuses, ["deployed", "failed", "not_attempted"], "{text}");
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(1));
    assert_eq!(kibana.writes.lock().unwrap().len(), writes, "{text}");
}

/// A Splunk deployer that keeps the body of each request it receives.
struct Recording(Mutex<Vec<Vec<u8>>>);

impl Deployer for Recording {
    fn deploy<'a>(
        &'a self,
        _cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        self.0.lock().unwrap().push(request.body.clone());
        deploying(async move { Ok(DeployOutcome::new(None, request.operation)) })
    }
}

/// [`Recording`] registered as the Splunk platform.
struct Recorded(&'static Recording);

impl Platform for Recorded {
    fn id(&self) -> &'static str {
        "splunk"
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self.0)
    }
}

/// A Splunk rule whose schedule opentide draws (a daily frequency, no
/// custom time) gets the same minute and hour on every deploy, from its
/// UUID, so a redeploy of the same rule sends the same settings and the
/// tenant can hold it unchanged (#1711). It was drawn at random each run.
#[test]
fn a_drawn_splunk_schedule_is_the_same_on_every_deploy() {
    let block = "  splunk:\n    status: STAGING\n    query: index=main\n    scheduling:\n      \
                 schedule:\n        frequency: 1d\n";
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"$SPLUNK_TOKEN\"\n",
        &three_rules(block),
    );
    let recording: &'static Recording = Box::leak(Box::new(Recording(Mutex::new(Vec::new()))));
    let mut registry = Registry::new();
    registry.register(Box::new(Recorded(recording))).unwrap();
    let env = Env::from_pairs([("SPLUNK_TOKEN", SECRET)]);
    let cron = |body: &[u8]| -> String {
        let settings: serde_json::Value = serde_json::from_slice(body).unwrap();
        settings["cron_schedule"].as_str().unwrap().to_owned()
    };
    deploy(ws.path(), "splunk", &env, &registry, 0);
    deploy(ws.path(), "splunk", &env, &registry, 3600 * 7 + 60 * 13);
    let bodies = recording.0.lock().unwrap().clone();
    assert_eq!(bodies.len(), 6);
    let mut crons = std::collections::BTreeSet::new();
    for rule in 0..3 {
        assert_eq!(bodies[rule], bodies[rule + 3], "rule {rule}");
        let cron = cron(&bodies[rule]);
        assert!(cron.ends_with(" */1 * *"), "{cron}");
        crons.insert(cron);
    }
    // The three UUIDs differ only in their last byte, and still get three
    // schedules: the whole UUID is hashed.
    assert_eq!(crons.len(), 3, "{crons:?}");
}

// #1712: a dry run's `api_request` is the requests a deploy sends. For each
// platform whose writes are built from the tenant, the dry run of a
// workspace is held to what the tenant's stand-in receives when the same
// workspace deploys: the recorded cassettes of the `send-*` golden cases (or
// the connector's own), or a wiremock tenant.

/// A copy of the golden fixture `name` (`tests/golden/fixtures/<name>`).
fn fixture(name: &str) -> tempfile::TempDir {
    fn copy(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }
    let dir = tempfile::tempdir().unwrap();
    copy(&repo().join("tests/golden/fixtures").join(name), dir.path());
    dir
}

/// Every write `deploy --dry-run --json` shows for `platform` in `ws`, rule
/// after rule, each `{"method", "url", "body"}`, members in their order; each
/// entry names the tenant `lab`.
fn planned_writes(ws: &Path, platform: &str) -> Vec<Json> {
    let (code, stdout, stderr) = cli(
        ws,
        &[
            "--json",
            "deploy",
            "--dry-run",
            "--platform",
            platform,
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
            "--keep-deprecated",
        ],
        &[],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let document = Json::parse(&stdout).unwrap();
    let result = document.get("result").unwrap_or(&document);
    let mut writes = Vec::new();
    for entry in result
        .get("payloads")
        .and_then(|payloads| payloads.get(platform))
        .and_then(Json::as_array)
        .unwrap()
    {
        let Some(requests) = entry.get("api_request").and_then(Json::as_array) else {
            panic!("api_request is not the requests: {}", entry.to_compact())
        };
        assert_eq!(
            entry.get("tenant").and_then(Json::as_str),
            Some("lab"),
            "{}",
            entry.to_compact()
        );
        writes.extend(requests.iter().cloned());
    }
    writes
}

/// `url` cut in two: its scheme and authority (`https://host:port`, empty
/// for a relative URL), and the rest, as written.
fn url_parts(url: &str) -> (&str, &str) {
    let Some(scheme) = url.find("://") else {
        return ("", url);
    };
    let after = &url[scheme + 3..];
    let at = scheme + 3 + after.find('/').unwrap_or(after.len());
    (&url[..at], &url[at..])
}

/// Whether `shown`, a write's `url`, is `url`, a request's, character for
/// character: the scheme and authority (any, for a request a local stand-in
/// received), then the path, its trailing slash and percent-encoding, and
/// the query, a `<tenant-read:NAME>` placeholder standing for one path
/// segment.
fn same_url(shown: &str, url: &str) -> bool {
    let (shown_authority, shown) = url_parts(shown);
    let (authority, url) = url_parts(url);
    let stand_in = ["://localhost", "://127.0.0.1"]
        .iter()
        .any(|local| authority.contains(local));
    if shown_authority.is_empty() || (shown_authority != authority && !stand_in) {
        return false;
    }
    let Some(at) = shown.find("<tenant-read:") else {
        return shown == url;
    };
    let (head, tail) = (&shown[..at], &shown[at..]);
    let tail = tail.find('>').map_or("", |end| &tail[end + 1..]);
    let Some(rest) = url.strip_prefix(head) else {
        return false;
    };
    let segment = rest.find('/').unwrap_or(rest.len());
    segment > 0 && &rest[segment..] == tail
}

#[test]
fn a_shown_url_is_the_whole_url_sent() {
    let sent = "https://splunk.invalid:8089/servicesNS/nobody/search/saved/searches/A%20b";
    assert!(same_url(sent, sent));
    // Not the path's end, nor the name as written, nor without its slash.
    assert!(!same_url("saved/searches/A b", sent));
    assert!(!same_url(
        "https://splunk.invalid:8089/servicesNS/nobody/search/saved/searches/A b",
        sent
    ));
    assert!(!same_url(
        "https://splunk.invalid:8089/servicesNS/nobody/search/saved/searches",
        "https://splunk.invalid:8089/servicesNS/nobody/search/saved/searches/"
    ));
    assert!(!same_url(
        "https://other.invalid:8089/servicesNS/nobody/search/saved/searches/A%20b",
        sent
    ));
    let org = "https://cbc.invalid/threathunter/watchlistmgr/v3/orgs/K";
    assert!(same_url(
        &format!("{org}/watchlists/<tenant-read:watchlist_id>"),
        &format!("{org}/watchlists/w-1")
    ));
    assert!(!same_url(
        "/threathunter/watchlistmgr/v3/orgs/K/watchlists/<tenant-read:watchlist_id>",
        &format!("{org}/watchlists/w-1")
    ));
}

/// A value as a Splunk form sends it (`json_text`).
fn form_text(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => other.to_compact(),
    }
}

/// Whether `shown`, a write's body, is `body`, a request's: the same JSON,
/// `<send-time:timestamp>` read as `now` and a `<tenant-read:NAME>` body
/// standing for any; or, for a form (Splunk), the same pairs in order.
fn same_body(shown: &Json, body: &[u8], now: i64) -> bool {
    if shown
        .as_str()
        .is_some_and(|text| text.starts_with("<tenant-read:"))
    {
        return !body.is_empty();
    }
    if shown.is_null() {
        return body.is_empty();
    }
    if let Ok(sent) = Json::parse(&String::from_utf8_lossy(body)) {
        let mut shown = shown.clone();
        if let Some(stamp) = shown.get_mut("timestamp")
            && stamp.as_str() == Some("<send-time:timestamp>")
        {
            *stamp = Json::Int(now);
        }
        return shown == sent;
    }
    let Some(fields) = shown.as_object() else {
        return false;
    };
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let expected: Vec<(String, String)> = fields
        .iter()
        .map(|(key, value)| (key.clone(), form_text(value)))
        .collect();
    pairs == expected
}

/// A request a tenant received: method, URL and body.
type Received = (String, String, Vec<u8>);

/// The writes a tenant received (every request but reads and sign-ins), as
/// `(method, url, body)`.
fn received_writes(requests: Vec<Received>) -> Vec<Received> {
    requests
        .into_iter()
        .filter(|(method, url, _)| method != "GET" && !url.contains("/oauth2/"))
        .collect()
}

/// The dry run's writes are the writes the tenant received, in order.
fn assert_sent_as_planned(planned: &[Json], received: &[Received], now: i64) {
    let shown: Vec<String> = planned.iter().map(Json::to_compact).collect();
    let sent: Vec<String> = received
        .iter()
        .map(|(method, url, body)| format!("{method} {url} {}", String::from_utf8_lossy(body)))
        .collect();
    assert_eq!(
        planned.len(),
        received.len(),
        "planned:\n{}\nreceived:\n{}",
        shown.join("\n"),
        sent.join("\n")
    );
    for (write, (method, url, body)) in planned.iter().zip(received) {
        let shown = write.to_compact();
        let text = |key: &str| write.get(key).and_then(Json::as_str).unwrap_or_default();
        assert_eq!(text("method"), method.as_str(), "{shown}\n{url}");
        assert!(same_url(text("url"), url), "{shown}\n{url}");
        assert!(
            same_body(write.get("body").unwrap_or(&Json::Null), body, now),
            "{shown}\nreceived: {}",
            String::from_utf8_lossy(body)
        );
    }
}

/// The requests a replaying proxy received.
fn replayed(proxy: &Proxy) -> Vec<Received> {
    proxy
        .requests()
        .into_iter()
        .map(|request| (request.method, request.url, request.body.bytes()))
        .collect()
}

/// Runs the `send-<platform>` golden case's deploy of `deploy-tenants`
/// against its cassette, after its dry run: what each showed and the tenant
/// received.
fn golden_send(platform: &str, scenario: &str, variable: &str) -> (Vec<Json>, Vec<Received>) {
    let ws = fixture("deploy-tenants");
    let planned = planned_writes(ws.path(), platform);
    let text =
        std::fs::read_to_string(repo().join(format!("tests/cassettes/{scenario}.json"))).unwrap();
    let all: Vec<usize> = (0..Cassette::parse(&text).unwrap().interactions.len()).collect();
    let (proxy, env, _ca) = replay(scenario, &all, variable);
    let (sent, _) = deploy(
        ws.path(),
        platform,
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    assert_eq!(proxy.verify(), Vec::new(), "{:?}", sent.result);
    (planned, received_writes(replayed(&proxy)))
}

/// #1886: a rule whose create Graph refuses because another rule holds its
/// alert title (one 1.0.0 left under the bare uuid) fails with
/// `microsoft_defender_rule_conflict` in its row's `error`, and a delete that
/// finds no `opentide-<uuid>` says so rather than "already gone".
#[test]
fn a_defender_rule_another_rule_blocks_fails_with_its_code() {
    let scenario = "golden/deploy-defender-continues";
    let ws = fixture("deploy-tenants");
    let text =
        std::fs::read_to_string(repo().join(format!("tests/cassettes/{scenario}.json"))).unwrap();
    let all: Vec<usize> = (0..Cassette::parse(&text).unwrap().interactions.len()).collect();
    let (proxy, env, _ca) = replay(scenario, &all, "DEFENDER_CLIENT_SECRET");
    let (sent, _) = deploy(
        ws.path(),
        "microsoft_defender",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    assert_eq!(proxy.verify(), Vec::new(), "{:?}", sent.result);
    let Json::Array(results) = value(&sent, "results") else {
        panic!("no results")
    };
    let row = |uuid: &str| {
        results
            .iter()
            .find(|row| row.get("id").and_then(Json::as_str) == Some(uuid))
            .unwrap_or_else(|| panic!("no row {uuid}"))
    };
    let text = |row: &Json, key: &str| row.get(key).and_then(Json::as_str).map(str::to_owned);
    let held = row("00000000-0000-4000-8047-0000000000d7");
    assert_eq!(text(held, "status").as_deref(), Some("failed"));
    let error = text(held, "error").unwrap_or_default();
    assert!(
        error.starts_with("microsoft_defender_rule_conflict: Graph refused to create"),
        "{error}"
    );
    let gone = row("00000000-0000-4000-8047-0000000000d5");
    assert_eq!(text(gone, "status").as_deref(), Some("skipped"));
    assert_eq!(
        text(gone, "reason").as_deref(),
        Some("no rule opentide-00000000-0000-4000-8047-0000000000d5 on the tenant")
    );
    // A refusal with no code of its own keeps its message as it was.
    let refused = row("00000000-0000-4000-8047-0000000000d6");
    assert!(
        text(refused, "error")
            .unwrap_or_default()
            .starts_with("Graph refused to update"),
        "{refused:?}"
    );
}

/// #1894: a Splunk rule written under its name whose old saved search (an
/// earlier name of the rule) Splunk's stand-in tenant refuses to delete
/// fails with `splunk_renamed_search_not_deleted` leading its row's error,
/// not the refusal's message alone.
#[test]
fn a_splunk_rename_cleanup_the_tenant_refuses_fails_with_its_code() {
    use opentide_cassette::cassette::Body;
    let ws = fixture("deploy-tenants");
    let text =
        std::fs::read_to_string(repo().join("tests/cassettes/golden/deploy-splunk.json")).unwrap();
    let mut cassette = Cassette::parse(&text).unwrap();
    let recorded = cassette.interactions.clone();
    // The listing of the saved searches naming the created rule holds one
    // an earlier name of it left, owned by `nobody` as opentide's are.
    let at = recorded
        .iter()
        .position(|interaction| {
            interaction.request.method == "GET"
                && interaction
                    .request
                    .url
                    .ends_with("saved/searches?search=00000000-0000-4000-8047-000000000041&count=0")
        })
        .expect("the listing of the created rule's saved searches");
    let mut listed = recorded[at].clone();
    let Body::Text(feed) = &listed.response.body else {
        panic!("the listing is a feed")
    };
    let entry = &feed[feed.find("<entry>").unwrap()..feed.find("</entry>").unwrap() + 8];
    let old = entry
        .replace("Splunk create rule", "Old create rule")
        .replace("Splunk%20create%20rule", "Old%20create%20rule");
    listed.response.body = Body::Text(feed.replacen("</feed>", &format!("{old}</feed>"), 1));
    let mut delete = recorded[at].clone();
    delete.request.method = "DELETE".into();
    delete.request.url =
        "https://splunk.invalid:8089/servicesNS/nobody/search/saved/searches/Old+create+rule"
            .into();
    delete.response.status = 403;
    delete.response.body = Body::Text(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<response>\n  <messages>\n    <msg \
         type=\"ERROR\">You do not have permission to delete this object</msg>\n  \
         </messages>\n</response>\n"
            .into(),
    );
    cassette.interactions = recorded[..at]
        .iter()
        .cloned()
        .chain([listed, delete])
        .chain(recorded[at + 1..].iter().cloned())
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
            .chain([("SPLUNK_TOKEN".to_owned(), SECRET.to_owned())]),
    );
    let (sent, text) = deploy(
        ws.path(),
        "splunk",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    assert_eq!(proxy.verify(), Vec::new(), "{text}");
    let Json::Array(results) = value(&sent, "results") else {
        panic!("no results: {text}")
    };
    let created = results
        .iter()
        .find(|row| {
            row.get("id").and_then(Json::as_str) == Some("00000000-0000-4000-8047-000000000041")
        })
        .unwrap_or_else(|| panic!("{results:?}"));
    assert_eq!(
        created.get("status").and_then(Json::as_str),
        Some("failed"),
        "{text}"
    );
    let error = created
        .get("error")
        .and_then(Json::as_str)
        .unwrap_or_default();
    assert!(
        error.starts_with(
            "splunk_renamed_search_not_deleted: saved search \"Splunk create rule\" was \
             written, but \"Old create rule\""
        ),
        "{error}"
    );
}

/// A HarfangLab deployer that refuses every request as one it cannot read
/// (`harfanglab_request_invalid`, which its connector raises before any
/// request reaches the tenant).
struct HarfangLabRefusing;

impl Deployer for HarfangLabRefusing {
    fn deploy<'a>(
        &'a self,
        _cx: TenantContext<'a>,
        _request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        use opentide_connectors::connector::DeployFailure;
        Box::pin(async move {
            Err(DeployError::rule(DeployFailure::new(
                opentide_connectors::harfanglab::REQUEST_INVALID,
                "A HarfangLab deploy request's body is {\"kind\": \"Sigma\" or \"YARA\", \
                 \"rule\": <the compiled rule>}: it is empty",
            )))
        })
    }
}

impl Platform for HarfangLabRefusing {
    fn id(&self) -> &'static str {
        "harfanglab"
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self)
    }
}

/// #1894: a HarfangLab rule its connector refuses with a code of its own
/// fails with that code leading its row's error.
#[test]
fn a_harfanglab_failure_with_its_own_code_keeps_it_in_the_row() {
    let fixture = |file: &str| {
        std::fs::read_to_string(repo().join(format!(
            "tests/golden/fixtures/deploy-tenants/objects/rules/{file}"
        )))
        .unwrap()
    };
    let ws = workspace(
        "harfanglab",
        "lab",
        "url = \"https://harfanglab.invalid\"\napi_token = \"$HARFANGLAB_API_TOKEN\"\n\
         source_id = \"s\"\n",
        &[("a.yaml", fixture("harfanglab-a-sigma.yaml"))],
    );
    let mut registry = Registry::new();
    registry.register(Box::new(HarfangLabRefusing)).unwrap();
    let env = Env::from_pairs([("HARFANGLAB_API_TOKEN".to_owned(), "token".to_owned())]);
    let (sent, text) = deploy(ws.path(), "harfanglab", &env, &registry, 0);
    let rows = rows(&sent);
    assert_eq!(rows.len(), 1, "{rows:?}\n{text}");
    assert_eq!(rows[0].0, "failed", "{text}");
    let error = rows[0].1.clone().unwrap_or_default();
    assert!(
        error.starts_with("harfanglab_request_invalid: A HarfangLab deploy request's body"),
        "{error}"
    );
}

#[test]
fn a_defender_dry_run_shows_the_requests_the_tenant_receives() {
    let (planned, received) = golden_send(
        "microsoft_defender",
        "golden/deploy-defender-continues",
        "DEFENDER_CLIENT_SECRET",
    );
    // Defender's dry run shows each rule's first request: the PATCH of its
    // rule id, `opentide-<uuid>` (an upsert or a disablement), or the DELETE
    // of a deletion. What
    // follows on the tenant's answer (a POST after a 404, one more PATCH
    // after a 409) is not planned, so each planned write is the first
    // request the tenant received at its URL.
    let at = |write: &Json, key: &str| write.get(key).cloned().unwrap_or(Json::Null);
    assert_eq!(
        planned
            .iter()
            .map(|write| at(write, "method"))
            .collect::<Vec<_>>(),
        [
            "PATCH", "PATCH", "PATCH", "PATCH", "DELETE", "PATCH", "PATCH"
        ]
        .map(Json::str)
    );
    // #1886: every uuid here begins with a digit, which Graph refuses as an
    // id; each request names `opentide-<uuid>`.
    for (write, number) in planned
        .iter()
        .zip(["d1", "d2", "d3", "d4", "d5", "d6", "d7"])
    {
        assert_eq!(
            write.get("url").and_then(Json::as_str),
            Some(
                format!(
                    "https://graph.microsoft.com/beta/security/rules/detectionRules/\
                     opentide-00000000-0000-4000-8047-0000000000{number}"
                )
                .as_str()
            )
        );
    }
    for write in &planned {
        let shown = write.to_compact();
        let text = |key: &str| write.get(key).and_then(Json::as_str).unwrap_or_default();
        let Some((method, _, body)) = received
            .iter()
            .find(|(_, url, _)| same_url(text("url"), url))
        else {
            panic!("the tenant never received {shown}")
        };
        assert_eq!(text("method"), method.as_str(), "{shown}");
        assert!(
            same_body(write.get("body").unwrap_or(&Json::Null), body, 0),
            "{shown}\nreceived: {}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn a_sentinel_one_dry_run_shows_the_requests_the_tenant_receives() {
    let (planned, received) =
        golden_send("sentinel_one", "golden/deploy-sentinel-one", "S1_API_TOKEN");
    assert_sent_as_planned(&planned, &received, 0);
}

#[test]
fn a_crowdstrike_dry_run_shows_the_requests_the_tenant_receives() {
    let (planned, received) = golden_send(
        "crowdstrike",
        "golden/deploy-crowdstrike",
        "CROWDSTRIKE_CLIENT_SECRET",
    );
    assert_sent_as_planned(&planned, &received, 0);
}

#[test]
fn a_splunk_dry_run_shows_the_requests_the_tenant_receives() {
    let (planned, received) = golden_send("splunk", "golden/deploy-splunk", "SPLUNK_TOKEN");
    // The saved search created, then its settings, each update with the
    // search first, as Splunk receives them.
    assert_eq!(planned.len(), 3);
    let first = |write: &Json| {
        write
            .get("body")
            .and_then(Json::as_object)
            .and_then(|body| body.first().map(|(key, _)| key.clone()))
    };
    assert_eq!(first(&planned[1]).as_deref(), Some("search"));
    assert_eq!(first(&planned[2]).as_deref(), Some("search"));
    assert_sent_as_planned(&planned, &received, 0);
}

#[test]
fn a_carbon_black_dry_run_shows_the_requests_the_tenant_receives() {
    let ws = cbc_workspace();
    let planned = planned_writes(ws.path(), "carbon_black_cloud");
    // The report, stamped at send time, then the watchlist the deploy reads.
    let body = |write: &Json| write.get("body").cloned().unwrap_or(Json::Null);
    assert_eq!(
        body(&planned[0]).get("timestamp"),
        Some(&Json::str("<send-time:timestamp>"))
    );
    assert_eq!(body(&planned[1]), Json::str("<tenant-read:watchlist>"));
    let (proxy, env, _ca) = replay("carbon_black/deploy", &[0, 1, 2, 3], "CBC_TOKEN");
    let (sent, _) = deploy(
        ws.path(),
        "carbon_black_cloud",
        &env,
        &opentide_connectors::builtin(),
        CBC_NOW,
    );
    assert_eq!(proxy.verify(), Vec::new());
    assert_eq!(rows(&sent), [("deployed".to_owned(), None)]);
    assert_sent_as_planned(&planned, &received_writes(replayed(&proxy)), CBC_NOW);
}

#[test]
fn a_harfanglab_dry_run_shows_the_requests_the_tenant_receives() {
    use wiremock::matchers::any;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(
        wiremock::Mock::given(any())
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server),
    );
    let sigma = |status: &str| {
        format!(
            "  harfanglab:\n    status: {status}\n    sigma:\n      logsource:\n        \
             category: process_creation\n        product: windows\n      selections:\n        \
             - name: selection\n          field: Image\n          value: cmd.exe\n      \
             condition: selection\n"
        )
    };
    let yara = "  harfanglab:\n    status: STAGING\n    yara:\n      meta:\n        os: \
                Windows\n      strings: '$a = \"loader\"'\n      condition: $a\n";
    let ws = workspace(
        "harfanglab",
        "lab",
        &format!(
            "url = \"{}\"\napi_token = \"$HARFANGLAB_API_TOKEN\"\nsource_id = \"src-0001\"\n",
            server.uri()
        ),
        &[
            (
                "a.yaml",
                rule(
                    "Sigma rule",
                    "00000000-0000-4000-8003-0000000000b1",
                    "A.",
                    &sigma("STAGING"),
                ),
            ),
            (
                "b.yaml",
                rule(
                    "YARA file",
                    "00000000-0000-4000-8003-0000000000b2",
                    "B.",
                    yara,
                ),
            ),
            (
                "c.yaml",
                rule(
                    "Gone Sigma",
                    "00000000-0000-4000-8003-0000000000b3",
                    "C.",
                    &sigma("REMOVED"),
                ),
            ),
        ],
    );
    let planned = planned_writes(ws.path(), "harfanglab");
    let env = Env::from_pairs([("HARFANGLAB_API_TOKEN".to_owned(), "token".to_owned())]);
    let (sent, _) = deploy(
        ws.path(),
        "harfanglab",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    assert_eq!(rows(&sent), vec![("deployed".to_owned(), None); 3]);
    let received = rt
        .block_on(server.received_requests())
        .unwrap()
        .into_iter()
        .map(|request| {
            (
                request.method.as_str().to_owned(),
                request.url.to_string(),
                request.body,
            )
        })
        .collect();
    assert_sent_as_planned(&planned, &received_writes(received), 0);
}

/// The dry run, with no variable set, of the `deploy-tenants` fixture rule
/// `file` (or `text`) on `platform` with one tenant, `lab`, of `setup`: its
/// exit code and the rule's payload entry.
fn dry_run_entry(platform: &str, setup: &str, file: &str, text: Option<String>) -> (i32, Json) {
    let text = text.unwrap_or_else(|| {
        std::fs::read_to_string(
            repo()
                .join("tests/golden/fixtures/deploy-tenants/objects/rules")
                .join(file),
        )
        .unwrap()
    });
    let ws = workspace(platform, "lab", setup, &[(file, text)]);
    let (code, stdout, stderr) = cli(
        ws.path(),
        &[
            "--json",
            "deploy",
            "--dry-run",
            "--platform",
            platform,
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
        ],
        &[],
    );
    let document = Json::parse(&stdout).unwrap_or_else(|_| panic!("{stdout}\n{stderr}"));
    let result = document.get("result").unwrap_or(&document);
    let entry = result
        .get("payloads")
        .and_then(|payloads| payloads.get(platform))
        .and_then(Json::as_array)
        .and_then(|entries| entries.first())
        .cloned()
        .unwrap_or_else(|| panic!("{stdout}"));
    (code, entry)
}

/// The `n`th write of a payload entry, its `key`.
fn write_at(entry: &Json, n: usize, key: &str) -> Json {
    entry
        .get("api_request")
        .and_then(Json::as_array)
        .and_then(|writes| writes.get(n))
        .and_then(|write| write.get(key))
        .cloned()
        .unwrap_or_else(|| panic!("{}", entry.to_compact()))
}

/// The `setup` keys the entry's `unresolved` lists.
fn unresolved_setup(entry: &Json) -> Vec<Json> {
    entry
        .get("unresolved")
        .and_then(|unresolved| unresolved.get("setup"))
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default()
}

// A setup value that names a variable is a placeholder in a dry run, which
// resolves none and needs no credential: a CrowdStrike tenant's `api =
// "$CS_API"` once failed the dry run with "Invalid API Domain" (#1719).
#[test]
fn a_dry_run_shows_a_crowdstrike_setup_variable_as_a_placeholder() {
    let (code, entry) = dry_run_entry(
        "crowdstrike",
        "api = \"$CS_API\"\ncustomer_id = \"${CS_CUSTOMER}\"\nclient_id = \"id\"\n\
         client_secret = \"$CS_SECRET\"\n",
        "crowdstrike-a-create.yaml",
        None,
    );
    assert_eq!(code, 0, "{}", entry.to_compact());
    assert_eq!(entry.get("tenant"), Some(&Json::str("lab")));
    assert_eq!(
        write_at(&entry, 0, "url"),
        Json::str("<tenant:api>/correlation-rules/entities/rules/v1")
    );
    assert_eq!(
        write_at(&entry, 0, "body").get("customer_id"),
        Some(&Json::str("<tenant:customer_id>"))
    );
    assert_eq!(
        unresolved_setup(&entry),
        ["api", "customer_id"].map(Json::str)
    );
}

#[test]
fn a_dry_run_shows_a_sentinel_one_setup_variable_as_a_placeholder() {
    let (code, entry) = dry_run_entry(
        "sentinel_one",
        "url = \"$S1_URL\"\naccount_id = \"$S1_ACCOUNT\"\napi_token = \"$S1_API_TOKEN\"\n",
        "sentinel-one-a-create.yaml",
        None,
    );
    assert_eq!(code, 0, "{}", entry.to_compact());
    assert_eq!(
        write_at(&entry, 0, "url"),
        Json::str("<tenant:url>/web/api/v2.1/cloud-detection/rules")
    );
    assert_eq!(
        write_at(&entry, 0, "body")
            .get("filter")
            .and_then(|filter| filter.get("accountIds"))
            .cloned(),
        Some(Json::Array(vec![Json::str("<tenant:account_id>")]))
    );
    assert_eq!(
        unresolved_setup(&entry),
        ["url", "account_id"].map(Json::str)
    );
}

#[test]
fn a_dry_run_shows_carbon_black_and_harfanglab_setup_variables_as_placeholders() {
    let (code, entry) = dry_run_entry(
        "carbon_black_cloud",
        "url = \"$CBC_URL\"\norg_key = \"$CBC_ORG_KEY\"\ntoken = \"$CBC_TOKEN\"\n\
         watchlist = \"Detections\"\n",
        "lucene.yaml",
        Some(rule(
            "Carbon Black Lucene Rule",
            "00000000-0000-4000-8003-000000000005",
            "A rule.",
            "  carbon_black_cloud:\n    status: STAGING\n    query: process_name:cmd.exe\n",
        )),
    );
    assert_eq!(code, 0, "{}", entry.to_compact());
    assert_eq!(
        write_at(&entry, 0, "url"),
        Json::str("<tenant:url>/threathunter/watchlistmgr/v3/orgs/<tenant:org_key>/reports")
    );
    assert_eq!(unresolved_setup(&entry), ["url", "org_key"].map(Json::str));
    let (code, entry) = dry_run_entry(
        "harfanglab",
        "url = \"$HL_URL\"\napi_token = \"$HL_TOKEN\"\nsource_id = \"src-0001\"\n",
        "harfanglab-a-sigma.yaml",
        None,
    );
    assert_eq!(code, 0, "{}", entry.to_compact());
    let url = write_at(&entry, 0, "url");
    assert!(
        url.as_str()
            .is_some_and(|url| url.starts_with("<tenant:url>/api/data/threat_intelligence/")),
        "{}",
        entry.to_compact()
    );
    assert_eq!(unresolved_setup(&entry), [Json::str("url")]);
}

// Splunk's writes go to the whole URL a deploy sends to (#1719): a variable
// is a placeholder in it, and the port and app default as the deploy's do.
// A setting the deploy reads as written still refuses a variable, with the
// deploy's own error.
#[test]
fn a_splunk_dry_run_shows_the_url_with_a_setup_variable_as_a_placeholder() {
    let (code, entry) = dry_run_entry(
        "splunk",
        "url = \"$SPLUNK_HOST\"\ntoken = \"$SPLUNK_TOKEN\"\n",
        "splunk-a-create.yaml",
        None,
    );
    assert_eq!(code, 0, "{}", entry.to_compact());
    let searches = "https://<tenant:url>:8089/servicesNS/nobody/search/saved/searches/";
    assert_eq!(write_at(&entry, 0, "url"), Json::str(searches));
    assert_eq!(
        write_at(&entry, 1, "url"),
        Json::str(format!("{searches}Splunk%20create%20rule"))
    );
    assert_eq!(unresolved_setup(&entry), [Json::str("url")]);
    let (code, entry) = dry_run_entry(
        "splunk",
        "url = \"splunk.invalid\"\ntoken = \"$SPLUNK_TOKEN\"\nenterprise_security = \"$ES\"\n",
        "splunk-a-create.yaml",
        None,
    );
    assert_eq!(code, 1, "{}", entry.to_compact());
    assert!(
        entry
            .get("error")
            .and_then(Json::as_str)
            .is_some_and(|error| error.contains("enterprise_security is the placeholder \"$ES\"")),
        "{}",
        entry.to_compact()
    );
}

/// The summary's `skipped` counts the rows the run skipped (a rule no
/// tenant takes) besides the rules a status left out of the plan, which
/// once replaced them (#1653).
#[test]
fn the_summary_counts_skipped_rows_and_rules_left_out() {
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"token\"\n",
        &[
            (
                "a.yaml",
                rule(
                    "Elsewhere",
                    "00000000-0000-4000-8047-000000000923",
                    "A rule.",
                    "  splunk:\n    status: STAGING\n    query: index=main\n    tenants: [other]\n",
                ),
            ),
            (
                "b.yaml",
                rule(
                    "Released",
                    "00000000-0000-4000-8047-000000000924",
                    "A rule.",
                    "  splunk:\n    status: PRODUCTION\n    query: index=main\n",
                ),
            ),
        ],
    );
    let (registry, _) = scripted("splunk", Vec::new());
    let args = Args {
        strategies: vec!["PREVIEW".into()],
        all: true,
        platform: Some("splunk".into()),
        ..Args::default()
    };
    let (sent, text) = deploy_with(
        ws.path(),
        &args,
        &Env::from_pairs(Vec::<(String, String)>::new()),
        &registry,
        0,
    );
    assert_eq!(rows(&sent), [("skipped".to_owned(), None)], "{text}");
    assert_eq!(
        value(&sent, "_summary").get("skipped"),
        Some(&Json::Int(2)),
        "{:?}",
        sent.result
    );
}

/// The tenant setup on the stand-in at `uri` and the rule text of
/// `platform`, for `a_tenant_that_signs_in_then_refuses_the_first_rule_fails_before_any_rule`.
fn signed_in_case(platform: &str, uri: &str) -> (String, String) {
    let (setup, block) = match platform {
        "exabeam" => (
            format!(
                "region = \"eu\"\nclient_id = \"c\"\nclient_secret = \"$OPENTIDE_TEST_SECRET\"\napi_url = \"{uri}/\"\n"
            ),
            EXABEAM_BLOCK.to_owned(),
        ),
        "google_secops" => (
            format!(
                "ssl = false\nproject = \"p\"\nlocation = \"eu\"\ninstance = \"i\"\nendpoint = \"{uri}\"\n"
            ),
            String::new(),
        ),
        "graylog" => (
            format!("url = \"{uri}\"\ntoken = \"$OPENTIDE_TEST_SECRET\"\n"),
            graylog_block("STAGING", "EventID:1"),
        ),
        _ => (
            format!(
                "url = \"{uri}\"\nelasticsearch_url = \"{uri}\"\napi_key = \"$OPENTIDE_TEST_SECRET\"\nindex = [\"logs-*\"]\n"
            ),
            elastic_block("STAGING", ""),
        ),
    };
    let text = if platform == "google_secops" {
        std::fs::read_to_string(
            repo().join("tests/fixtures/google_secops/rule-google-secops-process-1.0.yaml"),
        )
        .unwrap()
    } else {
        rule(
            "A rule",
            "00000000-0000-4000-8099-000000000931",
            "A.",
            &block,
        )
    };
    (setup, text)
}

/// A tenant that signs in, then refuses or cannot answer the first rule's
/// first write, has taken nothing: its rules are `not attempted` (#1701).
/// The sign-in and the read-only checks before the write (Elasticsearch's,
/// Graylog's query check, Google SecOps' `verifyRuleText`) do not count as
/// a rule sent. Exabeam and Google SecOps sign in before the first rule.
#[test]
fn a_tenant_that_signs_in_then_refuses_the_first_rule_fails_before_any_rule() {
    use wiremock::matchers::{method, path_regex};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut failed = Vec::new();
    for platform in ["exabeam", "google_secops", "graylog", "elastic"] {
        let server = rt.block_on(wiremock::MockServer::start());
        let uri = server.uri();
        rt.block_on(async {
            let ok = |body: serde_json::Value| {
                wiremock::ResponseTemplate::new(200).set_body_json(body)
            };
            for (verb, route, answer) in [
                ("POST", "^/auth/v1/token$", serde_json::json!({"access_token": "t", "expires_in": 3600})),
                ("POST", "^/token$", serde_json::json!({"access_token": "t", "expires_in": 3600})),
                ("POST", ":verifyRuleText$", serde_json::json!({"success": true, "allowedRunFrequencies": ["LIVE", "HOURLY", "DAILY"]})),
                ("GET", "^/api/system$", serde_json::json!({"version": "7.2.1"})),
                ("POST", "^/api/search/validate$", serde_json::json!({"status": "OK"})),
                ("GET", "/_field_caps$", serde_json::json!({"indices": ["logs-1"], "fields": {}})),
                ("POST", "^/_query$", serde_json::json!({"columns": [], "values": []})),
            ] {
                wiremock::Mock::given(method(verb))
                    .and(path_regex(route))
                    .respond_with(ok(answer))
                    .mount(&server)
                    .await;
            }
            // Every other request: the tenant refuses the credentials.
            wiremock::Mock::given(path_regex(".*"))
                .respond_with(wiremock::ResponseTemplate::new(401))
                .mount(&server)
                .await;
        });
        let (setup, text) = signed_in_case(platform, &uri);
        let ws = workspace(platform, "lab", &setup, &[("a.yaml", text)]);
        let adc = ws.path().join("adc.json");
        std::fs::write(
            &adc,
            format!(
                r#"{{"type": "authorized_user", "client_id": "c", "client_secret": "s",
                    "refresh_token": "r", "token_uri": "{uri}/token"}}"#
            ),
        )
        .unwrap();
        let env = Env::from_pairs([
            ("OPENTIDE_TEST_SECRET".to_owned(), SECRET.to_owned()),
            (
                "GOOGLE_APPLICATION_CREDENTIALS".to_owned(),
                adc.display().to_string(),
            ),
        ]);
        let (sent, text) = deploy(
            ws.path(),
            platform,
            &env,
            &opentide_connectors::builtin(),
            0,
        );
        let checked = std::panic::catch_unwind(|| {
            let statuses: Vec<String> = rows(&sent).into_iter().map(|(status, _)| status).collect();
            assert_eq!(statuses, ["not_attempted"], "{platform}: {text}");
            assert_eq!(value(&sent, "_exit_code"), &Json::Int(1), "{platform}");
        });
        if checked.is_err() {
            failed.push(platform);
        }
    }
    assert!(failed.is_empty(), "failed on {failed:?}");
}

/// Google SecOps signs in, then its instance cannot be reached: nothing was
/// sent, so its rule is `not attempted` (#1701).
#[test]
fn a_secops_tenant_signed_in_but_unreachable_fails_before_any_rule() {
    use wiremock::matchers::{method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(
        wiremock::Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token": "t", "expires_in": 3600})),
            )
            .expect(1)
            .mount(&server),
    );
    let setup = "ssl = false\nproject = \"p\"\nlocation = \"eu\"\ninstance = \"i\"\nendpoint = \"http://127.0.0.1:9\"\n";
    let text = std::fs::read_to_string(
        repo().join("tests/fixtures/google_secops/rule-google-secops-process-1.0.yaml"),
    )
    .unwrap();
    let ws = workspace("google_secops", "lab", setup, &[("a.yaml", text)]);
    let adc = ws.path().join("adc.json");
    std::fs::write(
        &adc,
        format!(
            r#"{{"type": "authorized_user", "client_id": "c", "client_secret": "s",
                "refresh_token": "r", "token_uri": "{}/token"}}"#,
            server.uri()
        ),
    )
    .unwrap();
    let env = Env::from_pairs([(
        "GOOGLE_APPLICATION_CREDENTIALS".to_owned(),
        adc.display().to_string(),
    )]);
    let (sent, _) = deploy(
        ws.path(),
        "google_secops",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    rt.block_on(server.verify());
    assert_failed_before_any_rule(&sent, "google_secops", "lab", "");
}

/// A write that left and got no answer (the connection closed once the
/// request was sent) may have landed: the rule it came on stays `failed`,
/// never `not attempted`, even as the tenant's first (#1701).
#[test]
fn a_first_write_whose_connection_dropped_stays_failed() {
    use std::io::Read as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            // Read the request, then close without an answer.
            let mut buffer = vec![0_u8; 65536];
            let _ = stream.read(&mut buffer);
        }
    });
    let setup =
        format!("url = \"http://{address}\"\naccount_id = 1001\napi_token = \"$S1_API_TOKEN\"\n");
    let ws = workspace(
        "sentinel_one",
        "lab",
        &setup,
        &[
            (
                "a.yaml",
                rule(
                    "First rule",
                    "00000000-0000-4000-8099-000000000941",
                    "A.",
                    &s1_block("STAGING"),
                ),
            ),
            (
                "b.yaml",
                rule(
                    "Second rule",
                    "00000000-0000-4000-8099-000000000942",
                    "B.",
                    &s1_block("STAGING"),
                ),
            ),
        ],
    );
    let env = Env::from_pairs([("S1_API_TOKEN".to_owned(), "token".to_owned())]);
    let (sent, text) = deploy(
        ws.path(),
        "sentinel_one",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    let statuses: Vec<String> = rows(&sent).into_iter().map(|(status, _)| status).collect();
    assert_eq!(statuses[0], "failed", "{text}");
}

/// Bitdefender's first rule is an update whose call got no answer (the
/// connection closed once the request was read): the connector reports the
/// tenant unreachable, but the update may have landed, so the rule stays
/// `failed` and only the rules after it are `not attempted` (#1701). The
/// connector's test `an_update_with_no_answer_counts_as_a_write_the_tenant_may_have_taken`
/// holds the same for a timeout.
#[test]
fn a_bitdefender_first_update_with_no_answer_stays_failed() {
    use std::io::Read as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buffer = vec![0_u8; 65536];
            let _ = stream.read(&mut buffer);
        }
    });
    let setup = format!(
        "ssl = false\nurl = \"http://{address}/api\"\napi_key = \"$GRAVITYZONE_API_KEY\"\n"
    );
    let ws = stated(
        "bitdefender",
        &setup,
        &[
            (
                "a.yaml",
                "00000000-0000-4000-8099-000000000971",
                bitdefender_block(false),
                "aaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "b.yaml",
                "00000000-0000-4000-8099-000000000972",
                bitdefender_block(false),
                "bbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ],
    );
    let env = Env::from_pairs([("GRAVITYZONE_API_KEY".to_owned(), "key".to_owned())]);
    let (sent, text) = deploy(
        ws.path(),
        "bitdefender",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    let statuses: Vec<String> = rows(&sent).into_iter().map(|(status, _)| status).collect();
    assert_eq!(statuses, ["failed", "not_attempted"], "{text}");
    let Json::Array(failures) = value(&sent, "failures") else {
        panic!("no failures")
    };
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(
        failures[0].get("id"),
        Some(&Json::str("00000000-0000-4000-8099-000000000971")),
        "{failures:?}"
    );
}

/// A tenant failure on a later rule, after an earlier rule was sent and
/// refused on its own, is a failure on a rule: that rule is `failed` and
/// the rest `not attempted` (#1701).
#[test]
fn a_tenant_failure_after_a_rule_was_sent_fails_its_rule() {
    use wiremock::matchers::method;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(async {
        wiremock::Mock::given(method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({"errors": [{"title": "invalid"}]})),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"errors": [{"title": "Unauthorized"}]})),
            )
            .mount(&server)
            .await;
    });
    let setup = format!(
        "url = \"{}\"\naccount_id = 1001\napi_token = \"$S1_API_TOKEN\"\n",
        server.uri()
    );
    let rules: Vec<(String, String)> = (1..=3)
        .map(|n| {
            (
                format!("r{n}.yaml"),
                rule(
                    &format!("Rule {n}"),
                    &format!("00000000-0000-4000-8099-00000000095{n}"),
                    "A.",
                    &s1_block("STAGING"),
                ),
            )
        })
        .collect();
    let refs: Vec<(&str, String)> = rules.iter().map(|(f, t)| (f.as_str(), t.clone())).collect();
    let ws = workspace("sentinel_one", "lab", &setup, &refs);
    let env = Env::from_pairs([("S1_API_TOKEN".to_owned(), "token".to_owned())]);
    let (sent, text) = deploy(
        ws.path(),
        "sentinel_one",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    let statuses: Vec<String> = rows(&sent).into_iter().map(|(status, _)| status).collect();
    assert_eq!(statuses, ["failed", "failed", "not_attempted"], "{text}");
}

/// Kibana answering the first rule's lookup (a `GET`) with a gateway's
/// 503, retried, has taken nothing: the tenant failed before any rule and
/// its rule is `not attempted` (#1701).
#[test]
fn an_elastic_gateway_error_on_the_first_lookup_fails_before_any_rule() {
    use wiremock::matchers::{method, path_regex};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(async {
        wiremock::Mock::given(method("GET"))
            .and(path_regex("/_field_caps$"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"indices": ["logs-1"], "fields": {}})),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(method("GET"))
            .and(path_regex("/api/detection_engine/rules$"))
            .respond_with(wiremock::ResponseTemplate::new(503).set_body_string("<html>down</html>"))
            .mount(&server)
            .await;
    });
    let ws = elastic_workspace(
        &server.uri(),
        &[(
            "a.yaml",
            "First rule",
            "00000000-0000-4000-8099-000000000961",
            elastic_block("STAGING", ""),
        )],
    );
    let env = Env::from_pairs([("ELASTIC_API_KEY".to_owned(), "key".to_owned())]);
    let (sent, text) = deploy(
        ws.path(),
        "elastic",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    let statuses: Vec<String> = rows(&sent).into_iter().map(|(status, _)| status).collect();
    assert_eq!(statuses, ["not_attempted"], "{text}");
}

/// A rule that has a skipped row (its Splunk block, which no tenant takes)
/// and a block a status left out (its Sentinel block) counts once in the
/// summary's `skipped`.
#[test]
fn the_summary_counts_a_skipped_rule_once() {
    let uuid = "00000000-0000-4000-8047-000000000925";
    let block = format!(
        "  splunk:\n    status: STAGING\n    query: index=main\n    tenants: [other]\n{}",
        SENTINEL_STAGING.replace("status: STAGING", "status: PRODUCTION")
    );
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"token\"\n",
        &[("a.yaml", rule("Both", uuid, "A rule.", &block))],
    );
    std::fs::write(
        ws.path()
            .join(".opentide/configurations/platforms/sentinel.toml"),
        format!(
            "[platform]\nenabled = true\nname = \"Stand-in\"\n\n[[tenants]]\nname = \"soc\"\n\
             strategies = [\"PREVIEW\", \"RELEASE\"]\n[tenants.setup]\n{SENTINEL_SETUP}"
        ),
    )
    .unwrap();
    let (registry, _) = scripted("splunk", Vec::new());
    let args = Args {
        strategies: vec!["PREVIEW".into()],
        all: true,
        ..Args::default()
    };
    let (sent, text) = deploy_with(
        ws.path(),
        &args,
        &Env::from_pairs(Vec::<(String, String)>::new()),
        &registry,
        0,
    );
    let Json::Array(left) = value(&sent, "skipped") else {
        panic!("{:?}", sent.result)
    };
    assert_eq!(left.len(), 1, "the Sentinel block is left out: {left:?}");
    assert_eq!(
        value(&sent, "_summary").get("skipped"),
        Some(&Json::Int(1)),
        "{text}\n{:?}",
        sent.result
    );
}

/// A Splunk tenant that answers an update with one old copy deleted, and a
/// delete with a cleanup that failed after one old copy was deleted; it
/// keeps each request's name, operation and body.
struct SplunkCleanup {
    seen: Mutex<Vec<(String, Operation, String)>>,
}

impl Deployer for SplunkCleanup {
    fn deploy<'a>(
        &'a self,
        _cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        use opentide_connectors::connector::{DeployFailure, DeployWarning};
        use opentide_connectors::splunk::{RENAMED_CLEANUP_FAILED, RENAMED_DELETED};
        self.seen.lock().unwrap().push((
            request.rule_id.clone(),
            request.operation,
            String::from_utf8_lossy(&request.body).into_owned(),
        ));
        let operation = request.operation;
        Box::pin(async move {
            if operation == Operation::Delete {
                Err(DeployError::rule(DeployFailure::new(
                    RENAMED_CLEANUP_FAILED,
                    "saved search \"Retired\" was deleted (or already absent), but \"Old B 2\" \
                     could not be deleted",
                ))
                .with_partial(DeployOutcome::new(None, operation).with_warnings(vec![
                    DeployWarning::new(RENAMED_DELETED, "Old B 1").unraised(),
                ])))
            } else {
                Ok(
                    DeployOutcome::new(Some("Kept".into()), operation).with_warnings(vec![
                        DeployWarning::new(RENAMED_DELETED, "Old A").unraised(),
                    ]),
                )
            }
        })
    }
}

struct SplunkCleanupPlatform(&'static SplunkCleanup);

impl Platform for SplunkCleanupPlatform {
    fn id(&self) -> &'static str {
        "splunk"
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self.0)
    }
}

/// A retired Splunk rule's request names the rule (its description, whose
/// last line is `opentide rule <uuid>`), so the connector can delete the
/// copies an earlier name left; and the old saved searches a cleanup
/// deleted are listed under `removed`, on a deployed row and on a row whose
/// cleanup failed part way (#1657).
#[test]
fn a_splunk_retirement_names_the_rule_and_removed_survives_a_failed_cleanup() {
    const KEPT: &str = "00000000-0000-4000-8047-000000000a01";
    const RETIRED: &str = "00000000-0000-4000-8047-000000000a02";
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"token\"\n",
        &[
            ("a.yaml", rule("Kept", KEPT, "A rule.", SPLUNK_BLOCK)),
            (
                "b.yaml",
                rule(
                    "Retired",
                    RETIRED,
                    "A retired rule.",
                    "  splunk:\n    status: REMOVED\n    query: index=main\n",
                ),
            ),
        ],
    );
    let deployer: &'static SplunkCleanup = Box::leak(Box::new(SplunkCleanup {
        seen: Mutex::new(Vec::new()),
    }));
    let mut registry = Registry::new();
    registry
        .register(Box::new(SplunkCleanupPlatform(deployer)))
        .unwrap();
    let args = Args {
        strategies: vec!["PREVIEW".into(), "RELEASE".into()],
        platform: Some("splunk".into()),
        all: true,
        keep_deprecated: Some(true),
        ..Args::default()
    };
    let (sent, text) = deploy_with(
        ws.path(),
        &args,
        &Env::from_pairs([("X", "y")]),
        &registry,
        0,
    );
    let seen = deployer.seen.lock().unwrap().clone();
    let retired = seen
        .iter()
        .find(|(name, ..)| name == "Retired")
        .unwrap_or_else(|| panic!("{seen:?}\n{text}"));
    assert_eq!(retired.1, Operation::Delete);
    let body: serde_json::Value = serde_json::from_str(&retired.2).unwrap();
    assert_eq!(
        body["description"].as_str(),
        Some(format!("A retired rule.\n\nopentide rule {RETIRED}").as_str()),
        "{body}"
    );
    let Json::Array(results) = value(&sent, "results") else {
        panic!("no results: {text}")
    };
    let row = |uuid: &str| {
        results
            .iter()
            .find(|row| row.get("id").and_then(Json::as_str) == Some(uuid))
            .unwrap_or_else(|| panic!("no row for {uuid}: {results:?}"))
    };
    let removed = |uuid: &str| -> Vec<String> {
        match row(uuid).get("removed") {
            Some(Json::Array(names)) => names
                .iter()
                .map(|name| name.as_str().unwrap().to_owned())
                .collect(),
            _ => Vec::new(),
        }
    };
    assert_eq!(
        row(KEPT).get("status").and_then(Json::as_str),
        Some("deployed")
    );
    assert_eq!(removed(KEPT), ["Old A"]);
    assert_eq!(
        row(RETIRED).get("status").and_then(Json::as_str),
        Some("failed"),
        "{text}"
    );
    assert_eq!(removed(RETIRED), ["Old B 1"]);
}

/// A cassette of the Sentinel sign-in, the `GET` of the one rule the
/// `deploy-tenants` workspace deploys (answered `status` with `held`) and,
/// when `put`, the `PUT` of its planned body (OT-3).
fn sentinel_read_replay(
    planned: &Json,
    status: u16,
    held: Option<&Json>,
    put: bool,
) -> (Proxy, Env, tempfile::NamedTempFile) {
    let text =
        std::fs::read_to_string(repo().join("tests/cassettes/sentinel/deploy.json")).unwrap();
    let mut cassette = Cassette::parse(&text).unwrap();
    let body = planned.to_compact();
    let at = |index: usize, rule: &str| {
        let mut interaction = cassette.interactions[index].clone();
        interaction.request.url = interaction
            .request
            .url
            .replace("soc%20workspace", "soc")
            .replace("00000000-0000-4000-8003-000000000001", rule);
        interaction
    };
    let deployed = "00000000-0000-4000-8047-000000000071";
    let mut read = at(6, deployed);
    read.request.method = "GET".into();
    read.response.status = status;
    read.response.body =
        opentide_cassette::cassette::Body::Text(held.map(Json::to_compact).unwrap_or_default());
    let mut interactions = vec![at(0, deployed), at(1, deployed), read];
    if put {
        let mut write = at(2, deployed);
        write.request.body = opentide_cassette::cassette::Body::Text(body);
        interactions.push(write);
    }
    // The workspace's other rule is retired: a `DELETE` ARM answers 200.
    interactions.push(at(6, "00000000-0000-4000-8047-000000000072"));
    cassette.interactions = interactions;
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
            .chain([("AZURE_CLIENT_SECRET".to_owned(), SECRET.to_owned())]),
    );
    (proxy, env, ca)
}

/// The action of the one result row.
fn only_action(sent: &Sent) -> String {
    let Json::Array(results) = value(sent, "results") else {
        panic!("no results")
    };
    // The deployed rule's row; the other rule is retired.
    let row = results
        .iter()
        .find(|row| {
            row.get("id").and_then(Json::as_str) == Some("00000000-0000-4000-8047-000000000071")
        })
        .unwrap();
    row.get("action")
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn sentinel_reports_what_arm_did_for_a_rule_it_read_first() {
    let ws = fixture("deploy-tenants");
    let (code, stdout, stderr) = cli(
        ws.path(),
        &[
            "--json",
            "deploy",
            "--dry-run",
            "--platform",
            "sentinel",
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
            "--keep-deprecated",
        ],
        &[],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let document = Json::parse(&stdout).unwrap();
    let result = document.get("result").unwrap_or(&document);
    let payloads = result
        .get("payloads")
        .and_then(|p| p.get("sentinel"))
        .and_then(Json::as_array)
        .unwrap();
    // The body a deploy sends is the dry run's `api_request`.
    let sent_body = payloads
        .iter()
        .find(|p| {
            p.get("uuid").and_then(Json::as_str) == Some("00000000-0000-4000-8047-000000000071")
        })
        .and_then(|p| p.get("api_request"))
        .unwrap()
        .clone();
    let planned = [sent_body.clone()];

    // Not there: a create, written once.
    let (proxy, env, _ca) = sentinel_read_replay(&planned[0], 404, None, true);
    let (sent, _) = deploy(ws.path(), "sentinel", &env, &sentinel_registry(), 0);
    assert_eq!(proxy.verify(), Vec::new(), "{:?}", sent.result);
    assert_eq!(only_action(&sent), "create");

    // Held as sent, with what ARM adds: unchanged, deployed, nothing written.
    let mut held = sent_body.clone();
    held.as_object_mut()
        .unwrap()
        .insert("etag".into(), Json::str("\"e\""));
    let (proxy, env, _ca) = sentinel_read_replay(&planned[0], 200, Some(&held), false);
    let (sent, stderr) = deploy(ws.path(), "sentinel", &env, &sentinel_registry(), 0);
    assert_eq!(proxy.verify(), Vec::new(), "{:?}", sent.result);
    assert_eq!(only_action(&sent), "unchanged");
    assert!(
        value(&sent, "message")
            .as_str()
            .is_some_and(|message| message.contains("1 deleted, 1 unchanged")),
        "{:?}",
        sent.result
    );
    assert!(stderr.contains("unchanged"), "{stderr}");

    // Held with another name: an update.
    let mut other = sent_body;
    other
        .get_mut("properties")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("displayName".into(), Json::str("another name"));
    let (proxy, env, _ca) = sentinel_read_replay(&planned[0], 200, Some(&other), true);
    let (sent, _) = deploy(ws.path(), "sentinel", &env, &sentinel_registry(), 0);
    assert_eq!(proxy.verify(), Vec::new(), "{:?}", sent.result);
    assert_eq!(only_action(&sent), "update");
}

/// A `DISABLED` rule the workspace holds enabled is written, and the row
/// keeps the plan's `disable` rather than an `update` (OT-3).
#[test]
fn sentinel_a_disabled_rule_held_enabled_is_written_and_stays_a_disable() {
    let ws = fixture("deploy-tenants");
    let file = ws.path().join("objects/rules/sentinel-a-create.yaml");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("status: STAGING"), "{text}");
    std::fs::write(&file, text.replace("status: STAGING", "status: DISABLED")).unwrap();
    let (code, stdout, stderr) = cli(
        ws.path(),
        &[
            "--json",
            "deploy",
            "--dry-run",
            "--platform",
            "sentinel",
            "--strategy",
            "RELEASE",
            "--all",
            "--keep-deprecated",
        ],
        &[],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let document = Json::parse(&stdout).unwrap();
    let result = document.get("result").unwrap_or(&document);
    let sent_body = result
        .get("payloads")
        .and_then(|p| p.get("sentinel"))
        .and_then(Json::as_array)
        .unwrap()
        .iter()
        .find(|p| {
            p.get("uuid").and_then(Json::as_str) == Some("00000000-0000-4000-8047-000000000071")
        })
        .and_then(|p| p.get("api_request"))
        .unwrap()
        .clone();
    assert_eq!(
        sent_body.get("properties").and_then(|p| p.get("enabled")),
        Some(&Json::Bool(false)),
        "{}",
        sent_body.to_compact()
    );
    let mut held = sent_body.clone();
    held.get_mut("properties")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("enabled".into(), Json::Bool(true));
    let (proxy, env, _ca) = sentinel_read_replay(&sent_body, 200, Some(&held), true);
    let args = Args {
        strategies: vec!["RELEASE".into()],
        all: true,
        platform: Some("sentinel".to_owned()),
        keep_deprecated: Some(true),
        ..Args::default()
    };
    let (sent, _) = deploy_with(ws.path(), &args, &env, &sentinel_registry(), 0);
    assert_eq!(proxy.verify(), Vec::new(), "{:?}", sent.result);
    assert_eq!(only_action(&sent), "disable");
}

// #1721: the body a deploy sends is compiled from the tenant's `setup` with
// each `$NAME` replaced by what the variable holds. The `deploy-tenants`
// fixture's tenants are rewritten to name a variable where they wrote the
// value, and the cassette recorded with the value written out is replayed: it
// holds only when the body carries the value, never the text `$NAME`.

/// What a deploy of the `deploy-tenants` fixture's `platform` gave.
#[derive(Debug, PartialEq)]
struct Outcome {
    /// The cassette's mismatches: the requests the tenant did not expect.
    mismatches: Vec<String>,
    /// Each row's status and error.
    rows: Vec<(String, Option<String>)>,
    /// The writes the tenant received.
    writes: Vec<Received>,
    /// Every request the tenant received (a Carbon Black report goes out
    /// after reads it makes).
    requests: Vec<Received>,
}

/// Deploys the `deploy-tenants` fixture's `platform` against `scenario`, its
/// setup line `from` rewritten as `to` (when given), with the sign-in
/// variable and `variables` set.
fn deployed_tenants(
    platform: &str,
    scenario: &str,
    sign_in: &str,
    rewrite: Option<(&str, &str)>,
    variables: &[(&str, &str)],
) -> Outcome {
    let ws = fixture("deploy-tenants");
    if let Some((from, to)) = rewrite {
        let file = ws.path().join(format!(
            ".opentide/configurations/platforms/{platform}.toml"
        ));
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains(from), "{from} is not in {text}");
        std::fs::write(&file, text.replace(from, to)).unwrap();
    }
    let text =
        std::fs::read_to_string(repo().join(format!("tests/cassettes/{scenario}.json"))).unwrap();
    let all: Vec<usize> = (0..Cassette::parse(&text).unwrap().interactions.len()).collect();
    let mut names = vec![(sign_in, SECRET)];
    names.extend_from_slice(variables);
    let (proxy, env, _ca) = replay_with(scenario, &all, &names);
    let (sent, _) = deploy(
        ws.path(),
        platform,
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    Outcome {
        mismatches: proxy.verify().iter().map(|m| format!("{m:?}")).collect(),
        rows: rows(&sent),
        writes: received_writes(replayed(&proxy)),
        requests: replayed(&proxy),
    }
}

/// A setup variable that is set gives the deploy the value written out: the
/// same requests, so the same rows and writes, and none holds the variable.
fn assert_variable_is_sent_as_its_value(
    platform: &str,
    scenario: &str,
    sign_in: &str,
    (from, to): (&str, &str),
    (variable, value): (&str, &str),
) {
    let written = deployed_tenants(platform, scenario, sign_in, None, &[]);
    let named = deployed_tenants(
        platform,
        scenario,
        sign_in,
        Some((from, to)),
        &[(variable, value)],
    );
    assert_eq!(named.mismatches, Vec::<String>::new(), "{named:?}");
    assert!(!named.requests.is_empty(), "{named:?}");
    assert_eq!(named, written);
    for (_, url, body) in &named.requests {
        let text = format!("{url} {}", String::from_utf8_lossy(body)).to_lowercase();
        assert!(!text.contains(&variable.to_lowercase()), "{text}");
    }
}

/// A setup variable that is unset fails the rules that read it, naming the
/// variable and never a value, and writes nothing to the tenant.
fn assert_unset_variable_fails_each_rule(
    rows: &[(String, Option<String>)],
    writes: &[Received],
    variable: &str,
) {
    let failed: Vec<&Option<String>> = rows
        .iter()
        .filter(|(status, _)| status == "failed")
        .map(|(_, error)| error)
        .collect();
    assert!(!failed.is_empty(), "{rows:?}");
    for error in failed {
        let error = error.as_deref().unwrap_or_default();
        assert!(
            error.contains(&format!(
                "names the environment variable {variable}, which is unset"
            )),
            "{error}"
        );
        assert!(!error.contains(SECRET), "{error}");
    }
    assert!(
        rows.iter().all(|(status, _)| status != "deployed"),
        "{rows:?}"
    );
    assert_eq!(writes, Vec::<Received>::new());
}

#[test]
fn crowdstrike_sends_a_customer_id_variable_as_its_value() {
    assert_variable_is_sent_as_its_value(
        "crowdstrike",
        "golden/deploy-crowdstrike",
        "CROWDSTRIKE_CLIENT_SECRET",
        (
            "customer_id = \"00000000000000000000000000000c1d\"",
            "customer_id = \"$CS_CUSTOMER_ID\"",
        ),
        ("CS_CUSTOMER_ID", "00000000000000000000000000000c1d"),
    );
}

#[test]
fn crowdstrike_fails_each_rule_whose_customer_id_variable_is_unset() {
    let unset = deployed_tenants(
        "crowdstrike",
        "golden/deploy-crowdstrike",
        "CROWDSTRIKE_CLIENT_SECRET",
        Some((
            "customer_id = \"00000000000000000000000000000c1d\"",
            "customer_id = \"$CS_CUSTOMER_ID\"",
        )),
        &[],
    );
    assert_unset_variable_fails_each_rule(&unset.rows, &unset.writes, "CS_CUSTOMER_ID");
}

#[test]
fn sentinel_one_sends_an_account_id_variable_as_its_value() {
    assert_variable_is_sent_as_its_value(
        "sentinel_one",
        "golden/deploy-sentinel-one",
        "S1_API_TOKEN",
        ("account_id = 1001", "account_id = \"$S1_ACCOUNT\""),
        ("S1_ACCOUNT", "1001"),
    );
}

// The connector resolves `account_id` for its own calls and fails the tenant
// when it is unset; `site_id`, which the body reads and no call does, is the
// setting a rule fails on.
#[test]
fn sentinel_one_fails_each_rule_whose_site_id_variable_is_unset() {
    let unset = deployed_tenants(
        "sentinel_one",
        "golden/deploy-sentinel-one",
        "S1_API_TOKEN",
        Some((
            "account_id = 1001",
            "account_id = 1001\nsite_id = \"$S1_SITE\"",
        )),
        &[],
    );
    assert_unset_variable_fails_each_rule(&unset.rows, &unset.writes, "S1_SITE");
}

#[test]
fn carbon_black_sends_a_watchlist_variable_as_its_value() {
    assert_variable_is_sent_as_its_value(
        "carbon_black_cloud",
        "golden/deploy-carbon-black",
        "CBC_TOKEN",
        ("watchlist = \"opentide\"", "watchlist = \"$CBC_WATCHLIST\""),
        ("CBC_WATCHLIST", "opentide"),
    );
}

#[test]
fn carbon_black_fails_each_rule_whose_watchlist_variable_is_unset() {
    let unset = deployed_tenants(
        "carbon_black_cloud",
        "golden/deploy-carbon-black",
        "CBC_TOKEN",
        Some(("watchlist = \"opentide\"", "watchlist = \"$CBC_WATCHLIST\"")),
        &[],
    );
    assert_unset_variable_fails_each_rule(&unset.rows, &unset.writes, "CBC_WATCHLIST");
}

/// A HarfangLab tenant on a wiremock server, its `source_id` the line
/// `source`, with a sigma rule: the deploy's rows, and the bodies the server
/// received.
fn harfanglab_source(
    source: &str,
    variables: &[(&str, &str)],
) -> (Vec<(String, Option<String>)>, Vec<String>) {
    use wiremock::matchers::any;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(
        wiremock::Mock::given(any())
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server),
    );
    let block = "  harfanglab:\n    status: STAGING\n    sigma:\n      logsource:\n        \
                 category: process_creation\n        product: windows\n      selections:\n        \
                 - name: selection\n          field: Image\n          value: cmd.exe\n      \
                 condition: selection\n";
    let ws = workspace(
        "harfanglab",
        "lab",
        &format!(
            "url = \"{}\"\napi_token = \"$HL_TOKEN\"\n{source}\n",
            server.uri()
        ),
        &[(
            "a.yaml",
            rule(
                "HarfangLab sigma",
                "00000000-0000-4000-8099-000000000721",
                "A.",
                block,
            ),
        )],
    );
    let env =
        Env::from_pairs(std::iter::once(("HL_TOKEN", SECRET)).chain(variables.iter().copied()));
    let (sent, _) = deploy(
        ws.path(),
        "harfanglab",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    let bodies = rt
        .block_on(server.received_requests())
        .unwrap()
        .into_iter()
        .filter(|request| request.method.as_str() != "GET")
        .map(|request| String::from_utf8_lossy(&request.body).into_owned())
        .collect();
    (rows(&sent), bodies)
}

#[test]
fn harfanglab_sends_a_source_id_variable_as_its_value() {
    let (rows, bodies) = harfanglab_source(
        "source_id = \"$HL_SOURCE\"",
        &[("HL_SOURCE", "src-from-the-environment")],
    );
    assert!(
        rows.iter().all(|(status, _)| status != "failed"),
        "{rows:?}"
    );
    assert!(!bodies.is_empty());
    for body in &bodies {
        assert!(body.contains("src-from-the-environment"), "{body}");
        assert!(!body.contains("HL_SOURCE"), "{body}");
    }
}

#[test]
fn harfanglab_fails_each_rule_whose_source_id_variable_is_unset() {
    let (rows, bodies) = harfanglab_source("source_id = \"$HL_SOURCE\"", &[]);
    assert_unset_variable_fails_each_rule(&rows, &[], "HL_SOURCE");
    assert_eq!(bodies, Vec::<String>::new());
}

/// A deployer that holds each rule until a second rule is in flight at the
/// same time (or five seconds pass), and keeps the most it saw at once.
struct Meeting {
    in_flight: std::sync::atomic::AtomicUsize,
    most: std::sync::atomic::AtomicUsize,
}

impl Deployer for Meeting {
    fn deploy<'a>(
        &'a self,
        _cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        use std::sync::atomic::Ordering;
        deploying(async move {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.most.fetch_max(now, Ordering::SeqCst);
            let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while self.most.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < until {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(DeployOutcome::new(None, request.operation))
        })
    }
}

/// [`Meeting`] as the Sentinel platform.
struct Meets(&'static Meeting);

impl Platform for Meets {
    fn id(&self) -> &'static str {
        "sentinel"
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self.0)
    }
}

/// The tenants of a platform deploy at once (#1940): two Sentinel tenants
/// each have a rule in flight at the same time. One tenant after another,
/// the first rule would wait alone.
#[test]
fn the_tenants_of_a_platform_deploy_at_once() {
    let ws = workspace(
        "sentinel",
        "soc",
        SENTINEL_SETUP,
        &three_rules(SENTINEL_STAGING)[..1],
    );
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/sentinel.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    let second = text.replacen(
        "[[tenants]]\nname = \"soc\"",
        "[[tenants]]\nname = \"lab\"",
        1,
    );
    let tenants = &second[second.find("[[tenants]]").unwrap()..];
    std::fs::write(&config, format!("{text}\n{tenants}")).unwrap();
    let meeting: &'static Meeting = Box::leak(Box::new(Meeting {
        in_flight: std::sync::atomic::AtomicUsize::new(0),
        most: std::sync::atomic::AtomicUsize::new(0),
    }));
    let mut registry = Registry::new();
    registry.register(Box::new(Meets(meeting))).unwrap();
    let env = Env::from_pairs([("AZURE_CLIENT_SECRET", SECRET)]);
    let (sent, stderr) = deploy(ws.path(), "sentinel", &env, &registry, 0);
    assert_eq!(
        meeting.most.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "{stderr}"
    );
    assert_eq!(
        rows(&sent),
        [("deployed".to_owned(), None), ("deployed".to_owned(), None)]
    );
}

/// Tenants deploying at once end in any order, and the run is still the
/// one a run sending to one tenant after another makes (#1940): four Sysdig
/// tenants, the first the slowest to answer, two of them refusing every
/// create. The rows are in the plan's order (tenant by tenant, as
/// configured), the failures and the run's error name the first tenant's
/// first, and each rule's deployment state shard holds the ids of the
/// tenants that created it, the same bytes whichever wrote first.
#[test]
fn tenants_deploying_at_once_report_and_record_in_the_plans_order() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // Each tenant's stand-in: (name, delay in ms, the status a create gets).
    let stands = [
        ("t1", 400, 500),
        ("t2", 300, 201),
        ("t3", 200, 500),
        ("t4", 100, 201),
    ];
    let uuids = [
        "00000000-0000-4000-8099-000000000191",
        "00000000-0000-4000-8099-000000000192",
    ];
    let (ws, _servers) = sysdig_stands(&rt, &stands, &uuids);
    let env = Env::from_pairs([("SYSDIG_SECURE_API_TOKEN".to_owned(), "token".to_owned())]);
    let (sent, stderr) = deploy(
        ws.path(),
        "sysdig",
        &env,
        &opentide_connectors::builtin(),
        0,
    );
    let Json::Array(results) = value(&sent, "results") else {
        panic!("no results")
    };
    let placed: Vec<(String, String, String)> = results
        .iter()
        .map(|row| {
            let text = |key| row.get(key).and_then(Json::as_str).unwrap().to_owned();
            (text("tenant"), text("id"), text("status"))
        })
        .collect();
    let mut expected = Vec::new();
    for (name, _, status) in stands {
        let outcome = if status == 201 { "deployed" } else { "failed" };
        for uuid in uuids {
            expected.push((name.to_owned(), uuid.to_owned(), outcome.to_owned()));
        }
    }
    assert_eq!(placed, expected, "{stderr}");
    let Json::Array(failures) = value(&sent, "failures") else {
        panic!("no failures")
    };
    let failed_on: Vec<&str> = failures
        .iter()
        .map(|failure| failure.get("tenant").and_then(Json::as_str).unwrap())
        .collect();
    assert_eq!(failed_on, ["t1", "t1", "t3", "t3"], "{failures:?}");
    // t1's answer (its id 10), though t3 refused first.
    assert_eq!(
        value(&sent, "error"),
        &Json::str(
            "Deployment to sysdig failed on First: create rule: HTTP 500: {\"id\": 10} (and 3 \
             more failures)"
        )
    );
    for uuid in uuids {
        let shard = std::fs::read_to_string(
            ws.path()
                .join(format!(".opentide/states/deployment/{uuid}.json")),
        )
        .unwrap();
        assert_eq!(
            shard,
            format!(
                "{{\n  \"object_uuid\": \"{uuid}\",\n  \"platforms\": {{\n    \"sysdig\": {{\n      \
                 \"t2\": \"20\",\n      \"t4\": \"40\"\n    }}\n  }},\n  \"schema\": \
                 \"deployment.state::1.0\"\n}}\n"
            )
        );
    }
}

/// A Sysdig workspace with a tenant for each of `stands` (name, delay in
/// ms, the status a create gets), each on a stand-in of its own that
/// answers every create after the delay, with an id of its own (10, 20,
/// …), and a rule for each of `uuids`.
fn sysdig_stands(
    rt: &tokio::runtime::Runtime,
    stands: &[(&str, u64, u16)],
    uuids: &[&str; 2],
) -> (tempfile::TempDir, Vec<wiremock::MockServer>) {
    use wiremock::matchers::{method, path};
    let mut servers = Vec::new();
    for (index, (_, delay, status)) in stands.iter().enumerate() {
        let server = rt.block_on(wiremock::MockServer::start());
        rt.block_on(
            wiremock::Mock::given(method("POST"))
                .and(path("/api/secure/rules"))
                .respond_with(
                    wiremock::ResponseTemplate::new(*status)
                        .set_body_string(format!(r#"{{"id": {}}}"#, (index + 1) * 10))
                        .set_delay(std::time::Duration::from_millis(*delay)),
                )
                .mount(&server),
        );
        servers.push(server);
    }
    let block = "  sysdig:\n    schema: platform::sysdig::1.0\n    status: STAGING\n    condition: \
                 spawned_process and container\n    tags: [container]\n";
    let ws = workspace(
        "sysdig",
        "t1",
        &format!(
            "url = \"{}\"\napi_token = \"$SYSDIG_SECURE_API_TOKEN\"\n",
            servers[0].uri()
        ),
        &[
            ("a.yaml", rule("First", uuids[0], "First.", block)),
            ("b.yaml", rule("Second", uuids[1], "Second.", block)),
        ],
    );
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/sysdig.toml");
    let mut text = std::fs::read_to_string(&config).unwrap();
    for ((name, ..), server) in stands.iter().zip(&servers).skip(1) {
        text.push_str(&format!(
            "\n[[tenants]]\nname = \"{name}\"\nstrategies = [\"PREVIEW\", \"RELEASE\"]\n\
             [tenants.setup]\nurl = \"{}\"\napi_token = \"$SYSDIG_SECURE_API_TOKEN\"\n",
            server.uri()
        ));
    }
    std::fs::write(&config, text).unwrap();
    (ws, servers)
}

/// A Sentinel workspace with a tenant for each of `names`, each taking
/// `rules`.
fn sentinel_tenants(names: &[&str], rules: &[(&'static str, String)]) -> tempfile::TempDir {
    let ws = workspace("sentinel", names[0], SENTINEL_SETUP, rules);
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/sentinel.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    let first = &text[text.find("[[tenants]]").unwrap()..];
    let mut all = text.clone();
    for name in &names[1..] {
        let tenant = first.replacen(
            &format!("[[tenants]]\nname = \"{}\"", names[0]),
            &format!("[[tenants]]\nname = \"{name}\""),
            1,
        );
        all.push('\n');
        all.push_str(&tenant);
    }
    std::fs::write(&config, all).unwrap();
    ws
}

/// A deployer that panics on the tenant `t1` once the four tenants deploying
/// at once have all started, and holds every other tenant's rule until the
/// worker thread that ran `t1` has ended (a minute at most), keeping the
/// tenants it was asked to deploy to.
struct Panicking {
    opened: Mutex<Vec<String>>,
}

/// Set when the worker thread that panicked on `t1` has ended: [`Exited`].
static T1_WORKER_EXITED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Sets [`T1_WORKER_EXITED`] when dropped.
struct Exited;

impl Drop for Exited {
    fn drop(&mut self) {
        T1_WORKER_EXITED.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

thread_local! {
    /// `t1`'s [`Exited`], kept by the worker thread that polls `t1`'s deploy
    /// (`runtime::block_on` polls it on the calling thread). A thread-local's
    /// destructor runs when its thread exits: by then the worker caught the
    /// panic, stopped the run and returned, so what waits for it needs no
    /// margin.
    static T1_WORKER: std::cell::RefCell<Option<Exited>> = const { std::cell::RefCell::new(None) };
}

/// Waits until `ready` says so. The minute only keeps a broken run from
/// hanging the test; a passing one ends on the event.
async fn wait_until(ready: impl Fn() -> bool) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !ready() && std::time::Instant::now() < until {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

impl Deployer for Panicking {
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        let tenant = cx.tenant.label.tenant.clone();
        self.opened.lock().unwrap().push(tenant.clone());
        deploying(async move {
            use std::sync::atomic::Ordering;
            if tenant == "t1" {
                // A barrier: every worker has taken its tenant, so none
                // finds the run stopped before it took one.
                wait_until(|| self.opened.lock().unwrap().len() >= 4).await;
                T1_WORKER.with(|worker| *worker.borrow_mut() = Some(Exited));
                panic!("the stand-in's crash");
            }
            // Once `t1`'s worker has exited, it had stopped the run: the
            // worker that finishes this tenant finds it stopped. No margin.
            wait_until(|| T1_WORKER_EXITED.load(Ordering::SeqCst)).await;
            Ok(DeployOutcome::new(None, request.operation))
        })
    }
}

/// [`Panicking`] as the Sentinel platform.
struct Panics(&'static Panicking);

impl Platform for Panics {
    fn id(&self) -> &'static str {
        "sentinel"
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self.0)
    }
}

/// A panic on one of the tenants deploying at once stops the run as it
/// did one tenant after another (#1998): of five Sentinel tenants, the
/// four first start, `t1` panics, and no tenant starts after it while the
/// three others finish.
#[test]
fn a_panic_on_a_tenant_deploying_at_once_starts_no_other_tenant() {
    let ws = sentinel_tenants(
        &["t0", "t1", "t2", "t3", "t4"],
        &three_rules(SENTINEL_STAGING)[..1],
    );
    let panicking: &'static Panicking = Box::leak(Box::new(Panicking {
        opened: Mutex::new(Vec::new()),
    }));
    let mut registry = Registry::new();
    registry.register(Box::new(Panics(panicking))).unwrap();
    let env = Env::from_pairs([("AZURE_CLIENT_SECRET", SECRET)]);
    let (sent, stderr) = deploy(ws.path(), "sentinel", &env, &registry, 0);
    assert_eq!(
        value(&sent, "message"),
        &Json::str("the deploy stopped unexpectedly"),
        "{stderr}"
    );
    let mut opened = panicking.opened.lock().unwrap().clone();
    opened.sort();
    assert_eq!(opened, ["t0", "t1", "t2", "t3"], "{stderr}");
}

/// A deployer that answers the rules of the tenants in `order`, one after
/// another: the n-th answer waits until n rules' lines are printed in
/// `buffer`.
struct Turns {
    order: &'static [&'static str],
    asked: Mutex<std::collections::HashMap<String, usize>>,
    buffer: Buffer,
}

impl Deployer for Turns {
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        let tenant = cx.tenant.label.tenant.clone();
        let nth = {
            let mut asked = self.asked.lock().unwrap();
            let count = asked.entry(tenant.clone()).or_default();
            *count += 1;
            *count
        };
        let turn = self
            .order
            .iter()
            .enumerate()
            .filter(|(_, name)| **name == tenant)
            .nth(nth - 1)
            .map(|(turn, _)| turn)
            .unwrap();
        deploying(async move {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while self.buffer.text().matches(" ✓ ").count() < turn
                && std::time::Instant::now() < until
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Ok(DeployOutcome::new(None, request.operation))
        })
    }
}

/// [`Turns`] as the Sentinel platform.
struct Takes(&'static Turns);

impl Platform for Takes {
    fn id(&self) -> &'static str {
        "sentinel"
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self.0)
    }
}

/// The lines of tenants deploying at once interleave, and each rule's line
/// stays under its own tenant's header (#1998): a line that follows
/// another tenant's prints its `Deploying to` header again first.
#[test]
fn interleaved_rule_lines_each_come_under_their_tenants_header() {
    let ws = sentinel_tenants(&["soc", "lab"], &three_rules(SENTINEL_STAGING)[..2]);
    let buffer = Buffer::default();
    let turns: &'static Turns = Box::leak(Box::new(Turns {
        order: &["soc", "lab", "lab", "soc"],
        asked: Mutex::new(std::collections::HashMap::new()),
        buffer: buffer.clone(),
    }));
    let mut registry = Registry::new();
    registry.register(Box::new(Takes(turns))).unwrap();
    let env = Env::from_pairs([("AZURE_CLIENT_SECRET", SECRET)]);
    let args = Args {
        strategies: vec!["PREVIEW".into(), "RELEASE".into()],
        all: true,
        platform: Some("sentinel".to_owned()),
        keep_deprecated: Some(true),
        ..Args::default()
    };
    let (sent, stderr) = deploy_into(ws.path(), &args, &env, &registry, 0, &buffer);
    // Each header, and each rule's line up to its mark.
    let lines: Vec<&str> = stderr
        .lines()
        .skip_while(|line| !line.starts_with("Deploying to"))
        .filter(|line| !line.is_empty())
        .map(|line| &line[..line.find(" ✓ ").unwrap_or(line.len())])
        .collect();
    assert_eq!(
        lines[..7],
        [
            "Deploying to sentinel / soc · 2 rules",
            "  [1/2]",
            "Deploying to sentinel / lab · 2 rules",
            "  [1/2]",
            "  [2/2]",
            "Deploying to sentinel / soc · 2 rules",
            "  [2/2]",
        ],
        "{stderr}"
    );
    assert_eq!(rows(&sent).len(), 4, "{stderr}");
}
