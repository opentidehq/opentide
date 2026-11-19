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
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        self.seen
            .lock()
            .unwrap()
            .push((request.rule_id.clone(), request.operation));
        let next = self.outcomes.lock().unwrap().pop_front().unwrap_or(Ok(()));
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
    let scripted: &'static Scripted = Box::leak(Box::new(Scripted {
        id: platform,
        outcomes: Mutex::new(outcomes.into()),
        seen: Mutex::new(Vec::new()),
    }));
    let mut registry = Registry::new();
    registry.register(Box::new(Forward(scripted))).unwrap();
    (registry, scripted)
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
/// next tenant gets every rule.
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
    let (registry, deployer) = scripted(
        "sentinel",
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
            ("soc", "failed"),
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
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(1));
    // One cause, one failure: the rule it came on carries it.
    let Json::Array(failures) = value(&sent, "failures") else {
        panic!("no failures")
    };
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(
        failures[0].get("error"),
        Some(&Json::str(
            "sentinel tenant 'soc': the credentials were refused"
        ))
    );
    assert_eq!(
        value(&sent, "error"),
        &Json::str(
            "Deployment to sentinel failed on First: sentinel tenant 'soc': the credentials were refused"
        )
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
    }));
    let splunk: &'static Scripted = Box::leak(Box::new(Scripted {
        id: "splunk",
        outcomes: Mutex::new(std::collections::VecDeque::new()),
        seen: Mutex::new(Vec::new()),
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
    let rows = rows(&sent);
    assert!(
        rows[0]
            .1
            .as_deref()
            .unwrap_or_default()
            .starts_with("bitdefender_tenant_unauthorized: "),
        "{rows:?}"
    );
    assert_eq!(value(&sent, "status"), &Json::str("failed"));
    assert_tenant_stopped(&sent, "lab");
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
    assert!(
        text.contains(
            "**1 failure**\n\n| Platform | Tenant | Rule | Error |\n|---|---|---|---|\n\
             | `sentinel` | soc | First (`00000000-0000-4000-8099-000000000001`) | Cannot reach"
        ),
        "{text}"
    );
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
    let text = std::fs::read_to_string(&rule).unwrap();
    assert!(text.contains("    status: PRODUCTION\n"), "{text}");
    // The promoted rule goes to the tenant, which does not resolve here:
    // the failure is that tenant's own.
    assert_eq!(code, 1, "{out}{err}");
    assert!(out.contains("\"tenant\":\"lab\""), "{out}");
    assert!(out.contains("\"failures\":[{"), "{out}");
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
    let ws = workspace(
        "splunk",
        "lab",
        "url = \"splunk.invalid\"\ntoken = \"$SPLUNK_TOKEN\"\n",
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
        ],
    );
    pushed(ws.path(), "objects/rules/r.yaml");
    let env = vec![
        ("GITHUB_ACTIONS", "true".to_owned()),
        ("GITHUB_EVENT_NAME", "push".to_owned()),
        ("GITHUB_SHA", "HEAD".to_owned()),
        ("GITHUB_WORKSPACE", ws.path().display().to_string()),
    ];
    let mut env = env;
    env.extend(
        extra
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned())),
    );
    let argv = [
        "--json",
        "deploy",
        "--platform",
        "splunk",
        "--strategy",
        "RELEASE",
    ];
    let (code, out, err) = cli(ws.path(), &argv, &env);
    // The promoted rule is routed to the tenant, which has no token here:
    // the tenant's own refusal fails the run.
    assert_eq!(code, 1, "{out}{err}");
    assert!(
        out.contains("\"tenant\":\"lab\"") && out.contains("SPLUNK_TOKEN"),
        "{out}{err}"
    );
    // Whole-folder promotion rewrites s.yaml too, but only the files the
    // push changed are deployed (#1653 tracks that gap).
    assert!(
        !out.contains("00000000-0000-4000-8047-000000000903"),
        "{out}"
    );
    let read = |name: &str| std::fs::read_to_string(ws.path().join("objects/rules").join(name));
    let changed = read("r.yaml").unwrap();
    assert!(changed.contains("    status: PRODUCTION\n"), "{changed}");
    let other = read("s.yaml").unwrap();
    other.contains("    status: PRODUCTION\n")
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
    // The first rule fails with the tenant; the second is never sent.
    assert!(
        err.contains("code: graylog_tenant_unauthenticated"),
        "{err}"
    );
    assert!(err.contains("✗ failed    First rule"), "{err}");
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
        "✓ deployed  Fresh rule",
        "✓ deployed  Present rule",
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

/// A tenant whose key Kibana refuses fails at its first rule, and no other
/// rule is sent to it.
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
    assert!(err.contains("✗ failed    First rule"), "{err}");
    assert!(
        err.contains("error: Elastic tenant deployment failed · tenant: *** · error: Tenant *** auth error: HTTP 401"),
        "{err}"
    );
}

/// A SentinelOne tenant that refuses the key (401) fails at its first rule,
/// as the SDK's `sentinel_one_unauthorized` (tenant scope) says: its other
/// rules are not attempted, and nothing more is sent to it.
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
    assert_eq!(rows[0].0, "failed", "{rows:?}");
    assert_eq!(rows[1], ("not_attempted".to_owned(), None), "{rows:?}");
    assert_eq!(value(&sent, "status"), &Json::str("failed"));
}

/// A platform none of whose tenants deployed is not in `deployed`, even when
/// its tenant failed mid-batch, on a rule (here Graylog's refused token
/// after its version was read): a failed deploy never looks deployed. The
/// tenant's other rules are not attempted, naming the tenant.
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
    assert_eq!(rows[0].0, "failed", "{rows:?}");
    assert_eq!(rows[1].0, "not_attempted", "{rows:?}");
    let Json::Array(results) = value(&sent, "results") else {
        panic!("no results")
    };
    assert_eq!(
        results[1].get("reason").and_then(Json::as_str),
        Some("not attempted: tenant lab failed")
    );
}

/// An Exabeam tenant that refuses the token on a rule fails there: its other
/// rule is not attempted, naming the tenant, and Exabeam is not deployed.
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
    assert_eq!(rows(&sent)[0].0, "failed", "{:?}", rows(&sent));
    assert_tenant_stopped(&sent, "lab");
}

/// Deployment state's Splunk entry for `uuid` on tenant `soc`: the saved
/// search's name the tenant got last, if any.
fn splunk_recorded(ws: &Path, uuid: &str) -> Option<String> {
    let text = shard_of(ws, uuid);
    if text.is_empty() {
        return None;
    }
    let shard: serde_json::Value = serde_json::from_str(&text).unwrap();
    shard["platforms"]["splunk"]["soc"]
        .as_str()
        .map(str::to_owned)
}

/// A Splunk saved search is named after its rule, so deployment state keeps
/// the name each tenant got (#1657, smoke E6): the first deploy records it,
/// a deploy under the same name sends nothing more, a renamed rule's old
/// saved search is deleted after the new one is written, and so is the one
/// a ` - Rule` suffix change leaves (`enterprise_security`); a deletion
/// forgets the name.
#[test]
fn a_renamed_splunk_rule_deletes_its_old_saved_search() {
    let uuid = "00000000-0000-4000-8099-000000000201";
    let setup = "url = \"splunk.invalid\"\ntoken = \"$SPLUNK_TOKEN\"\n";
    let ws = workspace(
        "splunk",
        "soc",
        setup,
        &[("r.yaml", rule("First name", uuid, "A rule.", SPLUNK_BLOCK))],
    );
    let env = Env::from_pairs([("SPLUNK_TOKEN", SECRET)]);
    let file = ws.path().join("objects/rules/r.yaml");
    let edit = |find: &str, replace: &str| {
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains(find), "{find}");
        std::fs::write(&file, text.replace(find, replace)).unwrap();
    };
    let sends = |expected: &[(&str, Operation)]| {
        let (registry, deployer) = scripted("splunk", Vec::new());
        let (sent, text) = deploy(ws.path(), "splunk", &env, &registry, 0);
        assert!(
            rows(&sent).iter().all(|(status, _)| status == "deployed"),
            "{text}"
        );
        let seen = deployer.seen.lock().unwrap().clone();
        let expected: Vec<(String, Operation)> = expected
            .iter()
            .map(|(name, operation)| ((*name).to_owned(), *operation))
            .collect();
        assert_eq!(seen, expected, "{text}");
    };
    // The first deploy: the name is recorded.
    sends(&[("First name", Operation::Update)]);
    assert_eq!(
        splunk_recorded(ws.path(), uuid).as_deref(),
        Some("First name")
    );
    // The same name: nothing else is sent.
    sends(&[("First name", Operation::Update)]);
    // Renamed: the new saved search, then the old one deleted.
    edit("name: First name\n", "name: Second name\n");
    sends(&[
        ("Second name", Operation::Update),
        ("First name", Operation::Delete),
    ]);
    assert_eq!(
        splunk_recorded(ws.path(), uuid).as_deref(),
        Some("Second name")
    );
    // The tenant turns Enterprise Security on: the saved search becomes a
    // correlation search named `<title> - Rule`, and the plain one goes.
    let config = ws
        .path()
        .join(".opentide/configurations/platforms/splunk.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        text.replace(
            "[tenants.setup]\n",
            "[tenants.setup]\nenterprise_security = true\n",
        ),
    )
    .unwrap();
    sends(&[
        ("Second name - Rule", Operation::Update),
        ("Second name", Operation::Delete),
    ]);
    assert_eq!(
        splunk_recorded(ws.path(), uuid).as_deref(),
        Some("Second name - Rule")
    );
    // Removed: deleted by its name, and forgotten.
    edit("status: STAGING", "status: REMOVED");
    sends(&[("Second name - Rule", Operation::Delete)]);
    assert_eq!(splunk_recorded(ws.path(), uuid), None);
}
