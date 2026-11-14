//! A platform plugin's `deploy` (UC-4.5b, #835): the built-in platforms'
//! deploy, with strategies, the dry run's plan and deployment state. A
//! plugin host made here stands in for the Python binding's: its one plugin,
//! `acme`, records each request its `Deployer` receives and answers as the
//! sample plugin's tenant would (`tests/fixtures/plugin_platform/`, which
//! `tests/test_platforms/test_plugin_hook.py` runs through the binding).

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken fixture is a failure"
)]

#[path = "common/replay.rs"]
mod replay;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};
use opentide_connectors::ConnectorError;
use opentide_connectors::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, Operation, Platform, TenantContext,
};
use opentide_connectors::plugin::{PluginError, PluginHost};
use serde_json::{Value, json};

const RULE: &str = "7f0c2a51-3a9e-4d7e-9d6b-2f1a8c0e5a01";
/// The rule the fake platform creates without answering an id.
const SILENT: &str = "7f0c2a51-3a9e-4d7e-9d6b-2f1a8c0e5a03";

/// What the plugin was sent: the operation and the request's body.
static SENT: Mutex<Vec<(Operation, String, Value)>> = Mutex::new(Vec::new());

struct Acme;

impl Deployer for Acme {
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            SENT.lock()
                .unwrap()
                .push((request.operation, request.rule_id.clone(), body.clone()));
            if body["configuration"]["severity"] == json!(9) {
                return Err(ConnectorError::Refused {
                    platform: "acme".into(),
                    tenant: cx.tenant.label.tenant.clone(),
                    message: "Acme answered 422".into(),
                    detail: Some("severity 9 is out of range".into()),
                });
            }
            let remote_id = match request.operation {
                Operation::Create if request.rule_id == SILENT => None,
                Operation::Create => Some("acme-rule-17".to_owned()),
                Operation::Update | Operation::Disable => body["remote_id"]
                    .as_str()
                    .map(|id| format!("{id}-again"))
                    .filter(|_| body["configuration"]["severity"] == json!(4)),
                Operation::Delete => None,
            };
            Ok(DeployOutcome {
                remote_id: remote_id.or_else(|| body["remote_id"].as_str().map(str::to_owned)),
                operation: request.operation,
            })
        })
    }
}

impl Platform for Acme {
    fn id(&self) -> &'static str {
        "acme"
    }
    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self)
    }
    fn is_plugin(&self) -> bool {
        true
    }
}

struct Plugins;

impl PluginHost for Plugins {
    fn platforms(&self) -> Vec<Result<Box<dyn Platform>, PluginError>> {
        vec![Ok(Box::new(Acme))]
    }
}

/// The tide corpus with the sample plugin's platform enabled and its rules.
fn workspace() -> (tempfile::TempDir, PathBuf) {
    opentide_cli::plugins::set_host(Box::new(Plugins));
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus", &ws);
    let sample = replay::repo().join("tests/fixtures/plugin_platform/workspace");
    let platforms = ws.join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::copy(sample.join("acme.toml"), platforms.join("acme.toml")).unwrap();
    let rules = ws.join("Objects/Detection Rules");
    std::fs::copy(
        sample.join("rule-acme-process.yaml"),
        rules.join("rule-acme-process.yaml"),
    )
    .unwrap();
    (scratch, ws)
}

fn rule_file(ws: &Path) -> PathBuf {
    ws.join("Objects/Detection Rules/rule-acme-process.yaml")
}

/// Rewrites the sample rule's file: *find* replaced by *replace*.
fn edit(ws: &Path, find: &str, replace: &str) {
    let path = rule_file(ws);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(find), "{find} is not in the rule");
    std::fs::write(&path, text.replace(find, replace)).unwrap();
}

fn shard(ws: &Path, uuid: &str) -> PathBuf {
    ws.join(format!(".opentide/states/deployment/{uuid}.json"))
}

/// `opentide --json <words>` from *cwd*: the exit code and the document.
fn opentide(cwd: &Path, words: &[&str]) -> (i32, Value) {
    let host = Host {
        version: "0.28.1".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: Arc::new(Mutex::new(replay::Buffer::default())) as Sink,
        cwd: Some(cwd.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let mut argv = vec!["--json".to_owned()];
    argv.extend(words.iter().map(|word| (*word).to_owned()));
    let home = cwd.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs([
        ("HOME".to_owned(), home.display().to_string()),
        ("ACME_URL".to_owned(), "http://127.0.0.1:9".to_owned()),
        ("ACME_TOKEN".to_owned(), "acme-test-token".to_owned()),
    ]);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run(&argv, &env, &host, &mut out, &mut err);
    let stdout = String::from_utf8(out).unwrap();
    let document = serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("{stdout}"));
    (code, document)
}

/// What the plugin received since the last call, for the sample rule.
fn sent(uuid: &str) -> Vec<(Operation, Value)> {
    let mut all = SENT.lock().unwrap();
    let mine: Vec<(Operation, Value)> = all
        .iter()
        .filter(|(_, rule_id, _)| rule_id == uuid)
        .map(|(operation, _, body)| (*operation, body.clone()))
        .collect();
    all.retain(|(_, rule_id, _)| rule_id != uuid);
    mine
}

fn deploy(ws: &Path, strategy: &str) -> (i32, Value) {
    opentide(
        ws,
        &[
            "deploy",
            "--platform",
            "acme",
            "--strategy",
            strategy,
            "--file",
            rule_file(ws).to_str().unwrap(),
        ],
    )
}

#[test]
fn a_plugin_deploy_creates_updates_disables_and_deletes_from_deployment_state() {
    let (_scratch, ws) = workspace();

    // No state: a create, whose id is recorded.
    let (code, document) = deploy(&ws, "PREVIEW");
    assert_eq!(code, 0, "{document}");
    let [(operation, body)] = &sent(RULE)[..] else {
        panic!("one request: {document}");
    };
    assert_eq!(*operation, Operation::Create);
    assert_eq!(body["rule"]["name"], "Acme Suspicious Shell");
    assert_eq!(body["configuration"]["severity"], 3);
    assert!(body.get("remote_id").is_none(), "{body}");
    assert_eq!(document["results"][0]["status"], "deployed", "{document}");
    assert_eq!(document["changes"][0]["action"], "create", "{document}");
    let state: Value = serde_json::from_slice(&std::fs::read(shard(&ws, RULE)).unwrap()).unwrap();
    assert_eq!(state["platforms"], json!({"acme": {"lab": "acme-rule-17"}}));

    // The id in state: an update of it; the dry run plans the same.
    let (code, plan) = opentide(
        &ws,
        &[
            "deploy",
            "--platform",
            "acme",
            "--strategy",
            "PREVIEW",
            "--all",
            "--dry-run",
        ],
    );
    assert_eq!(code, 0, "{plan}");
    assert_eq!(plan["changes"][0]["action"], "update", "{plan}");
    assert_eq!(plan["plan"], json!({"acme": [RULE]}), "{plan}");
    assert!(sent(RULE).is_empty(), "a dry run sends nothing");
    let (code, document) = deploy(&ws, "PREVIEW");
    assert_eq!(code, 0, "{document}");
    let [(operation, body)] = &sent(RULE)[..] else {
        panic!("one request: {document}");
    };
    assert_eq!(*operation, Operation::Update);
    assert_eq!(body["remote_id"], "acme-rule-17");

    // A strategy that does not deploy the status sends nothing.
    let (code, document) = deploy(&ws, "RELEASE");
    assert_eq!(code, 0, "{document}");
    assert!(sent(RULE).is_empty(), "{document}");

    // An update the plugin answers with another id: the state follows.
    edit(&ws, "severity: 3", "severity: 4");
    let (code, document) = deploy(&ws, "PREVIEW");
    assert_eq!(code, 0, "{document}");
    assert_eq!(sent(RULE).len(), 1);
    let state: Value = serde_json::from_slice(&std::fs::read(shard(&ws, RULE)).unwrap()).unwrap();
    assert_eq!(
        state["platforms"],
        json!({"acme": {"lab": "acme-rule-17-again"}})
    );
    edit(&ws, "severity: 4", "severity: 3");

    // A disabled status: a disable of the stored id, by a RELEASE run (the
    // run that retires rules).
    edit(
        &ws,
        "status: STAGING\n    query",
        "status: DISABLED\n    query",
    );
    let (code, document) = deploy(&ws, "RELEASE");
    assert_eq!(code, 0, "{document}");
    let [(operation, body)] = &sent(RULE)[..] else {
        panic!("one request: {document}");
    };
    assert_eq!(*operation, Operation::Disable);
    assert_eq!(body["remote_id"], "acme-rule-17-again");

    // A removed status: a delete, and the id is forgotten.
    edit(
        &ws,
        "status: DISABLED\n    query",
        "status: REMOVED\n    query",
    );
    let (code, document) = deploy(&ws, "RELEASE");
    assert_eq!(code, 0, "{document}");
    let [(operation, _)] = &sent(RULE)[..] else {
        panic!("one request: {document}");
    };
    assert_eq!(*operation, Operation::Delete);
    assert!(!shard(&ws, RULE).exists(), "the empty shard is removed");

    // Nothing known any more: nothing to delete, a warning.
    let (code, document) = deploy(&ws, "RELEASE");
    assert_eq!(code, 0, "{document}");
    assert!(sent(RULE).is_empty(), "{document}");
    assert_eq!(document["results"][0]["status"], "skipped", "{document}");
}

#[test]
fn a_plugin_create_without_an_id_or_refused_fails_the_run() {
    let (_scratch, ws) = workspace();
    edit(&ws, RULE, SILENT);
    let (code, document) = deploy(&ws, "PREVIEW");
    assert_eq!(code, 1, "{document}");
    assert_eq!(sent(SILENT).len(), 1);
    let error = document["results"][0]["error"].as_str().unwrap();
    assert!(error.contains("returned no remote_id"), "{error}");
    assert!(!shard(&ws, SILENT).exists());

    edit(&ws, "severity: 3", "severity: 9");
    let (code, document) = deploy(&ws, "PREVIEW");
    assert_eq!(code, 1, "{document}");
    assert_eq!(sent(SILENT).len(), 1);
    assert_eq!(document["results"][0]["status"], "failed", "{document}");
    let error = document["results"][0]["error"].as_str().unwrap();
    assert_eq!(
        error,
        "PlatformRefused: Acme answered 422: severity 9 is out of range"
    );
}

#[test]
fn a_plugin_deploy_needs_a_strategy() {
    let (_scratch, ws) = workspace();
    let (code, document) = opentide(&ws, &["deploy", "--platform", "acme", "--all"]);
    assert_eq!(code, 2, "{document}");
    assert_eq!(document["failure"]["code"], "usage_missing_option");
}
