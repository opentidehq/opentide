//! Google Security Operations through the CLI flow: `deploy` and
//! `validate query --live` against a stand-in instance (wiremock) that
//! answers the Chronicle API. The access token is taken on the stand-in too,
//! from a deterministic `authorized_user` Application Default Credentials
//! document, so no real credential is used. The connector's own tests hold
//! each request body to the 0.28.0 fixtures; these hold the CLI's handling:
//! a created rule's id recorded in deployment state, a refusal failing the
//! rule, unreadable credentials failing the tenant, and the live check's
//! diagnostics and warnings in the result.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::path::Path;
use std::sync::{Arc, Mutex};

use opentide_cli::commands::deploy_send::{self, Lines, Sent};
use opentide_cli::commands::validate_live::{self, Live};
use opentide_cli::commands::validate_query::Args as QueryArgs;
use opentide_cli::env::Env;
use opentide_cli::json::Json;
use opentide_cli::render::outcome::Console;
use opentide_cli::render::text::Colour;
use opentide_connectors::Registry;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PROJECT: &str = "acme-secops";
const LOCATION: &str = "eu";
const INSTANCE: &str = "3f0ac524-5ae1-4bfd-b86d-53afc953e7e6";
const RULE_ID: &str = "ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1";
const UUID: &str = "00000000-0000-4000-8003-000000000061";

fn resource() -> String {
    format!("projects/{PROJECT}/locations/{LOCATION}/instances/{INSTANCE}")
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The 0.28.0 fixture rule, `process`, its status `status`.
fn process_rule(status: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/google_secops/rule-google-secops-process-1.0.yaml");
    std::fs::read_to_string(path)
        .unwrap()
        .replace("status: STAGING", &format!("status: {status}"))
}

/// A workspace whose one Google SecOps tenant, `secops-eu`, is the stand-in
/// at `endpoint`, with the fixture rule; and the environment whose
/// Application Default Credentials take their token there.
fn workspace(endpoint: &str, status: &str) -> (tempfile::TempDir, Env) {
    let dir = tempfile::tempdir().unwrap();
    let platforms = dir.path().join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::write(
        platforms.join("google_secops.toml"),
        format!(
            "[platform]\nenabled = true\n\n[[tenants]]\nname = \"secops-eu\"\nstrategies = \
             [\"PREVIEW\", \"RELEASE\"]\n[tenants.setup]\nssl = false\nproject = \
             \"{PROJECT}\"\nlocation = \"{LOCATION}\"\ninstance = \"{INSTANCE}\"\nendpoint = \
             \"{endpoint}\"\ndeletion = \"archive\"\n"
        ),
    )
    .unwrap();
    let rules = dir.path().join("objects/rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(rules.join("process.yaml"), process_rule(status)).unwrap();
    let adc = dir.path().join("adc.json");
    std::fs::write(
        &adc,
        format!(
            r#"{{"type": "authorized_user", "client_id": "cid", "client_secret": "cs",
                "refresh_token": "rt", "token_uri": "{endpoint}/token"}}"#
        ),
    )
    .unwrap();
    let env = Env::from_pairs([(
        "GOOGLE_APPLICATION_CREDENTIALS".to_owned(),
        adc.to_str().unwrap().to_owned(),
    )]);
    (dir, env)
}

async fn mount_token(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"access_token": "ya29.test", "expires_in": 3600}),
            ),
        )
        .mount(server)
        .await;
}

async fn mount_verify(server: &MockServer, answer: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path(format!("/v1/{}:verifyRuleText", resource())))
        .respond_with(ResponseTemplate::new(200).set_body_json(answer))
        .mount(server)
        .await;
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

/// Runs `deploy --platform google_secops --all` in `ws` with `env`.
fn deploy(ws: &Path, env: &Env) -> (Sent, String) {
    let buffer = Buffer::default();
    let args = deploy_send::Args {
        strategies: vec!["PREVIEW".into(), "RELEASE".into()],
        all: true,
        platform: Some("google_secops".to_owned()),
        keep_deprecated: Some(true),
        ..deploy_send::Args::default()
    };
    let never = || false;
    let sent = deploy_send::run(
        &args,
        &deploy_send::Context {
            repo: Some(ws.to_str().unwrap()),
            env,
            cwd: ws,
            proxy: None,
            interrupted: &never,
            now: jiff::Timestamp::from_second(1_800_000_000).unwrap(),
            registry: &Registry::new(),
            lines: Lines {
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
            },
            json: false,
            debug: false,
        },
    );
    let stderr = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    (sent, stderr)
}

/// Runs `validate query --live --platform google_secops` in `ws` with `env`.
fn live(ws: &Path, env: &Env) -> Live {
    let args = QueryArgs {
        platform: Some("google_secops".to_owned()),
        live: true,
        ..QueryArgs::default()
    };
    let never = || false;
    validate_live::run(
        &args,
        &validate_live::Context {
            repo: Some(ws.to_str().unwrap()),
            env,
            cwd: ws,
            proxy: None,
            interrupted: &never,
            now: jiff::Timestamp::from_second(1_800_000_000).unwrap(),
            registry: &opentide_connectors::builtin(),
        },
    )
}

fn value<'a>(result: &'a [(String, Json)], key: &str) -> &'a Json {
    &result
        .iter()
        .find(|(name, _)| name == key)
        .unwrap_or_else(|| panic!("no {key} in {result:?}"))
        .1
}

/// Each result row's `status` and `error`.
fn rows(sent: &Sent) -> Vec<(String, Option<String>)> {
    let Json::Array(results) = value(&sent.result, "results") else {
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

#[test]
fn a_created_rule_records_its_id_in_deployment_state() {
    let runtime = runtime();
    let server = runtime.block_on(async {
        let server = MockServer::start().await;
        mount_token(&server).await;
        mount_verify(
            &server,
            serde_json::json!({"success": true, "allowedRunFrequencies": ["LIVE", "HOURLY", "DAILY"]}),
        )
        .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/{}/rules", resource())))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"name": format!("{}/rules/{RULE_ID}", resource())}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("/v1/{}/rules/{RULE_ID}/deployment", resource())))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;
        server
    });
    let (ws, env) = workspace(&server.uri(), "STAGING");
    let (sent, stderr) = deploy(ws.path(), &env);
    assert_eq!(rows(&sent), [("deployed".to_owned(), None)], "{stderr}");
    assert_eq!(value(&sent.result, "status"), &Json::str("completed"));
    let shard = std::fs::read_to_string(
        opentide_cli::commands::deploy_state::state_dir(ws.path()).join(format!("{UUID}.json")),
    )
    .unwrap();
    assert!(shard.contains(RULE_ID), "{shard}");
    runtime.block_on(server.verify());
}

#[test]
fn a_rule_google_refuses_fails_with_the_compile_error() {
    let runtime = runtime();
    let server = runtime.block_on(async {
        let server = MockServer::start().await;
        mount_token(&server).await;
        mount_verify(
            &server,
            serde_json::json!({"compilationDiagnostics": [{
                "message": "unknown field", "severity": "ERROR",
                "position": {"startLine": 11, "startColumn": 9}
            }]}),
        )
        .await;
        server
    });
    let (ws, env) = workspace(&server.uri(), "STAGING");
    let (sent, stderr) = deploy(ws.path(), &env);
    let found = rows(&sent);
    assert_eq!(found.len(), 1, "{stderr}");
    assert_eq!(found[0].0, "failed", "{stderr}");
    assert!(
        found[0].1.as_deref().unwrap().contains("unknown field"),
        "{found:?}"
    );
}

#[test]
fn unreadable_credentials_fail_the_tenant() {
    let (ws, _) = workspace("http://127.0.0.1:9", "STAGING");
    let env = Env::from_pairs([(
        "GOOGLE_APPLICATION_CREDENTIALS".to_owned(),
        ws.path().join("missing.json").to_str().unwrap().to_owned(),
    )]);
    let (sent, stderr) = deploy(ws.path(), &env);
    assert_eq!(
        value(&sent.result, "status"),
        &Json::str("failed"),
        "{stderr}"
    );
    assert_ne!(value(&sent.result, "_exit_code"), &Json::Int(0));
}

#[test]
fn the_live_check_reports_googles_errors_and_warnings() {
    let runtime = runtime();
    let server = runtime.block_on(async {
        let server = MockServer::start().await;
        mount_token(&server).await;
        mount_verify(
            &server,
            serde_json::json!({"compilationDiagnostics": [
                {"message": "unknown field", "severity": "ERROR",
                 "position": {"startLine": 11, "startColumn": 9}},
                {"message": "slow regex", "severity": "WARNING",
                 "position": {"startLine": 12, "startColumn": 9}}
            ]}),
        )
        .await;
        server
    });
    let (ws, env) = workspace(&server.uri(), "STAGING");
    let found = live(ws.path(), &env);
    assert_eq!(value(&found.result, "status"), &Json::str("failed"));
    // Each diagnostic is logged on its rule; the result counts them.
    assert_eq!(
        value(&found.result, "error"),
        &Json::str("Queries rejected on google_secops · 1 checked on 1 tenant")
    );
    assert_eq!(
        value(&found.result, "warnings"),
        &Json::Array(vec![Json::str(
            "Query validation reported warnings for google_secops"
        )])
    );

    // An instance that compiles the rule passes it.
    let runtime = self::runtime();
    let server = runtime.block_on(async {
        let server = MockServer::start().await;
        mount_token(&server).await;
        mount_verify(
            &server,
            serde_json::json!({"success": true, "allowedRunFrequencies": ["LIVE"]}),
        )
        .await;
        server
    });
    let (ws, env) = workspace(&server.uri(), "STAGING");
    let found = live(ws.path(), &env);
    assert_eq!(
        value(&found.result, "status"),
        &Json::str("passed"),
        "{:?}",
        found.result
    );
}

#[test]
fn the_live_check_fails_every_rule_when_credentials_cannot_be_read() {
    let (ws, _) = workspace("http://127.0.0.1:9", "STAGING");
    let env = Env::from_pairs([(
        "GOOGLE_APPLICATION_CREDENTIALS".to_owned(),
        ws.path().join("missing.json").to_str().unwrap().to_owned(),
    )]);
    let found = live(ws.path(), &env);
    assert_eq!(
        value(&found.result, "status"),
        &Json::str("failed"),
        "{:?}",
        found.result
    );
}
