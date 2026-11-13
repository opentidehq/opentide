//! The Google SecOps connector against a wiremock instance that answers the
//! Chronicle API: the create lifecycle sends `verifyRuleText`, `rules`, then
//! the run state (each body the 0.28.0 `.api.json` fixture), a bound rule is
//! unarchived and its text updated only when it changed, DELETION archives
//! the rule, the live check places Google's diagnostics on the block's
//! sections, and `udmSearch` returns rows. The access token is taken on the
//! wiremock server too, from a deterministic `authorized_user` document, so
//! no real credential is used.
#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::path::{Path, PathBuf};

use opentide_compile::Json;
use opentide_connectors::connector::{QueryRequest, TenantContext, TimeWindow};
use opentide_connectors::credentials::Mode;
use opentide_connectors::google_secops::auth::{Authorizer, Clock, load};
use opentide_connectors::google_secops::client::Client;
use opentide_connectors::google_secops::deploy::{Action, RuleDeploy, StateChange, deploy_rule};
use opentide_connectors::google_secops::{GoogleSecops, Instance, check_rule};
use opentide_connectors::{Environment, HttpClient, HttpSettings, Platform, Tenant, TenantLabel};
use opentide_schema::objects::platform::google_secops::assemble::AssembledRule;
use std::sync::Arc;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const RULE_ID: &str = "ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1";
const PROJECT: &str = "acme-secops";
const LOCATION: &str = "eu";
const INSTANCE_ID: &str = "3f0ac524-5ae1-4bfd-b86d-53afc953e7e6";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/google_secops")
}

fn read_json(stem: &str, kind: &str) -> serde_json::Value {
    let path = fixtures().join(format!("rule-google-secops-{stem}-1.0.{kind}.api.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn text_of(stem: &str) -> String {
    std::fs::read_to_string(fixtures().join(format!("rule-google-secops-{stem}-1.0.yaral")))
        .unwrap()
}

/// The instance resource path the fixtures carry.
fn resource() -> String {
    format!("projects/{PROJECT}/locations/{LOCATION}/instances/{INSTANCE_ID}")
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

/// A tenant whose client is unproxied, the client, and an environment whose
/// Application Default Credentials are a deterministic `authorized_user`
/// document whose token endpoint is the wiremock server (cassette
/// determinism, plan §7). The temporary directory is returned so it outlives
/// the test.
fn tenant(server: &MockServer) -> (Tenant, HttpClient, Environment, TempDir) {
    let label = TenantLabel::new("google_secops", "secops-eu");
    let settings = HttpSettings::default();
    let directory = tempfile::tempdir().unwrap();
    let adc = directory.path().join("adc.json");
    std::fs::write(
        &adc,
        serde_json::json!({
            "type": "authorized_user",
            "client_id": "cid",
            "client_secret": "cs",
            "refresh_token": "rt",
            "token_uri": format!("{}/token", server.uri()),
        })
        .to_string(),
    )
    .unwrap();
    let mut setup = toml::Table::new();
    setup.insert("project".into(), PROJECT.into());
    setup.insert("location".into(), LOCATION.into());
    setup.insert("instance".into(), INSTANCE_ID.into());
    setup.insert("endpoint".into(), server.uri().into());
    setup.insert("deletion".into(), "archive".into());
    let env = Environment::from_pairs([(
        "GOOGLE_APPLICATION_CREDENTIALS",
        adc.to_str().unwrap().to_owned(),
    )]);
    let tenant = Tenant::from_setup(
        "google_secops",
        "secops-eu",
        &setup,
        &env,
        Mode::Required,
        &settings,
    )
    .unwrap();
    let http = HttpClient::new(&label, &settings, &env, None).unwrap();
    (tenant, http, env, directory)
}

fn fixed_clock() -> Clock {
    Arc::new(|| jiff::Timestamp::from_second(1_800_000_000).unwrap())
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

fn assembled(stem: &str) -> AssembledRule {
    AssembledRule {
        name: text_of(stem)
            .strip_prefix("rule ")
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap()
            .to_owned(),
        text: text_of(stem),
        sections: Vec::new(),
    }
}

#[test]
fn a_create_verifies_then_creates_then_sets_the_run_state() {
    let runtime = runtime();
    runtime.block_on(async {
        let server = MockServer::start().await;
        mount_token(&server).await;
        let instance = resource();
        Mock::given(method("POST"))
            .and(path(format!("/v1/{instance}:verifyRuleText")))
            .and(body_json(
                read_json("process", "verify").get("body").unwrap().clone(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"success": true, "allowedRunFrequencies": ["LIVE", "DAILY"]}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/{instance}/rules")))
            .and(body_json(
                read_json("process", "create").get("body").unwrap().clone(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": format!("{instance}/rules/{RULE_ID}")
            })))
            .expect(1)
            .mount(&server)
            .await;
        let deployment_body = read_json("process", "deployment");
        Mock::given(method("PATCH"))
            .and(path(format!("/v1/{instance}/rules/{RULE_ID}/deployment")))
            .and(query_param("updateMask", "enabled,alerting,runFrequency"))
            .and(body_json(deployment_body.get("body").unwrap().clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;
        let (tenant, http, env, _dir) = tenant(&server);
        let authorizer = Authorizer::new(
            load(tenant.setup.get("credentials"), &env).unwrap(),
            fixed_clock(),
        );
        let cancel = CancellationToken::new();
        let cx = TenantContext {
            tenant: &tenant,
            http: &http,
            cancel: &cancel,
        };
        let rule = RuleDeploy {
            action: Action::Create,
            assembled: assembled("process"),
            run_state: opentide_compile::google_secops::run_state(
                &serde_json::from_str::<Json>(r#"{"run_frequency": "LIVE"}"#).unwrap(),
                opentide_compile::strategy::StatusStrategy::Preview,
            ),
            run_frequency: Some("LIVE".to_owned()),
            disabling: false,
            retiring: false,
            scope: None,
            delete: false,
            recreate_refusal: None,
        };
        let outcome = deploy_rule(cx, &authorizer, &server.uri(), &instance, &rule)
            .await
            .unwrap();
        assert_eq!(outcome.state, StateChange::Record(RULE_ID.to_owned()));
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        server.verify().await;
    });
}

#[test]
fn a_5xx_create_is_never_resent() {
    let runtime = runtime();
    runtime.block_on(async {
        let server = MockServer::start().await;
        mount_token(&server).await;
        let instance = resource();
        Mock::given(method("POST"))
            .and(path(format!("/v1/{instance}:verifyRuleText")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"success": true})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/{instance}/rules")))
            .respond_with(ResponseTemplate::new(500).set_body_json(
                serde_json::json!({"error": {"status": "INTERNAL", "message": "boom"}}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let (tenant, http, env, _dir) = tenant(&server);
        let authorizer = Authorizer::new(
            load(tenant.setup.get("credentials"), &env).unwrap(),
            fixed_clock(),
        );
        let cancel = CancellationToken::new();
        let cx = TenantContext {
            tenant: &tenant,
            http: &http,
            cancel: &cancel,
        };
        let rule = RuleDeploy {
            action: Action::Create,
            assembled: assembled("process"),
            run_state: opentide_compile::google_secops::RunState::disabled(),
            run_frequency: None,
            disabling: false,
            retiring: false,
            scope: None,
            delete: false,
            recreate_refusal: None,
        };
        let outcome = deploy_rule(cx, &authorizer, &server.uri(), &instance, &rule)
            .await
            .unwrap();
        assert_eq!(outcome.state, StateChange::Keep);
        assert_eq!(outcome.failures.len(), 1);
        assert_eq!(outcome.failures[0].code, "google_secops_create_unconfirmed");
        server.verify().await;
    });
}

#[test]
fn deletion_archives_the_rule() {
    let runtime = runtime();
    runtime.block_on(async {
        let server = MockServer::start().await;
        mount_token(&server).await;
        let instance = resource();
        Mock::given(method("GET"))
            .and(path(format!("/v1/{instance}/rules/{RULE_ID}/deployment")))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"enabled": true, "alerting": true, "archived": false}),
            ))
            .mount(&server)
            .await;
        let archive = read_json("process", "archive");
        let steps = archive.as_array().unwrap().clone();
        for step in steps {
            let mask = step["query"]["updateMask"].as_str().unwrap().to_owned();
            Mock::given(method("PATCH"))
                .and(path(format!("/v1/{instance}/rules/{RULE_ID}/deployment")))
                .and(query_param("updateMask", mask))
                .and(body_json(step["body"].clone()))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
                .expect(1)
                .mount(&server)
                .await;
        }
        let (tenant, http, env, _dir) = tenant(&server);
        let authorizer = Authorizer::new(
            load(tenant.setup.get("credentials"), &env).unwrap(),
            fixed_clock(),
        );
        let cancel = CancellationToken::new();
        let cx = TenantContext {
            tenant: &tenant,
            http: &http,
            cancel: &cancel,
        };
        let rule = RuleDeploy {
            action: Action::Delete(RULE_ID.to_owned()),
            assembled: assembled("process"),
            run_state: opentide_compile::google_secops::RunState::disabled(),
            run_frequency: None,
            disabling: false,
            retiring: true,
            scope: None,
            delete: false,
            recreate_refusal: None,
        };
        let outcome = deploy_rule(cx, &authorizer, &server.uri(), &instance, &rule)
            .await
            .unwrap();
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        server.verify().await;
    });
}

#[test]
fn the_live_check_places_diagnostics_on_sections_and_the_runner_returns_rows() {
    let runtime = runtime();
    runtime.block_on(async {
        let server = MockServer::start().await;
        mount_token(&server).await;
        let instance = resource();
        Mock::given(method("POST"))
            .and(path(format!("/v1/{instance}:verifyRuleText")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "compilationDiagnostics": [{
                    "message": "unknown field",
                    "severity": "ERROR",
                    "position": {"startLine": 11, "startColumn": 9}
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/{instance}:udmSearch")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "events": {"events": [{"udm": {"metadata": {"eventType": "PROCESS_LAUNCH"}}}]}
            })))
            .mount(&server)
            .await;
        let (tenant, http, env, _dir) = tenant(&server);
        let connector = GoogleSecops::with_clock(env, fixed_clock());
        let authorizer = connector.authorizer(&tenant).unwrap();
        let resolved = Instance::of(&tenant).unwrap();
        let cancel = CancellationToken::new();
        let cx = TenantContext {
            tenant: &tenant,
            http: &http,
            cancel: &cancel,
        };
        let client = Client::new(cx, &authorizer, &resolved.endpoint, &resolved.resource);
        let check = check_rule(&client, &assembled("process"), Some("LIVE"))
            .await
            .unwrap();
        assert_eq!(check.errors.len(), 1);
        // The diagnostics module's own tests prove a position maps to the
        // section key and line; here the assembled rule carries no sections,
        // so the finding lands on the block.
        assert!(
            check.errors[0]
                == "google_secops_compile_error: configurations.google_secops: unknown field",
            "{}",
            check.errors[0]
        );
        // The runner returns the event's flattened UDM.
        let window = TimeWindow::check(jiff::Timestamp::from_second(1_800_000_000).unwrap());
        let request = QueryRequest::new("$e.metadata.event_type = \"X\"", "yaral", window);
        let platform = connector.query_runner().unwrap();
        let outcome = platform.run(cx, &request).await.unwrap();
        assert_eq!(outcome.rows.len(), 1);
        assert_eq!(outcome.columns[0].name, "metadata.eventType");
    });
}
