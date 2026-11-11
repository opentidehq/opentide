//! Sysdig against the cassette the Python deployer recorded
//! (`tests/cassettes/sysdig/deploy.json`): the tide corpus's Falco rule,
//! compiled here by `opentide-compile` as the oracle compiled it (its macros
//! and lists expanded into the condition), goes through the same ten steps
//! as `client.py`, and every request is the Python deployer's, byte for byte
//! and in order; each step changes deployment state as the oracle's did
//! (the outcomes `client.py` printed when it recorded).

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod cassette_support;

use std::path::PathBuf;
use std::sync::Arc;

use cassette_support::{replay, repo, tenant};
use opentide_compile::strategy::StatusStrategy;
use opentide_compile::{Owned, Rule, sysdig as compile};
use opentide_connectors::body::python_json;
use opentide_connectors::connector::TenantContext;
use opentide_connectors::runtime::block_on;
use opentide_connectors::sysdig::{
    self, Action, RuleDeploy, RuleOutcome, StateChange, Warning, deploy_rule,
};
use opentide_connectors::{ConnectorError, Platform};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};
use tokio_util::sync::CancellationToken;

const TOKEN: (&str, &str) = ("SYSDIG_SECURE_API_TOKEN", "sysdig-test-token-only");
const UUID: &str = "00000000-0000-4000-8003-0000005d1a90";
const POLICY: &str = "opentide managed detections";
const SETUP: &str = r#"
ssl = true
url = "https://sysdig-tenant.invalid/"
api_token = "$SYSDIG_SECURE_API_TOKEN"
"#;

/// The corpus rule, with its block's *status* and, when given, a new *name*,
/// compiled for a tenant tagged `team-blue`.
fn compiled(status: &str, name: Option<&str>) -> (compile::FalcoRule, Vec<u8>, StatusStrategy) {
    let text = std::fs::read_to_string(repo().join(
        "tests/fixtures/tide_corpus/current/Objects/Detection Rules/rule-0013-sysdig-falco.yaml",
    ))
    .unwrap();
    let mut text = text.replace("    status: STAGING", &format!("    status: {status}"));
    if let Some(name) = name {
        text = text.replacen("name: Sysdig Falco Rule\n", &format!("name: {name}\n"), 1);
    }
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.write("/ws/objects/rules/rule-0013-sysdig-falco.yaml", text);
    let workspace = Workspace::open(
        fs as Arc<dyn FileSystem>,
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from("/ws")),
                cwd: PathBuf::from("/ws"),
                ..RootOptions::default()
            },
        },
    )
    .unwrap();
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", UUID).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    let strategy = compile::strategy(&cx, &rule).unwrap();
    let falco = compile::compile(&cx, &rule, strategy, &["team-blue".to_owned()]).unwrap();
    let body = python_json(&compile::api_body(&falco).unwrap()).unwrap();
    (falco, body, strategy)
}

/// One step of `client.py`.
fn step(action: Action, status: &str, name: Option<&str>, policies: &[&str]) -> RuleDeploy {
    let (falco, body, strategy) = compiled(status, name);
    RuleDeploy {
        action,
        body,
        name: falco.name,
        tuning: falco.tuning,
        disable: strategy == StatusStrategy::Disablement,
        policies: policies.iter().map(|policy| (*policy).to_owned()).collect(),
        recreate_refusal: None,
    }
}

fn update(id: &str) -> Action {
    Action::Update(id.to_owned())
}

#[test]
fn sysdig_deploys_as_the_python_deployer_does() {
    let replay = replay("sysdig/deploy", &[TOKEN]);
    let (tenant, http) = tenant(
        &replay,
        "sysdig",
        "staging",
        SETUP,
        &sysdig::http_defaults(),
    );
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let deploy = |rule: RuleDeploy| block_on(async { deploy_rule(cx, &rule).await }).unwrap();
    let ok = |state: StateChange| RuleOutcome {
        state,
        warnings: Vec::new(),
        failure: None,
    };
    let renamed = Some("Sysdig Falco Rule (renamed)");

    // Created, recorded, then added to the tenant's policy.
    assert_eq!(
        deploy(step(Action::Create, "STAGING", None, &[POLICY])).unwrap(),
        ok(StateChange::Record("42".to_owned()))
    );
    // Updated with the version the tenant holds; already in the policy.
    assert_eq!(
        deploy(step(update("42"), "STAGING", None, &[POLICY])).unwrap(),
        ok(StateChange::Keep)
    );
    // Renamed: the policy names it anew.
    assert_eq!(
        deploy(step(update("42"), "STAGING", renamed, &[POLICY])).unwrap(),
        ok(StateChange::Keep)
    );
    // Disabled: out of the policy.
    assert_eq!(
        deploy(step(update("42"), "DISABLED", renamed, &[POLICY])).unwrap(),
        ok(StateChange::Keep)
    );
    // Deleted: forgotten.
    assert_eq!(
        deploy(step(
            Action::Delete("42".to_owned()),
            "REMOVED",
            renamed,
            &[POLICY]
        ))
        .unwrap(),
        ok(StateChange::Forget)
    );
    // The recorded rule is gone: created again, with a warning.
    let recreated = deploy(step(update("42"), "STAGING", None, &[POLICY])).unwrap();
    assert_eq!(recreated.state, StateChange::Record("43".to_owned()));
    assert_eq!(
        recreated.warnings,
        [Warning {
            event: "sysdig_rule_recreated",
            detail: "the recorded rule no longer exists on the tenant; creating it again",
        }]
    );
    assert_eq!(recreated.failure, None);
    // Gone, and to be disabled: forgotten, with a warning.
    let forgotten = deploy(step(update("99"), "DISABLED", None, &[POLICY])).unwrap();
    assert_eq!(forgotten.state, StateChange::Forget);
    assert_eq!(forgotten.warnings[0].event, "sysdig_rule_missing");
    // A policy the tenant lacks: the rule is created and recorded, and fails.
    let missing = deploy(step(
        Action::Create,
        "STAGING",
        None,
        &[POLICY, "No such policy"],
    ))
    .unwrap();
    assert_eq!(missing.state, StateChange::Record("44".to_owned()));
    assert_eq!(
        missing.failure.unwrap().message,
        "sysdig_policy_missing: no runtime policy named 'No such policy' on tenant staging; \
         create it in Sysdig Secure, or change the block's or the tenant's policies"
    );
    // A rule the tenant rejects: nothing recorded.
    let rejected = deploy(step(
        Action::Create,
        "STAGING",
        Some("Rejected rule"),
        &[POLICY],
    ))
    .unwrap();
    assert_eq!(rejected.state, StateChange::Keep);
    let failure = rejected.failure.unwrap();
    assert_eq!(failure.status, Some(422));
    assert_eq!(
        failure.message,
        r#"create rule: HTTP 422: [{"reason":"condition does not compile"}]"#
    );
    // A token the tenant refuses stops the tenant.
    let refused = deploy(step(update("401"), "STAGING", None, &[POLICY])).unwrap_err();
    assert!(
        matches!(&refused, ConnectorError::Refused { message, .. }
            if message == "Tenant staging refused the API token: HTTP 403: Forbidden: missing permission secure.rules.read"),
        "{refused}"
    );
    assert_eq!(replay.proxy.verify(), Vec::new());
}

#[test]
fn sysdig_has_a_deployer_only() {
    let platform = sysdig::Sysdig;
    assert_eq!(platform.id(), "sysdig");
    assert!(platform.deployer().is_some());
    assert!(platform.live_validator().is_none(), "no live validation");
    assert!(platform.query_runner().is_none(), "no query runner");
}

/// A tenant served by *server* (plain HTTP, no proxy).
fn local(
    server: &wiremock::MockServer,
) -> (opentide_connectors::Tenant, opentide_connectors::HttpClient) {
    let env = opentide_connectors::Environment::from_pairs([(TOKEN.0, TOKEN.1)]);
    let setup: toml::Table = toml::from_str(&format!(
        "url = \"{}\"\napi_token = \"$SYSDIG_SECURE_API_TOKEN\"",
        server.uri()
    ))
    .unwrap();
    let tenant = opentide_connectors::Tenant::from_setup(
        "sysdig",
        "staging",
        &setup,
        &env,
        opentide_connectors::credentials::Mode::Required,
        &sysdig::http_defaults(),
    )
    .unwrap();
    let http =
        opentide_connectors::HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
    (tenant, http)
}

#[test]
fn sysdig_does_not_create_again_a_rule_deployment_state_cannot_record() {
    use wiremock::matchers::{method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(
        wiremock::Mock::given(method("GET"))
            .and(path("/api/secure/rules/42"))
            .respond_with(
                wiremock::ResponseTemplate::new(404).set_body_string(r#"{"message": "not found"}"#),
            )
            .expect(1)
            .mount(&server),
    );
    let (tenant, http) = local(&server);
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let mut rule = step(update("42"), "STAGING", None, &[POLICY]);
    rule.recreate_refusal =
        Some("deployment_state_ignored: .opentide/states is ignored".to_owned());
    let outcome = block_on(async { deploy_rule(cx, &rule).await })
        .unwrap()
        .unwrap();
    assert_eq!(outcome.state, StateChange::Keep);
    assert_eq!(outcome.warnings[0].event, "sysdig_rule_recreated");
    assert_eq!(
        outcome.failure.unwrap().message,
        "deployment_state_ignored: .opentide/states is ignored"
    );
    // Only the read: no create, no policy.
    assert_eq!(rt.block_on(server.received_requests()).unwrap().len(), 1);
}

#[test]
fn sysdig_the_generic_deployer_disables_with_the_held_version_and_no_policy() {
    use wiremock::matchers::{method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(async {
        wiremock::Mock::given(method("GET"))
            .and(path("/api/secure/rules/42"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(r#"{"id": 42, "version": 7, "name": "Sysdig Falco Rule"}"#),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(method("PUT"))
            .and(path("/api/secure/rules/42"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
    });
    let (tenant, http) = local(&server);
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let (_, body, _) = compiled("DISABLED", None);
    let request = opentide_connectors::connector::DeployRequest {
        rule_id: "42".to_owned(),
        operation: opentide_connectors::connector::Operation::Disable,
        body: body.clone(),
    };
    let platform = sysdig::Sysdig;
    let outcome = block_on(async { platform.deployer().unwrap().deploy(cx, &request).await })
        .unwrap()
        .unwrap();
    assert_eq!(outcome.remote_id.as_deref(), Some("42"));
    let received = rt.block_on(server.received_requests()).unwrap();
    assert_eq!(received.len(), 2, "a read and a write, no policy");
    // The body as compiled, with the tenant's id and version last.
    let mut expected = body[..body.len() - 1].to_vec();
    expected.extend_from_slice(b", \"id\": 42, \"version\": 7}");
    assert_eq!(received[1].body, expected);
}
