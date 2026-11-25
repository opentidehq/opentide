//! Sysdig against the cassette the Python deployer recorded
//! (`tests/cassettes/sysdig/deploy.json`): the tide corpus's Falco rule,
//! compiled here by `opentide-compile` as the oracle compiled it (its macros
//! and lists expanded into the condition), goes through the same ten steps
//! as `client.py`, and every request is the Python deployer's, in order
//! (a JSON body as the same data); each step changes deployment state as the oracle's did
//! (the outcomes `client.py` printed when it recorded).

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod cassette_support;

use std::path::PathBuf;
use std::sync::Arc;

use cassette_support::{replay, repo, tenant};
use opentide_compile::strategy::StatusStrategy;
use opentide_compile::{Owned, Rule, sysdig as compile};
use opentide_connectors::connector::{Deployer as _, TenantContext};
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
    let body = serde_json::to_vec(&compile::api_body(&falco).unwrap()).unwrap();
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

/// The platform's [`Deployer`] (what `opentide::Connection::deploy` runs)
/// adds a created rule to the tenant's policies, as `opentide deploy` does
/// for a block that names none: the cassette's first step, the create and
/// the policy update, request for request.
#[test]
fn sysdig_the_generic_deployer_adds_a_created_rule_to_the_tenants_policies() {
    let recorded = cassette_first_step();
    let replay = cassette_support::replay_cassette(recorded, &[TOKEN]);
    let setup = format!("{SETUP}policies = [\"{POLICY}\"]\n");
    let (tenant, http) = tenant(
        &replay,
        "sysdig",
        "staging",
        &setup,
        &sysdig::http_defaults(),
    );
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let (_, body, _) = compiled("STAGING", None);
    let request = opentide_connectors::connector::DeployRequest::new(
        UUID.to_owned(),
        opentide_connectors::connector::Operation::Create,
        body,
    );
    let platform = sysdig::Sysdig;
    let outcome = block_on(async { platform.deployer().unwrap().deploy(cx, &request).await })
        .unwrap()
        .unwrap();
    assert_eq!(outcome.remote_id.as_deref(), Some("42"));
    assert_eq!(
        outcome.warnings,
        Vec::new(),
        "a clean create raises nothing"
    );
    assert_eq!(replay.proxy.verify(), Vec::new());
}

/// #1142: the generic deployer hands back what the deploy raised. An update
/// of a rule the tenant lost creates it again, and says so, as
/// `opentide deploy` warns `sysdig_rule_recreated`.
#[test]
fn sysdig_the_generic_deployer_reports_a_rule_created_again() {
    use wiremock::matchers::{method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(async {
        wiremock::Mock::given(method("GET"))
            .and(path("/api/secure/rules/42"))
            .respond_with(
                wiremock::ResponseTemplate::new(404).set_body_string(r#"{"message": "not found"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/api/secure/rules"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(r#"{"id": 43}"#))
            .expect(1)
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
    let (_, body, _) = compiled("STAGING", None);
    let request = opentide_connectors::connector::DeployRequest::new(
        "42".to_owned(),
        opentide_connectors::connector::Operation::Update,
        body,
    )
    .with_policies(Some(Vec::new()));
    let platform = sysdig::Sysdig;
    let outcome = block_on(async { platform.deployer().unwrap().deploy(cx, &request).await })
        .unwrap()
        .unwrap();
    assert_eq!(outcome.remote_id.as_deref(), Some("43"));
    assert_eq!(
        outcome.warnings,
        vec![opentide_connectors::connector::DeployWarning::new(
            "sysdig_rule_recreated",
            "the recorded rule no longer exists on the tenant; creating it again",
        )]
    );
    rt.block_on(server.verify());
}

/// A recorded rule the tenant lost, when deployment state cannot record a
/// new id: the generic deployer fails the rule with the request's refusal,
/// its code kept, and creates nothing.
#[test]
fn sysdig_the_generic_deployer_refuses_to_create_again_with_the_requests_refusal() {
    use opentide_connectors::connector::{DeployFailure, DeployRequest, DeployScope, Operation};
    use wiremock::matchers::{method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(async {
        wiremock::Mock::given(method("GET"))
            .and(path("/api/secure/rules/42"))
            .respond_with(
                wiremock::ResponseTemplate::new(404).set_body_string(r#"{"message": "not found"}"#),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/api/secure/rules"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(r#"{"id": 43}"#))
            .expect(0)
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
    let (_, body, _) = compiled("STAGING", None);
    let refusal = DeployFailure::new(
        "deployment_state_unpersisted",
        "deployment state is not kept here, so the new id would be lost",
    );
    let request = DeployRequest::new("42".to_owned(), Operation::Update, body)
        .with_policies(Some(Vec::new()))
        .refusing_recreate(refusal.clone());
    let error = block_on(async {
        sysdig::Sysdig
            .deployer()
            .unwrap()
            .deploy(cx, &request)
            .await
    })
    .unwrap()
    .unwrap_err();
    assert_eq!(error.scope, DeployScope::Rule);
    assert_eq!(error.failure.code, "deployment_state_unpersisted");
    assert_eq!(error.failure.message, refusal.message);
    // The warning raised before the refusal is kept, as `opentide deploy` logs it.
    let partial = error.partial.as_deref().unwrap();
    assert_eq!(partial.remote_id, None);
    assert_eq!(
        partial
            .warnings
            .iter()
            .map(|w| w.code.as_str())
            .collect::<Vec<_>>(),
        ["sysdig_rule_recreated"]
    );
    rt.block_on(server.verify());
}

/// A create Sysdig takes, then the policies it cannot list: the rule fails
/// with Sysdig's status, and keeps the new id to record (its
/// `sysdig_rule_created` event); refused credentials fail the tenant.
#[test]
fn sysdig_a_rule_created_then_refused_keeps_its_id_and_a_refused_token_fails_the_tenant() {
    use opentide_connectors::connector::{DeployEvent, DeployRequest, DeployScope, Operation};
    use wiremock::matchers::{header, method, path};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    rt.block_on(async {
        wiremock::Mock::given(method("POST"))
            .and(path("/api/secure/rules"))
            .and(header(
                "authorization",
                format!("Bearer {}", TOKEN.1).as_str(),
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(r#"{"id": 43}"#))
            .mount(&server)
            .await;
        wiremock::Mock::given(method("GET"))
            .and(path("/api/v2/policies"))
            .respond_with(wiremock::ResponseTemplate::new(500).set_body_string("down"))
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/api/secure/rules"))
            .respond_with(wiremock::ResponseTemplate::new(401).set_body_string("no"))
            .mount(&server)
            .await;
    });
    let (_, body, _) = compiled("STAGING", None);
    let deploy = |token: &str| {
        let env = opentide_connectors::Environment::from_pairs([(TOKEN.0, token)]);
        let tenant = opentide_connectors::Tenant::from_setup(
            "sysdig",
            "staging",
            &toml::from_str(&format!(
                "url = \"{}\"\napi_token = \"$SYSDIG_SECURE_API_TOKEN\"\n",
                server.uri()
            ))
            .unwrap(),
            &env,
            opentide_connectors::credentials::Mode::Required,
            &sysdig::http_defaults(),
        )
        .unwrap();
        let http =
            opentide_connectors::HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
        let cancel = CancellationToken::new();
        let cx = TenantContext {
            tenant: &tenant,
            http: &http,
            cancel: &cancel,
        };
        let request = DeployRequest::new("", Operation::Create, body.clone())
            .with_policies(Some(vec![POLICY.to_owned()]));
        block_on(async { sysdig::Sysdig.deploy(cx, &request).await })
            .unwrap()
            .unwrap_err()
    };
    let error = deploy(TOKEN.1);
    assert_eq!(error.scope, DeployScope::Rule);
    assert_eq!(error.failure.code, sysdig::REQUEST_FAILED);
    assert_eq!(error.failure.status, Some(500));
    assert_eq!(error.failure.field("tenant"), Some("staging"));
    let partial = error.partial.as_deref().unwrap();
    assert_eq!(partial.remote_id.as_deref(), Some("43"));
    assert_eq!(
        partial.events,
        [DeployEvent::new(sysdig::RULE_CREATED).with_field("rule_id", "43")]
    );
    let refused = deploy("another-token");
    assert_eq!(refused.scope, DeployScope::Tenant);
    assert_eq!(refused.partial, None);
}

/// The cassette's first step: the create, the policies read, the policy
/// that takes the rule.
fn cassette_first_step() -> opentide_cassette::Cassette {
    let full = cassette_support::cassette("sysdig/deploy");
    opentide_cassette::Cassette::new(
        &full.scenario,
        full.recorded_from,
        full.interactions[..3].to_vec(),
    )
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
    local_with(server, "")
}

/// [`local`], its setup ending with *extra*.
fn local_with(
    server: &wiremock::MockServer,
    extra: &str,
) -> (opentide_connectors::Tenant, opentide_connectors::HttpClient) {
    let env = opentide_connectors::Environment::from_pairs([(TOKEN.0, TOKEN.1)]);
    let setup: toml::Table = toml::from_str(&format!(
        "url = \"{}\"\napi_token = \"$SYSDIG_SECURE_API_TOKEN\"\n{extra}",
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

/// A rule update is a `PUT` with the version the tenant held: a 503 after
/// the tenant may have applied it is not answered with a second copy, which
/// would name a stale version. The read before it is a `GET`, retried.
#[test]
fn sysdig_a_versioned_update_is_not_sent_again_after_a_503() {
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
            .respond_with(wiremock::ResponseTemplate::new(503).set_body_string("{}"))
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
    let request = opentide_connectors::connector::DeployRequest::new(
        "42".to_owned(),
        opentide_connectors::connector::Operation::Disable,
        body,
    );
    let platform = sysdig::Sysdig;
    let _outcome = block_on(async { platform.deployer().unwrap().deploy(cx, &request).await });
    let received = rt.block_on(server.received_requests()).unwrap();
    let puts = received
        .iter()
        .filter(|request| request.method.as_str() == "PUT")
        .count();
    assert_eq!(puts, 1, "the update is sent once");
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
    let request = opentide_connectors::connector::DeployRequest::new(
        "42".to_owned(),
        opentide_connectors::connector::Operation::Disable,
        body.clone(),
    );
    let platform = sysdig::Sysdig;
    let outcome = block_on(async { platform.deployer().unwrap().deploy(cx, &request).await })
        .unwrap()
        .unwrap();
    assert_eq!(outcome.remote_id.as_deref(), Some("42"));
    let received = rt.block_on(server.received_requests()).unwrap();
    assert_eq!(received.len(), 2, "a read and a write, no policy");
    // The body as compiled, with the tenant's id and version last.
    let mut expected = body[..body.len() - 1].to_vec();
    expected.extend_from_slice(b",\"id\":42,\"version\":7}");
    assert_eq!(received[1].body, expected);
}

/// Runs *operation* on rule 42 with *body* and the request's *policies*
/// through the platform's [`Deployer`] on a tenant whose setup names
/// `POLICY` (id 7), which holds *held*: the outcome and the requests sent.
/// The tenant has rule 42, named `Sysdig Falco Rule`, when *found*.
fn deploy_with_policy(
    operation: opentide_connectors::connector::Operation,
    body: Vec<u8>,
    policies: Option<Vec<String>>,
    held: &[&str],
    found: bool,
) -> (
    Result<opentide_connectors::connector::DeployOutcome, ConnectorError>,
    Vec<wiremock::Request>,
) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(wiremock::MockServer::start());
    let listed = serde_json::json!([{"id": 7, "name": POLICY, "ruleNames": held}]);
    rt.block_on(async {
        Mock::given(method("GET"))
            .and(path("/api/secure/rules/42"))
            .respond_with(if found {
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"id": 42, "version": 7, "name": "Sysdig Falco Rule"}),
                )
            } else {
                ResponseTemplate::new(404).set_body_string(r#"{"message": "not found"}"#)
            })
            .mount(&server)
            .await;
        for verb in ["PUT", "DELETE"] {
            Mock::given(method(verb))
                .and(path("/api/secure/rules/42"))
                .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/api/v2/policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(listed))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/api/v2/policies/7"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
    });
    let (tenant, http) = local_with(&server, &format!("policies = [\"{POLICY}\"]"));
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let request =
        opentide_connectors::connector::DeployRequest::new("42".to_owned(), operation, body)
            .with_policies(policies);
    let platform = sysdig::Sysdig;
    let outcome = block_on(async {
        platform
            .deployer()
            .unwrap()
            .deploy(cx, &request)
            .await
            .map_err(opentide_connectors::connector::DeployError::into_connector)
    })
    .unwrap();
    (outcome, rt.block_on(server.received_requests()).unwrap())
}

/// The rule names the policy was saved with.
fn saved_policy(requests: &[wiremock::Request]) -> serde_json::Value {
    let put = requests
        .iter()
        .find(|request| request.url.path() == "/api/v2/policies/7")
        .unwrap();
    put.body_json::<serde_json::Value>().unwrap()["ruleNames"].clone()
}

/// A delete sent without a body (as the SDKs send one) reads the rule's
/// name from the tenant and takes it out of the tenant's policies first.
#[test]
fn sysdig_the_generic_deployer_deletes_without_a_body_out_of_the_policies() {
    let (outcome, requests) = deploy_with_policy(
        opentide_connectors::connector::Operation::Delete,
        Vec::new(),
        None,
        &["Other rule", "Sysdig Falco Rule"],
        true,
    );
    assert_eq!(outcome.unwrap().remote_id, None);
    assert_eq!(saved_policy(&requests), serde_json::json!(["Other rule"]));
    let last = requests.last().unwrap();
    assert_eq!(last.method.as_str(), "DELETE");
    assert_eq!(last.url.path(), "/api/secure/rules/42");
}

/// A disable through the platform's [`Deployer`] takes the rule out of the
/// tenant's policies, as `opentide deploy` does.
#[test]
fn sysdig_the_generic_deployer_disables_out_of_the_tenants_policies() {
    let (_, body, _) = compiled("DISABLED", None);
    let (outcome, requests) = deploy_with_policy(
        opentide_connectors::connector::Operation::Disable,
        body,
        None,
        &["Sysdig Falco Rule", "Other rule"],
        true,
    );
    assert_eq!(outcome.unwrap().remote_id.as_deref(), Some("42"));
    assert_eq!(saved_policy(&requests), serde_json::json!(["Other rule"]));
}

/// The request's policies replace the tenant's, as a block's own do in
/// `opentide deploy`: none named, none read or changed.
#[test]
fn sysdig_the_generic_deployer_takes_the_requests_policies() {
    let (_, body, _) = compiled("DISABLED", None);
    let (outcome, requests) = deploy_with_policy(
        opentide_connectors::connector::Operation::Disable,
        body,
        Some(Vec::new()),
        &["Sysdig Falco Rule"],
        true,
    );
    assert_eq!(outcome.unwrap().remote_id.as_deref(), Some("42"));
    let paths: Vec<&str> = requests.iter().map(|request| request.url.path()).collect();
    assert_eq!(paths, ["/api/secure/rules/42", "/api/secure/rules/42"]);
}

/// A delete without a body of a rule the tenant no longer has: no name to
/// take out of a policy, the delete is sent and the id forgotten.
#[test]
fn sysdig_the_generic_deployer_deletes_a_rule_the_tenant_lost() {
    let (outcome, requests) = deploy_with_policy(
        opentide_connectors::connector::Operation::Delete,
        Vec::new(),
        None,
        &["Other rule"],
        false,
    );
    assert_eq!(outcome.unwrap().remote_id, None);
    let sent: Vec<(&str, &str)> = requests
        .iter()
        .map(|request| (request.method.as_str(), request.url.path()))
        .collect();
    assert_eq!(
        sent,
        [
            ("GET", "/api/secure/rules/42"),
            ("DELETE", "/api/secure/rules/42")
        ]
    );
}
