//! Bitdefender GravityZone deploys against a fake Incidents API: the cases
//! of 0.28.0's `tests/test_platforms/test_bitdefender_deployer.py`, whose
//! `FakeGravityZone` answers here as a wiremock responder, JSON-RPC errors
//! in HTTP 200 included. Everything above the HTTP boundary is real: the
//! client, the pacing, the deploy steps and `opentide-compile`'s params;
//! sleeps go to a recorded clock. The bodies sent are the
//! `tests/fixtures/bitdefender/*.api.json` goldens, without their `id`.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentide_compile::bitdefender::{GravityZoneRule, compile_rule};
use opentide_compile::strategy::StatusStrategy;
use opentide_compile::{Json, Owned, Rule};
use opentide_connectors::bitdefender::{
    self, Action, Clock, Failure, Pacer, RuleDeploy, RuleOutcome, StateChange, deploy_rule_with,
};
use opentide_connectors::connector::{BoxFuture, TenantContext};
use opentide_connectors::credentials::Mode;
use opentide_connectors::runtime::block_on;
use opentide_connectors::{ConnectorError, Environment, HttpClient, HttpSettings, Tenant};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const FIRST_ID: &str = "6372b7a3897aaa77ee021642";
const NEXT_ID: &str = "6372b7a3897aaa77ee021643";
const GONE: &str = "000000000000000000000000";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bitdefender")
}

/// An answer the fake gives ahead of its normal behaviour, from the body.
type Scripted = Box<dyn Fn(&Value) -> ResponseTemplate + Send>;

/// Custom rules, answered as the Incidents API answers them
/// (`FakeGravityZone`).
#[derive(Default)]
struct State {
    calls: Vec<Value>,
    headers: Vec<BTreeMap<String, String>>,
    rules: BTreeMap<String, Value>,
    ids: VecDeque<&'static str>,
    script: VecDeque<Scripted>,
}

#[derive(Clone)]
struct Fake(Arc<Mutex<State>>);

fn error(id: &Value, code: i64, message: &str, details: Option<&str>) -> Value {
    let mut error = json!({"code": code, "message": message});
    if let Some(details) = details {
        error["data"] = json!({"details": details});
    }
    json!({"jsonrpc": "2.0", "id": id, "error": error})
}

fn answer(status: u16, body: &Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(body)
}

impl Respond for Fake {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let mut state = self.0.lock().unwrap();
        assert_eq!(request.url.path(), "/api/v1.0/jsonrpc/incidents");
        assert_eq!(body["jsonrpc"], "2.0");
        assert!(body["id"].as_str().is_some_and(|id| !id.is_empty()));
        state.calls.push(body.clone());
        state.headers.push(
            request
                .headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        value.to_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect(),
        );
        if let Some(scripted) = state.script.pop_front() {
            drop(state);
            return scripted(&body);
        }
        let (method, params, id) = (&body["method"], &body["params"], &body["id"]);
        assert_eq!(params["type"], 1, "never an exclusion rule");
        match method.as_str().unwrap() {
            "createCustomRule" => {
                assert_eq!(params["returnRuleId"], true);
                if state
                    .rules
                    .values()
                    .any(|rule| rule["name"] == params["name"])
                {
                    return answer(
                        200,
                        &error(
                            id,
                            -32602,
                            "Invalid params",
                            Some("A rule with this name already exists"),
                        ),
                    );
                }
                let rule_id = state.ids.pop_front().unwrap();
                state.rules.insert(rule_id.to_owned(), params.clone());
                answer(200, &json!({"jsonrpc": "2.0", "id": id, "result": rule_id}))
            }
            method @ ("updateCustomRule" | "deleteCustomRule") => {
                let rule_id = params["ruleId"].as_str().unwrap().to_owned();
                if !state.rules.contains_key(&rule_id) {
                    return answer(200, &error(id, -32002, "Resource not found", None));
                }
                if method == "deleteCustomRule" {
                    state.rules.remove(&rule_id);
                } else {
                    state.rules.insert(rule_id, params.clone());
                }
                answer(200, &json!({"jsonrpc": "2.0", "id": id, "result": true}))
            }
            other => panic!("unexpected method {other}"),
        }
    }
}

/// A clock that sleeps by moving its time, and records each sleep.
#[derive(Default)]
struct Recorded {
    now: Mutex<Duration>,
    slept: Mutex<Vec<Duration>>,
}

impl Clock for Recorded {
    fn now(&self) -> Duration {
        *self.now.lock().unwrap()
    }

    fn sleep<'a>(
        &'a self,
        duration: Duration,
        _cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), ConnectorError>> {
        *self.now.lock().unwrap() += duration;
        self.slept.lock().unwrap().push(duration);
        Box::pin(async { Ok(()) })
    }
}

/// One fake tenant, and what deploys to it.
struct Run {
    /// Serves the fake for the run's life.
    _runtime: tokio::runtime::Runtime,
    server: MockServer,
    fake: Fake,
    clock: Recorded,
    pacer: Pacer,
}

impl Run {
    fn new() -> Self {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let server = runtime.block_on(MockServer::start());
        let fake = Fake(Arc::new(Mutex::new(State {
            ids: VecDeque::from([FIRST_ID, NEXT_ID, "6372b7a3897aaa77ee021644"]),
            ..State::default()
        })));
        runtime.block_on(
            Mock::given(wiremock::matchers::method("POST"))
                .respond_with(fake.clone())
                .mount(&server),
        );
        Self {
            _runtime: runtime,
            server,
            fake,
            clock: Recorded::default(),
            pacer: Pacer::new(),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.fake.0.lock().unwrap()
    }

    fn script(&self, answer: impl Fn(&Value) -> ResponseTemplate + Send + 'static) {
        self.state().script.push_back(Box::new(answer));
    }

    fn methods(&self) -> Vec<String> {
        self.state()
            .calls
            .iter()
            .map(|call| call["method"].as_str().unwrap().to_owned())
            .collect()
    }

    /// The tenant, with `extra` setup lines, and its client (a timeout of
    /// `timeout`).
    fn tenant(&self, extra: &str, timeout: Duration) -> (Tenant, HttpClient) {
        self.tenant_with_key("key", extra, timeout)
    }

    /// [`Run::tenant`] with the API key `key`.
    fn tenant_with_key(&self, key: &str, extra: &str, timeout: Duration) -> (Tenant, HttpClient) {
        let setup: toml::Table = toml::from_str(&format!(
            "ssl = false\nurl = \"{}/api\"\napi_key = \"$GRAVITYZONE_API_KEY\"\n{extra}",
            self.server.uri()
        ))
        .unwrap();
        let env = Environment::from_pairs([("NO_PROXY", "*"), ("GRAVITYZONE_API_KEY", key)]);
        let defaults = HttpSettings {
            timeout,
            ..bitdefender::http_defaults()
        };
        let tenant = Tenant::from_setup(
            "bitdefender",
            "gravityzone-eu",
            &setup,
            &env,
            Mode::Required,
            &defaults,
        )
        .unwrap();
        let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
        (tenant, http)
    }

    fn deploy_on(
        &self,
        rule: &RuleDeploy,
        extra: &str,
        timeout: Duration,
    ) -> Result<RuleOutcome, ConnectorError> {
        self.deploy_with_key(rule, "key", extra, timeout)
    }

    fn deploy_with_key(
        &self,
        rule: &RuleDeploy,
        key: &str,
        extra: &str,
        timeout: Duration,
    ) -> Result<RuleOutcome, ConnectorError> {
        let (tenant, http) = self.tenant_with_key(key, extra, timeout);
        let cancel = CancellationToken::new();
        let cx = TenantContext {
            tenant: &tenant,
            http: &http,
            cancel: &cancel,
        };
        block_on(deploy_rule_with(cx, rule, &self.pacer, &self.clock)).unwrap()
    }

    fn deploy(&self, rule: &RuleDeploy) -> Result<RuleOutcome, ConnectorError> {
        self.deploy_on(rule, "", Duration::from_secs(5))
    }

    fn slept(&self) -> Vec<Duration> {
        self.clock.slept.lock().unwrap().clone()
    }
}

/// The fixture rule `name` compiled under `strategy` for the fixture tenant.
fn compiled(name: &str, strategy: StatusStrategy) -> GravityZoneRule {
    let text = std::fs::read_to_string(fixtures().join(name)).unwrap();
    let uuid = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("uuid: "))
        .unwrap()
        .to_owned();
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.write("/ws/objects/rules/r.yaml", text);
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
    let rule = Rule::new(index.get("rule", &uuid).unwrap().root().unwrap(), None);
    let tenant: toml::Value =
        toml::from_str(&std::fs::read_to_string(fixtures().join("tenant.toml")).unwrap()).unwrap();
    let tenant: Json =
        serde_json::from_value(serde_json::to_value(&tenant["tenants"][0]).unwrap()).unwrap();
    compile_rule(&cx, &rule, strategy, Some(&tenant)).unwrap()
}

fn rule(action: Action, strategy: StatusStrategy) -> RuleDeploy {
    RuleDeploy {
        action,
        compiled: compiled("rule-bitdefender-detection-1.0.yaml", strategy),
        disable: strategy == StatusStrategy::Disablement,
        actions_unsupported: false,
        recreate_refusal: None,
    }
}

fn create() -> RuleDeploy {
    rule(Action::Create, StatusStrategy::Release)
}

fn update(id: &str) -> RuleDeploy {
    rule(Action::Update(id.to_owned()), StatusStrategy::Release)
}

fn golden(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixtures().join(name)).unwrap()).unwrap()
}

fn without_id(call: &Value) -> Value {
    let mut call = call.clone();
    call.as_object_mut().unwrap().remove("id");
    call
}

fn code(outcome: &RuleOutcome) -> Option<&'static str> {
    match &outcome.failure {
        Some(Failure::Request { code, .. }) => Some(code),
        _ => None,
    }
}

fn events(outcome: &RuleOutcome) -> Vec<(&'static str, bool)> {
    outcome
        .warnings
        .iter()
        .map(|warning| (warning.event, warning.raised))
        .collect()
}

// --- create, update, disable, delete -------------------------------------------------

#[test]
fn create_sends_the_golden_and_records_the_id() {
    let run = Run::new();
    let outcome = run.deploy(&create()).unwrap();
    assert_eq!(run.methods(), ["createCustomRule"]);
    assert_eq!(
        without_id(&run.state().calls[0]),
        golden("rule-bitdefender-detection-1.0.create.api.json")
    );
    assert_eq!(outcome.state, StateChange::Record(FIRST_ID.to_owned()));
    assert_eq!(outcome.failure, None);
}

#[test]
fn update_sends_the_whole_payload_and_keeps_the_binding() {
    let run = Run::new();
    run.state()
        .rules
        .insert(FIRST_ID.to_owned(), json!({"name": "old"}));
    let outcome = run.deploy(&update(FIRST_ID)).unwrap();
    assert_eq!(run.methods(), ["updateCustomRule"]);
    assert_eq!(
        without_id(&run.state().calls[0]),
        golden("rule-bitdefender-detection-1.0.update.api.json")
    );
    assert_eq!(outcome.state, StateChange::Keep);
    assert_eq!(outcome.failure, None);
}

#[test]
fn disablement_is_an_update_with_status_zero() {
    let run = Run::new();
    run.state()
        .rules
        .insert(FIRST_ID.to_owned(), json!({"name": "old"}));
    let disable = rule(
        Action::Update(FIRST_ID.to_owned()),
        StatusStrategy::Disablement,
    );
    let outcome = run.deploy(&disable).unwrap();
    assert_eq!(
        without_id(&run.state().calls[0]),
        golden("rule-bitdefender-detection-1.0.disable.api.json")
    );
    assert_eq!(outcome.state, StateChange::Keep);
}

#[test]
fn deletion_deletes_and_forgets_even_a_rule_already_gone() {
    let run = Run::new();
    run.state()
        .rules
        .insert(FIRST_ID.to_owned(), json!({"name": "old"}));
    let delete = rule(
        Action::Delete(FIRST_ID.to_owned()),
        StatusStrategy::Deletion,
    );
    let outcome = run.deploy(&delete).unwrap();
    assert_eq!(run.state().calls[0]["method"], "deleteCustomRule");
    assert_eq!(
        run.state().calls[0]["params"],
        json!({"ruleId": FIRST_ID, "type": 1})
    );
    assert_eq!(outcome.state, StateChange::Forget);
    let gone = run.deploy(&delete).unwrap();
    assert_eq!(gone.state, StateChange::Forget);
    assert_eq!(gone.failure, None);
}

#[test]
fn a_delete_refused_otherwise_fails_the_rule_and_keeps_its_id() {
    let run = Run::new();
    run.script(|body| answer(200, &error(&body["id"], -32000, "Server error", None)));
    let delete = rule(
        Action::Delete(FIRST_ID.to_owned()),
        StatusStrategy::Deletion,
    );
    let outcome = run.deploy(&delete).unwrap();
    assert_eq!(outcome.state, StateChange::Keep);
    assert_eq!(code(&outcome), Some("bitdefender_request_failed"));
}

// --- the rule is gone ----------------------------------------------------------------

#[test]
fn an_update_of_a_rule_gone_creates_it_again() {
    let run = Run::new();
    let outcome = run.deploy(&update(GONE)).unwrap();
    assert_eq!(run.methods(), ["updateCustomRule", "createCustomRule"]);
    assert_eq!(outcome.state, StateChange::Record(FIRST_ID.to_owned()));
    assert_eq!(events(&outcome), [("bitdefender_rule_recreated", true)]);
    assert_eq!(outcome.failure, None);
}

#[test]
fn disabling_a_rule_gone_forgets_it() {
    let run = Run::new();
    let disable = rule(Action::Update(GONE.to_owned()), StatusStrategy::Disablement);
    let outcome = run.deploy(&disable).unwrap();
    assert_eq!(run.methods(), ["updateCustomRule"]);
    assert_eq!(outcome.state, StateChange::Forget);
    assert_eq!(events(&outcome), [("bitdefender_rule_missing", true)]);
    assert_eq!(outcome.failure, None);
}

#[test]
fn a_rule_gone_is_not_created_again_when_state_cannot_take_it() {
    let run = Run::new();
    let mut lost = update(GONE);
    lost.recreate_refusal = Some("deployment state is ignored".to_owned());
    let outcome = run.deploy(&lost).unwrap();
    assert_eq!(run.methods(), ["updateCustomRule"]);
    assert_eq!(
        outcome.failure,
        Some(Failure::Refused("deployment state is ignored".to_owned()))
    );
    assert_eq!(outcome.state, StateChange::Keep);
}

// --- create answers ------------------------------------------------------------------

#[test]
fn a_create_answering_no_id_fails_the_rule() {
    let run = Run::new();
    run.script(|body| {
        answer(
            200,
            &json!({"jsonrpc": "2.0", "id": body["id"], "result": true}),
        )
    });
    let outcome = run.deploy(&create()).unwrap();
    assert_eq!(code(&outcome), Some("bitdefender_create_no_id"));
    let Some(Failure::Request { error, .. }) = &outcome.failure else {
        panic!("a failure");
    };
    assert!(
        error.contains("answered True, not a 24-hex rule id"),
        "{error}"
    );
    assert_eq!(outcome.state, StateChange::Keep);
}

#[test]
fn a_name_conflict_is_not_adopted() {
    let run = Run::new();
    run.state().rules.insert(
        GONE.to_owned(),
        json!({"name": "Office application spawns encoded PowerShell"}),
    );
    let outcome = run.deploy(&create()).unwrap();
    assert_eq!(run.methods(), ["createCustomRule"]);
    assert_eq!(code(&outcome), Some("bitdefender_name_conflict"));
    assert_eq!(outcome.state, StateChange::Keep);
}

#[test]
fn a_create_with_no_answer_is_retried_once() {
    let run = Run::new();
    run.script(|body| {
        answer(
            200,
            &json!({"jsonrpc": "2.0", "id": body["id"], "result": FIRST_ID}),
        )
        .set_delay(Duration::from_secs(2))
    });
    run.state().ids.pop_front();
    let outcome = run
        .deploy_on(&create(), "", Duration::from_millis(300))
        .unwrap();
    assert_eq!(run.methods(), ["createCustomRule", "createCustomRule"]);
    assert_eq!(outcome.state, StateChange::Record(NEXT_ID.to_owned()));
    assert_eq!(events(&outcome), [("bitdefender_create_retried", false)]);
    assert_eq!(outcome.failure, None);
}

#[test]
fn a_name_conflict_on_the_retry_is_unconfirmed() {
    let run = Run::new();
    let fake = run.fake.clone();
    run.script(move |body| {
        // The first create lands, and its answer is lost.
        fake.0
            .lock()
            .unwrap()
            .rules
            .insert(GONE.to_owned(), body["params"].clone());
        ResponseTemplate::new(200).set_delay(Duration::from_secs(2))
    });
    let outcome = run
        .deploy_on(&create(), "", Duration::from_millis(300))
        .unwrap();
    assert_eq!(run.methods(), ["createCustomRule", "createCustomRule"]);
    assert_eq!(code(&outcome), Some("bitdefender_create_unconfirmed"));
    let Some(Failure::Request { error, .. }) = &outcome.failure else {
        panic!("a failure");
    };
    assert!(error.ends_with("the retry found the name taken"), "{error}");
    assert_eq!(outcome.state, StateChange::Keep);
}

#[test]
fn two_creates_without_an_answer_fail_that_rule_only() {
    let run = Run::new();
    for _ in 0..2 {
        run.script(|_| ResponseTemplate::new(200).set_delay(Duration::from_secs(2)));
    }
    let outcome = run
        .deploy_on(&create(), "", Duration::from_millis(300))
        .unwrap();
    assert_eq!(run.methods(), ["createCustomRule", "createCustomRule"]);
    assert_eq!(code(&outcome), Some("bitdefender_create_unconfirmed"));
    // The tenant goes on to the next rule.
    let yara = RuleDeploy {
        compiled: compiled("rule-bitdefender-yara-1.0.yaml", StatusStrategy::Release),
        ..create()
    };
    let next = run.deploy(&yara).unwrap();
    assert_eq!(next.state, StateChange::Record(FIRST_ID.to_owned()));
}

// --- errors, rate limits, auth -------------------------------------------------------

#[test]
fn an_error_in_http_200_fails_the_rule() {
    let run = Run::new();
    run.script(|body| {
        answer(
            200,
            &error(&body["id"], -32000, "Server error", Some("boom")),
        )
    });
    let outcome = run.deploy(&create()).unwrap();
    assert_eq!(code(&outcome), Some("bitdefender_request_failed"));
    let Some(Failure::Request { error, .. }) = &outcome.failure else {
        panic!("a failure");
    };
    assert_eq!(error, "createCustomRule: error -32000: Server error (boom)");
    assert_eq!(outcome.state, StateChange::Keep);
}

#[test]
fn an_answer_that_is_not_json_or_has_no_result_fails_the_rule() {
    let run = Run::new();
    run.script(|_| ResponseTemplate::new(502).set_body_string("<html>bad gateway</html>"));
    let outcome = run.deploy(&create()).unwrap();
    assert_eq!(code(&outcome), Some("bitdefender_request_failed"));
    run.script(|body| answer(200, &json!({"jsonrpc": "2.0", "id": body["id"]})));
    let outcome = run.deploy(&create()).unwrap();
    let Some(Failure::Request { error, .. }) = &outcome.failure else {
        panic!("a failure");
    };
    assert_eq!(error, "createCustomRule: the answer has no result");
    run.script(|_| answer(500, &json!({"jsonrpc": "2.0"})));
    let outcome = run.deploy(&create()).unwrap();
    let Some(Failure::Request { error, .. }) = &outcome.failure else {
        panic!("a failure");
    };
    assert_eq!(error, "createCustomRule: HTTP 500");
}

#[test]
fn a_kind_change_fails_the_update() {
    let run = Run::new();
    run.script(|body| {
        answer(
            200,
            &error(
                &body["id"],
                -32602,
                "Invalid params",
                Some("Rule type mismatch"),
            ),
        )
    });
    let outcome = run.deploy(&update(FIRST_ID)).unwrap();
    assert_eq!(code(&outcome), Some("bitdefender_kind_changed"));
    assert_eq!(outcome.state, StateChange::Keep);
}

#[test]
fn an_unauthorized_tenant_stops() {
    let answers: Vec<(Scripted, &str)> = vec![
        (
            Box::new(|body: &Value| {
                answer(
                    200,
                    &error(&body["id"], -32001, "API Key is not allowed", None),
                )
            }),
            "bitdefender_tenant_unauthorized: tenant gravityzone-eu refused the API key: API Key \
             is not allowed",
        ),
        (
            Box::new(|_: &Value| ResponseTemplate::new(401)),
            "bitdefender_tenant_unauthorized: tenant gravityzone-eu refused the API key: HTTP 401",
        ),
        (
            Box::new(|_: &Value| answer(403, &json!({"message": "forbidden"}))),
            "bitdefender_tenant_unauthorized: tenant gravityzone-eu refused the API key: HTTP 403",
        ),
        (
            Box::new(|body: &Value| {
                answer(200, &error(&body["id"], -32601, "Method not found", None))
            }),
            "bitdefender_incidents_api_unavailable: tenant gravityzone-eu has no \
             createCustomRule (on-premises GravityZone has no Incidents API)",
        ),
    ];
    for (scripted, message) in answers {
        let run = Run::new();
        run.state().script.push_back(scripted);
        let error = run.deploy(&create()).unwrap_err();
        assert_eq!(error.to_string(), message);
        assert_eq!(
            run.methods().len(),
            1,
            "the tenant stops at the first refusal"
        );
    }
}

#[test]
fn an_unreachable_tenant_stops() {
    let run = Run::new();
    run.script(|_| ResponseTemplate::new(200).set_delay(Duration::from_secs(2)));
    let error = run
        .deploy_on(&update(FIRST_ID), "", Duration::from_millis(300))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("bitdefender_tenant_unreachable: "),
        "{error}"
    );
}

#[test]
fn a_rate_limit_waits_and_resends_the_same_request() {
    let limited: Vec<Scripted> = vec![
        Box::new(|_| ResponseTemplate::new(429).insert_header("Retry-After", "7")),
        Box::new(|body| {
            answer(429, &error(&body["id"], -32003, "Too many requests", None))
                .insert_header("Retry-After", "7")
        }),
        Box::new(|body| {
            answer(200, &error(&body["id"], -32003, "Too many requests", None))
                .insert_header("Retry-After", "7")
        }),
    ];
    for scripted in limited {
        let run = Run::new();
        run.state().script.push_back(scripted);
        let outcome = run.deploy(&create()).unwrap();
        assert_eq!(run.methods(), ["createCustomRule", "createCustomRule"]);
        let calls = run.state().calls.clone();
        assert_eq!(calls[0], calls[1], "the same request, id included");
        assert!(run.slept().contains(&Duration::from_secs(7)));
        assert_eq!(outcome.state, StateChange::Record(FIRST_ID.to_owned()));
    }
}

#[test]
fn a_long_retry_after_is_waited_for_at_most_120_seconds() {
    // A deliberate difference from 0.28.0, which waited as long as asked
    // (CHANGELOG, [Unreleased]): every connector caps a Retry-After.
    let run = Run::new();
    run.script(|_| ResponseTemplate::new(429).insert_header("Retry-After", "3600"));
    run.script(|body| {
        answer(200, &error(&body["id"], -32003, "Too many requests", None))
            .insert_header("Retry-After", "86400")
    });
    let outcome = run.deploy(&create()).unwrap();
    assert_eq!(run.methods().len(), 3);
    assert_eq!(run.slept(), [Duration::from_secs(120); 2]);
    assert_eq!(outcome.state, StateChange::Record(FIRST_ID.to_owned()));
}

#[test]
fn a_rate_limit_that_never_clears_fails() {
    let run = Run::new();
    for _ in 0..11 {
        run.script(|_| ResponseTemplate::new(429));
    }
    let outcome = run.deploy(&update(FIRST_ID)).unwrap();
    let Some(Failure::Request { error, .. }) = &outcome.failure else {
        panic!("a failure");
    };
    assert_eq!(
        error,
        "updateCustomRule: error -32003: still rate limited after 10 waits"
    );
    assert_eq!(run.methods().len(), 11);
    assert_eq!(run.slept(), vec![Duration::from_secs(60); 11]);
}

#[test]
fn creates_and_deletes_are_paced_five_per_minute_per_key() {
    let run = Run::new();
    for index in 0..6 {
        run.state()
            .rules
            .insert(format!("{index:024x}"), json!({"name": index}));
    }
    for index in 0..6 {
        let delete = rule(
            Action::Delete(format!("{index:024x}")),
            StatusStrategy::Deletion,
        );
        assert_eq!(run.deploy(&delete).unwrap().state, StateChange::Forget);
    }
    assert_eq!(run.slept(), [Duration::from_secs(60)]);
    run.clock.slept.lock().unwrap().clear();
    run.state()
        .rules
        .insert(GONE.to_owned(), json!({"name": "kept"}));
    run.deploy(&update(GONE)).unwrap();
    assert!(run.slept().is_empty(), "an update is not paced");
    // Another tenant with another key has its own budget.
    for _ in 0..5 {
        let delete = rule(Action::Delete(GONE.to_owned()), StatusStrategy::Deletion);
        run.deploy_with_key(&delete, "other", "", Duration::from_secs(5))
            .unwrap();
    }
    assert!(run.slept().is_empty(), "another key has its own budget");
    let delete = rule(Action::Delete(GONE.to_owned()), StatusStrategy::Deletion);
    run.deploy_with_key(&delete, "other", "", Duration::from_secs(5))
        .unwrap();
    assert_eq!(run.slept(), [Duration::from_secs(60)]);
}

#[test]
fn personal_and_service_keys() {
    let run = Run::new();
    run.deploy(&create()).unwrap();
    let personal = run.state().headers[0].clone();
    // HTTP Basic with the key as the user name and no password: "key:".
    assert_eq!(personal["authorization"], "Basic a2V5Og==");
    assert!(!personal.contains_key("x-api-key"));
    assert_eq!(personal["content-type"], "application/json");
    run.deploy_on(
        &update(FIRST_ID),
        "key_type = \"service\"",
        Duration::from_secs(5),
    )
    .unwrap();
    let service = run.state().headers[1].clone();
    assert_eq!(service["x-api-key"], "key");
    assert!(!service.contains_key("authorization"));
}

#[test]
fn a_tenant_without_automatic_actions_warns() {
    let run = Run::new();
    let mut unsupported = create();
    unsupported.actions_unsupported = true;
    let outcome = run.deploy(&unsupported).unwrap();
    assert_eq!(
        events(&outcome),
        [("bitdefender_actions_unsupported", true)]
    );
}

#[test]
fn deploy_never_lists_rules() {
    let run = Run::new();
    run.deploy(&create()).unwrap();
    run.deploy(&update(FIRST_ID)).unwrap();
    run.deploy(&rule(
        Action::Delete(FIRST_ID.to_owned()),
        StatusStrategy::Deletion,
    ))
    .unwrap();
    assert!(
        !run.methods()
            .iter()
            .any(|method| method == "getCustomRulesList")
    );
}

#[test]
fn an_unset_api_key_variable_is_refused_before_any_call() {
    let run = Run::new();
    let setup: toml::Table = toml::from_str(&format!(
        "url = \"{}/api\"\napi_key = \"$GRAVITYZONE_API_KEY\"\n",
        run.server.uri()
    ))
    .unwrap();
    let env = Environment::from_pairs([("NO_PROXY", "*")]);
    let refused = Tenant::from_setup(
        "bitdefender",
        "gravityzone-eu",
        &setup,
        &env,
        Mode::Required,
        &bitdefender::http_defaults(),
    )
    .unwrap_err();
    assert!(refused.to_string().contains("GRAVITYZONE_API_KEY"));
    let tenant = Tenant::from_setup(
        "bitdefender",
        "gravityzone-eu",
        &setup,
        &env,
        Mode::Counting,
        &bitdefender::http_defaults(),
    )
    .unwrap();
    let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let error = block_on(deploy_rule_with(cx, &create(), &run.pacer, &run.clock))
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(error, ConnectorError::MissingCredential { .. }),
        "{error}"
    );
    assert!(run.methods().is_empty());
}

#[test]
fn the_platform_deploys_from_create_params() {
    use opentide_connectors::Platform as _;
    use opentide_connectors::connector::{DeployRequest, Operation};
    let platform = bitdefender::Bitdefender;
    assert_eq!(platform.id(), "bitdefender");
    let deployer = platform.deployer().unwrap();
    assert!(platform.live_validator().is_none() && platform.query_runner().is_none());
    let run = Run::new();
    let body = golden("rule-bitdefender-detection-1.0.create.api.json");
    let (tenant, http) = run.tenant("", Duration::from_secs(5));
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let request = DeployRequest {
        rule_id: String::new(),
        operation: Operation::Create,
        body: serde_json::to_vec(&body).unwrap(),
    };
    let outcome = block_on(deployer.deploy(cx, &request)).unwrap().unwrap();
    assert_eq!(outcome.remote_id.as_deref(), Some(FIRST_ID));
    assert_eq!(without_id(&run.state().calls[0]), body);
    let refused = block_on(deployer.deploy(cx, &request))
        .unwrap()
        .unwrap_err();
    assert!(
        refused
            .to_string()
            .starts_with("bitdefender_name_conflict: "),
        "{refused}"
    );
}
