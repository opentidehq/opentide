//! Datadog against a stand-in tenant (wiremock), RFC
//! `docs/internal/rfc-datadog-cloud-siem.md` §8: the keys every call carries,
//! validation before each write, the create with the body of
//! `tests/fixtures/datadog/rule-datadog-threshold-1.0.create.api.json`, an
//! unchanged rule sent no `PUT`, an update with the `version` read, a
//! disable, a delete, a rule gone or a default rule, `429`s and their reset,
//! each failure code, and Logs Search for `opentide query` and `validate
//! query --live`.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentide_compile::Json;
use opentide_connectors::connector::{
    DeployRequest, DeployScope, Operation, QueryRequest, TenantContext, TimeWindow,
};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::datadog::{
    self, Action, Datadog, RuleDeploy, RuleOutcome, Session, StateChange, check_rule, deploy_rule,
};
use opentide_connectors::pace::Clock;
use opentide_connectors::{ConnectorError, Environment, HttpClient, Platform, Tenant};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{body_json, body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const RULES: &str = "/api/v2/security_monitoring/rules";
const VALIDATION: &str = "/api/v2/security_monitoring/rules/validation";
const SEARCH: &str = "/api/v2/logs/events/search";
const ID: &str = "m0o-hto-lkb";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/datadog")
}

/// The `body` of the RFC's §7.2 request.
fn golden() -> Json {
    let text =
        std::fs::read_to_string(fixtures().join("rule-datadog-threshold-1.0.create.api.json"))
            .unwrap();
    let request: Json = serde_json::from_str(&text).unwrap();
    request.get("body").unwrap().clone()
}

fn as_json(value: &Json) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}

/// The rule as Datadog holds it once the golden body was created: the body,
/// with what Datadog adds.
fn stored(version: i64) -> serde_json::Value {
    let mut rule = as_json(&golden());
    let fields = rule.as_object_mut().unwrap();
    fields.insert("id".into(), ID.into());
    fields.insert("version".into(), version.into());
    fields.insert("isDefault".into(), false.into());
    fields.insert("isDeleted".into(), false.into());
    fields.insert("createdAt".into(), 1_764_000_000_000_i64.into());
    fields.insert("defaultTags".into(), serde_json::json!(["source:okta"]));
    // Datadog answers tags in its own order, and defaults the body left out.
    fields["tags"].as_array_mut().unwrap().reverse();
    for query in fields["queries"].as_array_mut().unwrap() {
        query["hasOptionalGroupByFields"] = false.into();
        query["metrics"] = serde_json::json!([]);
    }
    rule
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
    ) -> opentide_connectors::connector::BoxFuture<'a, Result<(), ConnectorError>> {
        *self.now.lock().unwrap() += duration;
        self.slept.lock().unwrap().push(duration);
        Box::pin(async { Ok(()) })
    }
}

/// A stand-in tenant and what a call needs.
struct Stand {
    server: MockServer,
    tenant: Tenant,
    http: HttpClient,
    cancel: CancellationToken,
    clock: Arc<Recorded>,
}

impl Stand {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let setup = format!(
            "ssl = true\nsite = \"datadoghq.eu\"\napi_key = \"$DD_API_KEY\"\n\
             app_key = \"$DD_APP_KEY\"\napi_url = \"{}/\"\n",
            server.uri()
        );
        let tenant = Self::tenant(&setup);
        let http = HttpClient::new(&tenant.label, &tenant.http, &Self::env(), None).unwrap();
        Self {
            server,
            tenant,
            http,
            cancel: CancellationToken::new(),
            clock: Arc::new(Recorded::default()),
        }
    }

    fn env() -> Environment {
        Environment::default()
            .with("DD_API_KEY", "api-key")
            .with("DD_APP_KEY", "app-key")
    }

    fn tenant(setup: &str) -> Tenant {
        let setup: toml::Table = toml::from_str(setup).unwrap();
        Tenant::from_setup(
            "datadog",
            "datadog-eu",
            &setup,
            &Self::env(),
            Resolve::Required,
            &datadog::http_defaults(),
        )
        .unwrap()
    }

    fn cx(&self) -> TenantContext<'_> {
        TenantContext {
            tenant: &self.tenant,
            http: &self.http,
            cancel: &self.cancel,
        }
    }

    fn session(&self) -> Session<'_> {
        Session::new(self.cx(), Arc::clone(&self.clock) as Arc<dyn Clock>).unwrap()
    }

    fn slept(&self) -> Vec<Duration> {
        self.clock.slept.lock().unwrap().clone()
    }

    /// Answers validation with `status`.
    async fn validation(&self, status: u16, times: u64) {
        Mock::given(method("POST"))
            .and(path(VALIDATION))
            .respond_with(ResponseTemplate::new(status))
            .expect(times)
            .mount(&self.server)
            .await;
    }

    /// Answers `GET /rules/{id}` with `rule`.
    async fn stored(&self, rule: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(format!("{RULES}/{ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(rule))
            .expect(1)
            .mount(&self.server)
            .await;
    }

    /// Expects no `PUT`, `POST` or `DELETE` of a rule.
    async fn no_writes(&self) {
        for verb in ["PUT", "DELETE"] {
            Mock::given(method(verb))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .named(format!("no {verb}"))
                .mount(&self.server)
                .await;
        }
        Mock::given(method("POST"))
            .and(path(RULES))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .named("no create")
            .mount(&self.server)
            .await;
    }

    async fn requests(&self, verb: &str, at: &str) -> Vec<Request> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.method.as_str() == verb && request.url.path() == at)
            .collect()
    }
}

fn rule(action: Action) -> RuleDeploy {
    RuleDeploy {
        action,
        body: golden(),
        disable: false,
        recreate_refusal: None,
    }
}

fn update() -> RuleDeploy {
    rule(Action::Update(ID.to_owned()))
}

fn failure_code(outcome: &RuleOutcome) -> Option<&str> {
    outcome.failure.as_ref().map(|failure| failure.code)
}

fn warnings(outcome: &RuleOutcome) -> Vec<&str> {
    outcome.warnings.iter().map(|w| w.code).collect()
}

#[tokio::test]
async fn a_create_is_validated_then_sent_with_the_rfc_body_and_records_the_id() {
    let stand = Stand::start().await;
    Mock::given(method("POST"))
        .and(path(VALIDATION))
        .and(header("DD-API-KEY", "api-key"))
        .and(header("DD-APPLICATION-KEY", "app-key"))
        .and(body_json(as_json(&golden())))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&stand.server)
        .await;
    Mock::given(method("POST"))
        .and(path(RULES))
        .and(header("DD-API-KEY", "api-key"))
        .and(body_json(as_json(&golden())))
        .respond_with(ResponseTemplate::new(200).set_body_json(stored(1)))
        .expect(1)
        .mount(&stand.server)
        .await;
    let outcome = deploy_rule(&stand.session(), &rule(Action::Create))
        .await
        .unwrap();
    assert_eq!(outcome.failure, None);
    assert_eq!(outcome.state, StateChange::Record(ID.to_owned()));
    assert_eq!(outcome.done, Some(("datadog_rule_created", ID.to_owned())));
    assert_eq!(outcome.calls, ["POST validation", "POST"]);
    // The body is sent as compiled: the RFC's key order.
    let sent = &stand.requests("POST", RULES).await[0];
    let text = String::from_utf8(sent.body.clone()).unwrap();
    assert!(text.starts_with(r#"{"name":"Okta brute force"#), "{text}");
}

/// RFC §8.2: "A fake-API test holds that an unchanged rule sends no `PUT`."
#[tokio::test]
async fn an_unchanged_rule_sends_no_put() {
    let stand = Stand::start().await;
    stand.stored(stored(7)).await;
    stand.validation(204, 0).await;
    stand.no_writes().await;
    let outcome = deploy_rule(&stand.session(), &update()).await.unwrap();
    assert_eq!(outcome.failure, None);
    assert_eq!(outcome.state, StateChange::Keep);
    assert_eq!(outcome.done, Some(("rule_unchanged", ID.to_owned())));
    assert_eq!(outcome.calls, ["GET"]);
    assert!(
        stand
            .requests("PUT", &format!("{RULES}/{ID}"))
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn a_changed_rule_is_validated_and_put_with_the_version_read() {
    let stand = Stand::start().await;
    let mut drifted = stored(7);
    drifted["cases"][0]["condition"] = "failed > 3 && success > 0".into();
    drifted["tags"] = serde_json::json!(["added-in-the-ui"]);
    stand.stored(drifted).await;
    stand.validation(204, 1).await;
    // The update takes no `type`, and writes in the defaults the body leaves
    // out (RFC §8.2), so they are cleared on the tenant too.
    let mut expected = as_json(&golden());
    expected.as_object_mut().unwrap().remove("type");
    for query in expected["queries"].as_array_mut().unwrap() {
        query["hasOptionalGroupByFields"] = false.into();
    }
    expected["version"] = 7.into();
    Mock::given(method("PUT"))
        .and(path(format!("{RULES}/{ID}")))
        .and(body_json(expected))
        .respond_with(ResponseTemplate::new(200).set_body_json(stored(8)))
        .expect(1)
        .mount(&stand.server)
        .await;
    let outcome = deploy_rule(&stand.session(), &update()).await.unwrap();
    assert_eq!(outcome.failure, None);
    assert_eq!(outcome.done, Some(("datadog_rule_updated", ID.to_owned())));
    assert_eq!(outcome.changed, ["cases", "tags"]);
    assert_eq!(outcome.calls, ["GET", "POST validation", "PUT"]);
    assert_eq!(outcome.state, StateChange::Keep);
}

#[tokio::test]
async fn a_disable_puts_is_enabled_false_and_keeps_the_binding() {
    let stand = Stand::start().await;
    // Content Datadog would now refuse does not keep the rule enabled: a
    // disable is neither compared nor validated (RFC §8.2).
    let mut drifted = stored(2);
    drifted["message"] = "edited in the UI".into();
    stand.stored(drifted).await;
    stand.validation(400, 0).await;
    Mock::given(method("PUT"))
        .and(path(format!("{RULES}/{ID}")))
        .and(body_json(
            serde_json::json!({"isEnabled": false, "version": 2}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(stored(3)))
        .expect(1)
        .mount(&stand.server)
        .await;
    let mut body = golden();
    if let Json::Object(fields) = &mut body {
        fields.insert("isEnabled".into(), Json::Bool(false));
    }
    let disable = RuleDeploy {
        body,
        disable: true,
        ..update()
    };
    let outcome = deploy_rule(&stand.session(), &disable).await.unwrap();
    assert_eq!(outcome.done, Some(("datadog_rule_disabled", ID.to_owned())));
    assert_eq!(outcome.changed, ["isEnabled"]);
    assert_eq!(outcome.state, StateChange::Keep);
}

#[tokio::test]
async fn a_rule_already_disabled_is_sent_nothing() {
    let stand = Stand::start().await;
    let mut disabled = stored(2);
    disabled["isEnabled"] = false.into();
    stand.stored(disabled).await;
    stand.validation(204, 0).await;
    stand.no_writes().await;
    let outcome = deploy_rule(
        &stand.session(),
        &RuleDeploy {
            disable: true,
            ..update()
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome.done, Some(("rule_unchanged", ID.to_owned())));
}

/// A signal grouping set in the UI, which the block does not set, is
/// cleared by the update, so the next deploy finds the rule unchanged
/// instead of sending the same `PUT` on every run.
#[tokio::test]
async fn a_grouping_the_block_does_not_set_is_cleared_once() {
    let stand = Stand::start().await;
    let mut body = golden();
    if let Json::Object(fields) = &mut body {
        fields.shift_remove("groupSignalsBy");
    }
    let mut on_tenant = stored(3);
    on_tenant.as_object_mut().unwrap().remove("groupSignalsBy");
    on_tenant["groupSignalsBy"] = serde_json::json!(["@usr.id"]);
    stand.stored(on_tenant).await;
    stand.validation(204, 1).await;
    Mock::given(method("PUT"))
        .and(body_partial_json(
            serde_json::json!({"groupSignalsBy": [], "version": 3}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(stored(4)))
        .expect(1)
        .mount(&stand.server)
        .await;
    let outcome = deploy_rule(
        &stand.session(),
        &RuleDeploy {
            body: body.clone(),
            ..update()
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome.changed, ["groupSignalsBy"]);
    // Datadog now holds the empty grouping: nothing differs.
    let mut after = stored(4);
    after["groupSignalsBy"] = serde_json::json!([]);
    let Json::Object(after) = serde_json::from_value::<Json>(after).unwrap() else {
        panic!("an object")
    };
    assert!(datadog::differences(&body, &after).is_empty());
}

/// An optional group-by field turned on in the UI is a difference, though
/// the body leaves the key out (its default is `false`, RFC §8.2).
#[tokio::test]
async fn a_default_changed_on_the_tenant_is_a_difference() {
    let mut on_tenant = stored(3);
    on_tenant["queries"][1]["hasOptionalGroupByFields"] = true.into();
    let Json::Object(on_tenant) = serde_json::from_value::<Json>(on_tenant).unwrap() else {
        panic!("an object")
    };
    assert_eq!(datadog::differences(&golden(), &on_tenant), ["queries"]);
}

#[tokio::test]
async fn a_reset_too_large_for_a_duration_is_not_waited_for() {
    assert_eq!(datadog::rate_limit_reset("1e20"), Some(Duration::MAX));
    let stand = Stand::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("X-RateLimit-Reset", "1e20"))
        .expect(1)
        .mount(&stand.server)
        .await;
    let outcome = deploy_rule(&stand.session(), &update()).await.unwrap();
    assert_eq!(failure_code(&outcome), Some("datadog_rate_limited"));
    assert!(stand.slept().is_empty());
}

#[tokio::test]
async fn a_stale_version_is_a_concurrent_modification_not_a_refused_key() {
    let stand = Stand::start().await;
    let mut drifted = stored(4);
    drifted["message"] = "edited".into();
    stand.stored(drifted).await;
    stand.validation(204, 1).await;
    Mock::given(method("PUT"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({"errors": ["Unauthorized"]})),
        )
        .expect(1)
        .mount(&stand.server)
        .await;
    let outcome = deploy_rule(&stand.session(), &update()).await.unwrap();
    assert_eq!(
        failure_code(&outcome),
        Some("datadog_concurrent_modification")
    );
    assert_eq!(outcome.state, StateChange::Keep);
}

#[tokio::test]
async fn an_invalid_body_fails_with_datadog_s_errors_before_any_write() {
    let stand = Stand::start().await;
    Mock::given(method("POST"))
        .and(path(VALIDATION))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "errors": ["Invalid query: unbalanced parenthesis", "keepAlive is too long"]
        })))
        .expect(1)
        .mount(&stand.server)
        .await;
    stand.no_writes().await;
    let outcome = deploy_rule(&stand.session(), &rule(Action::Create))
        .await
        .unwrap();
    let failure = outcome.failure.unwrap();
    assert_eq!(failure.code, "datadog_rule_invalid");
    assert!(
        failure.message.contains("unbalanced parenthesis"),
        "{}",
        failure.message
    );
    assert_eq!(
        failure.fields,
        vec![(
            "errors",
            r#"["Invalid query: unbalanced parenthesis","keepAlive is too long"]"#.to_owned()
        )]
    );
    assert_eq!(outcome.state, StateChange::Keep);
}

#[tokio::test]
async fn a_default_rule_is_never_changed_nor_deleted() {
    for action in [Action::Update(ID.to_owned()), Action::Delete(ID.to_owned())] {
        let stand = Stand::start().await;
        let mut default = stored(1);
        default["isDefault"] = true.into();
        default["name"] = "Something else".into();
        stand.stored(default).await;
        stand.validation(204, 0).await;
        stand.no_writes().await;
        let outcome = deploy_rule(&stand.session(), &rule(action.clone()))
            .await
            .unwrap();
        assert_eq!(
            failure_code(&outcome),
            Some("datadog_rule_default"),
            "{action:?}"
        );
        assert_eq!(outcome.state, StateChange::Keep);
    }
}

#[tokio::test]
async fn a_rule_gone_is_created_again_and_its_new_id_recorded() {
    for gone in [
        None,
        Some(serde_json::json!({"id": ID, "isDeleted": true, "version": 3})),
    ] {
        let stand = Stand::start().await;
        let get = Mock::given(method("GET")).and(path(format!("{RULES}/{ID}")));
        match &gone {
            None => get.respond_with(ResponseTemplate::new(404)),
            Some(rule) => get.respond_with(ResponseTemplate::new(200).set_body_json(rule.clone())),
        }
        .expect(1)
        .mount(&stand.server)
        .await;
        stand.validation(204, 1).await;
        let mut created = stored(1);
        created["id"] = "new-id0-abc".into();
        Mock::given(method("POST"))
            .and(path(RULES))
            .respond_with(ResponseTemplate::new(200).set_body_json(created))
            .expect(1)
            .mount(&stand.server)
            .await;
        let outcome = deploy_rule(&stand.session(), &update()).await.unwrap();
        assert_eq!(warnings(&outcome), ["datadog_rule_recreated"], "{gone:?}");
        assert_eq!(outcome.state, StateChange::Record("new-id0-abc".to_owned()));
    }
}

#[tokio::test]
async fn a_rule_gone_is_not_created_again_when_its_id_could_not_be_kept() {
    let stand = Stand::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&stand.server)
        .await;
    stand.validation(204, 0).await;
    stand.no_writes().await;
    let refused = RuleDeploy {
        recreate_refusal: Some((
            "deployment_state_unpersisted",
            "a CI preview run cannot keep a new id".to_owned(),
        )),
        ..update()
    };
    let outcome = deploy_rule(&stand.session(), &refused).await.unwrap();
    assert_eq!(warnings(&outcome), ["datadog_rule_recreated"]);
    assert_eq!(failure_code(&outcome), Some("deployment_state_unpersisted"));
}

#[tokio::test]
async fn disabling_or_deleting_a_rule_gone_forgets_it() {
    for (action, disable) in [
        (Action::Update(ID.to_owned()), true),
        (Action::Delete(ID.to_owned()), false),
    ] {
        let stand = Stand::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&stand.server)
            .await;
        stand.no_writes().await;
        let outcome = deploy_rule(
            &stand.session(),
            &RuleDeploy {
                disable,
                ..rule(action)
            },
        )
        .await
        .unwrap();
        assert_eq!(warnings(&outcome), ["datadog_rule_missing"]);
        assert_eq!(outcome.state, StateChange::Forget);
        assert_eq!(outcome.failure, None);
    }
}

#[tokio::test]
async fn a_deletion_reads_the_rule_then_deletes_it() {
    let stand = Stand::start().await;
    stand.stored(stored(5)).await;
    Mock::given(method("DELETE"))
        .and(path(format!("{RULES}/{ID}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&stand.server)
        .await;
    let outcome = deploy_rule(&stand.session(), &rule(Action::Delete(ID.to_owned())))
        .await
        .unwrap();
    assert_eq!(outcome.done, Some(("datadog_rule_deleted", ID.to_owned())));
    assert_eq!(outcome.state, StateChange::Forget);
    assert_eq!(outcome.calls, ["GET", "DELETE"]);
}

#[tokio::test]
async fn a_create_that_gets_a_5xx_is_unconfirmed_and_not_sent_again() {
    let stand = Stand::start().await;
    stand.validation(204, 1).await;
    Mock::given(method("POST"))
        .and(path(RULES))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&stand.server)
        .await;
    let outcome = deploy_rule(&stand.session(), &rule(Action::Create))
        .await
        .unwrap();
    assert_eq!(failure_code(&outcome), Some("datadog_create_unconfirmed"));
    assert_eq!(outcome.state, StateChange::Keep);
    assert!(stand.slept().is_empty());
}

#[tokio::test]
async fn a_429_waits_out_the_reset_and_sends_the_same_request_again() {
    let stand = Stand::start().await;
    Mock::given(method("POST"))
        .and(path(VALIDATION))
        .respond_with(ResponseTemplate::new(429).insert_header("X-RateLimit-Reset", "7"))
        .up_to_n_times(2)
        .mount(&stand.server)
        .await;
    stand.validation(204, 1).await;
    Mock::given(method("POST"))
        .and(path(RULES))
        .respond_with(ResponseTemplate::new(429).insert_header("X-RateLimit-Reset", "3"))
        .up_to_n_times(1)
        .mount(&stand.server)
        .await;
    Mock::given(method("POST"))
        .and(path(RULES))
        .respond_with(ResponseTemplate::new(200).set_body_json(stored(1)))
        .expect(1)
        .mount(&stand.server)
        .await;
    let outcome = deploy_rule(&stand.session(), &rule(Action::Create))
        .await
        .unwrap();
    assert_eq!(outcome.failure, None);
    assert_eq!(outcome.state, StateChange::Record(ID.to_owned()));
    assert_eq!(
        stand.slept(),
        [
            Duration::from_secs(7),
            Duration::from_secs(7),
            Duration::from_secs(3)
        ]
    );
}

#[tokio::test]
async fn a_long_or_endless_rate_limit_fails_the_rule() {
    // A reset more than 120 seconds away is not waited for.
    let stand = Stand::start().await;
    Mock::given(method("POST"))
        .and(path(VALIDATION))
        .respond_with(ResponseTemplate::new(429).insert_header("X-RateLimit-Reset", "500"))
        .expect(1)
        .mount(&stand.server)
        .await;
    let outcome = deploy_rule(&stand.session(), &rule(Action::Create))
        .await
        .unwrap();
    assert_eq!(failure_code(&outcome), Some("datadog_rate_limited"));
    assert!(stand.slept().is_empty());
    // Three waits, then the rule fails.
    let stand = Stand::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("X-RateLimit-Reset", "1"))
        .expect(4)
        .mount(&stand.server)
        .await;
    let outcome = deploy_rule(&stand.session(), &update()).await.unwrap();
    assert_eq!(failure_code(&outcome), Some("datadog_rate_limited"));
    assert_eq!(stand.slept(), vec![Duration::from_secs(1); 3]);
}

#[tokio::test]
async fn a_gateway_failure_of_a_read_is_retried_on_the_shared_policy() {
    let stand = Stand::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(502))
        .up_to_n_times(2)
        .mount(&stand.server)
        .await;
    stand.stored(stored(7)).await;
    let outcome = deploy_rule(&stand.session(), &update()).await.unwrap();
    assert_eq!(outcome.done, Some(("rule_unchanged", ID.to_owned())));
    assert_eq!(
        stand.slept(),
        [Duration::from_millis(500), Duration::from_secs(1)]
    );
}

#[tokio::test]
async fn a_refused_key_stops_the_tenant() {
    for status in [401_u16, 403] {
        let stand = Stand::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&stand.server)
            .await;
        let failed = deploy_rule(&stand.session(), &update()).await.unwrap_err();
        assert_eq!(failed.code, "datadog_tenant_unauthorized", "{status}");
    }
}

#[tokio::test]
async fn the_site_names_the_api_host_and_an_unknown_one_is_refused() {
    let stand = Stand::start().await;
    let cx = |tenant| TenantContext {
        tenant,
        http: &stand.http,
        cancel: &stand.cancel,
    };
    let clock = || Arc::clone(&stand.clock) as Arc<dyn Clock>;
    let eu = Stand::tenant(
        "site = \"datadoghq.eu\"\napi_key = \"$DD_API_KEY\"\napp_key = \"$DD_APP_KEY\"\n",
    );
    assert_eq!(
        Session::new(cx(&eu), clock()).unwrap().base(),
        "https://api.datadoghq.eu"
    );
    let gov = Stand::tenant(
        "site = \"us2.ddog-gov.com\"\napi_key = \"$DD_API_KEY\"\napp_key = \"$DD_APP_KEY\"\n",
    );
    assert_eq!(
        Session::new(cx(&gov), clock()).unwrap().base(),
        "https://api.us2.ddog-gov.com"
    );
    let unknown = Stand::tenant(
        "site = \"datadoghq.moon\"\napi_key = \"$DD_API_KEY\"\napp_key = \"$DD_APP_KEY\"\n",
    );
    match Session::new(cx(&unknown), clock()) {
        Err(datadog::Failure::Tenant(error)) => {
            assert_eq!(error.code, "datadog_site");
            assert!(
                error.message.contains("datadoghq.moon"),
                "{}",
                error.message
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn an_unset_key_fails_before_any_call() {
    let stand = Stand::start().await;
    let setup: toml::Table = toml::from_str(
        "site = \"datadoghq.eu\"\napi_key = \"$DD_API_KEY\"\napp_key = \"$DD_APP_KEY\"\n",
    )
    .unwrap();
    let tenant = Tenant::from_setup(
        "datadog",
        "datadog-eu",
        &setup,
        &Environment::default().with("DD_API_KEY", "k"),
        Resolve::Counting,
        &datadog::http_defaults(),
    )
    .unwrap();
    let cx = TenantContext {
        tenant: &tenant,
        http: &stand.http,
        cancel: &stand.cancel,
    };
    let opened = Datadog::new().deployer().unwrap().open(cx).await;
    let error = opened.unwrap_err();
    assert!(
        matches!(
            error.connector.as_deref(),
            Some(ConnectorError::MissingCredential { .. })
        ),
        "{error:?}"
    );
    assert!(stand.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_block_s_rule_is_validated_whole() {
    let stand = Stand::start().await;
    stand.validation(204, 1).await;
    let check = check_rule(&stand.session(), &golden()).await.unwrap();
    assert!(check.errors.is_empty());
    let stand = Stand::start().await;
    Mock::given(method("POST"))
        .and(path(VALIDATION))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({"errors": [{"detail": "unknown query b"}]})),
        )
        .mount(&stand.server)
        .await;
    let check = check_rule(&stand.session(), &golden()).await.unwrap();
    assert_eq!(check.errors, ["datadog_rule_invalid: unknown query b"]);
    let stand = Stand::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&stand.server)
        .await;
    let refused = check_rule(&stand.session(), &golden()).await.unwrap_err();
    assert!(
        matches!(refused, ConnectorError::Authentication { .. }),
        "{refused:?}"
    );
    // Any other answer fails this rule only, never a pass.
    let stand = Stand::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&stand.server)
        .await;
    let check = check_rule(&stand.session(), &golden()).await.unwrap();
    assert_eq!(check.errors.len(), 1);
    assert!(
        check.errors[0].starts_with("datadog_request_failed: "),
        "{check:?}"
    );
}

fn window() -> TimeWindow {
    TimeWindow {
        start: "2026-11-27T10:00:00Z".parse().unwrap(),
        end: "2026-11-27T11:00:00Z".parse().unwrap(),
    }
}

fn event(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "type": "log",
        "attributes": {
            "timestamp": "2026-11-27T10:30:00Z",
            "service": "okta",
            "message": "login",
            "attributes": {"usr": {"email": "a@example.com"}, "evt": {"outcome": "FAILURE"}},
        },
    })
}

#[tokio::test]
async fn a_query_pages_through_logs_search() {
    let stand = Stand::start().await;
    Mock::given(method("POST"))
        .and(path(SEARCH))
        .and(body_partial_json(serde_json::json!({
            "filter": {"query": "source:okta", "from": "2026-11-27T10:00:00Z",
                       "to": "2026-11-27T11:00:00Z"},
            "page": {"limit": 3},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [event("e1"), event("e2")],
            "meta": {"page": {"after": "cursor-2"}},
        })))
        .expect(1)
        .mount(&stand.server)
        .await;
    Mock::given(method("POST"))
        .and(path(SEARCH))
        .and(body_partial_json(
            serde_json::json!({"page": {"limit": 1, "cursor": "cursor-2"}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [event("e3")],
            "meta": {"page": {"after": "cursor-3"}},
        })))
        .expect(1)
        .mount(&stand.server)
        .await;
    let request = QueryRequest {
        limit: 2,
        ..QueryRequest::new("source:okta", "datadog", window())
    };
    let outcome = Datadog::new()
        .query_runner()
        .unwrap()
        .run(stand.cx(), &request)
        .await
        .unwrap();
    assert_eq!(outcome.rows.len(), 2);
    assert!(outcome.truncated);
    assert_eq!(
        outcome.rows[0]["@usr.email"],
        Json::Str("a@example.com".into())
    );
    assert_eq!(outcome.rows[0]["service"], Json::Str("okta".into()));
    assert_eq!(outcome.language.as_deref(), Some("datadog"));
}

#[tokio::test]
async fn the_live_check_of_a_search_reads_200_and_400() {
    let stand = Stand::start().await;
    Mock::given(method("POST"))
        .and(path(SEARCH))
        .and(body_partial_json(serde_json::json!({"page": {"limit": 1}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .expect(1)
        .mount(&stand.server)
        .await;
    let request = QueryRequest::new("*:mimikatz", "datadog", window());
    let validator = Datadog::new();
    let check = validator
        .live_validator()
        .unwrap()
        .validate(stand.cx(), &request)
        .await
        .unwrap();
    assert!(check.errors.is_empty());
    let stand = Stand::start().await;
    Mock::given(method("POST"))
        .and(path(SEARCH))
        .respond_with(ResponseTemplate::new(400).set_body_json(
            serde_json::json!({"errors": ["Invalid query: unexpected token at position 7"]}),
        ))
        .mount(&stand.server)
        .await;
    let refused = validator
        .live_validator()
        .unwrap()
        .validate(stand.cx(), &request)
        .await
        .unwrap_err();
    assert!(
        refused.text().contains("unexpected token at position 7"),
        "{}",
        refused.text()
    );
}

#[tokio::test]
async fn the_platform_deploys_through_the_generic_interface() {
    let stand = Stand::start().await;
    stand.validation(204, 1).await;
    Mock::given(method("POST"))
        .and(path(RULES))
        .respond_with(ResponseTemplate::new(200).set_body_json(stored(1)))
        .expect(1)
        .mount(&stand.server)
        .await;
    let platform = Datadog::with_clock(Arc::clone(&stand.clock) as Arc<dyn Clock>);
    let deployer = platform.deployer().unwrap();
    deployer.open(stand.cx()).await.unwrap();
    let body = serde_json::to_vec(&golden()).unwrap();
    let request = DeployRequest::new("", Operation::Create, body);
    let done = deployer.deploy(stand.cx(), &request).await.unwrap();
    assert_eq!(done.remote_id.as_deref(), Some(ID));
    assert_eq!(done.events[0].name, "datadog_rule_created");
    // A rule Datadog refuses fails the rule, with its code.
    let stand = Stand::start().await;
    stand.stored(stored(1)).await;
    let mut drifted = golden();
    if let Json::Object(fields) = &mut drifted {
        fields.insert("message".into(), "new".into());
    }
    Mock::given(method("POST"))
        .and(path(VALIDATION))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(serde_json::json!({"errors": ["bad"]})),
        )
        .mount(&stand.server)
        .await;
    let request = DeployRequest::new(ID, Operation::Update, serde_json::to_vec(&drifted).unwrap());
    let failed = deployer.deploy(stand.cx(), &request).await.unwrap_err();
    assert_eq!(failed.scope, DeployScope::Rule);
    assert_eq!(Some(failed.failure.code), Some("datadog_rule_invalid"));
    // A refused key fails the tenant.
    let stand = Stand::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&stand.server)
        .await;
    let request = DeployRequest::new(
        ID,
        Operation::Update,
        serde_json::to_vec(&golden()).unwrap(),
    );
    let failed = deployer.deploy(stand.cx(), &request).await.unwrap_err();
    assert_eq!(failed.scope, DeployScope::Tenant);
    assert_eq!(
        Some(failed.failure.code),
        Some("datadog_tenant_unauthorized")
    );
}

#[tokio::test]
async fn the_probe_reads_the_rules_and_writes_nothing() {
    let stand = Stand::start().await;
    Mock::given(method("GET"))
        .and(path(RULES))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .expect(1)
        .mount(&stand.server)
        .await;
    Datadog::new()
        .prober()
        .unwrap()
        .probe(stand.cx())
        .await
        .unwrap();
    let stand = Stand::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&stand.server)
        .await;
    assert!(
        Datadog::new()
            .prober()
            .unwrap()
            .probe(stand.cx())
            .await
            .is_err()
    );
}
