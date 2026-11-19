//! Elastic Security against the cassettes recorded from the Python client
//! (`tests/cassettes/elastic/`, `cargo xtask cassettes record
//! elastic/<scenario>`): every request the connector sends must be the
//! Python client's, in order (a JSON body as the same data), the retries of a gateway's
//! answer included.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod support;

use opentide_compile::json::Json;
use opentide_connectors::ConnectorError;
use opentide_connectors::connector::{
    DeployRequest, DeployScope, Deployer, Operation, QueryRequest,
};
use opentide_connectors::elastic::{self, Deployed, Elastic, ElasticError, ElasticRule, Strategy};
use opentide_connectors::runtime::block_on;
use support::{Replayed, fixture, items, text, timestamp, window};

const SETUP: &str = r#"
ssl = true
url = "https://kibana.elastic.invalid"
elasticsearch_url = "https://es.elastic.invalid"
api_key = "$ELASTIC_API_KEY"
space = "soc"
index = ["logs-*", "winlogbeat-*"]
"#;

fn setup_index() -> Vec<String> {
    vec!["logs-*".into(), "winlogbeat-*".into()]
}

fn replay(scenario: &str) -> Replayed {
    Replayed::start(
        scenario,
        elastic::PLATFORM,
        SETUP,
        "ELASTIC_API_KEY",
        &elastic::http_settings(std::time::Duration::from_secs(30)),
    )
}

/// `elastic/query` as the connector sends it: the Python client retried a
/// search (a `POST`) its gateway answered with a 504 three times, and the
/// recording holds those copies; the connector sends a `POST` once.
fn replay_query() -> Replayed {
    let mut cassette = support::cassette("elastic/query");
    let recorded = cassette.interactions.len();
    cassette.interactions.dedup_by(|retry, sent| {
        retry.request.method == "POST"
            && retry.request == sent.request
            && retry.response.status == 504
    });
    assert_eq!(
        cassette.interactions.len(),
        recorded - 3,
        "the three retries"
    );
    Replayed::start_with(
        cassette,
        elastic::PLATFORM,
        SETUP,
        "ELASTIC_API_KEY",
        &elastic::http_settings(std::time::Duration::from_secs(30)),
    )
}

fn rules(key: &str) -> Vec<ElasticRule> {
    let inputs = fixture("elastic");
    items(inputs.get(key).unwrap())
        .iter()
        .map(|rule| ElasticRule {
            rule_id: text(rule.get("rule_id").unwrap()).to_owned(),
            name: text(rule.get("name").unwrap()).to_owned(),
            strategy: match text(rule.get("status").unwrap()) {
                "REMOVED" => Strategy::Deletion,
                "DISABLED" => Strategy::Disablement,
                _ => Strategy::Active,
            },
            block: rule.get("block").unwrap().clone(),
            payload: rule.get("payload").unwrap().clone(),
        })
        .collect()
}

fn summary(deployed: &Deployed) -> String {
    match deployed {
        Deployed::Failed {
            event,
            status,
            error,
        } => {
            format!("{event} {status:?}: {error}")
        }
        other => format!("{other:?}"),
    }
}

#[test]
fn elastic_deploy_sends_what_the_python_deployer_sent() {
    let tenant = replay("elastic/deploy");
    let seen = block_on(async {
        let mut seen = Vec::new();
        for rule in rules("deploy") {
            match Elastic
                .deploy_rule(tenant.cx(), &rule, &setup_index())
                .await
            {
                Ok(outcome) => seen.push(format!(
                    "{} {}{}",
                    &rule.rule_id[34..],
                    summary(&outcome.deployed),
                    if outcome.warnings.is_empty() {
                        String::new()
                    } else {
                        format!(" {:?}", outcome.warnings)
                    }
                )),
                // The tenant refuses the key: the rest of the batch is not sent.
                Err(ElasticError::Tenant(error)) => {
                    seen.push(format!("{} tenant: {error}", &rule.rule_id[34..]));
                    break;
                }
                Err(other) => panic!("{other:?}"),
            }
        }
        seen
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(
        seen,
        [
            "01 Created",
            "02 Updated",
            "03 Recreated",
            "04 refusing_to_modify_prebuilt_rule None: refusing to modify prebuilt rule",
            "05 Deleted",
            "06 Created",
            "07 Created",
            "08 Created",
            "09 elasticsearch_checks_failed None: Data view 'dv-missing' lookup failed (HTTP 404)",
            "0a tenant: Tenant replayed auth error: HTTP 401",
        ]
    );
}

#[test]
fn elastic_a_single_byte_off_fails() {
    let mut rule = rules("deploy").remove(0);
    if let Json::Object(payload) = &mut rule.payload {
        payload.insert("risk_score".into(), Json::Int(74));
    }
    let tenant = replay("elastic/deploy");
    let _ = block_on(async {
        Elastic
            .deploy_rule(tenant.cx(), &rule, &setup_index())
            .await
    });
    let mismatches = tenant.verify();
    // The lookup is the recorded one; the create's body is not.
    assert_eq!(mismatches[0].index, 1, "{mismatches:?}");
    assert!(mismatches[0].detail.starts_with("bodies differ at byte "));
}

/// A `_find` page that is not JSON stops the listing with serde_json's
/// reason and where it found the fault.
#[test]
fn elastic_find_rules_names_a_body_that_is_not_json() {
    let mut cassette = support::cassette("elastic/deploy");
    let mut lookup = cassette.interactions.remove(0);
    lookup.request.url =
        "https://kibana.elastic.invalid/s/soc/api/detection_engine/rules/_find?page=1&per_page=100"
            .into();
    lookup.response.status = 200;
    lookup.response.body = opentide_cassette::Body::Text("<html>".into());
    cassette.interactions = vec![lookup];
    let tenant = Replayed::start_with(
        cassette,
        elastic::PLATFORM,
        SETUP,
        "ELASTIC_API_KEY",
        &elastic::http_settings(std::time::Duration::from_secs(30)),
    );
    let error = block_on(async { Elastic.find_rules(tenant.cx(), 1, 100).await })
        .unwrap()
        .unwrap_err();
    assert!(tenant.verify().is_empty(), "{:?}", tenant.verify());
    assert!(matches!(error, elastic::FindError::NotJson(_)), "{error:?}");
    assert_eq!(
        error.to_string(),
        "the response is not JSON: expected value at line 1 column 1"
    );
}

#[test]
fn elastic_query_sends_what_the_python_runner_sent() {
    let inputs = fixture("elastic");
    let query = inputs.get("query").unwrap();
    let window = window(query.get("window").unwrap());
    let tenant = replay_query();
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for item in items(query.get("queries").unwrap()) {
            let mut request = QueryRequest::new(text(item.get("text").unwrap()), "", window);
            request.limit = match item.get("limit") {
                Some(Json::Int(limit)) => usize::try_from(*limit).unwrap(),
                _ => 100,
            };
            request.language = item
                .get("language")
                .map(|l| text(l).to_owned())
                .unwrap_or_default();
            request.index = item
                .get("index")
                .map(|index| items(index).iter().map(|i| text(i).to_owned()).collect())
                .unwrap_or_default();
            request.data_view = item.get("data_view").map(|v| text(v).to_owned());
            outcomes.push(Elastic.run(tenant.cx(), &request, &setup_index()).await);
        }
        outcomes
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    let rows = |at: usize| {
        let result = outcomes[at].as_ref().unwrap();
        (
            serde_json::to_string(&result.rows).unwrap(),
            result.truncated,
            result.language.clone().unwrap_or_default(),
        )
    };
    assert_eq!(
        rows(0),
        (
            r#"[{"host.name":"ws-1","user.name":"alice"}]"#.into(),
            true,
            "esql".into()
        )
    );
    assert_eq!(
        rows(2),
        (
            r#"[{"_index":"logs-1","process.name":"cmd.exe","tags":["a"]},{"_index":"logs-2","process.name":"cmd.exe","host":{}}]"#.into(),
            false,
            "lucene".into()
        )
    );
    assert_eq!(
        rows(3),
        (
            r#"[{"_sequence":1,"_index":"logs-1","process.name":"cmd.exe"},{"_sequence":1,"_index":"logs-1","process.name":"whoami.exe"}]"#.into(),
            false,
            "eql".into()
        )
    );
    assert_eq!(
        rows(4),
        (
            r#"[{"_index":".internal.preview.alerts-security.alerts-soc","@timestamp":"2026-10-27T07:58:00.000Z","process.name":"powershell.exe","process.pid":4242}]"#.into(),
            false,
            "kuery".into()
        )
    );
    assert_eq!(
        outcomes[4].as_ref().unwrap().vendor_query_id.as_deref(),
        Some("p-1")
    );
    assert_eq!(rows(5).2, "kuery");
    // The data view's title is the index; seven hits, one row asked for.
    assert!(rows(6).1);
    let refusals: Vec<String> = [1, 7, 8]
        .iter()
        .map(|&at| match &outcomes[at] {
            Err(refused @ ConnectorError::Refused { .. }) => refused.text(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        refusals,
        [
            "Elastic refused the ES|QL query on replayed (HTTP 400): Unknown index [nope]",
            "Elastic did not answer the Lucene query on replayed with JSON: HTTP 504 with an HTML \
             page titled \"Gateway Timeout\": HTTP 504 Gateway Timeout is what a gateway or proxy \
             in front of the tenant answers when the tenant does not answer it in time, so the \
             url and port are not at fault when other requests to the same address succeed",
            "Kibana refused the KQL query on replayed: Expected AND but found ':'",
        ]
    );
}

#[test]
fn elastic_validate_checks_and_previews_each_rule() {
    let inputs = fixture("elastic");
    let now = timestamp(inputs.get("now").unwrap());
    let tenant = replay("elastic/validate");
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for rule in rules("validate") {
            outcomes.push(
                match Elastic
                    .validate_rule(tenant.cx(), &rule, &setup_index(), now)
                    .await
                {
                    Ok(warnings) => format!("ok {warnings:?}"),
                    Err(ElasticError::Rule(error)) => format!("rule: {error}"),
                    Err(other) => format!("{other:?}"),
                },
            );
        }
        outcomes
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(
        outcomes,
        [
            r#"ok ["the rule matched no index yet"]"#,
            r#"ok ["ES|QL sources not onboarded yet: missing-*", "the rule matched no index yet"]"#,
            "rule: ES|QL parsing exception: line 1:20: mismatched input 'error'",
            "rule: Preview validation failed for rule 'Elastic rule 14': Expected AND but found ':'",
            r#"rule: Rule schema error on preview: {"statusCode": 400, "error": "Bad Request", "message": "[from]: bad"}"#,
            "rule: Field 'message' is not aggregatable in sources: logs-*",
        ]
    );
}

#[test]
fn elastic_advisories_name_the_codes_of_a_rule() {
    let rule = rules("validate").remove(1);
    let severity = rule.payload.get("severity").and_then(Json::as_str).unwrap();
    assert_eq!(
        elastic::advisories(&rule.block, severity, true, false).unwrap(),
        Vec::<String>::new()
    );
}

#[test]
fn elastic_query_runs_through_the_framework_traits_with_the_tenant_index() {
    use opentide_connectors::Platform as _;
    let inputs = fixture("elastic");
    let query = inputs.get("query").unwrap();
    let window = window(query.get("window").unwrap());
    let tenant = replay_query();
    assert_eq!(tenant.tenant.list("index"), setup_index().as_slice());
    let runner = Elastic.query_runner().unwrap();
    assert!(Elastic.live_validator().is_some());
    // The deployer takes the rule's block in its body.
    assert!(Elastic.deployer().is_some());
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for item in items(query.get("queries").unwrap()) {
            let mut request = QueryRequest::new(text(item.get("text").unwrap()), "", window);
            request.limit = match item.get("limit") {
                Some(Json::Int(limit)) => usize::try_from(*limit).unwrap(),
                _ => 100,
            };
            request.language = item
                .get("language")
                .map(|l| text(l).to_owned())
                .unwrap_or_default();
            request.index = item
                .get("index")
                .map(|index| items(index).iter().map(|i| text(i).to_owned()).collect())
                .unwrap_or_default();
            request.data_view = item.get("data_view").map(|v| text(v).to_owned());
            outcomes.push(runner.run(tenant.cx(), &request).await);
        }
        outcomes
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(
        outcomes[0].as_ref().unwrap().language.as_deref(),
        Some("esql")
    );
    assert!(matches!(outcomes[1], Err(ConnectorError::Refused { .. })));
}

/// `{"payload", "block"}`: the body `opentide deploy` and `deploy_plan` send.
fn full_body(rule: &ElasticRule) -> Vec<u8> {
    let mut body = opentide_compile::json::Object::new();
    body.insert("payload".into(), rule.payload.clone());
    body.insert("block".into(), rule.block.clone());
    serde_json::to_vec(&Json::Object(body)).unwrap()
}

fn request_of(rule: &ElasticRule) -> DeployRequest {
    match rule.strategy {
        Strategy::Deletion => DeployRequest::delete(rule.rule_id.clone()),
        Strategy::Disablement => {
            DeployRequest::new(rule.rule_id.clone(), Operation::Disable, full_body(rule))
        }
        Strategy::Active => {
            DeployRequest::new(rule.rule_id.clone(), Operation::Update, full_body(rule))
        }
    }
}

/// The platform's `Deployer` sends what the Python deployer sent, the
/// tenant's `index` the checks' fallback; each outcome names what was done,
/// each failure its event's code, and the refused key fails the tenant.
#[test]
fn elastic_deploys_through_the_platform_as_the_python_deployer_did() {
    let tenant = replay("elastic/deploy");
    let seen = block_on(async {
        let mut seen = Vec::new();
        for rule in rules("deploy") {
            let id = &rule.rule_id[34..];
            match Elastic.deploy(tenant.cx(), &request_of(&rule)).await {
                Ok(done) => {
                    assert_eq!(
                        done.remote_id.is_none(),
                        rule.strategy == Strategy::Deletion
                    );
                    let warnings: Vec<&str> =
                        done.warnings.iter().map(|w| w.code.as_str()).collect();
                    assert_eq!(
                        done.events[0].fields,
                        [("rule_id".to_owned(), rule.rule_id.clone())]
                    );
                    seen.push(format!("{id} {} {warnings:?}", done.events[0].name));
                }
                Err(error) if error.scope == DeployScope::Rule => {
                    seen.push(format!("{id} rule {}", error.failure.code));
                }
                Err(error) => {
                    assert!(error.connector.is_none(), "{error:?}");
                    seen.push(format!("{id} tenant {}", error.failure.code));
                    break;
                }
            }
        }
        seen
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(
        seen,
        [
            "01 elastic_rule_created []",
            "02 elastic_rule_updated []",
            "03 elastic_rule_recreated []",
            "04 rule refusing_to_modify_prebuilt_rule",
            "05 elastic_rule_deleted []",
            "06 elastic_rule_created []",
            "07 elastic_rule_created []",
            "08 elastic_rule_created []",
            "09 rule elasticsearch_checks_failed",
            "0a tenant tenant_refused",
        ]
    );
}

/// A bare Kibana rule deploys without the checks, which read the block, and
/// says so with an unraised warning; a Disable writes the rule disabled.
#[test]
fn a_bare_payload_skips_the_checks_and_says_so() {
    use wiremock::matchers::{method, path};
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let server = runtime.block_on(wiremock::MockServer::start());
    runtime.block_on(async {
        wiremock::Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/api/detection_engine/rules"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
    });
    let (tenant, http) = stand_tenant(&server.uri());
    let cancel = tokio_util::sync::CancellationToken::new();
    let cx = opentide_connectors::connector::TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let rule = &rules("deploy")[0];
    let request = DeployRequest::new(
        rule.rule_id.clone(),
        Operation::Disable,
        serde_json::to_vec(&rule.payload).unwrap(),
    );
    let done = runtime.block_on(Elastic.deploy(cx, &request)).unwrap();
    assert_eq!(done.warnings.len(), 1);
    assert_eq!(done.warnings[0].code, elastic::CHECKS_SKIPPED);
    assert!(!done.warnings[0].raised);
    assert_eq!(done.events[0].name, "elastic_rule_created");
    let requests = runtime.block_on(server.received_requests()).unwrap();
    let paths: Vec<&str> = requests.iter().map(|r| r.url.path()).collect();
    assert_eq!(
        paths, ["/api/detection_engine/rules"; 2],
        "no Elasticsearch check"
    );
    // The rule, as compiled, written disabled.
    let sent: Json = serde_json::from_slice(&requests[1].body).unwrap();
    let mut expected = rule.payload.as_object().unwrap().clone();
    expected.insert("enabled".into(), Json::Bool(false));
    assert_eq!(sent, Json::Object(expected));
}

/// A tenant on `server` (Kibana and Elasticsearch both), `index` `logs-*`.
fn stand_tenant(server: &str) -> (opentide_connectors::Tenant, opentide_connectors::HttpClient) {
    stand_tenant_at(server, server)
}

/// A tenant whose Kibana is `kibana` and Elasticsearch `elasticsearch`,
/// `index` `logs-*`.
fn stand_tenant_at(
    kibana: &str,
    elasticsearch: &str,
) -> (opentide_connectors::Tenant, opentide_connectors::HttpClient) {
    let setup: toml::Table = toml::from_str(&format!(
        "url = \"{kibana}\"\nelasticsearch_url = \"{elasticsearch}\"\nindex = [\"logs-*\"]\n"
    ))
    .unwrap();
    let env = opentide_connectors::Environment::default();
    let settings = elastic::http_settings(std::time::Duration::from_secs(30));
    let tenant = opentide_connectors::Tenant::from_setup(
        elastic::PLATFORM,
        "lab",
        &setup,
        &env,
        opentide_connectors::credentials::Mode::Required,
        &settings,
    )
    .unwrap();
    let http =
        opentide_connectors::HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
    (tenant, http)
}

/// `request` deployed to a stand-in that `mount` sets up, cancelled first
/// when `cancelled`: the outcome and the paths requested.
fn deploy_to_stand(
    mount: impl FnOnce(&wiremock::MockServer, &tokio::runtime::Runtime),
    request: &DeployRequest,
    cancelled: bool,
) -> (
    Result<
        opentide_connectors::connector::DeployOutcome,
        opentide_connectors::connector::DeployError,
    >,
    Vec<String>,
) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let server = runtime.block_on(wiremock::MockServer::start());
    mount(&server, &runtime);
    let (tenant, http) = stand_tenant(&server.uri());
    let cancel = tokio_util::sync::CancellationToken::new();
    if cancelled {
        cancel.cancel();
    }
    let cx = opentide_connectors::connector::TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let outcome = runtime.block_on(Elastic.deploy(cx, request));
    let requests = runtime.block_on(server.received_requests()).unwrap();
    (
        outcome,
        requests
            .iter()
            .map(|r| format!("{} {}", r.method, r.url.path()))
            .collect(),
    )
}

/// A rule on `logs-*` whose timestamp override the mappings lack, and its
/// full body.
fn overridden_rule(rule_type: &str) -> (String, Vec<u8>) {
    let rule_id = "11111111-1111-4111-8111-111111111111".to_owned();
    let body = serde_json::json!({
        "payload": {"rule_id": rule_id, "name": "Overridden", "type": rule_type,
                    "query": "process.name: cmd.exe", "index": ["logs-*"]},
        "block": {"type": rule_type, "index": ["logs-*"], "overrides": {"timestamp": "event.ingested"}},
    });
    (rule_id, serde_json::to_vec(&body).unwrap())
}

fn mount_kibana(
    server: &wiremock::MockServer,
    runtime: &tokio::runtime::Runtime,
    remote: Option<serde_json::Value>,
    create: u16,
) {
    use wiremock::matchers::{method, path, path_regex};
    runtime.block_on(async {
        wiremock::Mock::given(method("GET"))
            .and(path_regex("/_field_caps$"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"indices": ["logs-1"], "fields": {}})),
            )
            .mount(server)
            .await;
        let found = match remote {
            Some(remote) => wiremock::ResponseTemplate::new(200).set_body_json(remote),
            None => wiremock::ResponseTemplate::new(404),
        };
        wiremock::Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules"))
            .respond_with(found)
            .mount(server)
            .await;
        wiremock::Mock::given(method("DELETE"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("{}"))
            .mount(server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/api/detection_engine/rules"))
            .respond_with(
                wiremock::ResponseTemplate::new(create)
                    .set_body_json(serde_json::json!({"message": "storage down"})),
            )
            .mount(server)
            .await;
    });
}

/// A create Kibana refuses fails the rule with its code and status, the
/// checks' warning kept in `partial`; a Create does what an Update does.
#[test]
fn a_refused_create_keeps_its_status_and_the_checks_warning() {
    let (rule_id, body) = overridden_rule("query");
    let request = DeployRequest::new(rule_id, Operation::Create, body);
    let (outcome, _) = deploy_to_stand(
        |server, runtime| mount_kibana(server, runtime, None, 500),
        &request,
        false,
    );
    let error = outcome.unwrap_err();
    assert_eq!(error.scope, DeployScope::Rule);
    assert_eq!(error.failure.code, "create_elastic_rule_failed");
    assert_eq!(error.failure.status, Some(500));
    assert_eq!(error.failure.message, "storage down");
    let partial = error.partial.unwrap();
    assert_eq!(partial.remote_id, None);
    let codes: Vec<&str> = partial.warnings.iter().map(|w| w.code.as_str()).collect();
    assert_eq!(codes, [elastic::CHECK_WARNING]);
    assert!(partial.warnings[0].message.contains("event.ingested"));
    assert!(partial.events.is_empty());
}

/// A rule whose type changed is deleted, then created again; when the create
/// fails, `partial` says the rule was deleted.
#[test]
fn a_type_change_that_fails_to_create_says_the_rule_was_deleted() {
    let (rule_id, body) = overridden_rule("query");
    let request = DeployRequest::new(rule_id.clone(), Operation::Update, body);
    let (outcome, paths) = deploy_to_stand(
        |server, runtime| {
            mount_kibana(
                server,
                runtime,
                Some(serde_json::json!({"rule_id": rule_id, "type": "eql"})),
                500,
            );
        },
        &request,
        false,
    );
    let error = outcome.unwrap_err();
    assert_eq!(error.failure.code, "recreate_elastic_rule_failed");
    let partial = error.partial.unwrap();
    assert_eq!(partial.events.len(), 1);
    assert_eq!(partial.events[0].name, "elastic_rule_deleted");
    assert!(
        paths.contains(&"DELETE /api/detection_engine/rules".to_owned()),
        "{paths:?}"
    );
}

/// A body whose Kibana rule names another `rule_id`, or none, or whose block
/// is not a block, fails the rule before anything is sent.
#[test]
fn a_body_that_does_not_fit_the_request_is_refused_before_anything_is_sent() {
    let (rule_id, _) = overridden_rule("query");
    for body in [
        serde_json::json!({"payload": {"rule_id": "another", "type": "query"}, "block": {}}),
        serde_json::json!({"payload": {"type": "query"}}),
        serde_json::json!({"payload": {"rule_id": rule_id, "type": "query"}, "block": "x"}),
        serde_json::json!({"block": {"type": "query"}}),
        serde_json::json!({}),
    ] {
        let request = DeployRequest::new(
            rule_id.clone(),
            Operation::Update,
            serde_json::to_vec(&body).unwrap(),
        );
        let (outcome, paths) = deploy_to_stand(|_, _| {}, &request, false);
        let error = outcome.unwrap_err();
        assert_eq!(error.scope, DeployScope::Rule, "{body}");
        assert_eq!(error.failure.code, "tenant_refused", "{body}");
        assert!(paths.is_empty(), "{body}: {paths:?}");
    }
}

/// An interrupted deploy fails the tenant, its connector error kept.
#[test]
fn an_interrupted_deploy_fails_the_tenant() {
    let (rule_id, body) = overridden_rule("query");
    let request = DeployRequest::new(rule_id, Operation::Update, body);
    let (outcome, _) = deploy_to_stand(
        |server, runtime| mount_kibana(server, runtime, None, 200),
        &request,
        true,
    );
    let error = outcome.unwrap_err();
    assert_eq!(error.scope, DeployScope::Tenant);
    assert!(error.is_interrupted(), "{error:?}");
}

/// A Kibana stand-in that answers its first request (the rule lookup) 404,
/// then refuses every connection: its listener is closed before it answers.
fn kibana_gone_after_the_lookup() -> String {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap() == 1 {
            request.push(byte[0]);
        }
        drop(listener);
        stream
            .write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\
                  Content-Length: 2\r\nConnection: close\r\n\r\n{}",
            )
            .unwrap();
    });
    address
}

/// Elasticsearch on a stand-in answering the checks' `_field_caps`.
fn elasticsearch(runtime: &tokio::runtime::Runtime) -> wiremock::MockServer {
    use wiremock::matchers::{method, path_regex};
    let server = runtime.block_on(wiremock::MockServer::start());
    runtime.block_on(
        wiremock::Mock::given(method("GET"))
            .and(path_regex("/_field_caps$"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"indices": ["logs-1"], "fields": {}})),
            )
            .mount(&server),
    );
    server
}

/// `operation` deployed to a tenant whose Kibana is `kibana` and whose
/// Elasticsearch is a stand-in: the outcome, and the paths Elasticsearch
/// was asked.
fn deploy_with_kibana_at(
    runtime: &tokio::runtime::Runtime,
    kibana: &str,
    operation: Operation,
) -> (
    Result<
        opentide_connectors::connector::DeployOutcome,
        opentide_connectors::connector::DeployError,
    >,
    Vec<String>,
) {
    let es = elasticsearch(runtime);
    let (tenant, http) = stand_tenant_at(kibana, &es.uri());
    let cancel = tokio_util::sync::CancellationToken::new();
    let cx = opentide_connectors::connector::TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let (rule_id, body) = overridden_rule("query");
    let request = DeployRequest::new(rule_id, operation, body);
    let outcome = runtime.block_on(Elastic.deploy(cx, &request));
    let asked = runtime
        .block_on(es.received_requests())
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_owned())
        .collect();
    (outcome, asked)
}

/// A Kibana whose connection fails fails the tenant, not the rule (#1658,
/// E7): on the lookup of an update, on the create after a lookup that
/// answered 404, and on a delete. Its other rules would only wait on the
/// same retries. The Elasticsearch checks, on a reachable cluster, ran
/// first (a delete runs none).
#[test]
fn an_unreachable_kibana_fails_the_tenant_on_every_operation() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    // Port 1 on the loopback: nothing listens there.
    let closed = "http://127.0.0.1:1".to_owned();
    for (operation, kibana, checked) in [
        (Operation::Update, closed.clone(), true),
        (Operation::Create, kibana_gone_after_the_lookup(), true),
        (Operation::Delete, closed.clone(), false),
    ] {
        let (outcome, asked) = deploy_with_kibana_at(&runtime, &kibana, operation);
        let error = outcome.unwrap_err();
        assert_eq!(error.scope, DeployScope::Tenant, "{operation:?}: {error:?}");
        assert_eq!(error.failure.code, "tenant_unreachable", "{operation:?}");
        assert!(
            error
                .failure
                .message
                .starts_with(&format!("Cannot reach elastic tenant 'lab' at {kibana}")),
            "{operation:?}: {}",
            error.failure.message
        );
        assert_eq!(
            asked.iter().any(|path| path.ends_with("/_field_caps")),
            checked,
            "{operation:?}: {asked:?}"
        );
    }
}

/// A gateway's 503 in front of Kibana (Kibana down behind a proxy or
/// Elastic Cloud's front end) on the rule lookup or a delete fails the
/// tenant, once the client's retries ran out (#1658, E7).
#[test]
fn a_gateway_in_front_of_kibana_fails_the_tenant() {
    use wiremock::matchers::{method, path};
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for operation in [Operation::Update, Operation::Delete] {
        let kibana = runtime.block_on(wiremock::MockServer::start());
        runtime.block_on(
            wiremock::Mock::given(method(if operation == Operation::Delete {
                "DELETE"
            } else {
                "GET"
            }))
            .and(path("/api/detection_engine/rules"))
            .respond_with(
                wiremock::ResponseTemplate::new(503)
                    .set_body_string("<html><title>503 Service Unavailable</title></html>"),
            )
            .mount(&kibana),
        );
        let (outcome, _) = deploy_with_kibana_at(&runtime, &kibana.uri(), operation);
        let error = outcome.unwrap_err();
        assert_eq!(error.scope, DeployScope::Tenant, "{operation:?}: {error:?}");
        assert_eq!(error.failure.code, "tenant_gateway", "{operation:?}");
        assert!(
            error
                .failure
                .message
                .starts_with("Kibana of elastic tenant 'lab' answered "),
            "{}",
            error.failure.message
        );
        assert!(
            error.failure.message.contains("HTTP 503"),
            "{}",
            error.failure.message
        );
        // Nothing was created or written.
        let methods: Vec<String> = runtime
            .block_on(kibana.received_requests())
            .unwrap()
            .iter()
            .map(|r| r.method.to_string())
            .collect();
        assert!(
            !methods.iter().any(|m| m == "POST" || m == "PUT"),
            "{methods:?}"
        );
    }
}
