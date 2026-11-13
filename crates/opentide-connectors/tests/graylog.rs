//! Graylog against a stand-in server: the deploy sequence
//! (`GET /api/system`, the query check, then create, update, unschedule or
//! delete), the failure table, the live check and the message search. The
//! cases are 0.28.0's `tests/test_platforms/test_graylog_{deployer,runner}.py`;
//! the recorded cassette comes with the golden cases.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test: a failed set-up is a failure"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::graylog::{self as compile, CompiledDefinition, Version};
use opentide_compile::{Json, Owned, Rule};
use opentide_connectors::connector::{DeployRequest, Deployer, LiveValidator};
use opentide_connectors::connector::{
    Operation, QueryRequest, QueryRunner, TenantContext, TimeWindow,
};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::graylog::{
    Action, Graylog, RuleDeploy, RuleOutcome, StateChange, deploy_rule, http_defaults,
};
use opentide_connectors::{ConnectorError, Environment, HttpClient, Tenant};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "GRAYLOG_TOKEN";
const SECRET: &str = "graylog-test-token-only";
const DEFINITION_ID: &str = "65f1c0de2a3b4c5d6e7f8091";
const STREAM_ID: &str = "65f0c0ffee0123456789abcd";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(repo().join("tests/fixtures/graylog").join(name)).unwrap()
}

/// A server, on a runtime the test keeps.
fn server() -> (tokio::runtime::Runtime, MockServer) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let server = runtime.block_on(MockServer::start());
    (runtime, server)
}

/// The fixture tenant, pointed at `url`.
fn tenant(url: &str) -> (Tenant, HttpClient) {
    let setup: toml::Table = toml::from_str(&format!(
        r#"
ssl = true
url = "{url}"
token = "${TOKEN}"
streams = ["sysmon"]
tags = ["managed-by-opentide"]

[stream_ids]
sysmon = "{STREAM_ID}"

[notification_ids]
soc-slack = "65f0c0ffee0123456789abcf"
"#
    ))
    .unwrap();
    let env = Environment::from_pairs([(TOKEN.to_owned(), SECRET.to_owned())]);
    let tenant = Tenant::from_setup(
        "graylog",
        "graylog-prod",
        &setup,
        &env,
        Resolve::Required,
        &http_defaults(),
    )
    .unwrap();
    let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
    (tenant, http)
}

/// The aggregation fixture compiled for `version`, offline (its aliases are
/// the tenant's, resolved by the compiler's own test).
fn compiled(version: Version) -> CompiledDefinition {
    let text = fixture("rule-graylog-aggregation-1.0.yaml");
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.write("/ws/objects/rules/r.yaml", text.clone());
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
    let uuid = "00000000-0000-4000-8003-000000000060";
    let object = index.get("rule", uuid).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    compile::compile_definition(&cx, &rule, version, None, None).unwrap()
}

/// The definition the requests carry.
fn definition(version: Version) -> CompiledDefinition {
    compiled(version)
}

fn step(action: Action, disable: bool, version: Version) -> RuleDeploy {
    RuleDeploy {
        action,
        compiled: definition(version),
        disable,
        recreate_refusal: None,
    }
}

/// Runs one deploy against `server`.
fn deploy(
    runtime: &tokio::runtime::Runtime,
    server: &MockServer,
    rule: &RuleDeploy,
) -> Result<RuleOutcome, ConnectorError> {
    let (tenant, http) = tenant(&server.uri());
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    runtime.block_on(deploy_rule(cx, rule))
}

fn ok_verdict() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({"status": "OK"}))
}

async fn mount_validate(server: &MockServer, template: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/api/search/validate"))
        .respond_with(template)
        .mount(server)
        .await;
}

#[test]
fn a_create_checks_the_query_then_records_the_id() {
    let (runtime, server) = server();
    runtime.block_on(async {
        mount_validate(&server, ok_verdict()).await;
        Mock::given(method("POST"))
            .and(path("/api/events/definitions"))
            .and(query_param("schedule", "true"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": DEFINITION_ID})),
            )
            .mount(&server)
            .await;
    });
    let outcome = deploy(
        &runtime,
        &server,
        &step(Action::Create, false, Version(7, 2, 0)),
    )
    .unwrap();
    assert_eq!(outcome.state, StateChange::Record(DEFINITION_ID.to_owned()));
    assert_eq!(
        outcome.event,
        Some(("graylog_definition_created", DEFINITION_ID.to_owned()))
    );
    assert!(outcome.failure.is_none() && outcome.warnings.is_empty());
    // The query check came first, with the definition's query and window.
    let requests = runtime.block_on(server.received_requests()).unwrap();
    assert_eq!(requests[0].url.path(), "/api/search/validate");
    let body: serde_json::Value = requests[0].body_json().unwrap();
    assert_eq!(
        body["timerange"],
        serde_json::json!({"type": "relative", "range": 900})
    );
    assert_eq!(requests[0].headers["X-Requested-By"], "opentide");
    // HTTP Basic <token>:token.
    let authorization = requests[0].headers["Authorization"].to_str().unwrap();
    assert_eq!(
        authorization,
        format!("Basic {}", basic(&format!("{SECRET}:token")))
    );
    assert_eq!(requests[1].url.path(), "/api/events/definitions");
}

#[test]
fn a_create_that_answers_no_id_is_unconfirmed() {
    let (runtime, server) = server();
    runtime.block_on(async {
        mount_validate(&server, ok_verdict()).await;
        Mock::given(method("POST"))
            .and(path("/api/events/definitions"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>saved</html>"))
            .mount(&server)
            .await;
    });
    let outcome = deploy(
        &runtime,
        &server,
        &step(Action::Create, false, Version(7, 2, 0)),
    )
    .unwrap();
    let failure = outcome.failure.unwrap();
    assert_eq!(failure.code, "graylog_create_unconfirmed");
    assert!(
        failure.reason.contains("answered no 24-hex id"),
        "{failure:?}"
    );
    assert_eq!(outcome.state, StateChange::Keep);
}

#[test]
fn a_refused_query_saves_nothing() {
    let (runtime, server) = server();
    runtime.block_on(async {
        mount_validate(
            &server,
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ERROR",
                "explanations": [{
                    "error_type": "QUERY_PARSING_ERROR",
                    "error_title": "Cannot parse query",
                    "error_message": "incomplete query",
                    "begin_line": 1,
                    "begin_column": 9,
                }],
            })),
        )
        .await;
    });
    let outcome = deploy(
        &runtime,
        &server,
        &step(Action::Create, false, Version(7, 2, 0)),
    )
    .unwrap();
    let failure = outcome.failure.unwrap();
    assert_eq!(failure.code, "graylog_query_invalid");
    assert_eq!(
        failure.reason,
        "Graylog refuses the query, so nothing is saved: Cannot parse query: incomplete query \
         (line 1, column 9)"
    );
    // Nothing was saved.
    let requests = runtime.block_on(server.received_requests()).unwrap();
    assert_eq!(requests.len(), 1);
}

#[test]
fn a_warning_verdict_saves_and_warns() {
    let (runtime, server) = server();
    runtime.block_on(async {
        mount_validate(
            &server,
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "WARNING",
                "explanations": [{"error_type": "UNKNOWN_FIELD", "error_message": "no such field"}],
            })),
        )
        .await;
        Mock::given(method("PUT"))
            .and(path(format!("/api/events/definitions/{DEFINITION_ID}")))
            .and(query_param("schedule", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
    });
    let outcome = deploy(
        &runtime,
        &server,
        &step(
            Action::Update(DEFINITION_ID.to_owned()),
            false,
            Version(7, 2, 0),
        ),
    )
    .unwrap();
    assert!(outcome.failure.is_none());
    assert_eq!(outcome.warnings.len(), 1);
    assert_eq!(outcome.warnings[0].event, "graylog_unknown_field");
    assert_eq!(
        outcome.event,
        Some(("graylog_definition_updated", DEFINITION_ID.to_owned()))
    );
    // The update sends the whole definition with its id.
    let requests = runtime.block_on(server.received_requests()).unwrap();
    let body: serde_json::Value = requests[1].body_json().unwrap();
    assert_eq!(body["id"], DEFINITION_ID);
    assert_eq!(body["_scope"], "DEFAULT");
}

#[test]
fn a_disablement_skips_the_query_check_and_unschedules() {
    let (runtime, server) = server();
    runtime.block_on(async {
        Mock::given(method("PUT"))
            .and(path(format!("/api/events/definitions/{DEFINITION_ID}")))
            .and(query_param("schedule", "false"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
    });
    let outcome = deploy(
        &runtime,
        &server,
        &step(
            Action::Update(DEFINITION_ID.to_owned()),
            true,
            Version(7, 2, 0),
        ),
    )
    .unwrap();
    assert!(outcome.failure.is_none());
    let requests = runtime.block_on(server.received_requests()).unwrap();
    assert_eq!(requests.len(), 1, "no query check on a disablement");
    assert_eq!(requests[0].method.as_str(), "PUT");
}

#[test]
fn an_update_of_a_definition_graylog_lost_creates_it_again() {
    let (runtime, server) = server();
    runtime.block_on(async {
        mount_validate(&server, ok_verdict()).await;
        Mock::given(method("PUT"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"message": "Event definition not found"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/events/definitions"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": DEFINITION_ID})),
            )
            .mount(&server)
            .await;
    });
    let outcome = deploy(
        &runtime,
        &server,
        &step(
            Action::Update("65f1c0de2a3b4c5d6e7f0000".to_owned()),
            false,
            Version(7, 2, 0),
        ),
    )
    .unwrap();
    assert_eq!(outcome.warnings[0].event, "graylog_definition_recreated");
    assert_eq!(outcome.state, StateChange::Record(DEFINITION_ID.to_owned()));
}

#[test]
fn a_definition_graylog_lost_under_a_disablement_is_forgotten() {
    let (runtime, server) = server();
    runtime.block_on(async {
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
    });
    let outcome = deploy(
        &runtime,
        &server,
        &step(
            Action::Update(DEFINITION_ID.to_owned()),
            true,
            Version(7, 2, 0),
        ),
    )
    .unwrap();
    assert_eq!(outcome.warnings[0].event, "graylog_definition_missing");
    assert_eq!(outcome.state, StateChange::Forget);
}

#[test]
fn a_recreate_deployment_state_refuses_is_not_created() {
    let (runtime, server) = server();
    runtime.block_on(async {
        mount_validate(&server, ok_verdict()).await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
    });
    let mut rule = step(
        Action::Update(DEFINITION_ID.to_owned()),
        false,
        Version(7, 2, 0),
    );
    rule.recreate_refusal = Some("deployment_state_ignored: the shard is ignored".to_owned());
    let outcome = deploy(&runtime, &server, &rule).unwrap();
    assert_eq!(
        outcome.failure.unwrap().reason,
        "deployment_state_ignored: the shard is ignored"
    );
    assert_eq!(outcome.state, StateChange::Keep);
    let requests = runtime.block_on(server.received_requests()).unwrap();
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() != "POST"
                || request.url.path() == "/api/search/validate"),
        "nothing was created"
    );
}

#[test]
fn a_delete_forgets_the_id_and_asks_no_verdict() {
    let (runtime, server) = server();
    runtime.block_on(async {
        Mock::given(method("DELETE"))
            .and(path(format!("/api/events/definitions/{DEFINITION_ID}")))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
    });
    let outcome = deploy(
        &runtime,
        &server,
        &step(
            Action::Delete(DEFINITION_ID.to_owned()),
            false,
            Version(7, 2, 0),
        ),
    )
    .unwrap();
    assert_eq!(outcome.state, StateChange::Forget);
    assert_eq!(
        outcome.event,
        Some(("graylog_definition_deleted", DEFINITION_ID.to_owned()))
    );
    let requests = runtime.block_on(server.received_requests()).unwrap();
    assert_eq!(requests.len(), 1);
}

#[test]
fn the_failure_table_names_each_refusal() {
    for (status, body, code) in [
        (
            400,
            serde_json::json!({"message": "Immutable entity cannot be modified"}),
            "graylog_definition_immutable",
        ),
        (
            403,
            serde_json::json!({"message": "Not authorized"}),
            "graylog_forbidden",
        ),
        (
            400,
            serde_json::json!({"errors": {"config.query": ["cannot be blank"]}}),
            "graylog_definition_invalid",
        ),
        (
            500,
            serde_json::json!({"message": "Internal error"}),
            "graylog_request_failed",
        ),
    ] {
        let (runtime, server) = server();
        runtime.block_on(async {
            mount_validate(&server, ok_verdict()).await;
            Mock::given(method("PUT"))
                .respond_with(ResponseTemplate::new(status).set_body_json(body.clone()))
                .mount(&server)
                .await;
        });
        let outcome = deploy(
            &runtime,
            &server,
            &step(
                Action::Update(DEFINITION_ID.to_owned()),
                false,
                Version(7, 2, 0),
            ),
        )
        .unwrap();
        let failure = outcome.failure.unwrap();
        assert_eq!(failure.code, code, "HTTP {status}");
        assert_eq!(failure.status, Some(status));
    }
}

#[test]
fn a_delete_another_definition_depends_on_is_in_use() {
    let (runtime, server) = server();
    runtime.block_on(async {
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(409).set_body_json(
                serde_json::json!({"message": "The event definition is in use by a notification"}),
            ))
            .mount(&server)
            .await;
    });
    let outcome = deploy(
        &runtime,
        &server,
        &step(
            Action::Delete(DEFINITION_ID.to_owned()),
            false,
            Version(7, 2, 0),
        ),
    )
    .unwrap();
    let failure = outcome.failure.unwrap();
    assert_eq!(failure.code, "graylog_definition_in_use");
    assert!(
        failure
            .reason
            .starts_with("another definition depends on this one")
    );
    assert_eq!(outcome.state, StateChange::Keep);
}

#[test]
fn a_refused_token_stops_the_tenant() {
    let (runtime, server) = server();
    runtime.block_on(async {
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
    });
    let error = deploy(
        &runtime,
        &server,
        &step(Action::Create, false, Version(7, 2, 0)),
    )
    .unwrap_err();
    assert!(
        matches!(error, ConnectorError::Authentication { .. }),
        "{error:?}"
    );
    assert!(
        error.text().contains("graylog_tenant_unauthorized"),
        "{error:?}"
    );
}

#[test]
fn the_version_is_read_once_and_bounded_below() {
    let (runtime, server) = server();
    runtime.block_on(async {
        Mock::given(method("GET"))
            .and(path("/api/system"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"version": "6.2.9+abc"})),
            )
            .mount(&server)
            .await;
    });
    let (tenant, http) = tenant(&server.uri());
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let client = opentide_connectors::graylog::Client::new(cx);
    let error = runtime.block_on(client.version()).unwrap_err();
    assert!(
        error.text().contains("graylog_version_unsupported"),
        "{error:?}"
    );
    assert!(error.text().contains("'6.2.9+abc'"), "{error:?}");
}

#[test]
fn a_version_graylog_does_not_name_is_unsupported() {
    let (runtime, server) = server();
    runtime.block_on(async {
        Mock::given(method("GET"))
            .and(path("/api/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
    });
    let (tenant, http) = tenant(&server.uri());
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let client = opentide_connectors::graylog::Client::new(cx);
    let error = runtime.block_on(client.version()).unwrap_err();
    assert!(error.text().contains("no version"), "{error:?}");
}

fn window() -> TimeWindow {
    TimeWindow {
        start: "2026-10-26T08:00:00Z".parse().unwrap(),
        end: "2026-10-26T08:15:00Z".parse().unwrap(),
    }
}

#[test]
fn the_query_runner_searches_messages() {
    let (runtime, server) = server();
    runtime.block_on(async {
        Mock::given(method("GET"))
            .and(path("/api/system"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "7.2.2"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/search/messages"))
            .and(body_json(serde_json::json!({
                "query": "EventID:1",
                "streams": [STREAM_ID],
                "timerange": {
                    "type": "absolute",
                    "from": "2026-10-26T08:00:00.000Z",
                    "to": "2026-10-26T08:15:00.000Z",
                },
                "size": 3,
                "sort": "timestamp",
                "sort_order": "desc",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema": [{"field": "timestamp", "type": "date"}, {"field": "source"}],
                "datarows": [
                    ["2026-10-26T08:10:00Z", "host-1"],
                    ["2026-10-26T08:09:00Z", "host-2"],
                    ["2026-10-26T08:08:00Z", "-"],
                ],
            })))
            .mount(&server)
            .await;
    });
    let (tenant, http) = tenant(&server.uri());
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let mut request = QueryRequest::new("EventID:1", "lucene", window());
    request.limit = 2;
    let outcome = runtime.block_on(Graylog.run(cx, &request)).unwrap();
    assert_eq!(outcome.rows.len(), 2);
    assert!(outcome.truncated);
    assert_eq!(outcome.language.as_deref(), Some("lucene"));
    assert_eq!(
        outcome
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>(),
        ["timestamp", "source"]
    );
    assert_eq!(outcome.rows[0]["source"], Json::Str("host-1".to_owned()));
}

#[test]
fn before_7_2_a_search_asks_for_the_fields_the_query_names() {
    let (runtime, server) = server();
    runtime.block_on(async {
        Mock::given(method("GET"))
            .and(path("/api/system"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "7.1.12"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/search/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
    });
    let (tenant, http) = tenant(&server.uri());
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let request = QueryRequest::new("EventID:1 AND winlog.channel:Security", "lucene", window());
    let outcome = runtime.block_on(Graylog.run(cx, &request)).unwrap();
    assert!(outcome.rows.is_empty());
    let requests = runtime.block_on(server.received_requests()).unwrap();
    let body: serde_json::Value = requests[1].body_json().unwrap();
    assert_eq!(
        body["fields"],
        serde_json::json!([
            "timestamp",
            "source",
            "message",
            "EventID",
            "winlog.channel"
        ])
    );
}

#[test]
fn an_unknown_stream_alias_refuses_the_query() {
    let (runtime, server) = server();
    let (tenant, http) = tenant(&server.uri());
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let mut request = QueryRequest::new("EventID:1", "lucene", window());
    request.index = vec!["nowhere".to_owned()];
    let error = runtime.block_on(Graylog.run(cx, &request)).unwrap_err();
    assert!(error.text().contains("graylog_alias_unknown"), "{error:?}");
    // A 24-hex index is a stream id already.
    request.index = vec![STREAM_ID.to_owned()];
    runtime.block_on(async {
        Mock::given(method("GET"))
            .and(path("/api/system"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "7.2.2"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
    });
    assert!(runtime.block_on(Graylog.run(cx, &request)).is_ok());
}

#[test]
fn the_live_check_asks_for_a_verdict_and_runs_no_search() {
    let (runtime, server) = server();
    runtime.block_on(async {
        mount_validate(
            &server,
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "WARNING",
                "explanations": [{
                    "error_type": "UNKNOWN_FIELD",
                    "error_message": "unknown field",
                    "begin_line": 1,
                    "begin_column": 1,
                }],
            })),
        )
        .await;
    });
    let (tenant, http) = tenant(&server.uri());
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let request = QueryRequest::new("EventID:1", "lucene", window());
    let check = runtime.block_on(Graylog.validate(cx, &request)).unwrap();
    assert!(check.errors.is_empty() && check.result.is_none());
    assert_eq!(
        check.warnings,
        ["graylog_unknown_field: UNKNOWN_FIELD: unknown field (line 1, column 1)".to_owned()]
    );
    let requests = runtime.block_on(server.received_requests()).unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = requests[0].body_json().unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "query": "EventID:1",
            "streams": [STREAM_ID],
            "timerange": {"type": "relative", "range": 900},
        })
    );
}

#[test]
fn the_live_check_fails_on_an_error_verdict() {
    let (runtime, server) = server();
    runtime.block_on(async {
        mount_validate(
            &server,
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ERROR",
                "explanations": [{"error_type": "QUERY_PARSING_ERROR", "error_message": "no"}],
            })),
        )
        .await;
    });
    let (tenant, http) = tenant(&server.uri());
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let request = QueryRequest::new("EventID:1", "lucene", window());
    let error = runtime
        .block_on(Graylog.validate(cx, &request))
        .unwrap_err();
    assert!(matches!(error, ConnectorError::Refused { .. }), "{error:?}");
}

#[test]
fn the_platform_deploys_from_a_compiled_body() {
    let (runtime, server) = server();
    runtime.block_on(async {
        mount_validate(&server, ok_verdict()).await;
        Mock::given(method("POST"))
            .and(path("/api/events/definitions"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": DEFINITION_ID})),
            )
            .mount(&server)
            .await;
    });
    let (tenant, http) = tenant(&server.uri());
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let compiled = definition(Version(7, 2, 0));
    let request = DeployRequest {
        rule_id: compiled.uuid.clone(),
        operation: Operation::Create,
        body: opentide_connectors::body::python_json(&compile::create_body(&compiled)).unwrap(),
    };
    let outcome = runtime.block_on(Graylog.deploy(cx, &request)).unwrap();
    assert_eq!(outcome.remote_id.as_deref(), Some(DEFINITION_ID));
    assert_eq!(outcome.operation, Operation::Create);
    let requests = runtime.block_on(server.received_requests()).unwrap();
    let sent: serde_json::Value = requests[1].body_json().unwrap();
    assert_eq!(sent["entity"]["title"], serde_json::json!(compiled.title));
}

/// `text` in base64, as HTTP Basic sends it.
fn basic(text: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut block = [0_u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let packed = (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                let position = (packed >> (18 - 6 * index)) & 0x3f;
                out.push(char::from(ALPHABET[position as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}
