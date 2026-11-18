//! `connectors`: the tenants a workspace configures, and a query run, a live
//! check and a deploy on stand-in tenants (wiremock). Nothing leaves the
//! machine: every connection is given its environment, so no proxy of the
//! process's applies.

#![cfg(feature = "connectors")]
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: a stand-in that does not start is a failure"
)]

use std::time::Duration;

use opentide::Error;
use opentide::connectors::{
    self, ConnectOptions, Connection, DeployRequest, Operation, QueryRequest, TenantConfig,
    TimeWindow, Timestamp,
};
use wiremock::matchers::{body_string, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Options with an environment of their own: no proxy, no CA bundle.
fn options() -> ConnectOptions {
    ConnectOptions::default().environment([("HL_TOKEN", "hl-secret"), ("S1_TOKEN", "s1-secret")])
}

/// A HarfangLab tenant: no kind, as every tenant takes Sigma and YARA.
fn harfanglab(url: &str) -> TenantConfig {
    TenantConfig::new(
        "harfanglab",
        "lab",
        [("url", url), ("api_token", "$HL_TOKEN")],
    )
}

fn sentinel_one(url: &str) -> TenantConfig {
    TenantConfig::new(
        "sentinel_one",
        "soc",
        [
            ("url", url),
            ("api_token", "${S1_TOKEN}"),
            ("account_id", "42"),
        ],
    )
}

fn window() -> TimeWindow {
    TimeWindow::check(Timestamp::from_second(1_800_000_000).unwrap())
}

fn code(error: &Error) -> &'static str {
    error.code()
}

#[test]
fn a_workspace_lists_its_tenants_in_file_order() {
    let ws = opentide::Workspace::from_files(
        "/ws",
        [(
            ".opentide/configurations/platforms/splunk.toml",
            "[platform]\nenabled = true\n\n[[tenants]]\nname = \"prod\"\n[tenants.setup]\n\
             url = \"$SPLUNK_URL\"\nport = 8089\ntoken = \"$SPLUNK_TOKEN\"\n\n\
             [[tenants]]\nname = \"lab\"\n[tenants.setup]\nurl = \"https://lab.example\"\n",
        )],
    )
    .unwrap();
    let tenants = ws.tenants("splunk");
    let names: Vec<&str> = tenants.iter().map(TenantConfig::name).collect();
    assert_eq!(names, ["prod", "lab"]);
    assert_eq!(tenants[0].platform(), "splunk");
    assert_eq!(
        tenants[0].setup_keys().collect::<Vec<_>>(),
        ["port", "token", "url"]
    );
    assert!(ws.tenants("elastic").is_empty());
}

#[test]
fn the_platforms_and_what_each_can_do() {
    let platforms = connectors::platforms();
    assert_eq!(platforms.len(), 13);
    for platform in &platforms {
        assert!(connectors::capabilities(platform).is_some(), "{platform}");
    }
    let sysdig = connectors::capabilities("sysdig").unwrap();
    assert!(sysdig.deploy && !sysdig.query && !sysdig.live_validation);
    let elastic = connectors::capabilities("elastic").unwrap();
    assert!(elastic.deploy && elastic.query && elastic.live_validation);
    // Every built-in platform deploys through the SDK.
    assert!(
        platforms
            .iter()
            .all(|platform| connectors::capabilities(platform).is_some_and(|c| c.deploy))
    );
    let exabeam = connectors::capabilities("exabeam").unwrap();
    assert!(exabeam.deploy && exabeam.query && exabeam.live_validation);
    let google_secops = connectors::capabilities("google_secops").unwrap();
    assert!(google_secops.deploy && google_secops.query && google_secops.live_validation);
    let graylog = connectors::capabilities("graylog").unwrap();
    assert!(graylog.deploy && graylog.query && graylog.live_validation);
}

#[test]
fn opening_refuses_an_unknown_platform_and_an_unset_credential() {
    let error = Connection::open(
        &TenantConfig::new("nowhere", "x", [("url", "https://x")]),
        &options(),
    )
    .unwrap_err();
    assert_eq!(code(&error), connectors::OPERATION_UNSUPPORTED);
    assert_eq!(error.to_string(), "nowhere has no connector");

    let tenant = TenantConfig::new(
        "harfanglab",
        "lab",
        [("url", "https://hl.example"), ("api_token", "$UNSET_TOKEN")],
    );
    let error = Connection::open(&tenant, &options()).unwrap_err();
    assert_eq!(code(&error), "credential_unset");
    assert!(error.to_string().contains("UNSET_TOKEN"), "{error}");
    let Error::Connector {
        platform, tenant, ..
    } = &error
    else {
        panic!("{error:?}");
    };
    assert_eq!((platform.as_str(), tenant.as_str()), ("harfanglab", "lab"));

    let tenant = TenantConfig::new("splunk", "prod", [("ssl", "maybe")]);
    let error = Connection::open(&tenant, &options()).unwrap_err();
    assert_eq!(code(&error), "tenant_setup_invalid");
}

#[test]
fn nothing_prints_a_secret() {
    let tenant = harfanglab("https://hl.example");
    let printed = format!("{tenant:?}");
    assert!(
        printed.contains("api_token") && !printed.contains("HL_TOKEN"),
        "{printed}"
    );
    let options = options().proxy("http://proxy.internal:3128");
    let printed = format!("{options:?}");
    assert!(
        printed.contains("HL_TOKEN") && !printed.contains("hl-secret"),
        "{printed}"
    );
    let connection = Connection::open(&tenant, &options).unwrap();
    let printed = format!("{connection:?}");
    assert!(
        printed.contains("lab") && !printed.contains("hl-secret"),
        "{printed}"
    );
    assert_eq!(
        (connection.platform(), connection.tenant()),
        ("harfanglab", "lab")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_query_returns_the_tenant_rows() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data/telemetry/Processes/"))
        .and(query_param("process_name", "cmd.exe"))
        .and(query_param("limit", "3"))
        .and(header("Authorization", "Token hl-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"count": 3, "results": [{"process_name": "cmd.exe", "pid": 1}, {"process_name": "cmd.exe", "pid": 2}, {"process_name": "cmd.exe", "pid": 3}]}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    let connection = Connection::open(&harfanglab(&server.uri()), &options()).unwrap();
    assert!(connection.capabilities().query);
    let mut request = QueryRequest::new("processes process_name=cmd.exe", "telemetry", window());
    request.limit = 2;
    let outcome = connection.query(&request).await.unwrap();
    assert_eq!(outcome.rows.len(), 2);
    assert!(outcome.truncated);
    assert_eq!(outcome.language.as_deref(), Some("telemetry"));
    let names: Vec<&str> = outcome.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["process_name", "pid"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_keeps_the_vendor_words() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(400).set_body_string(r#"{"detail": "bad filter"}"#))
        .mount(&server)
        .await;
    let connection = Connection::open(&harfanglab(&server.uri()), &options()).unwrap();
    let request = QueryRequest::new("processes x=y", "telemetry", window());
    let error = connection.query(&request).await.unwrap_err();
    assert_eq!(code(&error), "tenant_refused");
    let Error::Connector { detail, .. } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(detail.as_deref(), Some(r#"{"detail": "bad filter"}"#));
    assert!(error.to_string().contains("(HTTP 400)"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_live_check_runs_on_a_platform_that_has_one_only() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/web/api/v2.1/dv/events/pq"))
        .and(header("Authorization", "ApiToken s1-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data": {"status": "FINISHED", "columns": [{"name": "event.type"}], "data": [["Process Creation"]]}}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    let connection = Connection::open(&sentinel_one(&server.uri()), &options()).unwrap();
    let request = QueryRequest::new("| columns event.type", "powerquery", window());
    let check = connection.validate_query(&request).await.unwrap();
    assert!(check.errors.is_empty());
    let result = check.result.unwrap();
    assert_eq!(result.rows.len(), 1);

    let connection = Connection::open(&harfanglab(&server.uri()), &options()).unwrap();
    let error = connection.validate_query(&request).await.unwrap_err();
    assert_eq!(code(&error), connectors::OPERATION_UNSUPPORTED);
    assert_eq!(error.to_string(), "harfanglab cannot check a query live");
}

/// One HarfangLab tenant takes a Sigma rule and a YARA file through the
/// SDK: each request names its kind, and the compiled rule reaches that
/// kind's endpoint byte for byte.
#[tokio::test(flavor = "multi_thread")]
async fn a_deploy_sends_the_compiled_body() {
    let server = MockServer::start().await;
    let rule = "11111111-1111-4111-8111-111111111111";
    let sigma = r#"{"name": "Example", "content": "title: Example"}"#;
    let yara = r#"{"name": "Loader", "content": "rule loader { condition: true }"}"#;
    Mock::given(method("PUT"))
        .and(path(format!(
            "/api/data/threat_intelligence/SigmaRule/{rule}/"
        )))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data/threat_intelligence/SigmaRule/"))
        .and(body_string(sigma))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data/threat_intelligence/YaraFile/"))
        .and(body_string(yara))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "/api/data/threat_intelligence/YaraFile/{rule}/"
        )))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let connection = Connection::open(&harfanglab(&server.uri()), &options()).unwrap();
    for (kind, operation, body) in [
        ("Sigma", Operation::Create, Some(sigma)),
        ("YARA", Operation::Create, Some(yara)),
        ("YARA", Operation::Delete, None),
    ] {
        let envelope = match body {
            Some(body) => format!(r#"{{"kind": "{kind}", "rule": {body}}}"#),
            None => format!(r#"{{"kind": "{kind}"}}"#),
        };
        let request = DeployRequest::new(rule.to_owned(), operation, envelope.into_bytes());
        let outcome = connection.deploy(&request).await.unwrap();
        assert_eq!(outcome.operation, operation);
        assert_eq!(outcome.remote_id, None);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_platform_without_the_operation_says_so() {
    let sysdig = TenantConfig::new("sysdig", "falco", [("url", "https://sysdig.example")]);
    let connection = Connection::open(&sysdig, &options()).unwrap();
    let error = connection
        .query(&QueryRequest::new("x", "falco", window()))
        .await
        .unwrap_err();
    assert_eq!(code(&error), connectors::OPERATION_UNSUPPORTED);
    assert!(!connection.capabilities().query);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_operation_stops() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;
    let connection = Connection::open(&harfanglab(&server.uri()), &options()).unwrap();
    let canceller = connection.canceller();
    assert!(!canceller.is_cancelled());
    let later = canceller.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        later.cancel();
    });
    let request = QueryRequest::new("processes", "telemetry", window());
    let error = tokio::time::timeout(Duration::from_secs(20), connection.query(&request))
        .await
        .expect("the cancellation stops the query")
        .unwrap_err();
    assert_eq!(code(&error), "interrupted");
    assert!(canceller.is_cancelled());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_tenant_is_named_by_its_address() {
    // Port 1 of the loopback: nothing listens there, and no test can take it,
    // since it is below every system's ephemeral range. A port bound and then
    // released could be taken by a stand-in server of a test running at the
    // same time, which answered: `tenant_refused` on a CI runner (#1433).
    let url = "http://127.0.0.1:1".to_string();
    let connection = Connection::open(&harfanglab(&url), &options()).unwrap();
    let error = connection
        .query(&QueryRequest::new("processes", "telemetry", window()))
        .await
        .unwrap_err();
    assert_eq!(code(&error), "tenant_unreachable");
    assert!(error.to_string().contains(&url), "{error}");
    assert!(!error.to_string().contains("hl-secret"), "{error}");
}

#[test]
fn block_on_runs_an_operation_from_synchronous_code() {
    let elastic = TenantConfig::new("elastic", "es", [("url", "https://es.example")]);
    let connection =
        Connection::open(&elastic, &options().timeout(Duration::from_secs(5))).unwrap();
    let request = DeployRequest::new("r", Operation::Update, Vec::new());
    let error = connectors::block_on(connection.deploy(&request))
        .unwrap()
        .unwrap_err();
    // An empty body is no Kibana rule: refused before anything is sent.
    assert_eq!(code(&error), "tenant_refused");
}

/// Every `api_request` of a deploy plan's document, wherever it sits.
fn api_requests(value: &serde_json::Value, found: &mut Vec<serde_json::Value>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                if key == "api_request" && item.is_object() {
                    found.push(item.clone());
                } else {
                    api_requests(item, found);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|item| api_requests(item, found)),
        _ => {}
    }
}

/// #1142: the plan payload of a STAGING (PREVIEW) Google SecOps rule
/// carries its run state, without alerting, and its sections, which the
/// SDK's deploy sends (`tests/google_secops_failures.rs` in the connectors
/// shows the deploy honouring it); the payload carried the text alone, and
/// the SDK deployed it under RELEASE.
#[test]
fn a_planned_preview_google_secops_rule_carries_its_run_state() {
    let rule = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/google_secops/rule-google-secops-process-1.0.yaml"),
    )
    .unwrap();
    assert!(rule.contains("status: STAGING"));
    let platform = "[platform]\nenabled = true\n\n[[tenants]]\nname = \"secops\"\nstrategies = \
                    [\"PREVIEW\"]\n[tenants.setup]\nproject = \"acme\"\nlocation = \"eu\"\n\
                    instance = \"i-1\"\n";
    let ws = opentide::Workspace::from_files(
        "/ws",
        [
            (
                ".opentide/configurations/platforms/google_secops.toml",
                platform.to_owned(),
            ),
            ("objects/rules/process.yaml", rule),
        ],
    )
    .unwrap();
    let plan = ws
        .deploy_plan(
            &opentide::DeployPlanOptions::new(opentide::Strategy::Preview)
                .platform("google_secops"),
        )
        .unwrap();
    let mut found = Vec::new();
    api_requests(plan.document().value(), &mut found);
    let [payload] = found.as_slice() else {
        panic!("{}", plan.document())
    };
    assert!(
        payload["text"]
            .as_str()
            .is_some_and(|text| text.starts_with("rule "))
    );
    assert_eq!(
        payload["run_state"]["body"]["alerting"],
        serde_json::json!(false),
        "{payload}"
    );
    assert_eq!(payload["run_frequency"], "LIVE", "{payload}");
    assert!(
        payload["sections"]
            .as_array()
            .is_some_and(|sections| !sections.is_empty()),
        "{payload}"
    );
}

/// #1142: `ConnectOptions::environment` is the environment Google SecOps
/// reads its Application Default Credentials from, as every other
/// connector reads its credentials: the process (which names none here)
/// is not read.
#[tokio::test(flavor = "multi_thread")]
async fn google_secops_reads_its_credentials_from_the_options_environment() {
    let server = MockServer::start().await;
    let resource = "projects/acme/locations/eu/instances/i-1";
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"access_token": "ya29.test", "expires_in": 3600}"#),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/{resource}:verifyRuleText")))
        .and(header("Authorization", "Bearer ya29.test"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"success": true}"#))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/{resource}/rules")))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"name": "{resource}/rules/ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1"}}"#
        )))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;
    let home = tempfile::tempdir().unwrap();
    let adc = home.path().join("adc.json");
    std::fs::write(
        &adc,
        format!(
            r#"{{"type": "authorized_user", "client_id": "cid", "client_secret": "cs",
                "refresh_token": "rt", "token_uri": "{}/token"}}"#,
            server.uri()
        ),
    )
    .unwrap();
    // Whatever the process names (a developer's own ADC), the options'
    // credentials are the ones read: the token request below is the stand-in's.
    let tenant = TenantConfig::new(
        "google_secops",
        "secops",
        [
            ("project", "acme"),
            ("location", "eu"),
            ("instance", "i-1"),
            ("endpoint", server.uri().as_str()),
        ],
    );
    let options = ConnectOptions::default().environment([
        ("GOOGLE_APPLICATION_CREDENTIALS", adc.to_str().unwrap()),
        ("HOME", home.path().to_str().unwrap()),
    ]);
    let connection = Connection::open(&tenant, &options).unwrap();
    let body = r#"{"text": "rule r {\n  events:\n    $e.metadata.event_type = \"PROCESS_LAUNCH\"\n  condition:\n    $e\n}\n"}"#;
    let request = DeployRequest::new("", Operation::Create, body.as_bytes().to_vec());
    let deployed = connection.deploy(&request).await.unwrap();
    assert_eq!(
        deployed.remote_id.as_deref(),
        Some("ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1")
    );
    server.verify().await;
}

/// #1142: a deploy plan's Elastic payload is the deploy body,
/// `{payload, block}`, so deploying it through the SDK runs the
/// Elasticsearch checks, which read the block (here they warn that the
/// timestamp override is not mapped yet), and raises no
/// `elastic_checks_skipped`.
#[tokio::test(flavor = "multi_thread")]
async fn a_planned_elastic_rule_deploys_with_its_checks() {
    let uuid = "00000000-0000-4000-8099-000000000161";
    let rule = format!(
        "name: Planned rule\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.0\n  version: 1\n  \
         created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: Planned.\n\
         response:\n  alert_severity: High\nconfigurations:\n  elastic:\n    status: STAGING\n    \
         type: query\n    language: kuery\n    query: 'process.name: \"cmd.exe\"'\n    index: \
         [\"logs-*\"]\n    overrides:\n      timestamp: event.ingested\n    scheduling:\n      \
         interval: 5m\n"
    );
    let platform = "[platform]\nenabled = true\n\n[[tenants]]\nname = \"es\"\nstrategies = \
                    [\"PREVIEW\"]\n[tenants.setup]\nurl = \"https://kibana.invalid\"\n";
    let ws = opentide::Workspace::from_files(
        "/ws",
        [
            (
                ".opentide/configurations/platforms/elastic.toml",
                platform.to_owned(),
            ),
            ("objects/rules/planned.yaml", rule),
        ],
    )
    .unwrap();
    let plan = ws
        .deploy_plan(
            &opentide::DeployPlanOptions::new(opentide::Strategy::Preview).platform("elastic"),
        )
        .unwrap();
    let mut found = Vec::new();
    api_requests(plan.document().value(), &mut found);
    let [body] = found.as_slice() else {
        panic!("{}", plan.document())
    };
    assert_eq!(body["payload"]["rule_id"], uuid, "{body}");
    assert_eq!(
        body["block"]["overrides"]["timestamp"], "event.ingested",
        "{body}"
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/logs-*/_field_caps"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"indices": ["logs-1"], "fields": {}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .expect(1)
        .mount(&server)
        .await;
    let tenant = TenantConfig::new(
        "elastic",
        "es",
        [("url", server.uri()), ("elasticsearch_url", server.uri())],
    );
    let connection = Connection::open(&tenant, &options()).unwrap();
    let request = DeployRequest::new(uuid, Operation::Update, serde_json::to_vec(body).unwrap());
    let outcome = connection.deploy(&request).await.unwrap();
    let codes: Vec<&str> = outcome.warnings.iter().map(|w| w.code.as_str()).collect();
    assert_eq!(codes, ["elasticsearch_check_warning"], "{outcome:?}");
    assert_eq!(outcome.events[0].name, "elastic_rule_created");
}
