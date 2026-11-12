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

fn harfanglab(url: &str, kind: &str) -> TenantConfig {
    TenantConfig::new(
        "harfanglab",
        "lab",
        [("url", url), ("api_token", "$HL_TOKEN"), ("type", kind)],
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
    assert_eq!(platforms.len(), 9);
    for platform in &platforms {
        assert!(connectors::capabilities(platform).is_some(), "{platform}");
    }
    let sysdig = connectors::capabilities("sysdig").unwrap();
    assert!(sysdig.deploy && !sysdig.query && !sysdig.live_validation);
    let elastic = connectors::capabilities("elastic").unwrap();
    assert!(!elastic.deploy && elastic.query && elastic.live_validation);
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
    let tenant = harfanglab("https://hl.example", "Sigma");
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
    let connection = Connection::open(&harfanglab(&server.uri(), "Sigma"), &options()).unwrap();
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
    let connection = Connection::open(&harfanglab(&server.uri(), "Sigma"), &options()).unwrap();
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

    let connection = Connection::open(&harfanglab(&server.uri(), "Sigma"), &options()).unwrap();
    let error = connection.validate_query(&request).await.unwrap_err();
    assert_eq!(code(&error), connectors::OPERATION_UNSUPPORTED);
    assert_eq!(error.to_string(), "harfanglab cannot check a query live");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deploy_sends_the_compiled_body() {
    let server = MockServer::start().await;
    let rule = "11111111-1111-4111-8111-111111111111";
    let body = r#"{"name": "Example", "content": "title: Example"}"#;
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
        .and(body_string(body))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;
    let connection = Connection::open(&harfanglab(&server.uri(), "Sigma"), &options()).unwrap();
    let request = DeployRequest {
        rule_id: rule.to_owned(),
        operation: Operation::Create,
        body: body.as_bytes().to_vec(),
    };
    let outcome = connection.deploy(&request).await.unwrap();
    assert_eq!(outcome.operation, Operation::Create);
    assert_eq!(outcome.remote_id, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_platform_without_the_operation_says_so() {
    let elastic = TenantConfig::new("elastic", "es", [("url", "https://es.example")]);
    let connection = Connection::open(&elastic, &options()).unwrap();
    let request = DeployRequest {
        rule_id: "r".into(),
        operation: Operation::Delete,
        body: Vec::new(),
    };
    let error = connection.deploy(&request).await.unwrap_err();
    assert_eq!(code(&error), connectors::OPERATION_UNSUPPORTED);

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
    let connection = Connection::open(&harfanglab(&server.uri(), "Sigma"), &options()).unwrap();
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
    // A port nothing listens on: bound, then released.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url = format!("http://127.0.0.1:{port}");
    let connection = Connection::open(&harfanglab(&url, "Sigma"), &options()).unwrap();
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
    let request = DeployRequest {
        rule_id: "r".into(),
        operation: Operation::Update,
        body: Vec::new(),
    };
    let error = connectors::block_on(connection.deploy(&request))
        .unwrap()
        .unwrap_err();
    assert_eq!(code(&error), connectors::OPERATION_UNSUPPORTED);
}
