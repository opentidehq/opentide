//! HarfangLab against the cassettes the Python client recorded
//! (`tests/cassettes/harfanglab/`): the deployer and the telemetry runner
//! send the Python client's requests, byte for byte and in order, and read
//! the answers as it does (the outcomes `client.py` printed when it
//! recorded).

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod cassette_support;

use std::time::Duration;

use cassette_support::{json, replay, rows, tenant, window};
use opentide_compile::Json;
use opentide_connectors::ConnectorError;
use opentide_connectors::Registry;
use opentide_connectors::body::python_json;
use opentide_connectors::connector::{
    DEFAULT_LIMIT, DEFAULT_QUERY_TIMEOUT, DeployRequest, Operation, QueryRequest, TenantContext,
};
use opentide_connectors::harfanglab::{self, HarfangLab};
use opentide_connectors::runtime::block_on;
use tokio_util::sync::CancellationToken;

const TOKEN: (&str, &str) = ("HARFANGLAB_API_TOKEN", "hl-test-token-only");
const RULE_ID: &str = "00000000-0000-4000-8003-000000000007";

const SIGMA_CONTENT: &str = "title: 'Mimikatz: sekurlsa — Ünïcode'\n\
id: 00000000-0000-4000-8003-000000000007\n\
status: experimental\n\
logsource:\n    category: process_creation\n    product: windows\n\
detection:\n    selection:\n        CommandLine|contains:\n            - sekurlsa\n    condition: selection\n\
level: high\n";

const YARA_CONTENT: &str = "import \"pe\"\n\nrule harfanglab_yara_loader {\n    meta:\n        \
id = \"00000000-0000-4000-8003-000000000008\"\n    strings:\n        $a = \"loader\"\n    \
condition:\n        $a\n}";

fn setup(kind: &str) -> String {
    format!(
        "ssl = true\ntype = \"{kind}\"\nurl = \"https://hl-tenant.invalid/\"\n\
         api_token = \"$HARFANGLAB_API_TOKEN\"\nsource_id = \"src-0001\"\n"
    )
}

fn object(pairs: Vec<(&str, Json)>) -> Json {
    Json::Object(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

/// The Sigma rule `client.py` sends (`SigmaRule`, `overwrite` true).
fn sigma(name: &str, enabled: bool) -> Vec<u8> {
    python_json(&object(vec![
        ("name", name.into()),
        ("content", SIGMA_CONTENT.into()),
        ("source_id", "src-0001".into()),
        ("enabled", Json::Bool(enabled)),
        (
            "global_state",
            if enabled { "block" } else { "disabled" }.into(),
        ),
        ("hl_status", "testing".into()),
        ("block_on_agent", Json::Bool(enabled)),
        ("quarantine_on_agent", Json::Bool(false)),
        ("rule_confidence_override", "strong".into()),
        ("rule_level_override", "high".into()),
        ("overwrite", Json::Bool(true)),
    ]))
    .unwrap()
}

/// The YARA file `client.py` sends (`YaraRule`, `overwrite` true).
fn yara(name: &str) -> Vec<u8> {
    python_json(&object(vec![
        ("name", name.into()),
        ("content", YARA_CONTENT.into()),
        ("source_id", "src-0001".into()),
        ("global_state", "alert".into()),
        ("hl_status", "stable".into()),
        ("rule_confidence_override", "moderate".into()),
        ("rule_level_override", "critical".into()),
        ("overwrite", Json::Bool(true)),
    ]))
    .unwrap()
}

fn registry() -> Registry {
    let mut registry = Registry::new();
    registry.register(Box::new(HarfangLab)).unwrap();
    registry
}

fn refusal(error: &ConnectorError) -> (String, Option<String>) {
    match error {
        ConnectorError::Refused {
            message, detail, ..
        } => (message.clone(), detail.clone()),
        other => panic!("not a refusal: {other}"),
    }
}

#[test]
fn harfanglab_deploys_as_the_python_client_does() {
    let replay = replay("harfanglab/deploy", &[TOKEN]);
    let registry = registry();
    let platform = registry.get("harfanglab").unwrap();
    assert!(platform.live_validator().is_none(), "no live validation");
    let deployer = platform.deployer().unwrap();
    let cancel = CancellationToken::new();
    let run = |kind: &str, operation, rule_id: &str, body: Vec<u8>| {
        let (tenant, http) = tenant(
            &replay,
            "harfanglab",
            "hl",
            &setup(kind),
            &harfanglab::http_defaults(),
        );
        let cx = TenantContext {
            tenant: &tenant,
            http: &http,
            cancel: &cancel,
        };
        let request = DeployRequest {
            rule_id: rule_id.to_owned(),
            operation,
            body,
        };
        block_on(async { deployer.deploy(cx, &request).await })
            .unwrap()
            .map(|outcome| outcome.remote_id)
    };
    let name = "Mimikatz: sekurlsa";
    // Not on the tenant: PUT is a 404, then POST creates it.
    assert_eq!(
        run("Sigma", Operation::Create, RULE_ID, sigma(name, true)).unwrap(),
        None
    );
    run("Sigma", Operation::Update, "sigma-1", sigma(name, true)).unwrap();
    run("Sigma", Operation::Disable, "sigma-1", sigma(name, false)).unwrap();
    run("Sigma", Operation::Delete, "sigma-1", Vec::new()).unwrap();
    let rejected = run(
        "Sigma",
        Operation::Update,
        RULE_ID,
        sigma("Rejected rule", true),
    )
    .unwrap_err();
    let (message, detail) = refusal(&rejected);
    assert_eq!(
        message,
        "Could not create or update the Sigma rule on HarfangLab tenant hl (HTTP 400)"
    );
    assert!(detail.unwrap().contains("detection.condition is missing"));
    let forbidden = run(
        "Sigma",
        Operation::Update,
        RULE_ID,
        sigma("Forbidden rule", true),
    )
    .unwrap_err();
    assert!(
        refusal(&forbidden)
            .0
            .contains("(HTTP 403): check the API token's permissions")
    );
    let missing = run("Sigma", Operation::Delete, "sigma-missing", Vec::new()).unwrap_err();
    assert_eq!(
        refusal(&missing).0,
        "Could not delete rule sigma-missing on HarfangLab tenant hl (HTTP 404)"
    );
    // A YARA tenant takes YARA files: posted, then deleted by the rule's UUID.
    run(
        "YARA",
        Operation::Create,
        RULE_ID,
        yara("HarfangLab YARA Loader"),
    )
    .unwrap();
    run("YARA", Operation::Delete, RULE_ID, Vec::new()).unwrap();
    let rejected = run("YARA", Operation::Update, RULE_ID, yara("Rejected YARA")).unwrap_err();
    assert_eq!(
        refusal(&rejected).0,
        "Could not create or update the YARA file on HarfangLab tenant hl (HTTP 400)"
    );
    run("YARA", Operation::Delete, "yara-missing", Vec::new()).unwrap_err();
    assert_eq!(replay.proxy.verify(), Vec::new());
}

fn query(text: &str, limit: usize, timeout: Duration) -> QueryRequest {
    QueryRequest {
        text: text.to_owned(),
        language: "telemetry".to_owned(),
        window: window(),
        limit,
        index: Vec::new(),
        data_view: None,
        timeout,
    }
}

#[test]
fn harfanglab_searches_telemetry_as_the_python_runner_does() {
    let replay = replay("harfanglab/query", &[TOKEN]);
    let (tenant, http) = tenant(
        &replay,
        "harfanglab",
        "hl",
        &setup("Sigma"),
        &harfanglab::http_defaults(),
    );
    let registry = registry();
    let runner = registry.get("harfanglab").unwrap().query_runner().unwrap();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let run = |request: QueryRequest| block_on(async { runner.run(cx, &request).await }).unwrap();

    // Quoted words and a Windows path, encoded as `requests` encodes them.
    let first = run(query(
        r#"Processes process_name=cmd.exe 'commandline__icontains=a b' image_name="C:\Windows\System32\cmd.exe" parent_name=*~x@y"#,
        1,
        DEFAULT_QUERY_TIMEOUT,
    ))
    .unwrap();
    let columns: Vec<&str> = first.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        columns,
        [
            "process_name",
            "agent.hostname",
            "agent.agentid",
            "@event_create_date"
        ]
    );
    assert_eq!(
        rows(&first.rows),
        json(
            r#"[{"process_name": "cmd.exe", "agent.hostname": "ws-01", "agent.agentid": "a1",
                 "@event_create_date": "2026-10-26T09:00:00.000Z"}]"#
        )
    );
    assert!(first.truncated, "count says 5 matched");
    assert_eq!(first.language.as_deref(), Some("telemetry"));
    let second = run(query(
        "dns requested_name=example.org",
        10,
        Duration::from_secs(30),
    ))
    .unwrap();
    assert_eq!(second.rows.len(), 2);
    assert_eq!(second.columns.len(), 5);
    assert!(!second.truncated);

    let broken = run(query(
        "processes process_name=broken.exe",
        DEFAULT_LIMIT,
        DEFAULT_QUERY_TIMEOUT,
    ))
    .unwrap_err();
    assert_eq!(
        refusal(&broken),
        (
            "HarfangLab refused the telemetry search on hl (HTTP 400)".to_owned(),
            Some(r#"{"detail": "Unknown field: process_nam"}"#.to_owned())
        )
    );
    let gateway = run(query(
        "processes process_name=gateway.exe",
        DEFAULT_LIMIT,
        DEFAULT_QUERY_TIMEOUT,
    ))
    .unwrap_err();
    let (message, detail) = refusal(&gateway);
    assert_eq!(
        message,
        "HarfangLab refused the telemetry search on hl (HTTP 502)"
    );
    assert!(
        detail.unwrap().starts_with(
            "HTTP 502 with an HTML page titled '502 Bad Gateway': HTTP 502 Bad Gateway is what a gateway"
        )
    );
    let unknown = run(query(
        "registry key=x",
        DEFAULT_LIMIT,
        DEFAULT_QUERY_TIMEOUT,
    ))
    .unwrap_err();
    assert_eq!(
        refusal(&unknown),
        (
            "a HarfangLab query starts with a telemetry source".to_owned(),
            Some(
                "one of: processes, binary, network, eventlog, dns, windows_authentications, \
                 linux_authentications, macos_authentications; then field=value filters"
                    .to_owned()
            )
        )
    );
    let unclosed = run(query(
        "processes 'unclosed",
        DEFAULT_LIMIT,
        DEFAULT_QUERY_TIMEOUT,
    ))
    .unwrap_err();
    assert_eq!(
        refusal(&unclosed),
        (
            "cannot read the telemetry query: No closing quotation".to_owned(),
            None
        )
    );
    assert_eq!(replay.proxy.verify(), Vec::new());
}
