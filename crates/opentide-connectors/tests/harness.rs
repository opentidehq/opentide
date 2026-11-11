//! The recorded-HTTP harness on a sample connector (a mock platform): the
//! cassette the Python client recorded (`tests/cassettes/mock-platform/
//! deploy.json`, `cargo xtask cassettes record`) is replayed through the
//! replaying proxy, and the Rust connector's requests must be the Python
//! client's, byte for byte, in order. One byte off fails.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use opentide_cassette::{Cassette, Mode, Proxy, Redaction};
use opentide_connectors::body::python_json;
use opentide_connectors::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, Operation, Platform, TenantContext,
};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::retry::RetryPolicy;
use opentide_connectors::runtime::block_on;
use opentide_connectors::{
    ConnectorError, Environment, HttpClient, HttpSettings, Registry, Tenant,
};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

const BASE: &str = "https://mock-tenant.invalid";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cassette(name: &str) -> Cassette {
    let path = repo().join(format!("tests/cassettes/{name}.json"));
    Cassette::parse(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

/// The rule the Python client deploys, in its key order.
#[derive(Clone, Serialize)]
#[expect(clippy::struct_field_names, reason = "the platform's key names")]
struct Rule {
    rule_id: &'static str,
    name: &'static str,
    enabled: bool,
    query: &'static str,
    tags: [&'static str; 2],
    severity: u32,
    risk: f64,
    references: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'static str>,
}

const RULE: Rule = Rule {
    rule_id: "5f1c3a2e-0b7d-4c1e-9a58-2f6d7e8c9b01",
    name: "Encoded PowerShell — Ünïcode",
    enabled: true,
    query: r#"process where process.name == "powershell.exe" and process.args : "-enc*""#,
    tags: ["attack.t1059.001", "opentide"],
    severity: 73,
    risk: 0.5,
    references: None,
    description: None,
};

/// The sample connector: the mock platform's rules API.
struct MockPlatform {
    /// Writes bodies as `json.dumps` does; off, as serde_json does.
    python_bodies: bool,
}

impl MockPlatform {
    async fn call(
        &self,
        cx: TenantContext<'_>,
        method: reqwest::Method,
        url: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, serde_json::Value), ConnectorError> {
        let token = cx.tenant.secret("token")?;
        let mut builder = cx
            .http
            .request(method, url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token.expose()));
        if let Some(body) = body {
            // The compiled bytes; off, the body as serde_json would write
            // it again (keys sorted, no spaces, raw UTF-8).
            let bytes = if self.python_bodies {
                body.to_vec()
            } else {
                let value: serde_json::Value = serde_json::from_slice(body).unwrap();
                serde_json::to_vec(&value).unwrap()
            };
            builder = builder.body(bytes);
        }
        let response = cx.http.send(builder.build().unwrap(), cx.cancel).await?;
        let status = response.status().as_u16();
        let bytes = cx.http.bytes(response, cx.cancel).await?;
        Ok((status, serde_json::from_slice(&bytes).unwrap_or_default()))
    }
}

/// The error of an answer the sample did not expect.
fn refused(status: u16) -> ConnectorError {
    ConnectorError::Answer {
        platform: "mock".into(),
        tenant: "sandbox".into(),
        address: BASE.into(),
        reason: format!("HTTP {status}"),
    }
}

impl Deployer for MockPlatform {
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let remote = match request.operation {
                Operation::Create => {
                    let mut lookup = url::Url::parse(&format!("{BASE}/api/v1/rules")).unwrap();
                    lookup
                        .query_pairs_mut()
                        .append_pair("rule_id", &request.rule_id);
                    let (_, found) = self
                        .call(cx, reqwest::Method::GET, lookup.as_str(), None)
                        .await?;
                    if found["data"] != serde_json::json!([]) {
                        return Err(refused(200));
                    }
                    let (status, created) = self
                        .call(
                            cx,
                            reqwest::Method::POST,
                            &format!("{BASE}/api/v1/rules"),
                            Some(request.body.as_slice()),
                        )
                        .await?;
                    if status != 201 {
                        return Err(refused(status));
                    }
                    created["id"].as_str().map(str::to_owned)
                }
                Operation::Update | Operation::Disable => {
                    let method = if request.operation == Operation::Update {
                        reqwest::Method::PUT
                    } else {
                        reqwest::Method::PATCH
                    };
                    let url = format!("{BASE}/api/v1/rules/{}", request.rule_id);
                    let (status, answer) = self
                        .call(cx, method, &url, Some(request.body.as_slice()))
                        .await?;
                    if status != 200 {
                        return Err(refused(status));
                    }
                    let _ = answer;
                    Some(request.rule_id.clone())
                }
                Operation::Delete => None,
            };
            Ok(DeployOutcome {
                remote_id: remote,
                operation: request.operation,
            })
        })
    }
}

impl Platform for MockPlatform {
    fn id(&self) -> &'static str {
        "mock"
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self)
    }
}

/// Runs the Python client's sequence with the sample connector against
/// *proxy*, returning the remote id and the 404's status.
fn deploy(
    proxy: &Proxy,
    rule: &Rule,
    python_bodies: bool,
) -> Result<(String, u16), ConnectorError> {
    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(proxy.ca_pem().as_bytes()).unwrap();
    let env = Environment::from_pairs(proxy.client_env(ca.path().to_str().unwrap()))
        .with("MOCK_PLATFORM_TOKEN", "a-test-token-only");
    let setup: toml::Table =
        toml::from_str("url = \"https://mock-tenant.invalid\"\ntoken = \"$MOCK_PLATFORM_TOKEN\"")
            .unwrap();
    let defaults = HttpSettings {
        retry: RetryPolicy::urllib3(
            3,
            0.5,
            &[429, 500, 502, 503, 504],
            &["GET", "PUT", "PATCH", "POST"],
        ),
        ..HttpSettings::default()
    };
    let tenant = Tenant::from_setup(
        "mock",
        "sandbox",
        &setup,
        &env,
        Resolve::Required,
        &defaults,
    )?;
    let http = HttpClient::new(&tenant.label, &tenant.http, &env, None)?;
    let mut registry = Registry::new();
    registry
        .register(Box::new(MockPlatform { python_bodies }))
        .unwrap();
    let platform = registry.get("mock").unwrap();
    let deployer = platform.deployer().unwrap();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    block_on(async {
        let created = deployer
            .deploy(
                cx,
                &DeployRequest {
                    rule_id: rule.rule_id.to_owned(),
                    operation: Operation::Create,
                    body: python_json(rule).unwrap(),
                },
            )
            .await?;
        let remote = created.remote_id.unwrap_or_default();
        let tuned = Rule {
            description: Some("Tuned: 2 exclusions"),
            ..rule.clone()
        };
        deployer
            .deploy(
                cx,
                &DeployRequest {
                    rule_id: remote.clone(),
                    operation: Operation::Update,
                    body: python_json(&tuned).unwrap(),
                },
            )
            .await?;
        deployer
            .deploy(
                cx,
                &DeployRequest {
                    rule_id: remote.clone(),
                    operation: Operation::Disable,
                    body: python_json(&serde_json::json!({"enabled": false})).unwrap(),
                },
            )
            .await?;
        let missing = MockPlatform { python_bodies }
            .call(
                cx,
                reqwest::Method::GET,
                &format!("{BASE}/api/v1/rules/r-404"),
                None,
            )
            .await?;
        Ok((remote, missing.0))
    })
    .unwrap()
}

fn replay(name: &str) -> Proxy {
    Proxy::start(
        Mode::Replay {
            cassette: cassette(name),
        },
        Redaction::new(["a-test-token-only".to_owned()]),
    )
    .unwrap()
}

#[test]
fn harness_sample_connector_sends_what_the_python_client_sent() {
    let proxy = replay("mock-platform/deploy");
    let outcome = deploy(&proxy, &RULE, true);
    assert_eq!(proxy.verify(), Vec::new());
    assert_eq!(outcome.unwrap(), ("r-1".to_owned(), 404));
}

#[test]
fn harness_a_single_byte_difference_fails() {
    // severity 74 instead of 73: one byte of the create body.
    let proxy = replay("mock-platform/deploy");
    let one_off = Rule {
        severity: 74,
        ..RULE
    };
    let outcome = deploy(&proxy, &one_off, true);
    let mismatches = proxy.verify();
    assert!(outcome.is_err() || !mismatches.is_empty());
    assert_eq!(mismatches[0].index, 1, "{mismatches:?}");
    assert!(
        mismatches[0].detail.starts_with("bodies differ at byte "),
        "{}",
        mismatches[0]
    );
    // serde_json's own layout (no spaces after separators, raw UTF-8) is
    // not the Python client's either.
    let proxy = replay("mock-platform/deploy");
    let _ = deploy(&proxy, &RULE, false);
    let mismatches = proxy.verify();
    assert_eq!(
        mismatches.first().map(|m| m.index),
        Some(1),
        "{mismatches:?}"
    );
    // A request the cassette does not hold, or one too few, fails too.
    let proxy = replay("mock-platform/deploy");
    let mismatches = proxy.verify();
    assert_eq!(
        mismatches.len(),
        cassette("mock-platform/deploy").interactions.len()
    );
    assert!(
        mismatches[0]
            .detail
            .ends_with("was recorded and never sent")
    );
}

#[test]
fn harness_cassettes_hold_no_credential() {
    // Every cassette's credentials are redacted: the bearer token of the
    // sample, recorded with a random value, is `Bearer REDACTED`.
    let deploy = cassette("mock-platform/deploy");
    for interaction in &deploy.interactions {
        let auth: Vec<&str> = interaction
            .request
            .headers
            .iter()
            .filter(|(name, _)| name == "authorization")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(auth, ["Bearer REDACTED"]);
        assert!(
            interaction
                .request
                .headers
                .iter()
                .all(|(name, _)| name != "user-agent" && name != "host")
        );
    }

    // Recording through the proxy: a secret in a header, the user info, a
    // query parameter, a JSON body, a form body and an answer never lands
    // in the recording.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let upstream = rt.block_on(wiremock::MockServer::start());
    rt.block_on(
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("set-cookie", "session=sess-abcdef123")
                    .set_body_string(r#"{"access_token": "at-0123456789", "ok": true}"#),
            )
            .mount(&upstream),
    );
    let known = "known-secret-42";
    let proxy = Proxy::start(
        Mode::Record {
            routes: BTreeMap::from([("tenant.invalid".to_owned(), upstream.uri())]),
        },
        Redaction::new([known.to_owned()]),
    )
    .unwrap();
    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(proxy.ca_pem().as_bytes()).unwrap();
    let env = Environment::from_pairs(proxy.client_env(ca.path().to_str().unwrap()));
    let label = opentide_connectors::TenantLabel::new("mock", "t");
    let client = HttpClient::new(&label, &HttpSettings::default(), &env, None).unwrap();
    let cancel = CancellationToken::new();
    block_on(async {
        for (url, body, header) in [
            (
                "https://user:pw-userinfo-77@tenant.invalid/a?api_key=qk-55555&page=2",
                r#"{"client_secret": "cs-9999999", "name": "x"}"#,
                ("X-Api-Key", "hk-1234567"),
            ),
            (
                "https://tenant.invalid/token",
                "grant_type=client_credentials&client_secret=fs-8888888&scope=x",
                ("Authorization", "Basic YmFzaWMtc2VjcmV0"),
            ),
            (
                "https://tenant.invalid/plain",
                r#"{"note": "carries known-secret-42 inline"}"#,
                ("X-Trace", known),
            ),
        ] {
            let request = client
                .request(reqwest::Method::POST, url)
                .header(header.0, header.1)
                .body(body)
                .build()
                .unwrap();
            let answer = client.send(request, &cancel).await.unwrap();
            assert_eq!(answer.status().as_u16(), 200);
            // The client itself still gets the real answer.
            let text = client.bytes(answer, &cancel).await.unwrap();
            assert!(String::from_utf8(text).unwrap().contains("at-0123456789"));
        }
    })
    .unwrap();
    let recorded = Cassette::new("redaction", vec![], proxy.interactions()).to_text();
    for secret in [
        "pw-userinfo-77",
        "qk-55555",
        "cs-9999999",
        "hk-1234567",
        "fs-8888888",
        "YmFzaWMtc2VjcmV0",
        known,
        "at-0123456789",
        "sess-abcdef123",
    ] {
        assert!(!recorded.contains(secret), "{secret} in\n{recorded}");
    }
    assert!(recorded.contains("page=2"));
    assert!(recorded.contains("\\\"name\\\": \\\"x\\\""));
    assert!(recorded.contains("Basic REDACTED"));
    assert!(recorded.contains("scope=x"));
}
