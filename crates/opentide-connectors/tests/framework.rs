//! The framework, per tenant: TLS, CA bundles, proxies, timeouts and retries,
//! with two or more tenants of different settings in one run; credentials,
//! redaction, the fan-out, cancellation and progress.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test: a failed set-up is a failure"
)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentide_cassette::tls::TestCa;
use opentide_cassette::{Mode, Proxy, Redaction};
use opentide_connectors::credentials::{self, Credential, Mode as Resolve, Origin};
use opentide_connectors::progress::{Ndjson, ProgressSink, TenantEvent};
use opentide_connectors::proxy::ProxySettings;
use opentide_connectors::retry::RetryPolicy;
use opentide_connectors::runtime::{block_on, fan_out};
use opentide_connectors::tls::TlsSettings;
use opentide_connectors::{
    ConnectorError, Environment, HttpClient, HttpSettings, Secret, Tenant, TenantLabel,
};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn label(name: &str) -> TenantLabel {
    TenantLabel::new("mock", name)
}

/// A wiremock server, on a runtime the test keeps.
fn wiremock() -> (tokio::runtime::Runtime, MockServer) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let server = runtime.block_on(MockServer::start());
    (runtime, server)
}

/// GET *url* through a client of *settings*, returning the status.
fn get(
    name: &str,
    settings: &HttpSettings,
    env: &Environment,
    explicit: Option<&str>,
    url: &str,
) -> Result<u16, ConnectorError> {
    let client = HttpClient::new(&label(name), settings, env, explicit)?;
    let cancel = CancellationToken::new();
    block_on(async {
        let request = client
            .request(reqwest::Method::GET, url)
            .build()
            .expect("a request");
        client
            .send(request, &cancel)
            .await
            .map(|answer| answer.status().as_u16())
    })
    .unwrap()
}

/// A TLS server for `localhost` with a certificate of *ca*, answering `ok`.
fn tls_server(ca: &TestCa) -> (tokio::runtime::Runtime, u16) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let config = ca.server_config("localhost").unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    runtime.spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buffer = [0u8; 4096];
                let _ = tls.read(&mut buffer).await;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (runtime, port)
}

fn write_ca(ca: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(ca.as_bytes()).unwrap();
    file
}

#[test]
fn framework_tls_and_ca_per_tenant_in_one_run() {
    let ca = TestCa::new().unwrap();
    let (_server, port) = tls_server(&ca);
    let bundle = write_ca(ca.pem());
    let url = format!("https://localhost:{port}/");
    let env = Environment::default();
    let trusting = HttpSettings {
        tls: TlsSettings {
            verify: true,
            ca_bundle: Some(bundle.path().to_path_buf()),
        },
        ..HttpSettings::default()
    };
    let verifying = HttpSettings::default();
    let unverified = HttpSettings {
        tls: TlsSettings {
            verify: false,
            ca_bundle: None,
        },
        ..HttpSettings::default()
    };
    let clients: Vec<(&str, HttpClient)> = [
        ("trusting", &trusting),
        ("verifying", &verifying),
        ("unverified", &unverified),
    ]
    .into_iter()
    .map(|(name, settings)| {
        (
            name,
            HttpClient::new(&label(name), settings, &env, None).unwrap(),
        )
    })
    .collect();
    let cancel = CancellationToken::new();
    let outcomes: BTreeMap<&str, Result<u16, ConnectorError>> = block_on(async {
        let mut outcomes = BTreeMap::new();
        for (name, client) in &clients {
            let request = client.request(reqwest::Method::GET, &url).build().unwrap();
            let outcome = client
                .send(request, &cancel)
                .await
                .map(|answer| answer.status().as_u16());
            outcomes.insert(*name, outcome);
        }
        outcomes
    })
    .unwrap();
    assert_eq!(outcomes["trusting"].as_ref().unwrap(), &200);
    assert_eq!(outcomes["unverified"].as_ref().unwrap(), &200);
    let refused = outcomes["verifying"].as_ref().unwrap_err();
    assert!(refused.is_unreachable(), "{refused}");
    let text = refused.to_string();
    assert!(
        text.starts_with(&format!(
            "Cannot reach mock tenant 'verifying' at https://localhost:{port}:"
        )),
        "{text}"
    );
    assert!(text.to_lowercase().contains("certificate"), "{text}");

    // A CA bundle the environment names (the agent proxy's) is trusted by a
    // verifying tenant; it does not turn verification back on for one that
    // asked for none.
    let exported =
        Environment::from_pairs([("REQUESTS_CA_BUNDLE", bundle.path().to_str().unwrap())]);
    assert_eq!(
        get("exported", &verifying, &exported, None, &url).unwrap(),
        200
    );
    assert_eq!(
        get("unverified", &unverified, &exported, None, &url).unwrap(),
        200
    );
    // A tenant's own bundle that cannot be read is a setup error.
    let missing = HttpSettings {
        tls: TlsSettings {
            verify: true,
            ca_bundle: Some("/nonexistent/ca.pem".into()),
        },
        ..HttpSettings::default()
    };
    let error = HttpClient::new(&label("broken"), &missing, &env, None).unwrap_err();
    assert!(
        error.to_string().starts_with(
            "mock tenant 'broken' setup: cannot read the CA bundle /nonexistent/ca.pem"
        ),
        "{error}"
    );
}

#[test]
fn framework_proxy_per_tenant_no_proxy_and_explicit_proxy() {
    let (_runtime, upstream) = wiremock();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(
        Mock::given(method("GET"))
            .and(path("/ping"))
            .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
            .mount(&upstream),
    );
    let proxy = Proxy::start(
        Mode::Record {
            routes: BTreeMap::from([("tenant-a.invalid".to_owned(), upstream.uri())]),
        },
        Redaction::default(),
    )
    .unwrap();
    let bundle = write_ca(proxy.ca_pem());
    let ca = bundle.path().to_str().unwrap().to_owned();
    // Tenant A goes through the proxy the environment names.
    let through = Environment::from_pairs([
        ("HTTPS_PROXY", proxy.url().as_str()),
        ("SSL_CERT_FILE", ca.as_str()),
    ]);
    let settings = HttpSettings::default();
    assert_eq!(
        get(
            "a",
            &settings,
            &through,
            None,
            "https://tenant-a.invalid/ping"
        )
        .unwrap(),
        200
    );
    assert_eq!(proxy.interactions().len(), 1);
    assert_eq!(
        proxy.interactions()[0].request.url,
        "https://tenant-a.invalid/ping"
    );
    // Tenant B's host is in no_proxy (lower case wins): it goes direct.
    let direct = through
        .clone()
        .with("HTTP_PROXY", &proxy.url())
        .with("NO_PROXY", "nothing.invalid")
        .with("no_proxy", "127.0.0.1");
    assert_eq!(
        get(
            "b",
            &settings,
            &direct,
            None,
            &format!("{}/ping", upstream.uri())
        )
        .unwrap(),
        200
    );
    assert_eq!(
        proxy.interactions().len(),
        1,
        "tenant B went through the proxy"
    );
    // The same request without no_proxy is proxied (plain HTTP, absolute form).
    let proxied = Environment::from_pairs([("http_proxy", proxy.url().as_str())]);
    assert_eq!(
        get(
            "c",
            &settings,
            &proxied,
            None,
            &format!("{}/ping", upstream.uri())
        )
        .unwrap(),
        200
    );
    assert_eq!(proxy.interactions().len(), 2);
    // --proxy (or OPENTIDE_PROXY) wins over the variables, which name a
    // proxy that refuses every connection.
    let refusing = Environment::from_pairs([
        ("HTTPS_PROXY", "http://127.0.0.1:9"),
        ("https_proxy", "http://127.0.0.1:9"),
        ("SSL_CERT_FILE", ca.as_str()),
    ]);
    let error = get(
        "d",
        &settings,
        &refusing,
        None,
        "https://tenant-a.invalid/ping",
    )
    .unwrap_err();
    assert!(error.is_unreachable(), "{error}");
    assert_eq!(
        get(
            "d",
            &settings,
            &refusing,
            Some(&proxy.url()),
            "https://tenant-a.invalid/ping"
        )
        .unwrap(),
        200
    );
    let from_env = refusing.clone().with("OPENTIDE_PROXY", &proxy.url());
    assert_eq!(
        get(
            "e",
            &settings,
            &from_env,
            None,
            "https://tenant-a.invalid/ping"
        )
        .unwrap(),
        200
    );
    assert_eq!(proxy.interactions().len(), 4);
}

/// A proxy that answers every `CONNECT` with *reply* (or, when `None`, takes
/// the connection and never answers), counting the connections it takes.
fn fake_proxy(reply: Option<&'static str>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let taken = Arc::new(AtomicUsize::new(0));
    let counter = taken.clone();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for mut stream in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            match reply {
                Some(reply) => {
                    use std::io::Read as _;
                    let mut buffer = [0u8; 4096];
                    let _ = stream.read(&mut buffer);
                    let _ = stream.write_all(reply.as_bytes());
                }
                None => held.push(stream),
            }
        }
    });
    (url, taken)
}

#[test]
fn framework_proxy_variables_as_python_reads_them() {
    // Lower case wins over upper case; all_proxy serves both schemes when
    // neither scheme variable is set; --proxy, then OPENTIDE_PROXY, replace
    // the scheme variables; no_proxy is read the same way.
    let env = Environment::from_pairs([
        ("https_proxy", "http://lower-https:1"),
        ("HTTPS_PROXY", "http://upper-https:1"),
        ("HTTP_PROXY", "http://upper-http:1"),
        ("NO_PROXY", "upper.invalid"),
        ("no_proxy", "lower.invalid"),
    ]);
    assert_eq!(
        ProxySettings::from_env(&env, None),
        ProxySettings {
            https: Some("http://lower-https:1".into()),
            http: Some("http://upper-http:1".into()),
            no_proxy: Some("lower.invalid".into()),
        }
    );
    let all = Environment::from_pairs([("ALL_PROXY", "http://all:1")]);
    assert_eq!(
        ProxySettings::from_env(&all, None),
        ProxySettings {
            https: Some("http://all:1".into()),
            http: Some("http://all:1".into()),
            no_proxy: None,
        }
    );
    let both = all.clone().with("all_proxy", "http://lower-all:1");
    assert_eq!(
        ProxySettings::from_env(&both, None).https.as_deref(),
        Some("http://lower-all:1")
    );
    let scheme_wins = all.clone().with("HTTPS_PROXY", "http://https:1");
    let settings = ProxySettings::from_env(&scheme_wins, None);
    assert_eq!(settings.https.as_deref(), Some("http://https:1"));
    assert_eq!(settings.http.as_deref(), Some("http://all:1"));
    let opentide = env.clone().with("OPENTIDE_PROXY", "http://opentide:1");
    let settings = ProxySettings::from_env(&opentide, None);
    assert_eq!(settings.https.as_deref(), Some("http://opentide:1"));
    assert_eq!(settings.http.as_deref(), Some("http://opentide:1"));
    let settings = ProxySettings::from_env(&opentide, Some(" http://flag:1 "));
    assert_eq!(settings.https.as_deref(), Some("http://flag:1"));
    assert_eq!(settings.http.as_deref(), Some("http://flag:1"));
    // A blank --proxy is no proxy given.
    let settings = ProxySettings::from_env(&env, Some("  "));
    assert_eq!(settings.https.as_deref(), Some("http://lower-https:1"));
}

#[test]
fn framework_https_proxy_spellings_all_proxy_and_no_proxy_on_the_wire() {
    let (_runtime, upstream) = wiremock();
    tokio::runtime::Runtime::new().unwrap().block_on(
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&upstream),
    );
    let proxy = Proxy::start(
        Mode::Record {
            routes: BTreeMap::from([("tenant-a.invalid".to_owned(), upstream.uri())]),
        },
        Redaction::default(),
    )
    .unwrap();
    let bundle = write_ca(proxy.ca_pem());
    let ca = bundle.path().to_str().unwrap().to_owned();
    let settings = HttpSettings::default();
    let url = "https://tenant-a.invalid/ping";
    let refusing = "http://127.0.0.1:9";
    // https_proxy wins over HTTPS_PROXY for an https:// request.
    let lower = Environment::from_pairs([
        ("https_proxy", proxy.url().as_str()),
        ("HTTPS_PROXY", refusing),
        ("SSL_CERT_FILE", ca.as_str()),
    ]);
    assert_eq!(get("lower", &settings, &lower, None, url).unwrap(), 200);
    let upper = Environment::from_pairs([
        ("https_proxy", refusing),
        ("HTTPS_PROXY", proxy.url().as_str()),
        ("SSL_CERT_FILE", ca.as_str()),
    ]);
    assert!(
        get("upper", &settings, &upper, None, url)
            .unwrap_err()
            .is_unreachable()
    );
    // ALL_PROXY alone serves an https:// request.
    let all = Environment::from_pairs([
        ("ALL_PROXY", proxy.url().as_str()),
        ("SSL_CERT_FILE", ca.as_str()),
    ]);
    assert_eq!(get("all", &settings, &all, None, url).unwrap(), 200);
    assert_eq!(proxy.interactions().len(), 2);

    // An https:// tenant in no_proxy goes direct though HTTPS_PROXY is set.
    let tenant_ca = TestCa::new().unwrap();
    let (_server, port) = tls_server(&tenant_ca);
    let tenant_bundle = write_ca(tenant_ca.pem());
    let trusting = HttpSettings {
        tls: TlsSettings {
            verify: true,
            ca_bundle: Some(tenant_bundle.path().to_path_buf()),
        },
        ..HttpSettings::default()
    };
    let direct_url = format!("https://localhost:{port}/");
    let proxied = Environment::from_pairs([("HTTPS_PROXY", refusing)]);
    assert!(
        get("proxied", &trusting, &proxied, None, &direct_url)
            .unwrap_err()
            .is_unreachable()
    );
    let direct = proxied.clone().with("no_proxy", "localhost");
    assert_eq!(
        get("direct", &trusting, &direct, None, &direct_url).unwrap(),
        200
    );
}

#[test]
fn framework_a_connect_timeout_is_unreachable() {
    // A proxy that takes the connection and never answers the CONNECT: the
    // tunnel is part of connecting, so the tenant could not be reached.
    let (silent, _) = fake_proxy(None);
    let env = Environment::from_pairs([("HTTPS_PROXY", silent.as_str())]);
    let short = HttpSettings {
        timeout: Duration::from_millis(200),
        ..HttpSettings::default()
    };
    let error = get("slow", &short, &env, None, "https://tenant.invalid/q").unwrap_err();
    assert!(
        matches!(error, ConnectorError::Unreachable { .. }),
        "a connect timeout is an unreachable tenant: {error:?}"
    );
}

#[test]
fn framework_a_connection_that_fails_is_retried_for_any_method() {
    let env_for = |url: &str| Environment::from_pairs([("HTTPS_PROXY", url)]);
    let policy = RetryPolicy::urllib3(2, 0.01, &[503], &["GET"]);
    let send = |settings: &HttpSettings, env: &Environment, verb: reqwest::Method| {
        let client = HttpClient::new(&label("t"), settings, env, None).unwrap();
        block_on(async {
            let request = client
                .request(verb, "https://tenant.invalid/q")
                .build()
                .unwrap();
            client.send(request, &CancellationToken::new()).await
        })
        .unwrap()
    };
    let retrying = HttpSettings {
        retry: policy,
        ..HttpSettings::default()
    };
    // The proxy refuses the tunnel every time: one attempt and two retries,
    // for a method the policy does not list too (urllib3's `connect`).
    for verb in [reqwest::Method::GET, reqwest::Method::POST] {
        let (refusing, taken) = fake_proxy(Some(
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
        ));
        let error = send(&retrying, &env_for(&refusing), verb.clone()).unwrap_err();
        assert!(error.is_unreachable(), "{error:?}");
        assert_eq!(taken.load(Ordering::SeqCst), 3, "{verb}");
    }
    // No retries: once.
    let (refusing, taken) = fake_proxy(Some(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
    ));
    send(
        &HttpSettings::default(),
        &env_for(&refusing),
        reqwest::Method::GET,
    )
    .unwrap_err();
    assert_eq!(taken.load(Ordering::SeqCst), 1);
}

#[test]
fn framework_retry_waits_as_urllib3_and_for_retry_after() {
    // urllib3 2.x: no wait before the first retry, then factor * 2^(n-1).
    let policy = RetryPolicy::urllib3(4, 0.5, &[503], &["GET"]);
    let delays: Vec<Duration> = policy.delays().collect();
    assert_eq!(
        delays,
        [
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4)
        ]
    );
    assert_eq!(RetryPolicy::none().delays().count(), 0);
    let capped: Vec<Duration> = RetryPolicy::urllib3(10, 60.0, &[503], &["GET"])
        .delays()
        .collect();
    assert_eq!(capped[0], Duration::ZERO);
    assert_eq!(capped[9], Duration::from_secs(120));
    assert_eq!(
        policy.retry_after(429, Some("1000")),
        Some(Duration::from_secs(120))
    );
    // send() waits as long as the answer's Retry-After asks, not the
    // (zero) backoff.
    let (_runtime, server) = wiremock();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        Mock::given(path("/busy"))
            .respond_with(ResponseTemplate::new(503).insert_header("Retry-After", "1"))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(path("/busy"))
            .respond_with(ResponseTemplate::new(200))
            .with_priority(2)
            .mount(&server)
            .await;
    });
    let settings = HttpSettings {
        retry: RetryPolicy::urllib3(3, 0.0, &[503], &["GET"]),
        ..HttpSettings::default()
    };
    let started = std::time::Instant::now();
    assert_eq!(
        get(
            "busy",
            &settings,
            &Environment::default(),
            None,
            &format!("{}/busy", server.uri())
        )
        .unwrap(),
        200
    );
    assert!(started.elapsed() >= Duration::from_millis(950));
}

#[test]
fn framework_max_in_flight_bounds_a_tenants_requests() {
    let (_runtime, server) = wiremock();
    tokio::runtime::Runtime::new().unwrap().block_on(
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(300)))
            .mount(&server),
    );
    let three = |max_in_flight: usize| {
        let settings = HttpSettings {
            max_in_flight,
            ..HttpSettings::default()
        };
        let client =
            HttpClient::new(&label("t"), &settings, &Environment::default(), None).unwrap();
        let cancel = CancellationToken::new();
        let started = std::time::Instant::now();
        block_on(async {
            let one = || async {
                let request = client
                    .request(reqwest::Method::GET, &server.uri())
                    .build()
                    .unwrap();
                client
                    .send(request, &cancel)
                    .await
                    .unwrap()
                    .status()
                    .as_u16()
            };
            let (a, b, c) = tokio::join!(one(), one(), one());
            assert_eq!([a, b, c], [200, 200, 200]);
        })
        .unwrap();
        started.elapsed()
    };
    assert!(three(1) >= Duration::from_millis(890));
    assert!(three(3) < Duration::from_millis(890));
}

#[test]
fn framework_timeout_per_tenant() {
    // A tenant that takes the connection and never answers.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let silent_port = silent.local_addr().unwrap().port();
    let held = Arc::new(Mutex::new(Vec::new()));
    let holder = held.clone();
    std::thread::spawn(move || {
        for stream in silent.incoming().flatten() {
            holder.lock().unwrap().push(stream);
        }
    });
    let (_runtime, server) = wiremock();
    tokio::runtime::Runtime::new().unwrap().block_on(
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(700)))
            .mount(&server),
    );
    let short = HttpSettings {
        timeout: Duration::from_millis(200),
        ..HttpSettings::default()
    };
    let long = HttpSettings {
        timeout: Duration::from_secs(5),
        ..HttpSettings::default()
    };
    let env = Environment::default();
    let error = get(
        "slow",
        &short,
        &env,
        None,
        &format!("http://127.0.0.1:{silent_port}/q"),
    )
    .unwrap_err();
    assert!(
        matches!(error, ConnectorError::Timeout { .. }),
        "a read timeout, not an unreachable tenant: {error:?}"
    );
    assert!(!error.is_unreachable());
    // The same 700 ms answer: too slow for one tenant (200 ms once
    // connected), in time for the other.
    let url = format!("{}/q", server.uri());
    assert!(matches!(
        get("short", &short, &env, None, &url),
        Err(ConnectorError::Timeout { .. })
    ));
    assert_eq!(get("long", &long, &env, None, &url).unwrap(), 200);

    // An answer whose body stops coming: each read of the body has the
    // tenant's timeout, as `requests`' read timeout.
    let stalling = TcpListener::bind("127.0.0.1:0").unwrap();
    let stalling_port = stalling.local_addr().unwrap().port();
    let kept = held.clone();
    std::thread::spawn(move || {
        for mut stream in stalling.incoming().flatten() {
            use std::io::Read as _;
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab");
            let _ = stream.flush();
            kept.lock().unwrap().push(stream);
        }
    });
    let client = HttpClient::new(&label("stall"), &short, &env, None).unwrap();
    let cancel = CancellationToken::new();
    let started = std::time::Instant::now();
    let outcome = block_on(async {
        let request = client
            .request(
                reqwest::Method::GET,
                &format!("http://127.0.0.1:{stalling_port}/q"),
            )
            .build()
            .unwrap();
        let answer = client.send(request, &cancel).await.unwrap();
        client.bytes(answer, &cancel).await
    })
    .unwrap();
    assert!(
        matches!(outcome, Err(ConnectorError::Timeout { .. })),
        "{outcome:?}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(390),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn framework_retry_per_tenant() {
    let (_runtime, server) = wiremock();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        Mock::given(path("/flaky"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(path("/flaky"))
            .respond_with(ResponseTemplate::new(200))
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(path("/down"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
    });
    let env = Environment::default();
    let retrying = HttpSettings {
        retry: RetryPolicy::urllib3(3, 0.01, &[429, 500, 502, 503, 504], &["GET", "PUT"]),
        ..HttpSettings::default()
    };
    let once = HttpSettings::default();
    assert_eq!(
        get(
            "elastic",
            &retrying,
            &env,
            None,
            &format!("{}/flaky", server.uri())
        )
        .unwrap(),
        200
    );
    // No retries: the 503 is the answer (raise_on_status=False), sent once.
    assert_eq!(
        get(
            "splunk",
            &once,
            &env,
            None,
            &format!("{}/down", server.uri())
        )
        .unwrap(),
        503
    );
    // Retries run out: the last 503 is the answer.
    assert_eq!(
        get(
            "elastic",
            &retrying,
            &env,
            None,
            &format!("{}/down", server.uri())
        )
        .unwrap(),
        503
    );
    let received = rt.block_on(server.received_requests()).unwrap();
    let count = |p: &str| received.iter().filter(|r| r.url.path() == p).count();
    assert_eq!(count("/flaky"), 3);
    assert_eq!(count("/down"), 1 + 4);
    // A method the policy does not retry is sent once.
    let client = HttpClient::new(&label("post"), &retrying, &env, None).unwrap();
    let status = block_on(async {
        let request = client
            .request(reqwest::Method::POST, &format!("{}/down", server.uri()))
            .build()
            .unwrap();
        client
            .send(request, &CancellationToken::new())
            .await
            .unwrap()
            .status()
            .as_u16()
    })
    .unwrap();
    assert_eq!(status, 503);
    let received = rt.block_on(server.received_requests()).unwrap();
    assert_eq!(
        received.iter().filter(|r| r.url.path() == "/down").count(),
        6
    );
    // Retry-After is read on a 429 or 503.
    assert_eq!(
        retrying.retry.retry_after(503, Some("2")),
        Some(Duration::from_secs(2))
    );
    assert_eq!(retrying.retry.retry_after(500, Some("2")), None);
}

#[test]
fn framework_a_read_timeout_is_retried_only_for_a_retried_method() {
    // urllib3 retries a read timeout only for the methods in its list: the
    // server may have acted on a POST it never answered in time, and sending
    // it again could deploy a rule twice. A GET is sent again.
    let (_runtime, server) = wiremock();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(
        Mock::given(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(700)))
            .mount(&server),
    );
    let settings = HttpSettings {
        timeout: Duration::from_millis(200),
        retry: RetryPolicy::urllib3(2, 0.01, &[503], &["GET"]),
        ..HttpSettings::default()
    };
    let env = Environment::default();
    let client = HttpClient::new(&label("deploy"), &settings, &env, None).unwrap();
    let url = format!("{}/slow", server.uri());
    let send = |verb: reqwest::Method| {
        block_on(async {
            let request = client.request(verb, &url).build().unwrap();
            client
                .send(request, &CancellationToken::new())
                .await
                .map(|answer| answer.status().as_u16())
        })
        .unwrap()
    };
    let received = |verb: &str| {
        rt.block_on(server.received_requests())
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == verb)
            .count()
    };
    let post = send(reqwest::Method::POST);
    assert!(
        matches!(post, Err(ConnectorError::Timeout { .. })),
        "{post:?}"
    );
    assert_eq!(
        received("POST"),
        1,
        "a POST that timed out is not sent again"
    );
    let get = send(reqwest::Method::GET);
    assert!(
        matches!(get, Err(ConnectorError::Timeout { .. })),
        "{get:?}"
    );
    assert_eq!(received("GET"), 1 + 2, "a GET that timed out is retried");
}

#[test]
fn framework_upper_case_no_proxy_alone_is_read() {
    // NO_PROXY with no lower-case spelling set is the list, as Python's
    // getproxies_environment reads it.
    let env = Environment::from_pairs([
        ("HTTPS_PROXY", "http://upper-https:1"),
        ("NO_PROXY", "internal.example,127.0.0.1"),
    ]);
    assert_eq!(
        ProxySettings::from_env(&env, None),
        ProxySettings {
            https: Some("http://upper-https:1".into()),
            http: None,
            no_proxy: Some("internal.example,127.0.0.1".into()),
        }
    );
}

#[test]
fn framework_credentials_placeholders_and_errors() {
    let env = Environment::from_pairs([
        ("MOCK_TOKEN", "s3cr3t-value"),
        ("AZ-SECRET", "legacy-value"),
    ]);
    let origin = Origin {
        platform: "mock",
        tenant: "prod",
        key: "token",
    };
    let set = credentials::resolve("$MOCK_TOKEN", &env, Resolve::Required, origin).unwrap();
    assert_eq!(set.credential.secret().unwrap().expose(), "s3cr3t-value");
    let braces = credentials::resolve("${MOCK_TOKEN}", &env, Resolve::Required, origin).unwrap();
    assert_eq!(braces.credential, set.credential);
    // Counting: an unset variable is a placeholder, named.
    let counted = credentials::resolve("$UNSET_TOKEN", &env, Resolve::Counting, origin).unwrap();
    assert_eq!(
        counted.credential,
        Credential::Placeholder {
            variable: "UNSET_TOKEN".into()
        }
    );
    // Sending: an unset variable is an error naming the variable only.
    let error = credentials::resolve("$UNSET_TOKEN", &env, Resolve::Required, origin).unwrap_err();
    assert_eq!(
        error.to_string(),
        "mock tenant 'prod' setup: token names the environment variable UNSET_TOKEN, which is unset"
    );
    assert_eq!(error.failure_code(), "command_failed");
    // A literal that starts with `$` is itself, unless the 0.21.0 reading finds a variable.
    let literal = credentials::resolve("$uP3r-S3cret!", &env, Resolve::Required, origin).unwrap();
    assert_eq!(
        literal.credential.secret().unwrap().expose(),
        "$uP3r-S3cret!"
    );
    assert_eq!(literal.legacy_variable, None);
    let legacy = credentials::resolve("$AZ-SECRET", &env, Resolve::Required, origin).unwrap();
    assert_eq!(legacy.credential.secret().unwrap().expose(), "legacy-value");
    assert_eq!(legacy.legacy_variable.as_deref(), Some("AZ-SECRET"));
    // A variable set to nothing is the value, as Python sends it
    // (`os.environ.get(name, "")`): only an unset one is missing.
    let empty = env.clone().with("EMPTY_TOKEN", "");
    for mode in [Resolve::Required, Resolve::Counting] {
        let resolved = credentials::resolve("$EMPTY_TOKEN", &empty, mode, origin).unwrap();
        assert_eq!(resolved.credential.secret().unwrap().expose(), "");
    }

    // A tenant's setup: ssl words, $VAR ssl, credentials.
    let setup: toml::Table = toml::from_str(
        "ssl = \"$MOCK_SSL\"\nurl = \"https://tenant.invalid\"\ntoken = \"$MOCK_TOKEN\"\n",
    )
    .unwrap();
    let defaults = HttpSettings::default();
    let off = env.clone().with("MOCK_SSL", "off");
    let tenant =
        Tenant::from_setup("mock", "prod", &setup, &off, Resolve::Required, &defaults).unwrap();
    assert!(!tenant.http.tls.verify);
    assert_eq!(tenant.secret("token").unwrap().expose(), "s3cr3t-value");
    assert!(!format!("{tenant:?}").contains("s3cr3t-value"));
    let unset =
        Tenant::from_setup("mock", "prod", &setup, &env, Resolve::Required, &defaults).unwrap_err();
    assert_eq!(
        unset.to_string(),
        "mock tenant 'prod' setup: ssl is unset ($MOCK_SSL). Set that environment variable to true or false before a live check."
    );
    let counted =
        Tenant::from_setup("mock", "prod", &setup, &env, Resolve::Counting, &defaults).unwrap();
    assert!(counted.http.tls.verify);
    let bad: toml::Table = toml::from_str("ssl = \"maybe\"").unwrap();
    assert!(
        Tenant::from_setup("mock", "prod", &bad, &env, Resolve::Counting, &defaults)
            .unwrap_err()
            .to_string()
            .ends_with("ssl must be true or false, got \"maybe\"")
    );
    // Two tenants of one platform keep their own ssl (#742).
    let first: toml::Table = toml::from_str("ssl = false").unwrap();
    let second: toml::Table = toml::from_str("ssl = \"yes\"").unwrap();
    let a = Tenant::from_setup("mock", "a", &first, &env, Resolve::Required, &defaults).unwrap();
    let b = Tenant::from_setup("mock", "b", &second, &env, Resolve::Required, &defaults).unwrap();
    assert!(!a.http.tls.verify);
    assert!(b.http.tls.verify);
    // The words are read trimmed and in any case, written or from a variable
    // (`tenant_tls_verify`).
    for (written, verify) in [
        ("False", false),
        (" Yes ", true),
        ("OFF", false),
        (" On", true),
        ("0 ", false),
    ] {
        let literal: toml::Table = toml::from_str(&format!("ssl = {written:?}")).unwrap();
        let tenant =
            Tenant::from_setup("mock", "w", &literal, &env, Resolve::Required, &defaults).unwrap();
        assert_eq!(tenant.http.tls.verify, verify, "ssl = {written:?}");
        let variable = env.clone().with("MOCK_SSL", written);
        let tenant =
            Tenant::from_setup("mock", "v", &setup, &variable, Resolve::Required, &defaults)
                .unwrap();
        assert_eq!(tenant.http.tls.verify, verify, "MOCK_SSL={written:?}");
    }
}

#[test]
fn framework_no_credential_in_errors_or_debug() {
    let secret = "tok-9f8e7d6c5b4a";
    assert_eq!(format!("{:?}", Secret::new(secret)), "***");
    assert_eq!(format!("{}", Secret::new(secret)), "***");
    // A refused connection to a URL carrying credentials in its user info
    // and its query: the error names the origin only.
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let url = format!("http://user:{secret}@127.0.0.1:{port}/api?token={secret}");
    let error = get(
        "prod",
        &HttpSettings::default(),
        &Environment::default(),
        None,
        &url,
    )
    .unwrap_err();
    let text = format!("{error} {error:?}");
    assert!(!text.contains(secret), "{text}");
    assert!(text.contains(&format!("http://127.0.0.1:{port}")), "{text}");
    // A proxy URL with a password that is not a proxy URL.
    let env = Environment::from_pairs([("HTTPS_PROXY", format!("http://u:{secret}@proxy:port"))]);
    let error = HttpClient::new(&label("prod"), &HttpSettings::default(), &env, None).unwrap_err();
    assert!(!format!("{error} {error:?}").contains(secret), "{error}");
    // Through a proxy that needs credentials and refuses: no password in the error.
    let env =
        Environment::from_pairs([("HTTP_PROXY", format!("http://u:{secret}@127.0.0.1:{port}"))]);
    let error = get(
        "prod",
        &HttpSettings::default(),
        &env,
        None,
        "http://tenant.invalid/x",
    )
    .unwrap_err();
    assert!(!format!("{error} {error:?}").contains(secret), "{error}");
}

#[derive(Default)]
struct Events(Mutex<Vec<TenantEvent>>);

impl ProgressSink for Events {
    fn emit(&self, event: &TenantEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

#[derive(Debug)]
struct Rows(u64);

impl opentide_connectors::runtime::Rows for Rows {
    fn rows(&self) -> u64 {
        self.0
    }
}

#[test]
fn framework_fan_out_is_bounded_ordered_reported_and_cancellable() {
    let running = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(Events::default());
    let tenants: Vec<TenantLabel> = (0..6).map(|n| label(&format!("t{n}"))).collect();
    let cancel = CancellationToken::new();
    let runs = block_on(fan_out(
        tenants.clone(),
        2,
        &cancel,
        events.clone(),
        |tenant, _token| {
            let running = running.clone();
            let peak = peak.clone();
            async move {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(30)).await;
                running.fetch_sub(1, Ordering::SeqCst);
                if tenant.tenant == "t3" {
                    Err(ConnectorError::Setup {
                        platform: "mock".into(),
                        tenant: "t3".into(),
                        message: "broken".into(),
                    })
                } else {
                    Ok(Rows(tenant.tenant[1..].parse().unwrap()))
                }
            }
        },
    ))
    .unwrap();
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    let names: Vec<&str> = runs.iter().map(|run| run.label.tenant.as_str()).collect();
    assert_eq!(names, ["t0", "t1", "t2", "t3", "t4", "t5"]);
    assert!(runs[3].result.is_err());
    let mut seen = events.0.lock().unwrap().clone();
    seen.sort_by(|a, b| a.tenant.cmp(&b.tenant));
    assert_eq!(seen.len(), 6);
    assert_eq!(seen[3].status, "failed");
    assert_eq!(seen[5].status, "ok");
    assert_eq!(seen[5].rows, 5);
    assert_eq!(seen[3].rows, 0);
    // The event's JSON, as `progress_events.tenant` writes it.
    let sink = Ndjson::new(Vec::new());
    let mut event = TenantEvent::new("sentinel", "prod-é", true, 120, 1800);
    sink.emit(&event);
    event.label = Some("q1".into());
    sink.emit(&event);
    assert_eq!(
        String::from_utf8(sink.into_inner()).unwrap(),
        "{\"event\":\"tenant\",\"platform\":\"sentinel\",\"tenant\":\"prod-\\u00e9\",\"status\":\"ok\",\"rows\":120,\"elapsed_ms\":1800}\n\
         {\"event\":\"tenant\",\"platform\":\"sentinel\",\"tenant\":\"prod-\\u00e9\",\"status\":\"ok\",\"rows\":120,\"elapsed_ms\":1800,\"label\":\"q1\"}\n"
    );

    // Cancelled: the tenants still waiting never start, the running one stops.
    let started = Arc::new(AtomicUsize::new(0));
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    let counted = started.clone();
    let events = Arc::new(Events::default());
    let cancelled_events = events.clone();
    let runs = block_on(async move {
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            trigger.cancel();
        });
        let runs = fan_out(tenants, 1, &cancel, cancelled_events, move |_, token| {
            let counted = counted.clone();
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                token.cancelled().await;
                Ok::<(), ConnectorError>(())
            }
        })
        .await;
        handle.await.unwrap();
        runs
    })
    .unwrap();
    assert_eq!(started.load(Ordering::SeqCst), 1);
    assert!(
        runs.iter()
            .all(|run| matches!(run.result, Err(ConnectorError::Cancelled)))
    );
    assert_eq!(ConnectorError::Cancelled.failure_code(), "interrupted");
    // A cancelled tenant is not reported as failed: no event at all.
    assert_eq!(events.0.lock().unwrap().len(), 0);
}

#[test]
fn framework_fan_out_reports_a_tenant_whose_work_panics() {
    let events = Arc::new(Events::default());
    let tenants: Vec<TenantLabel> = (0..3).map(|n| label(&format!("t{n}"))).collect();
    let runs = block_on(fan_out(
        tenants,
        2,
        &CancellationToken::new(),
        events.clone(),
        |tenant, _token| async move {
            assert!(tenant.tenant != "t1", "the t1 connector broke");
            Ok(Rows(1))
        },
    ))
    .unwrap();
    let names: Vec<&str> = runs.iter().map(|run| run.label.tenant.as_str()).collect();
    assert_eq!(names, ["t0", "t1", "t2"]);
    assert!(runs[0].result.is_ok());
    assert!(runs[2].result.is_ok());
    let error = runs[1].result.as_ref().unwrap_err();
    assert!(matches!(error, ConnectorError::Crashed { .. }), "{error:?}");
    assert_eq!(
        error.to_string(),
        "mock tenant 't1': the connector stopped unexpectedly: the t1 connector broke"
    );
    assert_eq!(error.failure_code(), "command_failed");
    let mut seen = events.0.lock().unwrap().clone();
    seen.sort_by(|a, b| a.tenant.cmp(&b.tenant));
    let statuses: Vec<&str> = seen.iter().map(|event| event.status).collect();
    assert_eq!(statuses, ["ok", "failed", "ok"]);
}

#[test]
fn framework_a_send_stops_when_cancelled() {
    let (_runtime, server) = wiremock();
    tokio::runtime::Runtime::new().unwrap().block_on(
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
            .mount(&server),
    );
    let client = HttpClient::new(
        &label("slow"),
        &HttpSettings::default(),
        &Environment::default(),
        None,
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let started = std::time::Instant::now();
    let outcome = block_on(async {
        let trigger = cancel.clone();
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watched = flag.clone();
        let _watch = opentide_connectors::runtime::cancel_when(&trigger, move || {
            watched.load(Ordering::SeqCst)
        });
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            flag.store(true, Ordering::SeqCst);
        });
        let request = client
            .request(reqwest::Method::GET, &server.uri())
            .build()
            .unwrap();
        client.send(request, &cancel).await
    })
    .unwrap();
    assert!(matches!(outcome, Err(ConnectorError::Cancelled)));
    assert!(started.elapsed() < Duration::from_secs(5));
}
