//! What the platforms' cassette tests share: a tenant served by the
//! replaying proxy of a cassette recorded from the Python client
//! (`tests/cassettes/<platform>/<scenario>.json`), and the inputs that client
//! was given (`tests/fixtures/<platform>.json`, written by its `client.py
//! fixture`).

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]
#![allow(dead_code, reason = "each test crate uses its own part of the support")]

use std::io::Write as _;
use std::path::{Path, PathBuf};

use opentide_cassette::{Cassette, Mismatch, Mode, Proxy, Redaction};
use opentide_compile::json::Json;
use opentide_connectors::connector::TenantContext;
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::search::TimeWindow;
use opentide_connectors::{Environment, HttpClient, HttpSettings, Tenant};
use tokio_util::sync::CancellationToken;

/// The value the replayed tenant's credential has; redacted in the
/// comparison, as the recording's random one was.
pub const SECRET: &str = "replayed-credential-value";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The cassette *name* (`defender/deploy`).
pub fn cassette(name: &str) -> Cassette {
    let path = repo().join(format!("tests/cassettes/{name}.json"));
    Cassette::parse(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

/// The inputs of *platform*'s scenarios, keys in their order.
pub fn fixture(platform: &str) -> Json {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/{platform}.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A timestamp of a fixture (`2026-10-26T08:00:00+00:00`).
pub fn timestamp(value: &Json) -> jiff::Timestamp {
    value.as_str().unwrap().parse().unwrap()
}

/// The fixture's `[start, end]` window.
pub fn window(value: &Json) -> TimeWindow {
    let Json::Array(ends) = value else {
        panic!("a window is [start, end]")
    };
    TimeWindow {
        start: timestamp(&ends[0]),
        end: timestamp(&ends[1]),
    }
}

/// A tenant whose requests the proxy replaying *scenario* answers.
pub struct Replayed {
    /// The replaying proxy.
    pub proxy: Proxy,
    /// The tenant.
    pub tenant: Tenant,
    /// Its client.
    pub http: HttpClient,
    /// The run's cancellation.
    pub cancel: CancellationToken,
    _ca: tempfile::NamedTempFile,
}

impl Replayed {
    /// *platform*'s tenant `setup` (TOML), its credential `variable` set to
    /// [`SECRET`], served by the cassette *scenario*.
    pub fn start(
        scenario: &str,
        platform: &str,
        setup: &str,
        variable: &str,
        settings: &HttpSettings,
    ) -> Self {
        Self::start_with(cassette(scenario), platform, setup, variable, settings)
    }

    /// [`Replayed::start`] with a cassette already read (or altered).
    pub fn start_with(
        cassette: Cassette,
        platform: &str,
        setup: &str,
        variable: &str,
        settings: &HttpSettings,
    ) -> Self {
        let proxy = Proxy::start(
            Mode::Replay { cassette },
            Redaction::new([SECRET.to_owned()]),
        )
        .unwrap();
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(proxy.ca_pem().as_bytes()).unwrap();
        let env = Environment::from_pairs(proxy.client_env(ca.path().to_str().unwrap()))
            .with(variable, SECRET);
        let setup: toml::Table = toml::from_str(setup).unwrap();
        let tenant = Tenant::from_setup(
            platform,
            "replayed",
            &setup,
            &env,
            Resolve::Required,
            settings,
        )
        .unwrap();
        let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
        Self {
            proxy,
            tenant,
            http,
            cancel: CancellationToken::new(),
            _ca: ca,
        }
    }

    /// The context every call takes.
    pub fn cx(&self) -> TenantContext<'_> {
        TenantContext {
            tenant: &self.tenant,
            http: &self.http,
            cancel: &self.cancel,
        }
    }

    /// Every request that differs from the cassette's, in order.
    pub fn verify(&self) -> Vec<Mismatch> {
        self.proxy.verify()
    }
}

/// The text of a JSON string value.
pub fn text(value: &Json) -> &str {
    value.as_str().unwrap()
}

/// The items of a JSON array value.
pub fn items(value: &Json) -> &[Json] {
    match value {
        Json::Array(items) => items,
        _ => panic!("not an array: {value:?}"),
    }
}
