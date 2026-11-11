//! What the platforms' cassette tests share (UC-4.2, #832): a cassette
//! recorded from the Python client (`tests/cassettes/<platform>/`, `cargo
//! xtask cassettes record`) replayed through the replaying proxy, and a
//! tenant whose client goes through it.

#![allow(dead_code, reason = "each test binary uses a part of it")]
#![expect(
    clippy::expect_used,
    reason = "test helpers: a failed set-up is a failure"
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

use opentide_cassette::{Cassette, Mode, Proxy, Redaction};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::{Environment, HttpClient, HttpSettings, Tenant};

/// The repository's root.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The cassette *name* (`crowdstrike/deploy`).
pub fn cassette(name: &str) -> Cassette {
    let path = repo().join(format!("tests/cassettes/{name}.json"));
    Cassette::parse(&std::fs::read_to_string(&path).expect("the cassette is readable"))
        .expect("the cassette parses")
}

/// A cassette being replayed, and the environment that sends a client
/// through it.
pub struct Replay {
    /// The replaying proxy.
    pub proxy: Proxy,
    /// The run's environment: the proxy, its CA, and the credentials.
    pub env: Environment,
    _ca: tempfile::NamedTempFile,
}

/// Replays the cassette *name*; *secrets* are the credentials' variables
/// and their values for this run (redacted as the recording redacted the
/// Python run's).
pub fn replay(name: &str, secrets: &[(&str, &str)]) -> Replay {
    let proxy = Proxy::start(
        Mode::Replay {
            cassette: cassette(name),
        },
        Redaction::new(secrets.iter().map(|(_, value)| (*value).to_owned())),
    )
    .expect("the replaying proxy starts");
    let mut ca = tempfile::NamedTempFile::new().expect("a temporary file");
    ca.write_all(proxy.ca_pem().as_bytes())
        .expect("the CA is written");
    let mut env =
        Environment::from_pairs(proxy.client_env(ca.path().to_str().expect("a UTF-8 path")));
    for (name, value) in secrets {
        env = env.with(name, value);
    }
    Replay {
        proxy,
        env,
        _ca: ca,
    }
}

/// The tenant *name* of *platform* from its `setup` table (TOML), and its
/// client, as a command that sends builds them.
pub fn tenant(
    replay: &Replay,
    platform: &str,
    name: &str,
    setup: &str,
    defaults: &HttpSettings,
) -> (Tenant, HttpClient) {
    let setup: toml::Table = toml::from_str(setup).expect("the setup is TOML");
    let tenant = Tenant::from_setup(
        platform,
        name,
        &setup,
        &replay.env,
        Resolve::Required,
        defaults,
    )
    .expect("the tenant is set up");
    let http = HttpClient::new(&tenant.label, &tenant.http, &replay.env, None)
        .expect("the client is built");
    (tenant, http)
}

/// The window every recorded search covers: 2026-10-26 08:00 to
/// 2026-10-27 08:00:00.250 UTC.
pub fn window() -> opentide_connectors::connector::TimeWindow {
    opentide_connectors::connector::TimeWindow {
        start: "2026-10-26T08:00:00Z".parse().expect("a timestamp"),
        end: "2026-10-27T08:00:00.25Z".parse().expect("a timestamp"),
    }
}

/// *text* as ordered JSON.
pub fn json(text: &str) -> opentide_compile::Json {
    serde_json::from_str(text).expect("the expectation is JSON")
}

/// *rows* as one JSON array, keys in order.
pub fn rows(rows: &[opentide_connectors::connector::Row]) -> opentide_compile::Json {
    opentide_compile::Json::Array(
        rows.iter()
            .cloned()
            .map(opentide_compile::Json::Object)
            .collect(),
    )
}
