//! The recorded-HTTP harness of opentide's connectors (UC-4.1, #831; plan
//! §5.4 "HTTP").
//!
//! A cassette ([`cassette`]) holds the requests a client sent in one
//! scenario and the answers it got, normalised so that no secret lands in it
//! and only what the client itself chose to send is kept ([`redact`]). The
//! Python client's cassettes are recorded through [`proxy::Proxy`] in record
//! mode, a proxy that stands in for every host with a CA made for the run
//! ([`tls`]); a Rust client is then run against the same cassette through
//! the proxy in replay mode, or straight against a [`replay::Replay`]
//! (wiremock), which serves the recorded answers in order and asserts that
//! the requests are the recorded ones: a JSON body as the same data, any
//! other byte for byte ([`replay::same_body`]).
//!
//! Test tooling: never shipped.

pub mod cassette;
pub mod proxy;
pub mod redact;
pub mod replay;
pub mod tls;

pub use cassette::{Body, Cassette, Interaction};
pub use proxy::{Mode, Proxy};
pub use redact::Redaction;
pub use replay::{Mismatch, Replay};

/// The header the replaying proxy adds to name the origin a tunnelled
/// request was for; never recorded or compared.
pub const ORIGIN_HEADER: &str = "x-opentide-cassette-origin";

/// `scheme://host[:port]` of *url*.
pub fn origin(url: &url::Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
}
