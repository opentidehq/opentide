//! opentide's tenant connectors (plan D-8, ADR 0008; UC-4.1, #831).
//!
//! One framework for every request opentide sends to a tenant or to the
//! network: the HTTP client ([`http::HttpClient`], reqwest on rustls), built
//! per tenant from that tenant's own settings, never another tenant's
//! (#742): TLS on or off, the CA bundles it trusts, the proxy it goes
//! through, its timeout and its retries. Around it: credentials resolved from
//! the environment and never printed ([`credentials`]), the connector traits
//! the platforms implement and their registry ([`connector`]), the tokio
//! runtime with a bounded fan-out over tenants and cancellation
//! ([`runtime`]), progress events ([`progress`]) and the errors with the
//! failure codes they map to ([`error`]).
//!
//! The platforms built on it (UC-4.2, #832): [`crowdstrike`], [`defender`],
//! [`elastic`], [`harfanglab`], [`sentinel_one`] and [`sysdig`], each a
//! request-for-request port of its Python client, deployer and query runner,
//! on one set of query types ([`connector::QueryRequest`],
//! [`connector::QueryOutcome`]); [`builtin`] registers them.
//!
//! The recorded-HTTP harness that proves a connector sends what the Python
//! client sends is `opentide-cassette`, a test crate.

pub mod answer;
pub mod body;
pub mod connector;
pub mod credentials;
pub mod crowdstrike;
pub mod defender;
pub mod elastic;
pub mod encode;
pub mod env;
pub mod error;
pub mod harfanglab;
pub mod http;
pub mod progress;
pub mod proxy;
pub mod python;
pub mod retry;
pub mod runtime;
pub mod sentinel_one;
pub mod sysdig;
pub mod tenant;
pub mod tls;

pub use connector::{Platform, Registry};
pub use credentials::{Credential, Secret};
pub use env::Environment;
pub use error::ConnectorError;
pub use http::{HttpClient, HttpSettings};
pub use tenant::{Tenant, TenantLabel};

/// The built-in platforms with a connector, in the order Python lists them:
/// CrowdStrike, HarfangLab and Sysdig (UC-4.2a), Defender for Endpoint,
/// Elastic and SentinelOne (UC-4.2b).
pub fn builtin() -> Registry {
    let platforms: [Box<dyn Platform>; 6] = [
        Box::new(defender::Defender::new()),
        Box::new(sentinel_one::SentinelOne),
        Box::new(crowdstrike::Crowdstrike::new()),
        Box::new(harfanglab::HarfangLab),
        Box::new(elastic::Elastic),
        Box::new(sysdig::Sysdig),
    ];
    let mut registry = Registry::new();
    for platform in platforms {
        // Six distinct identifiers: registering cannot be refused.
        let _ = registry.register(platform);
    }
    registry
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_builtin_registry_holds_the_six_rest_platforms_and_what_each_can_do() {
        let registry = super::builtin();
        assert_eq!(
            registry.ids(),
            [
                "defender_for_endpoint",
                "sentinel_one",
                "crowdstrike",
                "harfanglab",
                "elastic",
                "sysdig"
            ]
        );
        let can = |id: &str| {
            let platform = registry.get(id).expect("registered");
            (
                platform.deployer().is_some(),
                platform.live_validator().is_some(),
                platform.query_runner().is_some(),
            )
        };
        assert_eq!(can("defender_for_endpoint"), (true, true, true));
        assert_eq!(can("sentinel_one"), (true, true, true));
        assert_eq!(can("elastic"), (false, true, true));
        assert_eq!(can("crowdstrike"), (true, false, true));
        assert_eq!(can("harfanglab"), (true, false, true));
        assert_eq!(can("sysdig"), (true, false, false));
    }
}
