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
//! The platforms built on it: [`crowdstrike`], [`defender`], [`elastic`],
//! [`harfanglab`], [`sentinel_one`] and [`sysdig`] (UC-4.2, #832), the REST
//! platforms, and [`splunk`], [`carbon_black`] and [`sentinel`] (UC-4.3,
//! #833), which Python reaches through vendor SDKs; each a request-for-request
//! port of its Python client, deployer and query runner, on one set of query
//! types ([`connector::QueryRequest`], [`connector::QueryOutcome`]);
//! [`builtin`] registers them, and [`plugin::with_plugins`] adds the platforms
//! a Python package registers (UC-4.5, #835) after them.
//!
//! The recorded-HTTP harness that proves a connector sends what the Python
//! client sends is `opentide-cassette`, a test crate.

pub mod answer;
pub mod body;
pub mod carbon_black;
pub mod connector;
pub mod credentials;
pub mod crowdstrike;
pub mod defender;
pub mod elastic;
pub mod encode;
pub mod env;
pub mod error;
pub mod exabeam;
pub mod harfanglab;
pub mod http;
pub mod misp;
pub mod plugin;
pub mod progress;
pub mod proxy;
pub mod python;
pub mod retry;
pub mod runtime;
pub mod sentinel;
pub mod sentinel_one;
pub mod splunk;
pub mod sysdig;
pub mod tenant;
pub mod tls;
pub mod vulnerability;

pub use connector::{Platform, Registry};
pub use credentials::{Credential, Secret};
pub use env::Environment;
pub use error::ConnectorError;
pub use http::{HttpClient, HttpSettings};
pub use plugin::{PluginError, PluginHost};
pub use tenant::{Tenant, TenantLabel};

/// The HTTP settings *platform*'s client mounts: its timeout and retries,
/// as its Python client mounts them. *timeout* is the read timeout of the
/// clients that take the caller's (Elastic, Splunk and Carbon Black Cloud;
/// Sentinel's at least 300 s, azure-core's read); the others keep their own.
/// A platform without a connector gets the defaults.
pub fn http_settings(platform: &str, timeout: std::time::Duration) -> HttpSettings {
    match platform {
        "defender_for_endpoint" => defender::http_settings(),
        "sentinel_one" => sentinel_one::http_settings(),
        "crowdstrike" => crowdstrike::http_defaults(),
        "harfanglab" => harfanglab::http_defaults(),
        "sysdig" => sysdig::http_defaults(),
        "elastic" => elastic::http_settings(timeout),
        "splunk" => splunk::http_settings(timeout),
        "carbon_black_cloud" => carbon_black::http_settings(timeout),
        // azure-core reads for 300 s; the server holds a query up to its own
        // timeout (`Prefer: wait`).
        "sentinel" => sentinel::http_settings(timeout.max(std::time::Duration::from_secs(300))),
        _ => HttpSettings::default(),
    }
}

/// The built-in platforms with a connector, in the order Python lists them:
/// CrowdStrike, HarfangLab and Sysdig (UC-4.2a), Defender for Endpoint,
/// Elastic and SentinelOne (UC-4.2b), Sentinel, Splunk and Carbon Black
/// Cloud (UC-4.3).
pub fn builtin() -> Registry {
    let platforms: [Box<dyn Platform>; 9] = [
        Box::new(sentinel::Sentinel::new()),
        Box::new(defender::Defender::new()),
        Box::new(splunk::Splunk::new()),
        Box::new(sentinel_one::SentinelOne),
        Box::new(carbon_black::CarbonBlack),
        Box::new(crowdstrike::Crowdstrike::new()),
        Box::new(harfanglab::HarfangLab),
        Box::new(elastic::Elastic),
        Box::new(sysdig::Sysdig),
    ];
    let mut registry = Registry::new();
    for platform in platforms {
        // Nine distinct identifiers: registering cannot be refused.
        let _ = registry.register(platform);
    }
    registry
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[test]
    fn each_platform_mounts_its_own_http_settings() {
        let timeout = Duration::from_secs(7);
        assert_eq!(
            super::http_settings("elastic", timeout),
            super::elastic::http_settings(timeout)
        );
        assert_eq!(
            super::http_settings("sentinel", timeout),
            super::sentinel::http_settings(Duration::from_secs(300))
        );
        assert_eq!(
            super::http_settings("sentinel", Duration::from_secs(900)).timeout,
            super::sentinel::http_settings(Duration::from_secs(900)).timeout
        );
        assert_eq!(
            super::http_settings("defender_for_endpoint", timeout),
            super::defender::http_settings()
        );
        assert_eq!(
            super::http_settings("sysdig", timeout),
            super::sysdig::http_defaults()
        );
        assert_eq!(
            super::http_settings("unknown", timeout),
            super::HttpSettings::default()
        );
    }

    #[test]
    fn configured_tenants_keep_file_order_and_their_setup() {
        let config: opentide_compile::Json = serde_json::from_str(
            r#"{"platforms": {"splunk": {"tenants": [
                {"name": "prod", "setup": {"url": "$SPLUNK_URL", "port": 8089, "ssl": false,
                 "index": ["main", 3], "nested": {"a": 1}, "none": null, "ratio": 0.5}},
                {"name": "lab"},
                "not a table"
            ]}}}"#,
        )
        .expect("JSON");
        let tenants = super::tenant::configured(&config, "splunk");
        let names: Vec<&str> = tenants.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["prod", "lab"]);
        let setup = &tenants[0].1;
        assert_eq!(setup["url"].as_str(), Some("$SPLUNK_URL"));
        assert_eq!(setup["port"].as_integer(), Some(8089));
        assert_eq!(setup["ssl"].as_bool(), Some(false));
        assert_eq!(setup["ratio"].as_float(), Some(0.5));
        assert_eq!(
            setup["index"],
            toml::Value::Array(vec![
                toml::Value::String("main".into()),
                toml::Value::Integer(3)
            ])
        );
        assert!(!setup.contains_key("nested") && !setup.contains_key("none"));
        assert!(tenants[1].1.is_empty());
        assert!(super::tenant::configured(&config, "elastic").is_empty());
    }

    #[test]
    fn the_builtin_registry_holds_the_nine_platforms_and_what_each_can_do() {
        let registry = super::builtin();
        assert_eq!(
            registry.ids(),
            [
                "sentinel",
                "defender_for_endpoint",
                "splunk",
                "sentinel_one",
                "carbon_black_cloud",
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
        assert_eq!(can("sentinel"), (true, true, true));
        assert_eq!(can("splunk"), (true, true, true));
        assert_eq!(can("carbon_black_cloud"), (true, true, true));
        assert_eq!(can("defender_for_endpoint"), (true, true, true));
        assert_eq!(can("sentinel_one"), (true, true, true));
        assert_eq!(can("elastic"), (false, true, true));
        assert_eq!(can("crowdstrike"), (true, false, true));
        assert_eq!(can("harfanglab"), (true, false, true));
        assert_eq!(can("sysdig"), (true, false, false));
    }
}
