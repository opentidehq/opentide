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
//! The platforms built on it: [`crowdstrike`], [`microsoft_defender`], [`elastic`],
//! [`harfanglab`], [`sentinel_one`] and [`sysdig`] (UC-4.2, #832), the REST
//! platforms, and [`splunk`], [`carbon_black`] and [`sentinel`] (UC-4.3,
//! #833), whose vendors ship SDKs; each a client, deployer and query runner
//! that speaks its vendor's API directly, on one set of query types
//! ([`connector::QueryRequest`], [`connector::QueryOutcome`]);
//! [`builtin`] registers them, and [`plugin::with_plugins`] adds the platforms
//! a Python package registers (UC-4.5, #835) after them.
//!
//! The recorded-HTTP harness that proves a connector sends what the Python
//! client sends is `opentide-cassette`, a test crate.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead (its
//! `connectors` feature, and `plugins` for the plugin host).

pub mod answer;
pub mod bitdefender;
pub mod carbon_black;
pub mod connector;
pub mod credentials;
pub mod crowdstrike;
pub mod datadog;
pub mod elastic;
pub mod entra;
pub mod env;
pub mod error;
pub mod exabeam;
pub mod google_secops;
pub mod graylog;
pub mod harfanglab;
pub mod http;
pub mod microsoft_defender;
pub mod misp;
pub mod pace;
pub mod paging;
pub mod plugin;
pub mod progress;
pub mod proxy;
pub mod retry;
pub mod runtime;
pub mod sentinel;
pub mod sentinel_one;
pub mod splunk;
pub mod sysdig;
pub mod tenant;
pub mod tenant_codes;
pub mod text;
pub mod tls;
pub mod token;
pub mod transport;
pub mod vulnerability;

pub use connector::{Platform, Registry};
pub use credentials::{Credential, Secret};
pub use env::Environment;
pub use error::ConnectorError;
pub use http::{HttpClient, HttpSettings};
pub use plugin::{PluginError, PluginHost};
pub use tenant::{Tenant, TenantLabel};

/// The HTTP settings *platform*'s client mounts: its timeout and retries.
/// *timeout* is the read timeout of the
/// clients that take the caller's (Elastic, Splunk, Carbon Black Cloud and
/// Google SecOps; Sentinel's at least 300 s, azure-core's read); the others
/// keep their own.
/// A platform without a connector gets the defaults.
pub fn http_settings(platform: &str, timeout: std::time::Duration) -> HttpSettings {
    match platform {
        "microsoft_defender" => microsoft_defender::http_settings(),
        "sentinel_one" => sentinel_one::http_settings(),
        "crowdstrike" => crowdstrike::http_defaults(),
        "harfanglab" => harfanglab::http_defaults(),
        "sysdig" => sysdig::http_defaults(),
        "bitdefender" => bitdefender::http_defaults(),
        "exabeam" => exabeam::http_defaults(),
        "datadog" => datadog::http_defaults(),
        "google_secops" => google_secops::http_settings(timeout),
        "graylog" => graylog::http_defaults(),
        "elastic" => elastic::http_settings(timeout),
        "splunk" => splunk::http_settings(timeout),
        "carbon_black_cloud" => carbon_black::http_settings(timeout),
        // azure-core reads for 300 s; the server holds a query up to its own
        // timeout (`Prefer: wait`).
        "sentinel" => sentinel::http_settings(timeout.max(std::time::Duration::from_secs(300))),
        _ => HttpSettings::default(),
    }
}

/// The HTTP settings a deploy mounts for *platform* (`opentide deploy` and
/// `opentide::Connection::deploy`). A deploy takes no `--timeout`, so each
/// client reads for the timeout 0.28's deployer used: Sentinel's ARM session
/// 60 s (a deploy sends no query, so azure-core's 300 s does not apply),
/// Elastic 30 s, Google SecOps 60 s, and the transport's 120 s for the
/// clients that take the caller's; the others keep their own, as in
/// [`http_settings`]. Only the timeout follows 0.28: the retries are the
/// connectors' own ([`retry::RetryPolicy`]).
pub fn deploy_http_settings(platform: &str) -> HttpSettings {
    use std::time::Duration;
    match platform {
        "sentinel" => sentinel::http_settings(Duration::from_secs(60)),
        "elastic" => elastic::http_settings(Duration::from_secs(30)),
        "google_secops" => google_secops::http_defaults(),
        _ => http_settings(platform, http::DEFAULT_TIMEOUT),
    }
}

/// The built-in platforms with a connector, in the platform table's order
/// ([`plugin::BUILTIN`]): CrowdStrike,
/// HarfangLab and Sysdig (UC-4.2a), Microsoft Defender, Elastic and
/// SentinelOne (UC-4.2b), Sentinel, Splunk and Carbon Black Cloud (UC-4.3),
/// Bitdefender GravityZone and Graylog (the catch-up to 0.28.0), and Exabeam
/// New-Scale SIEM (P-EX), and Datadog Cloud SIEM. Google SecOps reads Application Default
/// Credentials from the process environment; [`builtin_with`] names another.
pub fn builtin() -> Registry {
    builtin_with(&Environment::process())
}

/// [`builtin`], each connector that reads the environment beyond a tenant's
/// setup (Google SecOps's Application Default Credentials:
/// `GOOGLE_APPLICATION_CREDENTIALS`, gcloud's well-known file, the metadata
/// server) reading `environment`, as a caller with an environment of its
/// own (the SDK's `ConnectOptions::environment`, the command line) sets it.
pub fn builtin_with(environment: &Environment) -> Registry {
    let mut platforms: Vec<Box<dyn Platform>> = vec![
        Box::new(sentinel::Sentinel::new()),
        Box::new(microsoft_defender::MicrosoftDefender::new()),
        Box::new(splunk::Splunk::new()),
        Box::new(sentinel_one::SentinelOne),
        Box::new(crowdstrike::Crowdstrike::new()),
        Box::new(harfanglab::HarfangLab),
        Box::new(carbon_black::CarbonBlack),
        Box::new(elastic::Elastic),
        Box::new(sysdig::Sysdig),
        Box::new(bitdefender::Bitdefender),
        Box::new(graylog::Graylog::new()),
        Box::new(exabeam::Exabeam::new()),
        // Application Default Credentials are the environment's ambient
        // credentials (google-auth's `default()`).
        Box::new(google_secops::GoogleSecops::new(environment.clone())),
        Box::new(datadog::Datadog::new()),
    ];
    // The table's order, wherever a connector is listed above; a connector
    // the table does not name would go last (the tests refuse one).
    platforms.sort_by_key(|platform| {
        plugin::BUILTIN
            .iter()
            .position(|id| *id == platform.id())
            .unwrap_or(usize::MAX)
    });
    let mut registry = Registry::new();
    for platform in platforms {
        // Distinct identifiers: registering cannot be refused.
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
            super::http_settings("sentinel", Duration::from_mins(15)).timeout,
            super::sentinel::http_settings(Duration::from_mins(15)).timeout
        );
        assert_eq!(
            super::http_settings("microsoft_defender", timeout),
            super::microsoft_defender::http_settings()
        );
        assert_eq!(
            super::http_settings("google_secops", timeout),
            super::google_secops::http_settings(timeout)
        );
        assert_eq!(
            super::http_settings("sysdig", timeout),
            super::sysdig::http_defaults()
        );
        assert_eq!(
            super::http_settings("exabeam", timeout),
            super::exabeam::http_defaults()
        );
        assert_eq!(
            super::http_settings("unknown", timeout),
            super::HttpSettings::default()
        );
    }

    #[test]
    fn a_deploy_reads_for_each_python_deployers_client_timeout() {
        // Every platform in the registry, so none goes unchecked.
        for platform in opentide_schema::platforms::PLATFORMS.iter().map(|p| p.id) {
            let seconds = match platform {
                "sentinel" | "google_secops" => 60,
                "elastic" | "exabeam" | "sysdig" | "bitdefender" | "graylog" | "datadog" => 30,
                "microsoft_defender" | "splunk" | "sentinel_one" | "carbon_black_cloud"
                | "crowdstrike" | "harfanglab" => 120,
                other => panic!("{other}: no deploy timeout pinned"),
            };
            assert_eq!(
                super::deploy_http_settings(platform).timeout,
                Duration::from_secs(seconds),
                "{platform}"
            );
        }
        assert_eq!(
            super::deploy_http_settings("sysdig"),
            super::sysdig::http_defaults()
        );
        assert_eq!(
            super::deploy_http_settings("sentinel").retry,
            super::sentinel::http_settings(Duration::from_secs(60)).retry
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
        // A table is kept, for the tenant's string tables (Graylog's
        // `stream_ids`); a null has no TOML form and is left out.
        assert_eq!(
            setup["nested"],
            toml::Value::Table(toml::map::Map::from_iter([(
                "a".to_owned(),
                toml::Value::Integer(1)
            )]))
        );
        assert!(!setup.contains_key("none"));
        assert!(tenants[1].1.is_empty());
        assert!(super::tenant::configured(&config, "elastic").is_empty());
    }

    #[test]
    fn the_builtin_registry_holds_the_platforms_and_what_each_can_do() {
        let registry = super::builtin();
        assert_eq!(registry.ids(), super::plugin::BUILTIN);
        assert_eq!(
            registry.ids(),
            [
                "sentinel",
                "microsoft_defender",
                "splunk",
                "sentinel_one",
                "crowdstrike",
                "harfanglab",
                "carbon_black_cloud",
                "elastic",
                "sysdig",
                "bitdefender",
                "graylog",
                "exabeam",
                "google_secops",
                "datadog"
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
        assert_eq!(can("microsoft_defender"), (true, true, true));
        assert_eq!(can("sentinel_one"), (true, true, true));
        assert_eq!(can("elastic"), (true, true, true));
        assert_eq!(can("crowdstrike"), (true, false, true));
        assert_eq!(can("harfanglab"), (true, false, true));
        assert_eq!(can("sysdig"), (true, false, false));
        assert_eq!(can("bitdefender"), (true, false, false));
        assert_eq!(can("exabeam"), (true, true, true));
        assert_eq!(can("google_secops"), (true, true, true));
        assert_eq!(can("graylog"), (true, true, true));
        assert_eq!(can("datadog"), (true, true, true));
        // The platform table says the same of each connector.
        for row in opentide_schema::platforms::PLATFORMS {
            let (_, live, query) = can(row.id);
            assert_eq!(
                (live, query),
                (row.live_check, row.query_runner),
                "{}",
                row.id
            );
        }
    }
}
