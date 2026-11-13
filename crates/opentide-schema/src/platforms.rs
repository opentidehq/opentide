//! The built-in platforms: one table, [`PLATFORMS`], that every crate reads
//! its platform lists from.
//!
//! A row says what a platform is (its identifier, label and model), how a
//! deployment state addresses its rules, what opentide does with it (deploy,
//! check a query on a tenant, run a query) and which query languages and
//! query-file suffixes it brings. The lists the command line prints are in
//! several orders, each of them behaviour (help text, JSON arrays, the order
//! a checklist names the platforms in): [`Order`] names them, and a row
//! carries its rank in each.
//!
//! Adding a platform is one row here plus its modules (the model in
//! `objects::platform`, its compiler, its connector). The dispatch that names
//! a module per platform (a `match` on the identifier, a clap value) stays
//! with that module; each consumer's tests check it covers every row.

/// How a deployment state records the remote rule a platform's deployer
/// created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalId {
    /// The deployer does not address rules by a vendor id: no state.
    None,
    /// A canonical decimal integer (no sign, no leading zero).
    Int,
    /// Text, matching `pattern` when the platform names one.
    Text {
        /// The regular expression a stored id matches, if any. No built-in
        /// platform names one yet (CrowdStrike's ids are free text); the
        /// platforms whose ids have a shape bring theirs with their row.
        pattern: Option<&'static str>,
    },
}

impl ExternalId {
    /// Whether the deployer addresses rules by a vendor id the deployment
    /// state keeps (`STATE_PLATFORMS`).
    pub const fn is_stored(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// The orders platform lists are printed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// The rule's `configurations` container (`PLATFORM_CONFIG_MODELS`): the
    /// table's own order. The deploy plan, `doctor`'s checklist and the
    /// workspace checks walk it.
    Container,
    /// The command line's (`DetectionPlatform`): `--platform`'s choices,
    /// `setup`'s flags and the wizard.
    Cli,
    /// The connectors' registry (`opentide.platforms`' entry points), and the
    /// pipelines' live query checks.
    Connector,
    /// The bundled configuration's platform models (`configuration` tables).
    Configuration,
    /// By identifier.
    Name,
}

/// One built-in platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "a row of capabilities, each one independent of the others"
)]
pub struct Platform {
    /// The identifier: the key under a rule's `configurations` and the
    /// configuration's `platforms`, and the `--platform` value.
    pub id: &'static str,
    /// The label the wizard and `info` show (`platform_label`).
    pub label: &'static str,
    /// The `[platform] name` of the bundled configuration file.
    pub configuration_name: &'static str,
    /// The block model's name in messages (`SentinelConfig`).
    pub config_class: &'static str,
    /// How the deployment state records its remote rules.
    pub external_id: ExternalId,
    /// Whether opentide deploys to it.
    pub deploys: bool,
    /// Whether its request body is built from the rule alone, with no tenant
    /// (`OFFLINE_COMPILERS`).
    pub compiles_offline: bool,
    /// Whether a tenant checks its queries (`QUERY_VALIDATION_PLATFORMS`).
    pub live_check: bool,
    /// Whether `opentide query` runs on it.
    pub query_runner: bool,
    /// The languages its query runner takes, the default first
    /// (`PLATFORM_LANGUAGES`).
    pub runner_languages: &'static [&'static str],
    /// The languages the engine parses for it offline
    /// (`OFFLINE_QUERY_LANGUAGES`); empty when it parses none.
    pub offline_languages: &'static [&'static str],
    /// The extensions of a query file in its languages.
    pub query_file_suffixes: &'static [&'static str],
    /// Its place in [`Order::Cli`].
    pub cli_rank: u8,
    /// Its place in [`Order::Connector`].
    pub connector_rank: u8,
    /// Its place in [`Order::Configuration`].
    pub configuration_rank: u8,
}

/// Every built-in platform, in [`Order::Container`].
pub const PLATFORMS: &[Platform] = &[
    Platform {
        id: "sentinel",
        label: "Microsoft Sentinel",
        configuration_name: "Microsoft Sentinel",
        config_class: "SentinelConfig",
        external_id: ExternalId::None,
        deploys: true,
        compiles_offline: true,
        live_check: true,
        query_runner: true,
        runner_languages: &["kql"],
        offline_languages: &["kql"],
        query_file_suffixes: &["kql"],
        cli_rank: 0,
        connector_rank: 0,
        configuration_rank: 0,
    },
    Platform {
        id: "defender_for_endpoint",
        label: "Microsoft Defender for Endpoint",
        configuration_name: "Microsoft Defender for Endpoint",
        config_class: "DefenderConfig",
        external_id: ExternalId::Int,
        deploys: true,
        compiles_offline: false,
        live_check: true,
        query_runner: true,
        runner_languages: &["kql"],
        offline_languages: &["kql"],
        query_file_suffixes: &["kql"],
        cli_rank: 3,
        connector_rank: 1,
        configuration_rank: 4,
    },
    Platform {
        id: "splunk",
        label: "Splunk Enterprise Security",
        configuration_name: "Splunk Enterprise",
        config_class: "SplunkConfig",
        external_id: ExternalId::None,
        deploys: true,
        compiles_offline: false,
        live_check: true,
        query_runner: true,
        runner_languages: &["spl"],
        offline_languages: &["spl"],
        query_file_suffixes: &["spl"],
        cli_rank: 1,
        connector_rank: 2,
        configuration_rank: 1,
    },
    Platform {
        id: "sentinel_one",
        label: "SentinelOne",
        configuration_name: "Sentinel One",
        config_class: "SentinelOneConfig",
        external_id: ExternalId::Int,
        deploys: true,
        compiles_offline: false,
        live_check: true,
        query_runner: true,
        runner_languages: &["powerquery"],
        offline_languages: &[],
        query_file_suffixes: &[],
        cli_rank: 4,
        connector_rank: 3,
        configuration_rank: 3,
    },
    Platform {
        id: "crowdstrike",
        label: "CrowdStrike Falcon",
        configuration_name: "Crowdstrike Falcon Correlation Rules",
        config_class: "CrowdstrikeConfig",
        external_id: ExternalId::Text { pattern: None },
        deploys: true,
        compiles_offline: false,
        live_check: false,
        query_runner: true,
        runner_languages: &["cql"],
        offline_languages: &["cql"],
        query_file_suffixes: &["cql"],
        cli_rank: 2,
        connector_rank: 5,
        configuration_rank: 5,
    },
    Platform {
        id: "harfanglab",
        label: "HarfangLab",
        configuration_name: "HarfangLab",
        config_class: "HarfangLabConfig",
        external_id: ExternalId::None,
        deploys: true,
        compiles_offline: false,
        live_check: false,
        query_runner: true,
        runner_languages: &["telemetry"],
        offline_languages: &[],
        query_file_suffixes: &[],
        cli_rank: 6,
        connector_rank: 6,
        configuration_rank: 6,
    },
    Platform {
        id: "carbon_black_cloud",
        label: "Carbon Black Cloud",
        configuration_name: "Carbon Black Cloud Enterprise EDR",
        config_class: "CarbonBlackConfig",
        external_id: ExternalId::None,
        deploys: true,
        compiles_offline: false,
        live_check: true,
        query_runner: true,
        runner_languages: &["lucene"],
        offline_languages: &["lucene"],
        query_file_suffixes: &["lucene"],
        cli_rank: 5,
        connector_rank: 4,
        configuration_rank: 2,
    },
    Platform {
        id: "elastic",
        label: "Elastic Security",
        configuration_name: "Elastic Security",
        config_class: "ElasticConfig",
        external_id: ExternalId::None,
        deploys: true,
        compiles_offline: true,
        live_check: true,
        query_runner: true,
        runner_languages: &["esql", "eql", "lucene", "kuery"],
        offline_languages: &["esql", "eql", "kuery", "lucene"],
        query_file_suffixes: &["esql", "eql", "kuery", "lucene"],
        cli_rank: 7,
        connector_rank: 7,
        configuration_rank: 7,
    },
    Platform {
        id: "sysdig",
        label: "Sysdig Secure",
        configuration_name: "Sysdig Secure",
        config_class: "SysdigConfig",
        external_id: ExternalId::Int,
        deploys: true,
        compiles_offline: true,
        live_check: false,
        query_runner: false,
        runner_languages: &[],
        offline_languages: &["falco"],
        query_file_suffixes: &["falco"],
        cli_rank: 8,
        connector_rank: 8,
        configuration_rank: 8,
    },
];

/// How many platforms are built in.
pub const COUNT: usize = PLATFORMS.len();

/// Platforms the recorded golden oracle (opentide 0.23.0) lacks: those the
/// catch-up train ports onto it after it was recorded (the plan's §4). The
/// oracle-comparing tests leave these out before comparing, so a new
/// platform's row does not break a comparison with a recording that predates
/// it; the live-table tests (orders, capabilities, the router) still hold the
/// whole table. O2 re-records from 0.28.x and empties this list.
///
/// Every id is listed up front, before its row lands, which is harmless: an id
/// with no row filters nothing. The guard test
/// (`tests/since_oracle.rs`) keeps the list empty wherever the report-only
/// marker (`tests/golden/REPORT_ONLY`) is absent, so it cannot reach
/// integration with the oracle still 0.23.0.
pub const SINCE_ORACLE: &[&str] = &["bitdefender", "exabeam", "google_secops", "graylog"];

/// Whether `id` names a platform the recorded oracle lacks ([`SINCE_ORACLE`]).
#[must_use]
pub fn after_oracle(id: &str) -> bool {
    SINCE_ORACLE.contains(&id)
}

impl Platform {
    /// Its rank in `order` (its index in the table for [`Order::Container`];
    /// none for [`Order::Name`], which sorts).
    const fn rank(&self, order: Order, index: usize) -> usize {
        match order {
            Order::Cli => self.cli_rank as usize,
            Order::Connector => self.connector_rank as usize,
            Order::Configuration => self.configuration_rank as usize,
            Order::Container | Order::Name => index,
        }
    }

    /// The languages the engine parses for it offline; `None` when it parses
    /// none of its queries.
    pub fn offline(&self) -> Option<&'static [&'static str]> {
        (!self.offline_languages.is_empty()).then_some(self.offline_languages)
    }
}

/// Whether `a` sorts before `b`, byte by byte.
const fn str_lt(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut index = 0;
    while index < a.len() && index < b.len() {
        if a[index] != b[index] {
            return a[index] < b[index];
        }
        index += 1;
    }
    a.len() < b.len()
}

/// Every identifier, in `order`, as a constant.
///
/// # Panics
///
/// At compile time, when two rows share a rank in `order`, or a rank is out
/// of range (the tests check every order).
pub const fn ordered(order: Order) -> [&'static str; COUNT] {
    let mut out = [""; COUNT];
    let mut index = 0;
    while index < COUNT {
        let rank = PLATFORMS[index].rank(order, index);
        assert!(
            rank < COUNT && out[rank].is_empty(),
            "a rank is out of range or taken twice"
        );
        out[rank] = PLATFORMS[index].id;
        index += 1;
    }
    if let Order::Name = order {
        // Insertion sort: nine to a few dozen rows.
        let mut end = 1;
        while end < COUNT {
            let mut at = end;
            while at > 0 && str_lt(out[at], out[at - 1]) {
                let swap = out[at];
                out[at] = out[at - 1];
                out[at - 1] = swap;
                at -= 1;
            }
            end += 1;
        }
    }
    out
}

/// The platform `id` names, if it is built in.
pub fn get(id: &str) -> Option<&'static Platform> {
    PLATFORMS.iter().find(|platform| platform.id == id)
}

/// Whether `id` names a built-in platform.
pub fn is_builtin(id: &str) -> bool {
    get(id).is_some()
}

/// The platforms `keep` selects, in `order`.
pub fn select(order: Order, keep: impl Fn(&Platform) -> bool) -> Vec<&'static Platform> {
    ordered(order)
        .into_iter()
        .filter_map(get)
        .filter(|platform| keep(platform))
        .collect()
}

/// The identifiers of the platforms `keep` selects, in `order`.
pub fn ids_where(order: Order, keep: impl Fn(&Platform) -> bool) -> Vec<&'static str> {
    select(order, keep)
        .into_iter()
        .map(|platform| platform.id)
        .collect()
}

/// Every identifier, in `order`.
pub fn ids(order: Order) -> Vec<&'static str> {
    ordered(order).to_vec()
}

/// The platforms whose deployer addresses the remote rule by a vendor id kept
/// in the deployment state (`STATE_PLATFORMS`), by name.
pub fn state_platforms() -> Vec<&'static str> {
    ids_where(Order::Name, |platform| platform.external_id.is_stored())
}

/// Whether `id`'s external id is a canonical decimal integer.
pub fn has_integer_id(id: &str) -> bool {
    get(id).is_some_and(|platform| platform.external_id == ExternalId::Int)
}

/// The extensions of a query file, each one query in the language it names:
/// every row's suffixes, the first time each appears.
pub fn query_file_suffixes() -> Vec<&'static str> {
    let mut suffixes: Vec<&'static str> = Vec::new();
    for suffix in PLATFORMS
        .iter()
        .flat_map(|platform| platform.query_file_suffixes)
    {
        if !suffixes.contains(suffix) {
            suffixes.push(suffix);
        }
    }
    suffixes
}

#[cfg(test)]
mod tests {
    use super::{
        COUNT, ExternalId, Order, PLATFORMS, ids, ids_where, ordered, query_file_suffixes,
        state_platforms,
    };

    const ORDERS: [Order; 5] = [
        Order::Container,
        Order::Cli,
        Order::Connector,
        Order::Configuration,
        Order::Name,
    ];

    #[test]
    fn each_order_lists_every_platform_once() {
        let mut expected = ids(Order::Container);
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(expected.len(), COUNT, "identifiers are distinct");
        for order in ORDERS {
            let mut listed = ordered(order).to_vec();
            listed.sort_unstable();
            assert_eq!(listed, expected, "{order:?}");
        }
        let mut by_name = ids(Order::Container);
        by_name.sort_unstable();
        assert_eq!(ids(Order::Name), by_name);
    }

    #[test]
    fn the_orders_are_the_oracles() {
        assert_eq!(
            ids(Order::Container),
            [
                "sentinel",
                "defender_for_endpoint",
                "splunk",
                "sentinel_one",
                "crowdstrike",
                "harfanglab",
                "carbon_black_cloud",
                "elastic",
                "sysdig"
            ]
        );
        assert_eq!(
            ids(Order::Cli),
            [
                "sentinel",
                "splunk",
                "crowdstrike",
                "defender_for_endpoint",
                "sentinel_one",
                "carbon_black_cloud",
                "harfanglab",
                "elastic",
                "sysdig"
            ]
        );
        assert_eq!(
            ids(Order::Connector),
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
        assert_eq!(
            ids(Order::Configuration),
            [
                "sentinel",
                "splunk",
                "carbon_black_cloud",
                "sentinel_one",
                "defender_for_endpoint",
                "crowdstrike",
                "harfanglab",
                "elastic",
                "sysdig"
            ]
        );
    }

    #[test]
    fn the_capability_lists_are_the_oracles() {
        assert_eq!(
            state_platforms(),
            [
                "crowdstrike",
                "defender_for_endpoint",
                "sentinel_one",
                "sysdig"
            ]
        );
        assert_eq!(
            ids_where(Order::Name, |p| p.external_id == ExternalId::Int),
            ["defender_for_endpoint", "sentinel_one", "sysdig"]
        );
        assert_eq!(
            ids_where(Order::Name, |p| p.live_check),
            [
                "carbon_black_cloud",
                "defender_for_endpoint",
                "elastic",
                "sentinel",
                "sentinel_one",
                "splunk"
            ]
        );
        assert_eq!(
            ids_where(Order::Name, |p| p.query_runner).len(),
            PLATFORMS.len() - 1
        );
        assert_eq!(
            ids_where(Order::Container, |p| p.compiles_offline),
            ["sentinel", "elastic", "sysdig"]
        );
        assert_eq!(
            query_file_suffixes(),
            [
                "kql", "spl", "cql", "lucene", "esql", "eql", "kuery", "falco"
            ]
        );
    }

    #[test]
    fn every_platform_model_is_registered_under_its_class() {
        let models = crate::objects::platform::PLATFORM_CONFIG_MODELS;
        let registered: Vec<(&str, &str)> = models.iter().map(|m| (m.key, m.model)).collect();
        let table: Vec<(&str, &str)> = PLATFORMS.iter().map(|p| (p.id, p.config_class)).collect();
        assert_eq!(registered, table);
    }

    #[test]
    fn every_bundled_configuration_names_its_platform() {
        for platform in PLATFORMS {
            let text =
                crate::configuration::bundled::text(&format!("platforms/{}.toml", platform.id))
                    .unwrap_or_else(|| panic!("{} has a bundled configuration", platform.id));
            let name = format!("name = \"{}\"", platform.configuration_name);
            assert!(text.contains(&name), "{}: {name}", platform.id);
        }
    }
}
