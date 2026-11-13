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

    /// What a stored id `text` lacks to be one of these, or `None` when it is
    /// one (or the platform stores none). An empty id is the caller's to
    /// refuse first: each says so in its own words.
    pub fn shape_problem(self, text: &str) -> Option<IdShape> {
        match self {
            Self::Int => (!is_canonical_decimal(text)).then_some(IdShape::CanonicalDecimal),
            Self::Text {
                pattern: Some(pattern),
            } => (!matches_whole(pattern, text)).then_some(IdShape::Pattern(pattern)),
            Self::Text { pattern: None } | Self::None => None,
        }
    }
}

/// The shape a stored external id lacks ([`ExternalId::shape_problem`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdShape {
    /// A canonical decimal integer: no sign, no leading zero.
    CanonicalDecimal,
    /// The whole id matches this regular expression.
    Pattern(&'static str),
}

/// Whether `text` is a canonical decimal integer (no sign, no leading zero).
pub fn is_canonical_decimal(text: &str) -> bool {
    text == "0"
        || (text.starts_with(|c: char| ('1'..='9').contains(&c))
            && text.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Whether the whole of `text` matches `pattern`. The table's patterns are
/// compiled once; a pattern that does not compile matches nothing (the tests
/// compile every row's).
fn matches_whole(pattern: &'static str, text: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    static COMPILED: LazyLock<Mutex<HashMap<&'static str, Option<regex::Regex>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    let Ok(mut compiled) = COMPILED.lock() else {
        return anchored(pattern).is_some_and(|regex| regex.is_match(text));
    };
    compiled
        .entry(pattern)
        .or_insert_with(|| anchored(pattern))
        .as_ref()
        .is_some_and(|regex| regex.is_match(text))
}

/// `pattern`, anchored at both ends.
fn anchored(pattern: &str) -> Option<regex::Regex> {
    regex::Regex::new(&format!("^(?:{pattern})$")).ok()
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
    Platform {
        id: "bitdefender",
        label: "Bitdefender GravityZone",
        configuration_name: "Bitdefender GravityZone",
        config_class: "BitdefenderConfig",
        external_id: ExternalId::Text {
            pattern: Some("^[0-9a-f]{24}$"),
        },
        deploys: true,
        // The createCustomRule request, without the tenant's targets.
        compiles_offline: true,
        live_check: false,
        query_runner: false,
        runner_languages: &[],
        // `yara` (the Bitdefender profile), and `.yar`/`.yara` files, come
        // with the YARA lane.
        offline_languages: &[],
        query_file_suffixes: &[],
        cli_rank: 9,
        connector_rank: 9,
        configuration_rank: 9,
    },
    Platform {
        id: "graylog",
        label: "Graylog",
        configuration_name: "Graylog",
        config_class: "GraylogConfig",
        external_id: ExternalId::Text {
            pattern: Some("[0-9a-f]{24}"),
        },
        deploys: true,
        compiles_offline: true,
        live_check: true,
        query_runner: true,
        runner_languages: &["lucene"],
        // The Graylog dialect of Lucene comes with the engine import (E1):
        // until then no query is parsed offline, rather than parsed as
        // Elastic's Lucene.
        offline_languages: &[],
        query_file_suffixes: &[],
        cli_rank: 10,
        connector_rank: 10,
        configuration_rank: 10,
    },
    Platform {
        id: "exabeam",
        label: "Exabeam New-Scale SIEM",
        configuration_name: "Exabeam New-Scale SIEM",
        config_class: "ExabeamConfig",
        // The rule UUID Exabeam assigns, kept lower-case and canonical.
        external_id: ExternalId::Text {
            pattern: Some("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
        },
        deploys: true,
        compiles_offline: true,
        live_check: true,
        query_runner: true,
        runner_languages: &["exabeam"],
        // The sequence filters, profile `rule`, and a `.exabeam` file or an
        // `system: exabeam` hunt, profile `search` (exabeam-1.0).
        offline_languages: &["exabeam"],
        query_file_suffixes: &["exabeam"],
        cli_rank: 11,
        connector_rank: 11,
        configuration_rank: 11,
    },
    Platform {
        id: "google_secops",
        label: "Google Security Operations",
        configuration_name: "Google Security Operations",
        config_class: "GoogleSecopsConfig",
        // google-secops-1.0: the rule id, never a revision (`@v_…`) or a
        // resource name.
        external_id: ExternalId::Text {
            pattern: Some("^ru_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
        },
        deploys: true,
        compiles_offline: true,
        live_check: true,
        query_runner: true,
        runner_languages: &["yaral"],
        // The offline YARA-L check arrives with the engine import (E1).
        offline_languages: &["yaral"],
        query_file_suffixes: &["yaral"],
        cli_rank: 12,
        connector_rank: 12,
        configuration_rank: 12,
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

/// What the stored id `text` of built-in platform `id` lacks
/// ([`ExternalId::shape_problem`]); `None` for a valid id or a platform that
/// is not built in (a plugin's ids are its own).
pub fn external_id_problem(id: &str, text: &str) -> Option<IdShape> {
    get(id)?.external_id.shape_problem(text)
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
                "sysdig",
                "bitdefender",
                "graylog",
                "exabeam",
                "google_secops"
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
                "sysdig",
                "bitdefender",
                "graylog",
                "exabeam",
                "google_secops"
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
                "sysdig",
                "bitdefender",
                "graylog",
                "exabeam",
                "google_secops"
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
                "sysdig",
                "bitdefender",
                "graylog",
                "exabeam",
                "google_secops"
            ]
        );
    }

    #[test]
    fn the_capability_lists_are_the_oracles() {
        assert_eq!(
            state_platforms(),
            [
                "bitdefender",
                "crowdstrike",
                "defender_for_endpoint",
                "exabeam",
                "google_secops",
                "graylog",
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
                "exabeam",
                "google_secops",
                "graylog",
                "sentinel",
                "sentinel_one",
                "splunk"
            ]
        );
        assert_eq!(
            ids_where(Order::Name, |p| p.query_runner).len(),
            PLATFORMS.len() - 2
        );
        assert_eq!(
            ids_where(Order::Container, |p| p.compiles_offline),
            [
                "sentinel",
                "elastic",
                "sysdig",
                "bitdefender",
                "graylog",
                "exabeam",
                "google_secops"
            ]
        );
        assert_eq!(
            query_file_suffixes(),
            [
                "kql", "spl", "cql", "lucene", "esql", "eql", "kuery", "falco", "exabeam", "yaral"
            ]
        );
    }

    #[test]
    fn a_graylog_id_is_24_lower_case_hex() {
        use super::{IdShape, external_id_problem};
        assert!(!super::has_integer_id("graylog"));
        assert_eq!(
            external_id_problem("graylog", "65f1c0ffee0123456789abcd"),
            None
        );
        for bad in ["65F1C0FFEE0123456789ABCD", "65f1c0ffee0123456789abc", "12"] {
            assert_eq!(
                external_id_problem("graylog", bad),
                Some(IdShape::Pattern("[0-9a-f]{24}")),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_stored_id_has_its_platforms_shape() {
        use super::{IdShape, anchored, external_id_problem};
        let int = ExternalId::Int;
        assert_eq!(int.shape_problem("17"), None);
        assert_eq!(int.shape_problem("0"), None);
        for bad in ["017", "-1", "+1", "1.0", "x"] {
            assert_eq!(
                int.shape_problem(bad),
                Some(IdShape::CanonicalDecimal),
                "{bad}"
            );
        }
        let free = ExternalId::Text { pattern: None };
        assert_eq!(free.shape_problem("anything at all"), None);
        let hex = ExternalId::Text {
            pattern: Some("[0-9a-f]{24}"),
        };
        assert_eq!(hex.shape_problem("0123456789abcdef01234567"), None);
        // The whole id matches, not a part of it.
        for bad in [
            "0123456789abcdef0123456",
            "x0123456789abcdef01234567",
            "0123456789ABCDEF01234567",
        ] {
            assert_eq!(
                hex.shape_problem(bad),
                Some(IdShape::Pattern("[0-9a-f]{24}")),
                "{bad}"
            );
        }
        let either = ExternalId::Text {
            pattern: Some("a|b"),
        };
        assert_eq!(either.shape_problem("ab"), Some(IdShape::Pattern("a|b")));
        assert_eq!(either.shape_problem("b"), None);
        assert_eq!(ExternalId::None.shape_problem(""), None);
        // Through the table: built-in rows only.
        assert_eq!(
            external_id_problem("sysdig", "012"),
            Some(IdShape::CanonicalDecimal)
        );
        assert_eq!(external_id_problem("crowdstrike", "012"), None);
        assert_eq!(external_id_problem("acme", "012"), None);
        for platform in PLATFORMS {
            if let ExternalId::Text {
                pattern: Some(pattern),
            } = platform.external_id
            {
                assert!(anchored(pattern).is_some(), "{}: {pattern}", platform.id);
            }
        }
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
