//! The built-in platforms: one table, [`PLATFORMS`], that every crate reads
//! its platform lists from.
//!
//! A row says what a platform is (its identifier, label and model), how a
//! deployment state addresses its rules, what opentide does with it (deploy,
//! check a query on a tenant, run a query) and which query languages and
//! query-file suffixes it brings. Every list of platforms opentide prints or
//! walks (`--platform`'s choices, `setup`, `info`, the checklists, the
//! deploy plan, messages) is in the table's order.
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
        /// The shape a stored id has, if any (`_PATTERNED_IDS`): Bitdefender's,
        /// Graylog's, Exabeam's and Google SecOps' ids have one; CrowdStrike's
        /// are free text.
        pattern: Option<IdPattern>,
    },
}

/// The shape of a platform's text ids (`_PATTERNED_IDS`): a regular
/// expression the whole id matches, and how messages name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdPattern {
    /// The regular expression, matched against the whole id.
    pub regex: &'static str,
    /// The shape in words, as a message says what the id is not
    /// ("24 lower-case hex digits").
    pub shape: &'static str,
}

impl ExternalId {
    /// Whether the deployer addresses rules by a vendor id the deployment
    /// state keeps ([`state_platforms`]).
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
            } => (!matches_whole(pattern.regex, text)).then_some(IdShape::Pattern(pattern)),
            Self::Text { pattern: None } | Self::None => None,
        }
    }

    /// The shape a number given as an id is not, when the platform's ids are
    /// patterned text (`"<id> is a number, not <shape>"`); `None` when a
    /// number is stored as its decimal text.
    pub const fn refuses_number(self) -> Option<IdPattern> {
        match self {
            Self::Text { pattern } => pattern,
            Self::Int | Self::None => None,
        }
    }
}

/// The shape a stored external id lacks ([`ExternalId::shape_problem`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdShape {
    /// A canonical decimal integer: no sign, no leading zero.
    CanonicalDecimal,
    /// The whole id matches this pattern.
    Pattern(IdPattern),
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
}

/// Every built-in platform, in the one order every list of them takes.
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
    },
    Platform {
        id: "microsoft_defender",
        label: "Microsoft Defender",
        configuration_name: "Microsoft Defender",
        config_class: "MicrosoftDefenderConfig",
        external_id: ExternalId::None,
        deploys: true,
        compiles_offline: false,
        live_check: true,
        query_runner: true,
        runner_languages: &["kql"],
        offline_languages: &["kql"],
        query_file_suffixes: &["kql"],
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
        // harfanglab-1.0 1.2: its YARA (the HarfangLab profile), and `.yar`
        // and `.yara` files, checked offline as YARA-X 1.x compiles them
        // (#1225), YARA-X-only syntax refused under the profile.
        offline_languages: &["yara"],
        query_file_suffixes: &["yar", "yara"],
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
    },
    Platform {
        id: "bitdefender",
        label: "Bitdefender GravityZone",
        configuration_name: "Bitdefender GravityZone",
        config_class: "BitdefenderConfig",
        external_id: ExternalId::Text {
            pattern: Some(IdPattern {
                regex: "[0-9a-f]{24}",
                shape: "24 lower-case hex digits",
            }),
        },
        deploys: true,
        // The createCustomRule request, without the tenant's targets.
        compiles_offline: true,
        live_check: false,
        query_runner: false,
        runner_languages: &[],
        // A YARA signature, under the Bitdefender profile.
        offline_languages: &["yara"],
        query_file_suffixes: &["yar", "yara"],
    },
    Platform {
        id: "graylog",
        label: "Graylog",
        configuration_name: "Graylog",
        config_class: "GraylogConfig",
        external_id: ExternalId::Text {
            pattern: Some(IdPattern {
                regex: "[0-9a-f]{24}",
                shape: "24 lower-case hex digits",
            }),
        },
        deploys: true,
        compiles_offline: true,
        live_check: true,
        query_runner: true,
        runner_languages: &["lucene"],
        // Lucene in the engine's Graylog dialect (graylog-1.0, "Query
        // dialect"): Elastic's checks and Graylog's own.
        offline_languages: &["lucene"],
        query_file_suffixes: &["lucene"],
    },
    Platform {
        id: "exabeam",
        label: "Exabeam New-Scale SIEM",
        configuration_name: "Exabeam New-Scale SIEM",
        config_class: "ExabeamConfig",
        // The rule UUID Exabeam assigns, kept lower-case and canonical.
        external_id: ExternalId::Text {
            pattern: Some(IdPattern {
                regex: "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                shape: "a canonical lower-case UUID (8-4-4-4-12 hex digits)",
            }),
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
    },
    Platform {
        id: "google_secops",
        label: "Google Security Operations",
        configuration_name: "Google Security Operations",
        config_class: "GoogleSecopsConfig",
        // google-secops-1.0: the rule id, never a revision (`@v_…`) or a
        // resource name.
        external_id: ExternalId::Text {
            pattern: Some(IdPattern {
                regex: "ru_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                shape: "ru_ and a lower-case UUID (ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1)",
            }),
        },
        deploys: true,
        compiles_offline: true,
        live_check: true,
        query_runner: true,
        runner_languages: &["yaral"],
        // The offline YARA-L check arrives with the engine import (E1).
        offline_languages: &["yaral"],
        query_file_suffixes: &["yaral", "yl2"],
    },
    Platform {
        id: "datadog",
        label: "Datadog Cloud SIEM",
        configuration_name: "Datadog Cloud SIEM",
        config_class: "DatadogConfig",
        // The rule id Datadog assigns. Its format is unverified (RFC
        // rfc-datadog-cloud-siem.md §8.5, open question 4), so no pattern
        // refuses a real shard.
        external_id: ExternalId::Text { pattern: None },
        deploys: true,
        compiles_offline: true,
        live_check: true,
        query_runner: true,
        runner_languages: &["datadog"],
        // A block's queries, profile `rule`, and a `.datadog` file or a
        // `system: datadog` hunt, profile `search` (RFC §6.1).
        offline_languages: &["datadog"],
        query_file_suffixes: &["datadog"],
    },
];

/// How many platforms are built in.
pub const COUNT: usize = PLATFORMS.len();

impl Platform {
    /// The languages the engine parses for it offline; `None` when it parses
    /// none of its queries.
    pub fn offline(&self) -> Option<&'static [&'static str]> {
        (!self.offline_languages.is_empty()).then_some(self.offline_languages)
    }
}

/// Every identifier, in the table's order.
pub const IDS: [&str; COUNT] = {
    let mut out = [""; COUNT];
    let mut index = 0;
    while index < COUNT {
        out[index] = PLATFORMS[index].id;
        index += 1;
    }
    out
};

/// A built-in platform, by name: what code matches on in place of its
/// identifier's text. Its variants are [`PLATFORMS`]'s rows, in their order.
/// A platform plugin's identifier is none of them (`PlatformId::parse` gives
/// `None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PlatformId {
    /// `sentinel`: Microsoft Sentinel.
    Sentinel,
    /// `microsoft_defender`: Microsoft Defender.
    MicrosoftDefender,
    /// `splunk`: Splunk Enterprise Security.
    Splunk,
    /// `sentinel_one`: SentinelOne.
    SentinelOne,
    /// `crowdstrike`: CrowdStrike Falcon.
    Crowdstrike,
    /// `harfanglab`: HarfangLab.
    Harfanglab,
    /// `carbon_black_cloud`: Carbon Black Cloud.
    CarbonBlackCloud,
    /// `elastic`: Elastic Security.
    Elastic,
    /// `sysdig`: Sysdig Secure.
    Sysdig,
    /// `bitdefender`: Bitdefender GravityZone.
    Bitdefender,
    /// `graylog`: Graylog.
    Graylog,
    /// `exabeam`: Exabeam New-Scale SIEM.
    Exabeam,
    /// `google_secops`: Google Security Operations.
    GoogleSecops,
    /// `datadog`: Datadog Cloud SIEM.
    Datadog,
}

impl PlatformId {
    /// Every built-in platform, in [`PLATFORMS`]'s order.
    pub const ALL: [Self; COUNT] = [
        Self::Sentinel,
        Self::MicrosoftDefender,
        Self::Splunk,
        Self::SentinelOne,
        Self::Crowdstrike,
        Self::Harfanglab,
        Self::CarbonBlackCloud,
        Self::Elastic,
        Self::Sysdig,
        Self::Bitdefender,
        Self::Graylog,
        Self::Exabeam,
        Self::GoogleSecops,
        Self::Datadog,
    ];

    /// Its row of [`PLATFORMS`].
    pub const fn spec(self) -> &'static Platform {
        &PLATFORMS[self as usize]
    }

    /// The identifier: the key under a rule's `configurations`, the
    /// configuration's `platforms` and the `--platform` value.
    pub const fn as_str(self) -> &'static str {
        self.spec().id
    }

    /// The identifier the variant is written for; [`PLATFORMS`]' row must
    /// hold it, which a compile-time check below makes sure of.
    const fn written(self) -> &'static str {
        match self {
            Self::Sentinel => "sentinel",
            Self::MicrosoftDefender => "microsoft_defender",
            Self::Splunk => "splunk",
            Self::SentinelOne => "sentinel_one",
            Self::Crowdstrike => "crowdstrike",
            Self::Harfanglab => "harfanglab",
            Self::CarbonBlackCloud => "carbon_black_cloud",
            Self::Elastic => "elastic",
            Self::Sysdig => "sysdig",
            Self::Bitdefender => "bitdefender",
            Self::Graylog => "graylog",
            Self::Exabeam => "exabeam",
            Self::GoogleSecops => "google_secops",
            Self::Datadog => "datadog",
        }
    }

    /// The built-in platform `id` names; `None` for any other text, a
    /// plugin's identifier included.
    pub fn parse(id: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|platform| platform.as_str() == id)
    }
}

/// [`PlatformId::spec`] indexes [`PLATFORMS`] by the variant: a row moved,
/// added or removed without the enum following fails the build here.
const _: () = {
    const fn same(a: &str, b: &str) -> bool {
        let (a, b) = (a.as_bytes(), b.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        let mut i = 0;
        while i < a.len() {
            if a[i] != b[i] {
                return false;
            }
            i += 1;
        }
        true
    }
    let mut index = 0;
    while index < COUNT {
        let platform = PlatformId::ALL[index];
        assert!(
            platform as usize == index,
            "PlatformId::ALL is out of the enum's order"
        );
        assert!(
            same(PLATFORMS[index].id, platform.written()),
            "PLATFORMS and PlatformId disagree on a row"
        );
        index += 1;
    }
};

impl std::fmt::Display for PlatformId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Text that names no built-in platform: a plugin's identifier, a typo, or
/// an identifier in another case (`Sentinel`). It carries the text as given.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a built-in platform")]
pub struct UnknownPlatform(pub String);

impl std::str::FromStr for PlatformId {
    type Err = UnknownPlatform;

    /// [`PlatformId::parse`], with the text kept in the error.
    fn from_str(id: &str) -> Result<Self, Self::Err> {
        Self::parse(id).ok_or_else(|| UnknownPlatform(id.to_owned()))
    }
}

/// Written as its identifier (`"sentinel_one"`), as `configurations` and
/// `platforms` hold it.
impl serde::Serialize for PlatformId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Read from its identifier, exactly: any other text, a plugin's included,
/// is an `unknown variant` error listing the built-in identifiers.
impl<'de> serde::Deserialize<'de> for PlatformId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = PlatformId;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a built-in platform identifier")
            }

            fn visit_str<E: serde::de::Error>(self, id: &str) -> Result<PlatformId, E> {
                PlatformId::parse(id).ok_or_else(|| E::unknown_variant(id, &IDS))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

/// The identifier of a platform plugin: text that names no built-in platform.
/// Only [`PlatformKey`] makes one, so it never holds a built-in identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PluginId(String);

impl PluginId {
    /// The identifier, as the configuration's `platforms` table keys it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PluginId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A platform a run reaches: a built-in one, or a platform plugin's. Code
/// that serves plugins as well as the built-in platforms (the plan, the dry
/// run, the deploy, the modifiers) takes it in place of the identifier's
/// text; code for built-in platforms alone takes [`PlatformId`].
///
/// Every text is a key: a built-in identifier reads as
/// [`PlatformKey::BuiltIn`], any other text (`Sentinel` included) as
/// [`PlatformKey::Plugin`]. [`FromStr`](std::str::FromStr), `Display` and
/// serde round-trip the text exactly.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PlatformKey {
    /// A row of [`PLATFORMS`].
    BuiltIn(PlatformId),
    /// A platform plugin's identifier.
    Plugin(PluginId),
}

impl PlatformKey {
    /// The key `id` names: the built-in platform, else a plugin's.
    pub fn new(id: &str) -> Self {
        PlatformId::parse(id).map_or_else(|| Self::Plugin(PluginId(id.to_owned())), Self::BuiltIn)
    }

    /// The identifier: the key under a rule's `configurations` and the
    /// configuration's `platforms`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::BuiltIn(platform) => platform.as_str(),
            Self::Plugin(plugin) => plugin.as_str(),
        }
    }

    /// The built-in platform, if it is one.
    pub const fn builtin(&self) -> Option<PlatformId> {
        match self {
            Self::BuiltIn(platform) => Some(*platform),
            Self::Plugin(_) => None,
        }
    }
}

impl From<PlatformId> for PlatformKey {
    fn from(platform: PlatformId) -> Self {
        Self::BuiltIn(platform)
    }
}

impl std::fmt::Display for PlatformKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for PlatformKey {
    type Err = std::convert::Infallible;

    /// [`PlatformKey::new`]: every text names a platform.
    fn from_str(id: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(id))
    }
}

/// Written as its identifier, as [`PlatformId`] is.
impl serde::Serialize for PlatformKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Read from any string ([`PlatformKey::new`]).
impl<'de> serde::Deserialize<'de> for PlatformKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = PlatformKey;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a platform identifier")
            }

            fn visit_str<E: serde::de::Error>(self, id: &str) -> Result<PlatformKey, E> {
                Ok(PlatformKey::new(id))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

/// The platform `id` names, if it is built in.
pub fn get(id: &str) -> Option<&'static Platform> {
    PLATFORMS.iter().find(|platform| platform.id == id)
}

/// Whether `id` names a built-in platform.
pub fn is_builtin(id: &str) -> bool {
    get(id).is_some()
}

/// The platforms `keep` selects, in the table's order.
pub fn select(keep: impl Fn(&Platform) -> bool) -> Vec<&'static Platform> {
    PLATFORMS.iter().filter(|platform| keep(platform)).collect()
}

/// The identifiers of the platforms `keep` selects, in the table's order.
pub fn ids_where(keep: impl Fn(&Platform) -> bool) -> Vec<&'static str> {
    select(keep)
        .into_iter()
        .map(|platform| platform.id)
        .collect()
}

/// Every identifier, in the table's order.
pub fn ids() -> Vec<&'static str> {
    IDS.to_vec()
}

/// The platforms whose deployer addresses the remote rule by a vendor id kept
/// in the deployment state, in the table's order.
pub fn state_platforms() -> Vec<&'static str> {
    ids_where(|platform| platform.external_id.is_stored())
}

/// Whether `id`'s external id is a canonical decimal integer.
pub fn has_integer_id(id: &str) -> bool {
    get(id).is_some_and(|platform| platform.external_id == ExternalId::Int)
}

/// How platform `id` stores its external ids. A platform that is not built
/// in (a plugin's) stores free text: its ids are its own.
pub fn external_id_kind(id: &str) -> ExternalId {
    get(id).map_or(ExternalId::Text { pattern: None }, |platform| {
        platform.external_id
    })
}

/// What the stored id `text` of built-in platform `id` lacks
/// ([`ExternalId::shape_problem`]); `None` for a valid id or a platform that
/// is not built in (a plugin's ids are its own).
pub fn external_id_problem(id: &str, text: &str) -> Option<IdShape> {
    external_id_kind(id).shape_problem(text)
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
    /// Each variant names its own row, in the table's order, and only the
    /// table's identifiers parse.
    #[test]
    fn platform_ids_are_the_tables_rows() {
        for (index, platform) in super::PlatformId::ALL.into_iter().enumerate() {
            assert_eq!(platform.as_str(), super::PLATFORMS[index].id);
            assert_eq!(
                super::PlatformId::parse(super::PLATFORMS[index].id),
                Some(platform)
            );
            assert_eq!(platform.to_string(), super::IDS[index]);
        }
        assert_eq!(super::PlatformId::parse("my_plugin"), None);
        assert_eq!(super::PlatformId::parse("Sentinel"), None);
    }

    /// `FromStr`, `Display` and serde round-trip every identifier exactly;
    /// anything else (a plugin's id, another case, padding, non-ASCII text)
    /// is refused, its text kept in the error.
    #[test]
    fn platform_ids_round_trip_through_text_and_serde() {
        use super::{PlatformId, UnknownPlatform};
        for platform in PlatformId::ALL {
            let text = platform.to_string();
            assert_eq!(text.parse::<PlatformId>(), Ok(platform));
            let json = serde_json::to_string(&platform).unwrap();
            assert_eq!(json, format!("\"{text}\""));
            assert_eq!(serde_json::from_str::<PlatformId>(&json).unwrap(), platform);
        }
        for unknown in [
            "",
            "my_plugin",
            "Sentinel",
            "SENTINEL",
            " sentinel",
            "sentinel ",
            "sentinel-one",
            "sentinél",
            "😀",
            "sentinel\u{0}",
        ] {
            assert_eq!(
                unknown.parse::<PlatformId>(),
                Err(UnknownPlatform(unknown.to_owned()))
            );
            let json = serde_json::to_string(unknown).unwrap();
            let error = serde_json::from_str::<PlatformId>(&json).unwrap_err();
            assert!(error.to_string().contains("unknown variant"), "{error}");
        }
        assert_eq!(
            "sentinél".parse::<PlatformId>().unwrap_err().to_string(),
            "\"sentinél\" is not a built-in platform"
        );
        assert!(serde_json::from_str::<PlatformId>("1").is_err());
    }

    /// A built-in identifier is a built-in key, any other text a plugin's;
    /// `FromStr`, `Display` and serde round-trip both exactly, non-ASCII
    /// text included.
    #[test]
    fn platform_keys_round_trip_built_in_and_plugin_ids() {
        use super::{PlatformId, PlatformKey};
        let round_trip = |text: &str| {
            let key: PlatformKey = text.parse().unwrap();
            assert_eq!(key, PlatformKey::new(text));
            assert_eq!(key.as_str(), text);
            assert_eq!(key.to_string(), text);
            let json = serde_json::to_string(&key).unwrap();
            assert_eq!(json, serde_json::to_string(text).unwrap());
            assert_eq!(serde_json::from_str::<PlatformKey>(&json).unwrap(), key);
            key
        };
        for platform in PlatformId::ALL {
            let key = round_trip(platform.as_str());
            assert_eq!(key, PlatformKey::BuiltIn(platform));
            assert_eq!(key, PlatformKey::from(platform));
            assert_eq!(key.builtin(), Some(platform));
        }
        for plugin in [
            "my_plugin",
            "Sentinel",
            " sentinel",
            "sentinel-one",
            "sentinél",
            "😀",
            "",
        ] {
            let key = round_trip(plugin);
            assert!(matches!(&key, PlatformKey::Plugin(id) if id.as_str() == plugin));
            assert_eq!(key.builtin(), None);
        }
        assert!(serde_json::from_str::<PlatformKey>("1").is_err());
    }

    use super::{
        COUNT, ExternalId, IDS, PLATFORMS, ids, ids_where, query_file_suffixes, state_platforms,
    };

    #[test]
    fn every_platform_is_listed_once_in_the_tables_order() {
        let mut distinct = ids();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), COUNT, "identifiers are distinct");
        assert_eq!(IDS.to_vec(), ids());
    }

    #[test]
    fn the_one_order_is_the_tables() {
        assert_eq!(
            ids(),
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
    }

    #[test]
    fn the_capability_lists_are_in_the_tables_order() {
        // The platforms whose external ids the state stores (a message quotes them).
        assert_eq!(
            state_platforms(),
            [
                "sentinel_one",
                "crowdstrike",
                "sysdig",
                "bitdefender",
                "graylog",
                "exabeam",
                "google_secops",
                "datadog"
            ]
        );
        assert_eq!(
            ids_where(|p| p.external_id == ExternalId::Int),
            ["sentinel_one", "sysdig"]
        );
        assert_eq!(
            ids_where(|p| p.live_check),
            [
                "sentinel",
                "microsoft_defender",
                "splunk",
                "sentinel_one",
                "carbon_black_cloud",
                "elastic",
                "graylog",
                "exabeam",
                "google_secops",
                "datadog"
            ]
        );
        assert_eq!(ids_where(|p| p.query_runner).len(), PLATFORMS.len() - 2);
        assert_eq!(
            ids_where(|p| p.compiles_offline),
            [
                "sentinel",
                "elastic",
                "sysdig",
                "bitdefender",
                "graylog",
                "exabeam",
                "google_secops",
                "datadog"
            ]
        );
        assert_eq!(
            query_file_suffixes(),
            [
                "kql", "spl", "cql", "yar", "yara", "lucene", "esql", "eql", "kuery", "falco",
                "exabeam", "yaral", "yl2", "datadog"
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
                Some(IdShape::Pattern(super::IdPattern {
                    regex: "[0-9a-f]{24}",
                    shape: "24 lower-case hex digits",
                })),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_stored_id_has_its_platforms_shape() {
        use super::{IdPattern, IdShape, anchored, external_id_kind, external_id_problem};
        const HEX: IdPattern = IdPattern {
            regex: "[0-9a-f]{24}",
            shape: "24 lower-case hex digits",
        };
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
        let hex = ExternalId::Text { pattern: Some(HEX) };
        assert_eq!(hex.shape_problem("0123456789abcdef01234567"), None);
        // The whole id matches, not a part of it.
        for bad in [
            "0123456789abcdef0123456",
            "x0123456789abcdef01234567",
            "0123456789ABCDEF01234567",
        ] {
            assert_eq!(hex.shape_problem(bad), Some(IdShape::Pattern(HEX)), "{bad}");
        }
        let a_or_b = IdPattern {
            regex: "a|b",
            shape: "a or b",
        };
        let either = ExternalId::Text {
            pattern: Some(a_or_b),
        };
        assert_eq!(either.shape_problem("ab"), Some(IdShape::Pattern(a_or_b)));
        assert_eq!(either.shape_problem("b"), None);
        assert_eq!(ExternalId::None.shape_problem(""), None);
        // Through the table: built-in rows only.
        assert_eq!(
            external_id_problem("sysdig", "012"),
            Some(IdShape::CanonicalDecimal)
        );
        assert_eq!(external_id_problem("crowdstrike", "012"), None);
        assert_eq!(external_id_problem("acme", "012"), None);
        // A number is refused only where ids are patterned text.
        assert_eq!(hex.refuses_number(), Some(HEX));
        assert_eq!(free.refuses_number(), None);
        assert_eq!(int.refuses_number(), None);
        assert_eq!(external_id_kind("acme"), free);
        for platform in PLATFORMS {
            if let ExternalId::Text {
                pattern: Some(pattern),
            } = platform.external_id
            {
                assert!(
                    anchored(pattern.regex).is_some(),
                    "{}: {pattern:?}",
                    platform.id
                );
                assert!(!pattern.shape.is_empty(), "{}", platform.id);
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
