//! The revision registry (UC-1.7, #813; ADR 0009): every schema revision
//! opentide reads, which struct reads it, what happens with a revision the
//! registry does not hold, and the newest revision of each family.
//!
//! - [`SchemaId`]: `family::major.minor`, normalised and ordered
//!   (`models/version.py` `SchemaVersion`).
//! - [`REVISIONS`]: the Tide objects (`rule::1.0`, `rule::1.1`,
//!   `objective::1.0`, `threat::1.0`), the visibility file
//!   (`visibility::1.0`), the nine platform blocks (`platform::<id>::1.0`) and
//!   the MISP sharing block (`sharing::misp::1.0`); [`lookup`] and [`newest`]
//!   answer from it, the newest being what `new` and the templates write.
//! - [`dispatch`]: `metadata.schema` first, then that revision's conversion
//!   and checks. A revision of the expected family that the registry does not
//!   hold is checked against the family's newest revision without the
//!   unknown-key check, and keeps its finding at `metadata.schema`.
//!
//! The forward migrations between revisions are [`crate::migration`]'s.

pub mod dispatch;
mod id;

#[cfg(test)]
mod tests;

pub use dispatch::{Read, Rejection, Selection, TideObject, read, select};
pub use id::{SchemaId, SchemaIdError};

/// What a revision describes, and so where its identifier is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A Tide object file (`objects/**/*.yaml`), selected by its
    /// `metadata.schema`.
    Object,
    /// A configuration file that the oracle registers with the objects
    /// (`visibility.toml`, `visibility::1.0`); its model is
    /// [`crate::configuration`]'s.
    Configuration,
    /// A rule's platform block (`configurations.<platform>`), selected by the
    /// block's key; its models are UC-1.4's (#810).
    Platform,
    /// A sharing connector block (`[[misp]]` in `sharing.toml`); its model is
    /// [`crate::configuration::models::MispIntegration`].
    Sharing,
}

/// One registered revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Revision {
    /// The identifier, as files write it: `rule::1.1`.
    pub identifier: &'static str,
    /// What it describes.
    pub kind: Kind,
    /// The oracle's model class (`DetectionRule_v1_1`), which is also the
    /// JSON Schema's title.
    pub model: &'static str,
}

impl Revision {
    /// The identifier, parsed.
    #[expect(
        clippy::expect_used,
        reason = "every identifier of REVISIONS parses: revisions::tests::every_registered_identifier_parses_and_prints_back"
    )]
    pub fn id(&self) -> SchemaId {
        SchemaId::parse(self.identifier).expect("a registered identifier parses")
    }

    /// Whether the oracle's object registry holds it
    /// (`schema_registry.is_registered`): the identifiers `metadata.schema`
    /// accepts, [`crate::objects::checks::REGISTERED`].
    pub fn in_object_registry(&self) -> bool {
        matches!(self.kind, Kind::Object | Kind::Configuration)
    }
}

const fn revision(identifier: &'static str, kind: Kind, model: &'static str) -> Revision {
    Revision {
        identifier,
        kind,
        model,
    }
}

/// Every revision, by family and then by version: the one table the
/// registry, the dispatch and the migration chain read.
pub const REVISIONS: &[Revision] = &[
    revision("objective::1.0", Kind::Object, "DetectionObjective"),
    revision(
        "platform::carbon_black_cloud::1.0",
        Kind::Platform,
        "CarbonBlackConfig",
    ),
    revision(
        "platform::crowdstrike::1.0",
        Kind::Platform,
        "CrowdstrikeConfig",
    ),
    revision(
        "platform::defender_for_endpoint::1.0",
        Kind::Platform,
        "DefenderConfig",
    ),
    revision("platform::elastic::1.0", Kind::Platform, "ElasticConfig"),
    revision("platform::graylog::1.0", Kind::Platform, "GraylogConfig"),
    revision(
        "platform::harfanglab::1.0",
        Kind::Platform,
        "HarfangLabConfig",
    ),
    revision("platform::sentinel::1.0", Kind::Platform, "SentinelConfig"),
    revision(
        "platform::sentinel_one::1.0",
        Kind::Platform,
        "SentinelOneConfig",
    ),
    revision("platform::splunk::1.0", Kind::Platform, "SplunkConfig"),
    revision("platform::sysdig::1.0", Kind::Platform, "SysdigConfig"),
    revision("rule::1.0", Kind::Object, "DetectionRule"),
    revision("rule::1.1", Kind::Object, "DetectionRule_v1_1"),
    revision("sharing::misp::1.0", Kind::Sharing, "MispIntegration"),
    revision("threat::1.0", Kind::Object, "ThreatVector"),
    revision("visibility::1.0", Kind::Configuration, "VisibilityConfig"),
];

/// The revision an identifier names, written exactly as registered
/// (`schema_registry.resolve_model`: `Rule::1.0` and `rule::1` are not
/// registered identifiers).
pub fn lookup(identifier: &str) -> Option<&'static Revision> {
    REVISIONS
        .iter()
        .find(|revision| revision.identifier == identifier)
}

/// A family's revisions, oldest first. The family is normalised as
/// [`SchemaId`] normalises it.
pub fn revisions_of(family: &str) -> Vec<&'static Revision> {
    let family = family.trim().to_lowercase();
    let mut revisions: Vec<&'static Revision> = REVISIONS
        .iter()
        .filter(|revision| revision.id().family() == family)
        .collect();
    revisions.sort_by_key(|revision| revision.id());
    revisions
}

/// A family's newest revision (`schema_registry.latest_identifier`): what
/// `new` and the templates write, and what an unknown revision of the family
/// is checked against.
pub fn newest(family: &str) -> Option<&'static Revision> {
    revisions_of(family).pop()
}

/// The families, each once, sorted.
pub fn families() -> Vec<String> {
    let mut families: Vec<String> = REVISIONS
        .iter()
        .map(|revision| revision.id().family().to_owned())
        .collect();
    families.sort();
    families.dedup();
    families
}
