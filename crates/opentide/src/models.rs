//! The Tide models (`schema` feature): one struct per published revision of
//! each object family, their shared parts, and the schema identifiers
//! (`rule::1.1`) that select a revision.
//!
//! Each model derives `serde` (its YAML and JSON shape, field order and
//! closure), `garde::Validate` (its constraints) and `schemars::JsonSchema`
//! (the published JSON Schema).
//!
//! ```
//! use opentide::models::SchemaId;
//!
//! let id = SchemaId::parse("rule::1.1")?;
//! assert_eq!((id.family(), id.major(), id.minor()), ("rule", 1, 1));
//! assert!(opentide::models::revision("rule::1.1").is_some());
//! # Ok::<(), opentide::models::SchemaIdError>(())
//! ```

pub use opentide_schema::objects::{
    Any, DetectionExample, DetectionSignal, ExternalDetector, Killchain, ObjectMetadata,
    ObjectReferences, Objective, ObjectiveBody, ObjectiveComposition, ObjectiveV1_0, Organisation,
    ResponseProcedure, ResponseSearch, Rule, RuleConfigurations, RuleMetadata, RuleResponse,
    RuleV1_0, RuleV1_1, SignalData, ThreatActor, ThreatBody, ThreatVector, ThreatVectorV1_0,
    Version,
};
pub use opentide_schema::revisions::{Revision, SchemaId, SchemaIdError, TideObject};
pub use opentide_schema::{SchemaError, Surface};

/// Every published revision, oldest first within each family.
pub fn revisions() -> &'static [Revision] {
    opentide_schema::revisions::REVISIONS
}

/// The revision `identifier` (`rule::1.1`) names, if it is published.
pub fn revision(identifier: &str) -> Option<&'static Revision> {
    opentide_schema::revisions::lookup(identifier)
}

/// The newest revision of `family` (`rule`, `threat`, `objective`).
pub fn newest(family: &str) -> Option<&'static Revision> {
    opentide_schema::revisions::newest(family)
}
