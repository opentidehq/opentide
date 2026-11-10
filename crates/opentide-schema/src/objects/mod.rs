//! The Tide object models (UC-1.3, #809): metadata, references, the rule's
//! response, the threat vector (`threat::1.0`), the detection objective
//! (`objective::1.0`) and the detection rule (`rule::1.0`, `rule::1.1`),
//! ported from `src/opentide/models` with their validators.
//!
//! Each model follows ADR 0001: field names, serialised names, order,
//! optional and defaulted fields, closure and `tide.*` keys are Pydantic's,
//! and each doc comment is the Python docstring, so the schema's
//! descriptions are the same text (`cargo xtask schema diff --against
//! python`). The structural conversion ([`crate::from_node`]) reads a file
//! with every error placed; garde ([`garde::Validate`]) checks a value built
//! in memory. The validators both run are in [`checks`].
//!
//! The rule's platform blocks (UC-1.4) are [`platform`]'s.

pub mod any;
pub mod checks;
pub mod metadata;
pub mod objective;
pub mod platform;
pub mod response;
pub mod role;
pub mod rule;
pub mod threat;

pub use any::Any;
pub use metadata::{ObjectMetadata, ObjectReferences, Organisation, RuleMetadata, Version};
pub use objective::{
    DetectionExample, DetectionSignal, ExternalDetector, Objective, ObjectiveBody,
    ObjectiveComposition, ObjectiveV1_0, SignalData,
};
pub use response::{ResponseProcedure, ResponseSearch, RuleResponse};
pub use role::FieldRole;
pub use rule::{Rule, RuleConfigurations, RuleV1_0, RuleV1_1};
pub use threat::{Killchain, ThreatActor, ThreatBody, ThreatVector, ThreatVectorV1_0};

#[cfg(test)]
mod table;
#[cfg(test)]
mod tests;
