//! Deploy compile and plan (plan §4, `opentide-compile`; UC-3.1, #823): what
//! `opentide deploy` would send, computed locally.
//!
//! - [`strategy`]: status strategies, `--strategy`, the configured statuses.
//! - [`sentinel`], [`elastic`]: the request bodies of the platforms whose body
//!   is built from the rule alone (`compile_offline`), byte for byte the
//!   oracle's ([`json::Json`] keeps the order keys are built in).
//! - [`preview`]: a dry run's payload entries.
//! - [`duration`], [`kql`], [`attack`]: what the compilers share.
//!
//! The crate does no I/O: the workspace (`opentide-workspace`) is loaded by
//! the caller.

pub mod attack;
pub mod dry_run;
pub mod duration;
pub mod elastic;
pub mod git;
pub mod json;
pub mod kql;
pub mod plan;
pub mod preview;
pub mod rule;
pub mod sentinel;
pub mod strategy;

pub use json::Json;
pub use rule::{CompileError, Rule};

use opentide_schema::vocab::Vocabularies;
use opentide_workspace::Index;

/// What a compiler reads besides the rule: the workspace's index (techniques
/// a rule inherits), the `att&ck` vocabulary and the configured statuses.
pub struct Context<'a> {
    /// The workspace's index.
    pub index: &'a Index,
    /// The `att&ck` vocabulary.
    pub attack: &'a attack::Attack,
    /// The configured statuses.
    pub statuses: &'a strategy::Statuses,
}

/// Everything a [`Context`] borrows, owned.
pub struct Owned {
    /// The `att&ck` vocabulary.
    pub attack: attack::Attack,
    /// The configured statuses.
    pub statuses: strategy::Statuses,
}

impl Owned {
    /// The vocabulary of `vocabularies` and the statuses of `resolved`.
    pub fn new(
        vocabularies: &Vocabularies,
        resolved: &opentide_schema::configuration::resolve::Resolved,
    ) -> Self {
        Self {
            attack: attack::Attack::new(vocabularies),
            statuses: strategy::Statuses::from_resolved(resolved),
        }
    }

    /// The context over `index`.
    pub fn context<'a>(&'a self, index: &'a Index) -> Context<'a> {
        Context {
            index,
            attack: &self.attack,
            statuses: &self.statuses,
        }
    }
}
