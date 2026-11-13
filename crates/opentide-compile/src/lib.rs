//! Deploy compile and plan (plan §4, `opentide-compile`; UC-3.1, #823): what
//! `opentide deploy` would send, computed locally.
//!
//! - [`strategy`]: status strategies, `--strategy`, the configured statuses.
//! - [`sentinel`], [`elastic`], [`sysdig`]: the request bodies of the platforms whose body
//!   is built from the rule alone (`compile_offline`), byte for byte the
//!   oracle's ([`json::Json`] keeps the order keys are built in).
//! - [`defender`], [`splunk`], [`sentinel_one`], [`crowdstrike`],
//!   [`harfanglab`], [`carbon_black`]: the writes a deployer sends for a rule
//!   to one tenant, built from the tenant and the deployment state
//!   ([`deploy`]: create, update or delete).
//! - [`promotion`]: the status promotion of a RELEASE deploy on a push.
//! - [`preview`]: a dry run's payload entries; for a platform the oracle
//!   shows as the block's model dump, the block serialised from
//!   opentide-schema's model.
//! - [`duration`], [`kql`], [`attack`]: what the compilers share.
//!
//! The crate does no I/O: the workspace (`opentide-workspace`) is loaded by
//! the caller.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

pub mod attack;
pub mod carbon_black;
pub mod ci;
pub mod crowdstrike;
pub mod defender;
pub mod deploy;
pub mod dry_run;
pub mod duration;
pub mod elastic;
pub mod exabeam;
pub mod generate;
pub mod git;
pub mod harfanglab;
pub mod json;
pub mod kql;
pub mod modifiers;
pub mod plan;
pub mod preview;
pub mod promotion;
pub mod rule;
pub mod sentinel;
pub mod sentinel_one;
pub mod splunk;
pub mod strategy;
pub mod sysdig;

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
    /// The resolved configuration: the platforms' tenants and modifiers,
    /// `deployment.toml` (`default_responders`).
    pub config: &'a Json,
}

/// Everything a [`Context`] borrows, owned.
pub struct Owned {
    /// The `att&ck` vocabulary.
    pub attack: attack::Attack,
    /// The configured statuses.
    pub statuses: strategy::Statuses,
    /// The resolved configuration.
    pub config: Json,
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
            config: Json::from_node(&resolved.tree),
        }
    }

    /// The context over `index`.
    pub fn context<'a>(&'a self, index: &'a Index) -> Context<'a> {
        Context {
            index,
            attack: &self.attack,
            statuses: &self.statuses,
            config: &self.config,
        }
    }
}
