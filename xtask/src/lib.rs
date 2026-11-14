//! The repository's Rust tooling, run as `cargo xtask <command>`
//! (`.cargo/config.toml`). `xtask/AGENTS.md` describes the commands.
//!
//! The library holds what the commands compute, so that tests drive it
//! without a workspace or a subprocess; `main.rs` reads the inputs and prints.

pub mod bench;
pub mod cassettes;
pub mod codegen;
pub mod conformance;
pub mod corpus;
pub mod coverage;
pub mod layers;
pub mod lsp;
pub mod mutants;
pub mod parallel;
#[cfg(unix)]
pub mod script;
pub mod spec_fields;
pub mod stubs;
pub mod vocab;
