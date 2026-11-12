//! The repository's Rust tooling, run as `cargo xtask <command>`
//! (`.cargo/config.toml`). `xtask/AGENTS.md` describes the commands.
//!
//! The library holds what the commands compute, so that tests drive it
//! without a workspace or a subprocess; `main.rs` reads the inputs and prints.

pub mod bench;
pub mod cassettes;
pub mod codegen;
pub mod compare;
pub mod config;
pub mod conformance;
pub mod corpus;
pub mod coverage;
pub mod golden;
pub mod layers;
pub mod lint;
pub mod lsp;
pub mod mcp;
pub mod mutants;
pub mod parity;
pub mod parity_inputs;
pub mod payloads;
pub mod registry;
pub mod schema;
pub mod stubs;
pub mod validate;
pub mod verdict;
pub mod vocab;
