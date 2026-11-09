//! The repository's Rust tooling, run as `cargo xtask <command>`
//! (`.cargo/config.toml`). `xtask/AGENTS.md` describes the commands.
//!
//! The library holds what the commands compute, so that tests drive it
//! without a workspace or a subprocess; `main.rs` reads the inputs and prints.

pub mod bench;
pub mod corpus;
pub mod golden;
pub mod layers;
